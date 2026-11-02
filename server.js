'use strict';
/*
 * Squadrons Multiplayer — Phase 2 relay server (v2).
 *
 * Zero-dependency Node: static file serving + a minimal WebSocket relay
 * (the same hand-rolled framing as Phase 1), hardened for online use:
 *
 *   ROOMS       A host registers a room and gets a random 6-character
 *               room code. A guest must present that code to join.
 *               One host + one guest per room; extra joins are rejected
 *               with a clear joinError message. Rooms are isolated:
 *               traffic never crosses between rooms.
 *   HEARTBEAT   The relay pings every connection (WS ping frame) and
 *               drops any connection with no inbound traffic (message
 *               or pong) for MP_TIMEOUT_MS. The peer is notified with
 *               guestLeft / hostLeft, exactly like a clean disconnect.
 *   CAPS        Messages over MP_MAX_MSG bytes (default 256 KB) drop
 *               the connection (a WS stream cannot be resynchronised
 *               after an oversized frame). Per-connection rate limit
 *               MP_RATE_MAX messages per MP_RATE_WINDOW_MS. Malformed
 *               JSON is ignored, never fatal. Nothing a client sends
 *               can crash the relay (handlers are wrapped).
 *   TLS         If env TLS_CERT and TLS_KEY point at PEM files, the
 *               server runs HTTPS/WSS (node's built-in https); otherwise
 *               plain HTTP/WS for localhost / tunnel / Tailscale use.
 *
 * Run:  node server.js            (port: env PORT, default 8000)
 *       TLS_CERT=cert.pem TLS_KEY=key.pem node server.js
 *
 * Protocol (JSON text frames):
 *   host  -> {type:'hello', role:'host'}            (first message)
 *   relay -> host {type:'room', code:'ABC123'}
 *   guest -> {type:'join', role:'guest', race, code} (first message)
 *   relay -> guest {type:'joinError', msg}           (bad/full room)
 *   relay forwards the join to the host; afterwards all messages are
 *   forwarded verbatim within the room (start / snapshot / order /
 *   orderResult / gameOver / guestBack ...). On disconnect the relay
 *   sends the peer {type:'guestLeft'} or {type:'hostLeft'}. A guest
 *   slot frees on disconnect, so the same guest (or the same person in
 *   a new tab) can rejoin with the code while the host lives; when the
 *   host disconnects the room is destroyed and the code dies with it.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8000', 10);
const ROOT = __dirname;
const MAX_MSG = parseInt(process.env.MP_MAX_MSG || String(256 * 1024), 10);
const RATE_MAX = parseInt(process.env.MP_RATE_MAX || '300', 10);
const RATE_WINDOW = parseInt(process.env.MP_RATE_WINDOW_MS || '10000', 10);
const HEARTBEAT_MS = parseInt(process.env.MP_HEARTBEAT_MS || '10000', 10);
const TIMEOUT_MS = parseInt(process.env.MP_TIMEOUT_MS || '35000', 10);

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.md': 'text/plain; charset=utf-8' };

function staticHandler(req, res) {
  try {
    let urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    if (urlPath === '/') urlPath = '/game.html';
    const fp = path.normalize(path.join(ROOT, urlPath));
    if (!fp.startsWith(ROOT) || !fs.existsSync(fp) || fs.statSync(fp).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp).toLowerCase()] || 'application/octet-stream' });
    fs.createReadStream(fp).pipe(res);
  } catch (e) { try { res.writeHead(500); res.end('error'); } catch (e2) {} }
}

const useTls = !!(process.env.TLS_CERT && process.env.TLS_KEY);
let server;
if (useTls) {
  server = https.createServer({ cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY) }, staticHandler);
} else {
  server = http.createServer(staticHandler);
}

/* ---------------- rooms ---------------- */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; /* no 0/O/1/I/L */
const rooms = new Map(); /* code -> { host: conn|null, guest: conn|null } */
function newRoomCode() {
  let code;
  do { code = ''; for (let i = 0; i < 6; i++) code += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; } while (rooms.has(code));
  return code;
}

/* ---------------- minimal WebSocket framing (as Phase 1) ---------------- */
function wsAccept(key) { return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64'); }
function wsFrame(str) {
  const payload = Buffer.from(str, 'utf8');
  let head;
  if (payload.length < 126) { head = Buffer.alloc(2); head[1] = payload.length; }
  else if (payload.length < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(payload.length, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(payload.length), 2); }
  head[0] = 0x81;
  return Buffer.concat([head, payload]);
}
const PING_FRAME = Buffer.from([0x89, 0x00]); /* ping, empty payload */
const PONG_FRAME = Buffer.from([0x8a, 0x00]); /* pong (reply to a client ping) */

let nextId = 1;
const conns = new Set();

function sendTo(conn, obj) {
  if (!conn || conn.dead) return;
  try { conn.sock.write(wsFrame(JSON.stringify(obj))); } catch (e) { killConn(conn, 'send failed'); }
}

function cleanupRoom(conn) {
  if (!conn.room) return;
  const room = rooms.get(conn.room);
  if (!room) { conn.room = null; return; }
  if (conn.role === 'host' && room.host === conn) {
    if (room.guest) { sendTo(room.guest, { type: 'hostLeft' }); room.guest.room = null; room.guest.role = null; }
    rooms.delete(conn.room);
  } else if (conn.role === 'guest' && room.guest === conn) {
    room.guest = null;
    sendTo(room.host, { type: 'guestLeft' });
  }
  conn.room = null; conn.role = null;
}

function killConn(conn, why) {
  if (conn.dead) return;
  conn.dead = true;
  cleanupRoom(conn);
  conns.delete(conn);
  try { conn.sock.destroy(); } catch (e) {}
  console.log('[relay] conn ' + conn.id + ' dropped (' + why + ')');
}

function routeMessage(conn, msg) {
  let o = null;
  try { o = JSON.parse(msg); } catch (e) { return; } /* malformed JSON: ignore, never fatal */
  if (!o || typeof o.type !== 'string') return;
  if (!conn.role) {
    if (o.type === 'hello' && o.role === 'host') {
      const code = newRoomCode();
      rooms.set(code, { host: conn, guest: null });
      conn.role = 'host'; conn.room = code;
      sendTo(conn, { type: 'room', code });
      console.log('[relay] room ' + code + ' created by conn ' + conn.id);
    } else if (o.type === 'join' && o.role === 'guest') {
      const code = typeof o.code === 'string' ? o.code.trim().toUpperCase() : '';
      const room = code ? rooms.get(code) : null;
      if (!room || !room.host) { sendTo(conn, { type: 'joinError', msg: 'Room not found — check the code the host gave you' }); return; }
      if (room.guest) { sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' }); return; }
      room.guest = conn; conn.role = 'guest'; conn.room = code;
      sendTo(room.host, o); /* host learns the guest's race from the original join */
      console.log('[relay] guest conn ' + conn.id + ' joined room ' + code);
    }
    return; /* anything else before hello/join is ignored */
  }
  const room = rooms.get(conn.room);
  if (!room) return;
  const peer = conn.role === 'host' ? room.guest : room.host;
  if (peer && !peer.dead) { try { peer.sock.write(wsFrame(msg)); } catch (e) { killConn(peer, 'forward failed'); } }
}

server.on('upgrade', (req, sock, head) => {
  try {
    const key = req.headers['sec-websocket-key'];
    if (!key) { sock.destroy(); return; }
    sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
    const conn = { id: nextId++, sock, buf: Buffer.alloc(0), role: null, room: null, dead: false, lastSeen: Date.now(), rate: [] };
    conns.add(conn);
    sock.on('data', (chunk) => {
      if (conn.dead) return;
      conn.lastSeen = Date.now();
      conn.buf = Buffer.concat([conn.buf, chunk]);
      /* parse as many complete frames as are buffered */
      for (;;) {
        if (conn.buf.length < 2) return;
        const b0 = conn.buf[0], b1 = conn.buf[1];
        const opcode = b0 & 0x0f, masked = !!(b1 & 0x80);
        let len = b1 & 0x7f, off = 2;
        if (len === 126) { if (conn.buf.length < off + 2) return; len = conn.buf.readUInt16BE(off); off += 2; }
        else if (len === 127) { if (conn.buf.length < off + 8) return; const big = conn.buf.readBigUInt64BE(off); off += 8; if (big > BigInt(MAX_MSG)) { killConn(conn, 'oversized message'); return; } len = Number(big); }
        if (len > MAX_MSG) { killConn(conn, 'oversized message'); return; }
        if (masked) off += 4;
        if (conn.buf.length < off + len) return; /* wait for the rest */
        let payload = conn.buf.slice(off, off + len);
        if (masked) { const mask = conn.buf.slice(off - 4, off); const un = Buffer.alloc(len); for (let i = 0; i < len; i++) un[i] = payload[i] ^ mask[i & 3]; payload = un; }
        conn.buf = conn.buf.slice(off + len);
        if (opcode === 8) { killConn(conn, 'client closed'); return; }         /* close */
        if (opcode === 9) { try { sock.write(PONG_FRAME); } catch (e) {} continue; } /* ping -> pong */
        if (opcode === 10) continue;                                            /* pong: activity only */
        if (opcode !== 1) continue;                                             /* text only */
        /* per-connection rate limit (sliding window) */
        const now = Date.now();
        conn.rate = conn.rate.filter((t) => now - t < RATE_WINDOW);
        conn.rate.push(now);
        if (conn.rate.length > RATE_MAX) { killConn(conn, 'rate limit'); return; }
        try { routeMessage(conn, payload.toString('utf8')); } catch (e) { console.log('[relay] route error (ignored): ' + e.message); }
        if (conn.dead) return;
      }
    });
    sock.on('close', () => killConn(conn, 'socket closed'));
    sock.on('error', () => killConn(conn, 'socket error'));
  } catch (e) { try { sock.destroy(); } catch (e2) {} }
});

/* Heartbeat: ping everyone; reap connections silent past the timeout. */
setInterval(() => {
  const now = Date.now();
  for (const conn of Array.from(conns)) {
    if (now - conn.lastSeen > TIMEOUT_MS) { killConn(conn, 'heartbeat timeout'); continue; }
    try { conn.sock.write(PING_FRAME); } catch (e) { killConn(conn, 'ping failed'); }
  }
}, HEARTBEAT_MS);

server.listen(PORT, () => {
  console.log('[relay] Squadrons Phase 2 relay on ' + (useTls ? 'https' : 'http') + '://localhost:' + PORT + '/game.html' + (useTls ? ' (TLS on)' : ''));
  console.log('[relay] caps: max msg ' + MAX_MSG + ' B, rate ' + RATE_MAX + '/' + RATE_WINDOW + ' ms, heartbeat ' + HEARTBEAT_MS + ' ms, timeout ' + TIMEOUT_MS + ' ms');
});
