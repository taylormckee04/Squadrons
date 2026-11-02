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
 *   FRONT DOOR  (Stage A+B, additive — everything above is unchanged.)
 *   AUTH        Clients may send {type:'auth', idToken} at any time.
 *               With env GOOGLE_CLIENT_ID set (production), the token
 *               is verified against Google's tokeninfo endpoint and the
 *               connection gains an identity {sub, name, picture};
 *               unauthenticated connections are then refused rooms and
 *               the queue with {type:'auth_required', msg:'Please sign
 *               in first'}. Without GOOGLE_CLIENT_ID the relay runs in
 *               AUTH DEV MODE (loud startup warning): tokens of the
 *               literal form 'dev:<DisplayName>' authenticate locally
 *               and custom room-code games stay ungated, exactly as
 *               before this build.
 *   QUEUE       Authenticated clients may {type:'queue_join'}; the
 *               first MATCH_HUMANS in the pool get a ready check
 *               ({type:'game_found'} -> {type:'ready'} within
 *               READY_MS), then a relay-run animal draft (unique picks,
 *               PICK_MS per turn, timeout = random remaining animal),
 *               then the relay seats both players into a normal room
 *               and hands them {type:'queue_start', ...} — from the
 *               lockstep 'start' onward a queue match is byte-for-byte
 *               a custom-game match. SQ_READY_MS / SQ_PICK_MS /
 *               SQ_FILL_MS env vars shrink the timers for tests.
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

/* ---------------- front door: auth + matchmaking (Stage A+B) ---------------- */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const AUTH_DEV_MODE = !GOOGLE_CLIENT_ID;
const READY_MS = parseInt(process.env.SQ_READY_MS || '10000', 10);   /* ready-check window */
const PICK_MS = parseInt(process.env.SQ_PICK_MS || '6000', 10);      /* per-turn draft clock */
const FILL_MS = parseInt(process.env.SQ_FILL_MS || '30000', 10);     /* Stage C fill wait (see tryMatch) */
/* Stage B scope: a queue match pairs TWO humans (teams 0-1); the other
   two teams are Normal AI, as in custom games. Stage C raises this to
   4 — the pool/matcher below is written against the constant, and the
   room seating in finishDraft is the one place that still assumes 2. */
const MATCH_HUMANS = 2;
const ANIMALS = ['hamster', 'fox', 'bunny', 'otter', 'beaver', 'turtle']; /* race keys, game order */
if (AUTH_DEV_MODE) console.log('[relay] *** AUTH DEV MODE: GOOGLE_CLIENT_ID not set — dev: tokens accepted ***');

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
  cleanupMatchmaking(conn);
  cleanupRoom(conn);
  conns.delete(conn);
  try { conn.sock.destroy(); } catch (e) {}
  console.log('[relay] conn ' + conn.id + ' dropped (' + why + ')');
}

/* ---------------- front door: identity ----------------
 * A connection carries at most one identity, set by 'auth'. In
 * production the ID token is verified with Google (tokeninfo); the
 * check is async, so messages that arrive while verification is in
 * flight are deferred and replayed in order once it settles — the
 * client sends auth and its first action back-to-back, and neither
 * may be processed before the other. In dev mode verification is
 * local and synchronous ('dev:<DisplayName>' tokens). */
function verifyGoogleToken(token, cb) {
  let done = false;
  const finish = (info) => { if (!done) { done = true; cb(info); } };
  try {
    const req = https.get('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(token), (res) => {
      let body = '';
      res.on('data', (d) => { body += d; if (body.length > 65536) { try { req.destroy(); } catch (e) {} finish(null); } });
      res.on('end', () => {
        try {
          const j = JSON.parse(body);
          const verified = j && j.aud === GOOGLE_CLIENT_ID && (j.email_verified === 'true' || j.email_verified === true) && typeof j.sub === 'string' && j.sub;
          finish(verified ? { sub: j.sub, name: j.name || j.email || 'Player', picture: j.picture || null } : null);
        } catch (e) { finish(null); }
      });
    });
    req.setTimeout(5000, () => { try { req.destroy(); } catch (e) {} finish(null); });
    req.on('error', () => finish(null));
  } catch (e) { finish(null); }
}

function handleAuth(conn, token) {
  if (typeof token !== 'string' || !token) { sendTo(conn, { type: 'auth_fail', reason: 'missing token' }); return; }
  if (AUTH_DEV_MODE) {
    if (token.indexOf('dev:') === 0) {
      const name = token.slice(4).trim().slice(0, 40);
      if (!name) { sendTo(conn, { type: 'auth_fail', reason: 'dev token needs a display name (dev:<DisplayName>)' }); return; }
      conn.identity = { sub: 'dev:' + name, name, picture: null };
      sendTo(conn, { type: 'auth_ok', name, picture: null });
      console.log('[relay] conn ' + conn.id + ' signed in (dev) as ' + name);
    } else {
      sendTo(conn, { type: 'auth_fail', reason: 'unrecognised token — dev mode accepts dev:<DisplayName>' });
    }
    return;
  }
  conn.authPending = true;
  verifyGoogleToken(token, (info) => {
    conn.authPending = false;
    if (conn.dead) { conn.deferred = null; return; }
    if (info) {
      conn.identity = info;
      sendTo(conn, { type: 'auth_ok', name: info.name, picture: info.picture });
      console.log('[relay] conn ' + conn.id + ' signed in as ' + info.name);
    } else {
      sendTo(conn, { type: 'auth_fail', reason: 'Google sign-in could not be verified' });
    }
    const deferred = conn.deferred || [];
    conn.deferred = null;
    for (const m of deferred) { if (conn.dead) break; try { routeMessage(conn, m); } catch (e) { console.log('[relay] route error (ignored): ' + e.message); } }
  });
}

/* ---------------- front door: queue + ready check + draft ----------------
 * The matcher is a small state machine over authenticated connections:
 *   pool (FIFO) -> match.phase 'ready' -> match.phase 'draft' -> room.
 * A player is in exactly one of: the pool, a match, a room, or none.
 * conn.fdMatch points at the live match object while in one. */
const queuePool = [];        /* conns waiting for a match, FIFO */
const fdMatches = new Set(); /* live ready/draft matches */
let nextMatchId = 1;
let fillTimer = null;        /* Stage C only (MATCH_HUMANS > 2) */

function fdName(conn) { return (conn.identity && conn.identity.name) || 'Player'; }
function fdInPool(conn) { return queuePool.indexOf(conn) >= 0; }
function fdRemoveFromPool(conn) { const i = queuePool.indexOf(conn); if (i >= 0) queuePool.splice(i, 1); }
function fdRequeueFront(conns) {
  const alive = conns.filter((c) => c && !c.dead && !c.fdMatch && !fdInPool(c));
  if (alive.length) queuePool.unshift(...alive);
}

function queueJoin(conn) {
  if (!conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
  if (conn.room || conn.role) { sendTo(conn, { type: 'queue_error', msg: 'Leave your current room before joining the queue' }); return; }
  if (conn.fdMatch) { sendTo(conn, { type: 'queue_error', msg: 'You are already in a match' }); return; }
  if (fdInPool(conn)) return; /* double-join is a no-op */
  queuePool.push(conn);
  console.log('[relay] conn ' + conn.id + ' (' + fdName(conn) + ') joined the queue (' + queuePool.length + ' waiting)');
  tryMatch();
}

function queueLeave(conn) {
  if (fdInPool(conn)) { fdRemoveFromPool(conn); console.log('[relay] conn ' + conn.id + ' left the queue'); return; }
  if (conn.fdMatch) fdAbandonMatch(conn.fdMatch, conn);
}

/* Pair the first MATCH_HUMANS players in the pool into a ready check.
   Players beyond them stay queued for the next match. With a future
   MATCH_HUMANS of 4, a partial group (>= 2) that waits FILL_MS would
   launch short-handed + extra AI — that branch is inert at 2. */
function tryMatch() {
  while (queuePool.length >= MATCH_HUMANS) {
    const players = queuePool.splice(0, MATCH_HUMANS);
    startReadyCheck(players);
  }
  if (MATCH_HUMANS > 2 && queuePool.length >= 2 && !fillTimer) {
    fillTimer = setTimeout(() => {
      fillTimer = null;
      if (queuePool.length >= 2 && queuePool.length < MATCH_HUMANS) startReadyCheck(queuePool.splice(0, queuePool.length));
    }, FILL_MS);
    if (fillTimer.unref) fillTimer.unref();
  }
}

function startReadyCheck(players) {
  const match = { id: nextMatchId++, players: players.slice(), phase: 'ready', readyBy: new Set(), timer: null, draft: null };
  fdMatches.add(match);
  for (const p of players) p.fdMatch = match;
  const names = players.map(fdName);
  players.forEach((p, i) => sendTo(p, { type: 'game_found', players: names, you: i, readyMs: READY_MS }));
  console.log('[relay] match ' + match.id + ': game found for ' + names.join(' vs '));
  match.timer = setTimeout(() => failReadyCheck(match, null), READY_MS);
  if (match.timer.unref) match.timer.unref();
}

/* Someone readied or the window closed: the players who DID ready go
   back to the FRONT of the queue; the others are out. `gone` is a
   player who disconnected/left (they get nothing and are simply out). */
function failReadyCheck(match, gone) {
  if (!fdMatches.has(match)) return;
  if (match.timer) { clearTimeout(match.timer); match.timer = null; }
  fdMatches.delete(match);
  const requeue = [];
  for (const p of match.players) {
    p.fdMatch = null;
    if (p === gone) continue;
    const wasReady = match.readyBy.has(p);
    sendTo(p, { type: 'ready_failed', requeued: wasReady });
    if (wasReady) requeue.push(p);
  }
  console.log('[relay] match ' + match.id + ': ready check failed (' + requeue.length + ' re-queued at the front)');
  fdRequeueFront(requeue);
  tryMatch();
}

function matchReady(conn) {
  const match = conn.fdMatch;
  if (!match || match.phase !== 'ready' || fdMatches.has(match) === false) return;
  match.readyBy.add(conn);
  if (match.readyBy.size >= match.players.length) {
    if (match.timer) { clearTimeout(match.timer); match.timer = null; }
    startDraft(match);
  }
}

function fdShuffled(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); const t = a[i]; a[i] = a[j]; a[j] = t; }
  return a;
}

function startDraft(match) {
  match.phase = 'draft';
  const order = fdShuffled(match.players);
  match.draft = { order, turn: 0, picks: new Map(), taken: new Set(), deadline: 0 };
  console.log('[relay] match ' + match.id + ': draft order is ' + order.map(fdName).join(' -> '));
  for (const p of match.players) sendTo(p, { type: 'draft_start', order: order.map(fdName), pickMs: PICK_MS, animals: ANIMALS.slice() });
  draftNextTurn(match);
}

function draftNextTurn(match) {
  const d = match.draft;
  if (d.turn >= d.order.length) { finishDraft(match); return; }
  const picker = d.order[d.turn];
  d.deadline = Date.now() + PICK_MS;
  const playerIdx = match.players.indexOf(picker);
  for (const p of match.players) sendTo(p, { type: 'draft_turn', player: playerIdx, deadline: d.deadline });
  match.timer = setTimeout(() => {
    match.timer = null;
    if (!fdMatches.has(match) || match.phase !== 'draft') return;
    const remaining = [];
    for (let i = 0; i < ANIMALS.length; i++) if (!d.taken.has(i)) remaining.push(i);
    if (!remaining.length) return;
    applyPick(match, picker, remaining[crypto.randomInt(remaining.length)], true);
  }, PICK_MS);
  if (match.timer.unref) match.timer.unref();
}

function applyPick(match, conn, animal, auto) {
  const d = match.draft;
  if (match.timer) { clearTimeout(match.timer); match.timer = null; }
  d.picks.set(conn, animal);
  d.taken.add(animal);
  const playerIdx = match.players.indexOf(conn);
  for (const p of match.players) sendTo(p, { type: 'draft_picked', player: playerIdx, animal, auto: !!auto });
  console.log('[relay] match ' + match.id + ': ' + fdName(conn) + ' picked ' + ANIMALS[animal] + (auto ? ' (auto)' : ''));
  d.turn++;
  draftNextTurn(match);
}

function draftPick(conn, o) {
  const match = conn.fdMatch;
  if (!match || match.phase !== 'draft' || !fdMatches.has(match)) return;
  const d = match.draft;
  if (d.order[d.turn] !== conn) { sendTo(conn, { type: 'draft_error', msg: 'It is not your pick yet' }); return; }
  const animal = o ? o.animal : null;
  if (typeof animal !== 'number' || animal % 1 !== 0 || animal < 0 || animal >= ANIMALS.length) { sendTo(conn, { type: 'draft_error', msg: 'Pick one of the six animals' }); return; }
  if (d.taken.has(animal)) { sendTo(conn, { type: 'draft_error', msg: ANIMALS[animal] + ' is already taken' }); return; }
  applyPick(match, conn, animal, false);
}

/* All humans have picked: the remaining teams are Normal AI with
   unique animals from the leftover pool. The player who QUEUED FIRST
   (players[0], draft order is irrelevant) hosts. The relay pre-creates
   the room and seats both connections, so from the client's 'start'
   message onward this is an ordinary custom-game room. */
function finishDraft(match) {
  fdMatches.delete(match);
  const players = match.players;
  for (const p of players) p.fdMatch = null;
  const teamAnimals = players.map((p) => ANIMALS[match.draft.picks.get(p)]);
  const leftovers = fdShuffled(ANIMALS.filter((a) => teamAnimals.indexOf(a) < 0));
  while (teamAnimals.length < 4) teamAnimals.push(leftovers[teamAnimals.length - players.length]);
  const aiTeams = [];
  for (let t = players.length; t < 4; t++) aiTeams.push(t);
  const lineup = { teamAnimals, aiTeams, aiDifficulty: 'Normal' };
  /* Room seating assumes exactly 2 humans (Stage B / MATCH_HUMANS=2):
     the lockstep room protocol is one host + one guest. */
  const code = newRoomCode();
  rooms.set(code, { host: players[0], guest: players[1] });
  players[0].role = 'host'; players[0].room = code;
  players[1].role = 'guest'; players[1].room = code;
  sendTo(players[0], { type: 'queue_start', role: 'host', room: code, lineup });
  sendTo(players[1], { type: 'queue_start', role: 'guest', room: code, lineup });
  console.log('[relay] match ' + match.id + ': queue match seated in room ' + code + ' — lineup ' + teamAnimals.join('/') + ', AI teams ' + aiTeams.join(','));
}

/* A player left or disconnected mid-match (before seating). Ready
   phase collapses like a failed ready check; a draft in progress is
   aborted and the remaining player goes back to the front of the
   queue. */
function fdAbandonMatch(match, gone) {
  if (!fdMatches.has(match)) return;
  if (match.phase === 'ready') { failReadyCheck(match, gone); return; }
  if (match.timer) { clearTimeout(match.timer); match.timer = null; }
  fdMatches.delete(match);
  const rest = [];
  for (const p of match.players) {
    p.fdMatch = null;
    if (p === gone) continue;
    sendTo(p, { type: 'draft_aborted', msg: 'The other player left — you are back in the queue.' });
    rest.push(p);
  }
  console.log('[relay] match ' + match.id + ': draft aborted, a player left');
  fdRequeueFront(rest);
  tryMatch();
}

function cleanupMatchmaking(conn) {
  fdRemoveFromPool(conn);
  if (conn.fdMatch) fdAbandonMatch(conn.fdMatch, conn);
}


function routeMessage(conn, msg) {
  let o = null;
  try { o = JSON.parse(msg); } catch (e) { return; } /* malformed JSON: ignore, never fatal */
  if (!o || typeof o.type !== 'string') return;
  /* Front-door messages are consumed by the relay, never forwarded to
     a room peer. Auth comes first — it is the only message that may
     change a connection's gate state, and a token must never leak
     across a room. While a production auth check is in flight, every
     other message waits and is replayed in order (see handleAuth). */
  if (o.type === 'auth') { handleAuth(conn, o.idToken); return; }
  if (conn.authPending) { (conn.deferred = conn.deferred || []).push(msg); return; }
  if (o.type === 'queue_join') { queueJoin(conn); return; }
  if (o.type === 'queue_leave') { queueLeave(conn); return; }
  if (o.type === 'ready') { matchReady(conn); return; }
  if (o.type === 'draft_pick') { draftPick(conn, o); return; }
  if (!conn.role) {
    if (o.type === 'hello' && o.role === 'host') {
      if (!AUTH_DEV_MODE && !conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
      const code = newRoomCode();
      rooms.set(code, { host: conn, guest: null });
      conn.role = 'host'; conn.room = code;
      sendTo(conn, { type: 'room', code });
      console.log('[relay] room ' + code + ' created by conn ' + conn.id);
    } else if (o.type === 'join' && o.role === 'guest') {
      if (!AUTH_DEV_MODE && !conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
      const code = typeof o.code === 'string' ? o.code.trim().toUpperCase() : '';
      const room = code ? rooms.get(code) : null;
      if (!room || !room.host) { sendTo(conn, { type: 'joinError', msg: 'Room not found — check the code the host gave you' }); return; }
      if (room.guest) { sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' }); return; }
      room.guest = conn; conn.role = 'guest'; conn.room = code;
      if (conn.identity) o.name = conn.identity.name; /* the host's lobby slot shows who joined */
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
    const conn = { id: nextId++, sock, buf: Buffer.alloc(0), role: null, room: null, dead: false, lastSeen: Date.now(), rate: [], identity: null, authPending: false, deferred: null, fdMatch: null };
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
