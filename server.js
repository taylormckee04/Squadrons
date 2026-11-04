'use strict';
/*
 * Squadrons Multiplayer — Phase 2 relay server (v2).
 *
 * Zero-dependency Node: static file serving + a minimal WebSocket relay
 * (the same hand-rolled framing as Phase 1), hardened for online use:
 *
 *   ROOMS       A host registers a room and gets a random 6-character
 *               room code. Guests must present that code to join.
 *               A room whose host runs the current client (it declares
 *               4 seats at creation — see CUSTOM 4 below) seats up to
 *               4 players; legacy rooms keep the classic one host +
 *               one guest shape and extra joins are rejected with a
 *               clear joinError message. Rooms are isolated: traffic
 *               never crosses between rooms.
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
 *               pool forms a ready check ({type:'game_found'} ->
 *               {type:'ready'} within READY_MS), then a relay-run
 *               animal draft (unique picks, PICK_MS per turn, timeout
 *               = random remaining animal), then the relay seats the
 *               players into a room and hands them
 *               {type:'queue_start', ...} — from the lockstep 'start'
 *               onward a queue match is byte-for-byte a custom-game
 *               match. SQ_READY_MS / SQ_PICK_MS / SQ_FILL_MS env vars
 *               shrink the timers for tests.
 *
 *   STAGE C     (4-player queue.) MATCH_HUMANS is 4: the queue launches
 *               a ready check the moment 4 players are waiting, or —
 *               once at least 2 have waited FILL_MS (20 s) — with the
 *               2-3 who are there, AI backfilling the empty teams. A
 *               2-human match keeps the EXACT Stage B seating (legacy
 *               host+guest room). 3-4 humans get a seated room
 *               (room.queueRoom): every seat's traffic fans out to the
 *               other seats, drops are held per seat for the reconnect
 *               grace, and a seat whose player never returns is
 *               announced as {type:'lsConvert', seat, tick} so every
 *               client converts that team to AI on the same tick.
 *
 *   CUSTOM 4    (4-player custom games.) The current client's host
 *               declares {type:'customCapacity', seats:4} right after
 *               creating a room, marking it multiSeat. The room keeps
 *               the legacy host+guest shape while it holds 2 players;
 *               when a THIRD join arrives pre-launch the relay promotes
 *               it to a seated room (room.customRoom, riding the Stage
 *               C seated machinery via room.queueRoom) with positional
 *               seats 0-3 and relay-owned lobby state: each player
 *               sends {type:'lobbyPick', race} for their own seat, the
 *               host sends {type:'lobbyDiff', difficulty}, and the
 *               relay broadcasts {type:'lobbyState', ...} after every
 *               change. A 5th joiner is refused ('room is full'). The
 *               host launches with {type:'customLaunch'} (2-4 humans);
 *               the relay compacts the seats, builds the lineup (human
 *               picks in seat order — duplicates allowed — then AI
 *               backfill from the unused animals at the host's chosen
 *               difficulty) and hands every seat the ordinary
 *               {type:'queue_start', ..., custom:true}, so from the
 *               start broadcast onward a custom match is
 *               indistinguishable from a queue match to the lockstep
 *               layer (fan-out, barrier, per-seat grace/reclaim, AI
 *               conversion). Pre-launch, a guest leaving frees their
 *               seat; the host leaving closes the room. No MMR or stats
 *               recording happens here — that stays queue-only.
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
/* Fix E: how long a dropped match player's seat is held for a
   reconnect before the room falls back to the old teardown. */
const REJOIN_GRACE_MS = parseInt(process.env.SQ_REJOIN_GRACE_MS || '45000', 10);

/* ---------------- front door: auth + matchmaking (Stage A+B) ---------------- */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const AUTH_DEV_MODE = !GOOGLE_CLIENT_ID;
const READY_MS = parseInt(process.env.SQ_READY_MS || '10000', 10);   /* ready-check window */
const PICK_MS = parseInt(process.env.SQ_PICK_MS || '6000', 10);      /* per-turn draft clock */
const FILL_MS = parseInt(process.env.SQ_FILL_MS || '20000', 10);    /* Stage C fill wait (see tryMatch) */
/* Stage C scope (Taylor's calls, 2026-11-03): a queue match seats up
   to FOUR humans (teams 0-3 in queue order); the queue waits FILL_MS
   (20 s) for a 4th before launching with 3 or 2 humans + AI backfill.
   The pool/matcher below is written against this constant; the room
   seating in finishDraft branches on the actual group size (2 humans
   keep the legacy host+guest room, 3-4 get a Stage C seated room). */
const MATCH_HUMANS = 4;
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

function clearAwayTimer(room) {
  if (room.awayTimer) { clearTimeout(room.awayTimer); room.awayTimer = null; }
}
/* Fix E: when a player drops out of a STARTED match, hold their seat
   for REJOIN_GRACE_MS instead of tearing the room down at once. The
   peer is told the seat is being held (peerAway); if the player
   reclaims the seat in time nothing else changes, otherwise the old
   guestLeft / hostLeft semantics run at expiry. Only authenticated
   players get a held seat — the raw protocol flows never authenticate,
   so their disconnect semantics are unchanged. */
function graceExpire(code, room) {
  room.awayTimer = null;
  if (rooms.get(code) !== room) return;
  if (room.awayGuest) {
    room.awayGuest = null;
    if (room.host) sendTo(room.host, { type: 'guestLeft' });
  } else if (room.awayHost) {
    room.awayHost = null;
    if (room.guest) {
      sendTo(room.guest, { type: 'hostLeft' });
      room.guest.room = null;
      room.guest.role = null;
      room.guest = null;
    }
    rooms.delete(code);
  }
}
function graceHold(conn, room, code) {
  const role = conn.role;
  const peer = role === 'host' ? room.guest : room.host;
  if (role === 'host') { room.awayHost = { sub: conn.identity.sub, name: conn.identity.name }; room.host = null; }
  else { room.awayGuest = { sub: conn.identity.sub, name: conn.identity.name }; room.guest = null; }
  conn.room = null;
  conn.role = null;
  sendTo(peer, { type: 'peerAway', role: role, graceMs: REJOIN_GRACE_MS });
  clearAwayTimer(room);
  room.awayTimer = setTimeout(function () { graceExpire(code, room); }, REJOIN_GRACE_MS);
  if (room.awayTimer.unref) room.awayTimer.unref();
}
function cleanupRoom(conn) {
  if (!conn.room) return;
  const room = rooms.get(conn.room);
  if (!room) { conn.room = null; return; }
  if (room.customRoom) { cleanupCustomRoom(conn, room); conn.room = null; conn.role = null; conn.seat = null; return; }
  if (room.queueRoom) { cleanupQueueSeat(conn, room); conn.room = null; conn.role = null; conn.seat = null; return; }
  /* Fix E grace: a started match with a live peer and an authenticated
     dropper -> hold the seat instead of the immediate teardown. */
  if (room.started && conn.identity && (conn.role === 'host' || conn.role === 'guest')) {
    const peerE = conn.role === 'host' ? room.guest : room.host;
    const otherAway = conn.role === 'host' ? room.awayGuest : room.awayHost;
    if (peerE && !otherAway) { const codeE = conn.room; graceHold(conn, room, codeE); return; }
  }
  if (conn.role === 'host' && room.host === conn) {
    if (room.guest) { sendTo(room.guest, { type: 'hostLeft' }); room.guest.room = null; room.guest.role = null; }
    clearAwayTimer(room);
    rooms.delete(conn.room);
  } else if (conn.role === 'guest' && room.guest === conn) {
    room.guest = null;
    sendTo(room.host, { type: 'guestLeft' });
  }
  conn.room = null; conn.role = null;
}

/* ---------------- Stage C: seated queue rooms (3-4 humans) ----------------
 * A queue room with 3-4 humans is NOT a host+guest pair: room.seats[i]
 * holds the connection playing team i (null while the seat is empty),
 * and all in-match traffic fans out to every other seat. Seat 0 is
 * the match host (it launches). Drops are held PER SEAT for the same
 * REJOIN_GRACE_MS the 2-player fix established; reclaiming is by
 * verified identity only (hello+code for seat 0, join+code for the
 * others). A seat whose player never returns converts to AI: the
 * relay announces {type:'lsConvert', seat, tick} to the remaining
 * seats, where tick is derived from the frame coverage the dropped
 * seat itself advertised — every client's present tick is bounded by
 * that coverage (the lockstep barrier), so the announced tick is
 * safely ahead of all of them and every sim switches on the same
 * tick. Rooms with 2 humans never take this shape (finishDraft keeps
 * the legacy seating), and custom rooms never do. */
function broadcastRoom(room, exceptSeat, obj) {
  for (let s = 0; s < room.seats.length; s++) {
    if (s === exceptSeat) continue;
    const c = room.seats[s];
    if (c && !c.dead) sendTo(c, obj);
  }
}
function clearSeatTimer(room, seat) {
  if (room.seatTimers && room.seatTimers[seat]) { clearTimeout(room.seatTimers[seat]); room.seatTimers[seat] = null; }
}
function cleanupQueueSeat(conn, room) {
  const seat = conn.seat;
  if (seat == null || room.seats[seat] !== conn) return;
  const code = conn.room;
  room.seats[seat] = null;
  const othersLive = room.seats.some((c) => c && !c.dead);
  if (room.started && conn.identity && othersLive && !room.convSeats[seat]) {
    /* Hold the seat for the reconnect grace, exactly like the
       2-player rule — just per seat, with the others notified. */
    room.awaySeats[seat] = { sub: conn.identity.sub, name: conn.identity.name };
    broadcastRoom(room, seat, { type: 'peerAway', seat, role: seat === 0 ? 'host' : 'guest', name: conn.identity.name, graceMs: REJOIN_GRACE_MS });
    clearSeatTimer(room, seat);
    room.seatTimers[seat] = setTimeout(function () { convertSeat(code, room, seat); }, REJOIN_GRACE_MS);
    if (room.seatTimers[seat].unref) room.seatTimers[seat].unref();
    console.log('[relay] queue room ' + code + ': seat ' + seat + ' (' + conn.identity.name + ') dropped — held for the reconnect grace');
  } else if (!othersLive && !Object.keys(room.awaySeats).length) {
    for (const k of Object.keys(room.seatTimers)) clearSeatTimer(room, parseInt(k, 10));
    rooms.delete(code);
    console.log('[relay] queue room ' + code + ' closed (nobody left)');
  }
}
function convertSeat(code, room, seat) {
  room.seatTimers[seat] = null;
  if (rooms.get(code) !== room) return;
  if (!room.awaySeats[seat]) return; /* reclaimed in time after all */
  delete room.awaySeats[seat];
  room.convSeats[seat] = true;
  /* tickHint[seat] is the dropped seat's last advertised frame
     coverage (upto = its tick + input delay - 1). Every remaining
     client's tick is <= hint + 1 by the barrier, so +150 ticks of
     margin puts the conversion safely in everyone's future while
     arriving soon enough to matter (5 s of game time). */
  const hint = (typeof room.tickHint[seat] === 'number') ? room.tickHint[seat] : Math.max(-1, ...Object.values(room.tickHint));
  const tick = hint + 151;
  broadcastRoom(room, -1, { type: 'lsConvert', seat, tick });
  console.log('[relay] queue room ' + code + ': seat ' + seat + ' did not return — its team converts to AI at tick ' + tick);
  if (!room.seats.some((c) => c) && !Object.keys(room.awaySeats).length) rooms.delete(code);
}
function reclaimQueueSeat(conn, room, code, seat) {
  clearSeatTimer(room, seat);
  delete room.awaySeats[seat];
  room.seats[seat] = conn;
  conn.role = seat === 0 ? 'host' : 'guest';
  conn.room = code;
  conn.seat = seat;
  sendTo(conn, { type: 'queue_start', role: conn.role, seat, seats: room.nSeats, room: code, lineup: room.lineup, rejoin: true });
  broadcastRoom(room, seat, { type: 'peerRejoin', seat });
  console.log('[relay] queue room ' + code + ': seat ' + seat + ' reclaimed by conn ' + conn.id + ' within the reconnect grace');
}
function forwardQueueRoom(conn, room, o, msg) {
  /* Addressed heal traffic goes ONLY to its target seat. (The
     clients also guard on `to`, but fanning a snapshot out to
     every seat wastes the room's bandwidth and hands uninvolved
     clients state they must never act on.) */
  if ((o.type === 'lsSnap' || o.type === 'lsSnapChunk') && typeof o.to === 'number') {
    const t = room.seats[o.to];
    if (t && !t.dead && t.sock) { try { t.sock.write(wsFrame(msg)); } catch (e) { killConn(t, 'forward failed'); } }
    return;
  }
  /* Track how far each seat has advertised (frame coverage / hash
     checkpoints): convertSeat reads the dropped seat's own hint to
     pick a conversion tick ahead of every client's present tick. */
  if (conn.seat != null) {
    if (o.type === 'lsFrame' && typeof o.upto === 'number') room.tickHint[conn.seat] = Math.max(room.tickHint[conn.seat] || -1, o.upto);
    else if (o.type === 'lsHash' && typeof o.tick === 'number') room.tickHint[conn.seat] = Math.max(room.tickHint[conn.seat] || -1, o.tick);
  }
  for (let s = 0; s < room.seats.length; s++) {
    if (s === conn.seat) continue;
    const peer = room.seats[s];
    if (peer && !peer.dead) { try { peer.sock.write(wsFrame(msg)); } catch (e) { killConn(peer, 'forward failed'); } }
  }
}

/* ---------------- Custom 4: 4-player room-code games ----------------
 * See the header's CUSTOM 4 section. A custom room is legacy-shaped
 * (room.host / room.guest) until a third player joins pre-launch;
 * promotion converts it in place to the seated shape and sets BOTH
 * room.customRoom (lobby ownership + cleanup semantics) and
 * room.queueRoom (so forwardQueueRoom / cleanupQueueSeat /
 * reclaimQueueSeat / convertSeat serve the started match verbatim).
 * Seats are positional with holes while the lobby fills; the launch
 * compacts them, so a started custom room is indistinguishable from
 * a queue room. Lobby state is relay-owned (names from verified
 * identities, picks/difficulty from the seat holders) and rebroadcast
 * in full after every change — clients render it verbatim. */
const CUSTOM_DIFFS = ['easy', 'normal', 'hard', 'nightmare'];

function lobbyStateFor(room, you) {
  const seats = [];
  for (let s = 0; s < 4; s++) {
    const c = room.seats[s];
    seats.push(c ? { name: fdName(c), race: ANIMALS.indexOf(c.seatRace) >= 0 ? c.seatRace : 'fox', build: c.build || null } : null);
  }
  return { type: 'lobbyState', you, difficulty: CUSTOM_DIFFS.indexOf(room.difficulty) >= 0 ? room.difficulty : 'normal', seats };
}
function broadcastLobbyState(room) {
  for (let s = 0; s < 4; s++) {
    const c = room.seats[s];
    if (c && !c.dead) sendTo(c, lobbyStateFor(room, s));
  }
}
function promoteCustomRoom(room, code) {
  const host = room.host, guest = room.guest;
  room.customRoom = true;
  room.queueRoom = true; /* the started match rides the Stage C seated machinery verbatim */
  room.seats = [host, guest, null, null];
  room.nSeats = 4; /* lobby capacity; launch rewrites it to the human count */
  room.awaySeats = {}; room.convSeats = {}; room.seatTimers = {}; room.tickHint = {};
  room.lineup = null;
  if (CUSTOM_DIFFS.indexOf(room.difficulty) < 0) room.difficulty = 'normal';
  host.seat = 0; guest.seat = 1;
  room.host = null; room.guest = null; /* seating lives in room.seats from here */
  /* Both occupants learn their seat numbers; their clients answer by
     re-sending their current picks, which converges the relay's
     lobby state (and repaints every lobby) within a round trip. */
  sendTo(host, { type: 'roomSeats', seat: 0, room: code });
  sendTo(guest, { type: 'roomSeats', seat: 1, room: code });
  broadcastLobbyState(room);
  console.log('[relay] custom room ' + code + ' promoted to 4 seats (a third player joined)');
}
function seatCustomGuest(conn, room, code, o) {
  let seat = -1;
  for (let s = 1; s < 4; s++) { if (!room.seats[s]) { seat = s; break; } }
  if (seat < 0) { sendTo(conn, { type: 'joinError', msg: 'That room is full — a game seats at most 4 players' }); return; }
  room.seats[seat] = conn;
  conn.role = 'guest'; conn.room = code; conn.seat = seat;
  conn.seatRace = ANIMALS.indexOf(o && o.race) >= 0 ? o.race : 'fox';
  if (o && typeof o.build === 'string') conn.build = o.build;
  sendTo(conn, { type: 'roomSeats', seat, room: code });
  broadcastLobbyState(room);
  console.log('[relay] guest conn ' + conn.id + ' took seat ' + seat + ' in custom room ' + code);
}
function launchCustomRoom(conn, room) {
  if (room.started) return;
  const code = conn.room;
  const humans = [];
  for (let s = 0; s < 4; s++) if (room.seats[s]) humans.push(room.seats[s]);
  if (humans.length < 2) { sendTo(conn, { type: 'launchError', msg: 'You need at least one guest to launch — a custom game seats 2 to 4 players' }); return; }
  /* Lineup: the humans' own picks in seat order (duplicates allowed —
     team colours distinguish), then AI backfill from the animals no
     human picked, at the host's chosen difficulty. */
  const picks = humans.map((c) => ANIMALS.indexOf(c.seatRace) >= 0 ? c.seatRace : 'fox');
  const leftovers = fdShuffled(ANIMALS.filter((a) => picks.indexOf(a) < 0));
  const teamAnimals = picks.slice();
  while (teamAnimals.length < 4) teamAnimals.push(leftovers[teamAnimals.length - humans.length]);
  const aiTeams = [];
  for (let t = humans.length; t < 4; t++) aiTeams.push(t);
  const diffKey = CUSTOM_DIFFS.indexOf(room.difficulty) >= 0 ? room.difficulty : 'normal';
  const lineup = { teamAnimals, aiTeams, aiDifficulty: diffKey.charAt(0).toUpperCase() + diffKey.slice(1) };
  room.lineup = lineup;
  room.started = true;
  room.nSeats = humans.length;
  room.seats = humans; /* compact: seat i now plays team i, no holes */
  humans.forEach((c, i) => {
    c.seat = i; c.role = i === 0 ? 'host' : 'guest';
    sendTo(c, { type: 'queue_start', role: c.role, seat: i, seats: humans.length, room: code, lineup, custom: true });
  });
  console.log('[relay] custom room ' + code + ': launched with ' + humans.length + ' humans — lineup ' + teamAnimals.join('/') + ', AI teams ' + aiTeams.join(','));
}
function cleanupCustomRoom(conn, room) {
  const code = conn.room;
  if (room.started) { cleanupQueueSeat(conn, room); return; }
  const seat = conn.seat;
  if (seat == null || room.seats[seat] !== conn) return;
  room.seats[seat] = null;
  if (seat === 0) {
    /* The host leaving pre-launch closes the room (legacy behaviour):
       every remaining seat is told and detached. */
    for (let s = 1; s < 4; s++) {
      const c = room.seats[s];
      if (c) { sendTo(c, { type: 'hostLeft' }); c.room = null; c.role = null; c.seat = null; room.seats[s] = null; }
    }
    rooms.delete(code);
    console.log('[relay] custom room ' + code + ' closed (host left the lobby)');
  } else {
    broadcastLobbyState(room);
    console.log('[relay] custom room ' + code + ': seat ' + seat + ' freed (guest left the lobby)');
  }
}

function killConn(conn, why) {  if (conn.dead) return;
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
    /* Fix A test hook: dev:EXPIRED:<name> simulates an expired Google
       credential, so the client's stale-token recovery can be driven
       end-to-end in dev mode. */
    if (token.indexOf('dev:EXPIRED:') === 0) { sendTo(conn, { type: 'auth_fail', reason: 'Sign-in expired' }); return; }
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
let fillTimer = null;        /* the partial-group fill window (Stage C) */

function fdName(conn) { return (conn.identity && conn.identity.name) || 'Player'; }
function fdInPool(conn) { return queuePool.indexOf(conn) >= 0; }
function fdRemoveFromPool(conn) { const i = queuePool.indexOf(conn); if (i >= 0) queuePool.splice(i, 1); if (queuePool.length < 2 && fillTimer) { clearTimeout(fillTimer); fillTimer = null; } /* a dissolved group must not leave a stale deadline that matches the NEXT pair early */ }
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

/* Form a ready check from the pool: a full group of MATCH_HUMANS
   launches at once; a partial group of >= 2 that has waited FILL_MS
   launches short-handed (the remaining teams are AI). Players beyond
   a formed group stay queued for the next match. A lone player never
   starts the fill timer — they simply wait for company. */
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
  if (fillTimer) { clearTimeout(fillTimer); fillTimer = null; } /* a formed match consumes the queue group the fill timer was counting for */
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
   the room and seats the players into it, so from the client's 'start'
   message onward this is an ordinary lockstep match. */
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
  const code = newRoomCode();
  if (players.length === 2) {
    /* Two humans keep the proven Stage B seating exactly: one host +
       one guest in the legacy room shape, so every pre-Stage-C flow
       (seat grace, rejoin, pairwise forwarding) behaves byte-for-byte
       as before. The seat/seats fields in queue_start are additive —
       older clients ignore them. */
    rooms.set(code, { host: players[0], guest: players[1], started: true }); /* Fix E: a seated queue match is live — seat grace applies */
    players[0].role = 'host'; players[0].room = code;
    players[1].role = 'guest'; players[1].room = code;
    sendTo(players[0], { type: 'queue_start', role: 'host', seat: 0, seats: 2, room: code, lineup });
    sendTo(players[1], { type: 'queue_start', role: 'guest', seat: 1, seats: 2, room: code, lineup });
  } else {
    /* Stage C: 3-4 humans get a seated room (see the Stage C room
       section above): seat i plays team i, traffic fans out, drops
       are held per seat, a no-return seat converts to AI. */
    const room = { queueRoom: true, seats: players.slice(), nSeats: players.length, started: true, awaySeats: {}, convSeats: {}, seatTimers: {}, tickHint: {}, lineup };
    rooms.set(code, room);
    players.forEach((p, i) => {
      p.role = i === 0 ? 'host' : 'guest'; p.room = code; p.seat = i;
      sendTo(p, { type: 'queue_start', role: p.role, seat: i, seats: players.length, room: code, lineup });
    });
  }
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
    sendTo(p, { type: 'draft_aborted', msg: match.players.length > 2 ? 'A player left — you are back in the queue.' : 'The other player left — you are back in the queue.' });
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
      /* Fix E: hello WITH a code = a host reclaiming a seat held by
         the reconnect grace. Only the same identity may reclaim. */
      if (typeof o.code === 'string' && o.code) {
        const rcode = o.code.trim().toUpperCase();
        const rroom = rooms.get(rcode);
        if (rroom && rroom.queueRoom) {
          /* Stage C: seat 0 reclaims through hello+code, like the
             legacy host reclaim but for a seated room. */
          if (rroom.awaySeats[0] && conn.identity && conn.identity.sub === rroom.awaySeats[0].sub) {
            reclaimQueueSeat(conn, rroom, rcode, 0);
          } else {
            sendTo(conn, { type: 'joinError', msg: 'That room is gone — it cannot be rejoined' });
          }
          return;
        }
        if (rroom && rroom.awayHost && (!rroom.awayHost.sub || (conn.identity && conn.identity.sub === rroom.awayHost.sub))) {
          rroom.awayHost = null;
          clearAwayTimer(rroom);
          rroom.host = conn; conn.role = 'host'; conn.room = rcode;
          sendTo(conn, { type: 'room', code: rcode });
          if (rroom.guest) sendTo(rroom.guest, { type: 'peerBack', role: 'host' });
          console.log('[relay] host conn ' + conn.id + ' reclaimed room ' + rcode + ' within the reconnect grace');
        } else {
          sendTo(conn, { type: 'joinError', msg: 'That room is gone — it cannot be rejoined' });
        }
        return;
      }
      const code = newRoomCode();
      rooms.set(code, { host: conn, guest: null });
      conn.role = 'host'; conn.room = code;
      sendTo(conn, { type: 'room', code });
      console.log('[relay] room ' + code + ' created by conn ' + conn.id);
    } else if (o.type === 'join' && o.role === 'guest') {
      if (!AUTH_DEV_MODE && !conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
      const code = typeof o.code === 'string' ? o.code.trim().toUpperCase() : '';
      const room = code ? rooms.get(code) : null;
      if (room && room.customRoom) {
        /* Custom 4 room: while the lobby is open, a join takes the
           lowest free seat (or is refused — the room is full); once
           the match has started, a join may ONLY reclaim a seat the
           relay is holding for this verified identity (reconnect
           grace), exactly as in a queue room. */
        if (room.started) {
          let seat = -1;
          if (conn.identity) { for (const k of Object.keys(room.awaySeats)) { if (room.awaySeats[k].sub === conn.identity.sub) { seat = parseInt(k, 10); break; } } }
          if (seat >= 0) reclaimQueueSeat(conn, room, code, seat);
          else sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' });
        } else {
          seatCustomGuest(conn, room, code, o);
        }
        return;
      }
      if (room && room.queueRoom) {
        /* Stage C: every seat of a queue room was filled at draft
           time, so a join may ONLY reclaim a seat the relay is
           holding for this verified identity (reconnect grace);
           anything else is refused with the legacy full-room words. */
        let seat = -1;
        if (conn.identity) { for (const k of Object.keys(room.awaySeats)) { if (room.awaySeats[k].sub === conn.identity.sub) { seat = parseInt(k, 10); break; } } }
        if (seat > 0) reclaimQueueSeat(conn, room, code, seat);
        else sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' });
        return;
      }
      if (!room || !room.host) { sendTo(conn, { type: 'joinError', msg: 'Room not found — check the code the host gave you' }); return; }
      if (room.guest) {
        /* Custom 4: a room whose host declared 4 seats at creation
           PROMOTES on the third join instead of refusing it. Rooms
           whose host never asked keep the classic refusal exactly. */
        if (!room.started && room.multiSeat) { promoteCustomRoom(room, code); seatCustomGuest(conn, room, code, o); }
        else sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' });
        return;
      }
      /* Fix E: the guest seat may be held for a dropped player
         (reconnect grace). Only the same identity may reclaim it. */
      if (room.awayGuest) {
        if (room.awayGuest.sub && !(conn.identity && conn.identity.sub === room.awayGuest.sub)) { sendTo(conn, { type: 'joinError', msg: 'That room already has a guest' }); return; }
        room.awayGuest = null;
        clearAwayTimer(room);
        if (room.host) sendTo(room.host, { type: 'peerBack', role: 'guest' });
      }
      room.guest = conn; conn.role = 'guest'; conn.room = code;
      /* Custom 4: remember the pick + build on the connection, so a
         later promotion already knows this seat's lobby state. */
      conn.seatRace = ANIMALS.indexOf(o.race) >= 0 ? o.race : 'fox';
      if (typeof o.build === 'string') conn.build = o.build;
      if (conn.identity) o.name = conn.identity.name; /* the host's lobby slot shows who joined */
      sendTo(room.host, o); /* host learns the guest's race from the original join */
      console.log('[relay] guest conn ' + conn.id + ' joined room ' + code);
    }
    return; /* anything else before hello/join is ignored */
  }
  const room = rooms.get(conn.room);
  if (!room) return;
  if (o.type === 'customCapacity') {
    /* Custom 4: the host's client declares at room creation that
       this room may seat up to 4 (see promoteCustomRoom). Legacy
       clients never send it and their rooms stay exactly 2-player.
       Relay-consumed; never forwarded. */
    if (conn.role === 'host' && !room.started && !room.queueRoom && o.seats === 4) room.multiSeat = true;
    return;
  }
  if (room.customRoom && !room.started) {
    /* Custom 4 lobby: the relay owns lobby state. Picks/difficulty
       update the sender's seat and rebroadcast; the legacy lobby
       message shapes are accepted too (a click that raced the
       promotion notice still lands). Nothing else fans out
       pre-launch — in particular a raw 'start' cannot bypass the
       seated launch. */
    if (o.type === 'lobbyPick') { if (ANIMALS.indexOf(o.race) >= 0) { conn.seatRace = o.race; broadcastLobbyState(room); } return; }
    if (o.type === 'lobbyDiff') { if (conn.seat === 0 && CUSTOM_DIFFS.indexOf(o.difficulty) >= 0) { room.difficulty = o.difficulty; broadcastLobbyState(room); } return; }
    if (o.type === 'customLaunch') { if (conn.seat === 0) launchCustomRoom(conn, room); return; }
    if (o.type === 'race' && conn.seat > 0) { if (ANIMALS.indexOf(o.race) >= 0) { conn.seatRace = o.race; broadcastLobbyState(room); } return; }
    if (o.type === 'lobby' && conn.seat === 0) { if (ANIMALS.indexOf(o.hostRace) >= 0) conn.seatRace = o.hostRace; if (CUSTOM_DIFFS.indexOf(o.difficulty) >= 0) room.difficulty = o.difficulty; broadcastLobbyState(room); return; }
    return;
  }
  if (room.queueRoom) { forwardQueueRoom(conn, room, o, msg); return; }
  if (conn.role === 'host' && o.type === 'start') room.started = true; /* Fix E: the match is live — seat grace applies from here */
  /* Custom 4: while a multiSeat room is still in its legacy shape,
     keep the relay's copy of the lobby picks current (the host's
     'lobby' sync and the guest's 'race' changes), so a promotion
     starts from the picks everyone already sees. The messages
     themselves still forward verbatim below, exactly as before. */
  if (room.multiSeat) {
    if (conn.role === 'host' && o.type === 'lobby') { if (ANIMALS.indexOf(o.hostRace) >= 0) conn.seatRace = o.hostRace; if (CUSTOM_DIFFS.indexOf(o.difficulty) >= 0) room.difficulty = o.difficulty; }
    else if (conn.role === 'guest' && o.type === 'race' && ANIMALS.indexOf(o.race) >= 0) conn.seatRace = o.race;
  }
  const peer = conn.role === 'host' ? room.guest : room.host;
  if (peer && !peer.dead) { try { peer.sock.write(wsFrame(msg)); } catch (e) { killConn(peer, 'forward failed'); } }
}

server.on('upgrade', (req, sock, head) => {
  try {
    const key = req.headers['sec-websocket-key'];
    if (!key) { sock.destroy(); return; }
    sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
    const conn = { id: nextId++, sock, buf: Buffer.alloc(0), role: null, room: null, seat: null, seatRace: null, build: null, dead: false, lastSeen: Date.now(), rate: [], identity: null, authPending: false, deferred: null, fdMatch: null };
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
