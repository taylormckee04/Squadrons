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
 *   ACCOUNTS    (Step 2: Neon Postgres + gamertags.) With env
 *               DATABASE_URL set, the relay loads the `pg` package
 *               and each signed-in connection gets a persistent
 *               profile keyed by its Google `sub`: a unique gamertag
 *               (3-16 chars, letters/numbers/underscore, uniqueness
 *               case-insensitive, first come first served). A player
 *               with no tag yet must claim one before queueing or
 *               entering a room ({type:'tag_required'}); claims and
 *               changes go through {type:'tag_claim', tag} and are
 *               answered with tag_ok / tag_error. Changing a tag
 *               releases the old name into a 30-day lock
 *               (tag_locks) during which NOBODY can claim it. Once
 *               accounts are on, other players NEVER see a Google
 *               display name: every name the relay broadcasts (queue,
 *               draft, lobbies, peer-away banners) is the gamertag,
 *               or "Player" for a player without one. FAIL SOFT: no
 *               DATABASE_URL, a missing `pg` package, or an
 *               unreachable database leaves the relay serving games
 *               exactly as before — profiles just report
 *               accountsDown and nobody is gated. (In step 2 the
 *               matches / match_players tables were created but
 *               never written; step 3 below writes them.)
 *
 *   MMR         (Step 3: queue-match records + pairwise-Elo ratings
 *               + the leaderboard.) QUEUE matches only: finishDraft
 *               stamps each seated queue match with a relay-issued
 *               matchId (rides queue_start) and remembers the human
 *               seats' identities. At match end each human client
 *               sends {type:'match_report', matchId, places, conv,
 *               stats, dur} — places = the four teams in finishing
 *               order off the deterministic end table, conv = the
 *               Option A frozen placement of any human seat whose
 *               player dropped and converted to AI, stats = the end
 *               table's per-team lines. The relay records the match
 *               when agreeing reports reach a majority of the human
 *               seats (both in a 2-human match, 2 of 3, 3 of 4 —
 *               floor(N/2)+1); disagreeing reports that can no longer
 *               reach that bar are recorded UNRATED (stats kept, no
 *               MMR movement, no games_played credit). A report is
 *               only ever accepted from a connection whose verified
 *               identity the relay itself seated in that match; the
 *               first report per player counts, duplicates are
 *               ignored, so a match is recorded at most once and MMR
 *               applied at most once. RATED recording is a single
 *               transaction: the match row, one match_players row
 *               per human (AI seats are never participants), and the
 *               MMR updates. MMR is pairwise Elo among the humans at
 *               K=32 over RECORDED placements (a converted player's
 *               frozen placement, everyone else's finishing place),
 *               deltas summed over all human pairs and rounded once;
 *               AI placements never enter the math. Each human then
 *               gets {type:'match_result', ...} for their end screen.
 *               Custom and single-player matches are never recorded.
 *               GET /leaderboard serves a plain page of gamertag /
 *               MMR / rated games / 1st places for players with at
 *               least MIN_GAMES_LEADERBOARD rated games. FAIL SOFT
 *               as accounts: no database (or one that dies before a
 *               match ends) ⇒ the match plays out normally, nothing
 *               is recorded, no rating is shown, nothing retro-fires
 *               when the database returns.
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

/* ---------------- accounts: Postgres + gamertags (step 2) ----------------
 * The relay's first dependency: `pg`, loaded ONLY when DATABASE_URL
 * is set, so a database-less deployment (including every test suite)
 * never even requires it. Everything in this section is fail-soft by
 * construction: the pool is built in a try/catch, schema creation is
 * idempotent and retried lazily, and every query path answers
 * {down:true} instead of throwing — auth, rooms and matches never
 * wait on the database except for the one profile lookup that rides
 * the (already async) sign-in, and even that settles either way.
 * Accounts code lives entirely outside the lockstep simulation. */
const DATABASE_URL = process.env.DATABASE_URL || '';
let dbPool = null;
let ACCOUNTS_ON = false;
if (DATABASE_URL) {
  let PgPoolCtor = null;
  try { PgPoolCtor = require('pg').Pool; } catch (e) { console.log('[relay] *** DATABASE_URL is set but the "pg" package is not installed — accounts OFF (run npm install); games unaffected ***'); }
  if (PgPoolCtor) {
    /* Neon (and hosted Postgres generally) needs TLS; a local test
       database does not. Honour sslmode in the URL, and treat a Neon
       host as requiring it even if the parameter was forgotten. */
    const needsSsl = /[?&]sslmode=(require|verify-ca|verify-full)/i.test(DATABASE_URL) || /(^|[.@])neon\.tech(?=[:/?]|$)/i.test(DATABASE_URL);
    try {
      const cfg = { connectionString: DATABASE_URL, max: 4, connectionTimeoutMillis: 5000, query_timeout: 5000 };
      if (needsSsl) cfg.ssl = { rejectUnauthorized: false };
      dbPool = new PgPoolCtor(cfg);
      dbPool.on('error', (e) => console.log('[relay] accounts db pool error (ignored): ' + e.message));
      ACCOUNTS_ON = true;
    } catch (e) { console.log('[relay] *** accounts OFF: unusable DATABASE_URL (' + e.message + ') — games unaffected ***'); dbPool = null; }
  }
}
const DB_SCHEMA = [
  'CREATE TABLE IF NOT EXISTS players (sub TEXT PRIMARY KEY, gamertag TEXT, tag_lower TEXT UNIQUE, mmr INTEGER NOT NULL DEFAULT 1000, games_played INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())',
  'CREATE TABLE IF NOT EXISTS tag_locks (tag_lower TEXT PRIMARY KEY, released_by TEXT, locked_until TIMESTAMPTZ NOT NULL, released_at TIMESTAMPTZ NOT NULL DEFAULT now())',
  /* Step 3 (records + MMR) writes these; creating them now means it
     extends the schema instead of migrating it. */
  'CREATE TABLE IF NOT EXISTS matches (id BIGSERIAL PRIMARY KEY, played_at TIMESTAMPTZ NOT NULL DEFAULT now(), kind TEXT NOT NULL, lineup JSONB)',
  'CREATE TABLE IF NOT EXISTS match_players (match_id BIGINT NOT NULL REFERENCES matches(id), sub TEXT NOT NULL, placement INTEGER, stats JSONB, mmr_before INTEGER, mmr_after INTEGER, PRIMARY KEY (match_id, sub))',
  /* Step 3: matches learn whether they were rated. ADD COLUMN IF NOT
     EXISTS so a database the step-2 build already created (which has
     the tables above without this column) gains it in place. */
  'ALTER TABLE matches ADD COLUMN IF NOT EXISTS rated BOOLEAN NOT NULL DEFAULT true',
  /* Amendment (Taylor, 2026-11-04): match_players learn each human's
     animal, for the leaderboard's per-animal table. Animals come from
     the relay's own lineup record — never from a client report. */
  'ALTER TABLE match_players ADD COLUMN IF NOT EXISTS animal TEXT'
];
let dbSchemaReady = false, dbInitPromise = null, dbLastAttempt = 0;
function ensureSchema() {
  if (!dbPool) return Promise.resolve(false);
  if (dbSchemaReady) return Promise.resolve(true);
  if (dbInitPromise) return dbInitPromise;
  if (Date.now() - dbLastAttempt < 5000) return Promise.resolve(false); /* do not hammer a sick database */
  dbLastAttempt = Date.now();
  dbInitPromise = (async () => {
    try {
      for (const sql of DB_SCHEMA) await dbPool.query(sql);
      dbSchemaReady = true;
      console.log('[relay] accounts database ready (players / tag_locks / matches / match_players)');
      return true;
    } catch (e) {
      console.log('[relay] accounts database unavailable: ' + e.message + ' — games continue without accounts');
      return false;
    } finally { dbInitPromise = null; }
  })();
  return dbInitPromise;
}
if (ACCOUNTS_ON) { console.log('[relay] accounts ON: gamertags via Postgres (DATABASE_URL set)'); ensureSchema(); }
else if (!DATABASE_URL) console.log('[relay] accounts off (DATABASE_URL not set) — running without gamertags');

/* Load one player's gamertag by Google sub. Never throws: a database
   problem answers {down:true}, which the caller treats as "accounts
   unavailable" (no gating, names fall back to 'Player'). */
async function dbLoadProfile(sub) {
  if (!dbPool || !(await ensureSchema())) return { down: true };
  try {
    const r = await dbPool.query('SELECT gamertag FROM players WHERE sub = $1', [sub]);
    return { tag: r.rows.length ? r.rows[0].gamertag : null };
  } catch (e) { console.log('[relay] profile lookup failed: ' + e.message); return { down: true }; }
}

const TAG_RE = /^[A-Za-z0-9_]{3,16}$/;
function tagFormatError(tag) {
  if (typeof tag !== 'string' || !tag.trim()) return 'Type a gamertag first.';
  const t = tag.trim();
  if (t.length < 3) return 'Gamertags are at least 3 characters.';
  if (t.length > 16) return 'Gamertags are at most 16 characters.';
  if (!TAG_RE.test(t)) return 'Gamertags use letters, numbers and underscores only.';
  return null;
}
/* Claim (or change to) a gamertag. One transaction: a live 30-day
   lock refuses everyone (the released name cannot be sniped — not
   even by the player who gave it up); another player's tag refuses
   as taken; claiming the tag you already hold is a friendly no-op.
   A change first locks the released name, then moves the player's
   row. The tag_lower UNIQUE constraint is the final arbiter of a
   claim race (23505 -> taken). Never throws. */
async function dbClaimTag(sub, tag) {
  if (!dbPool || !(await ensureSchema())) return { ok: false, code: 'down' };
  const lower = tag.toLowerCase();
  let client = null;
  try {
    client = await dbPool.connect();
    await client.query('BEGIN');
    const lock = await client.query('SELECT locked_until FROM tag_locks WHERE tag_lower = $1', [lower]);
    if (lock.rows.length && new Date(lock.rows[0].locked_until) > new Date()) { await client.query('ROLLBACK'); return { ok: false, code: 'locked' }; }
    const owner = await client.query('SELECT sub, gamertag FROM players WHERE tag_lower = $1', [lower]);
    if (owner.rows.length) {
      if (owner.rows[0].sub !== sub) { await client.query('ROLLBACK'); return { ok: false, code: 'taken' }; }
      await client.query('COMMIT');
      return { ok: true, tag: owner.rows[0].gamertag, same: true };
    }
    const me = await client.query('SELECT tag_lower FROM players WHERE sub = $1', [sub]);
    if (me.rows.length && me.rows[0].tag_lower && me.rows[0].tag_lower !== lower) {
      await client.query("INSERT INTO tag_locks (tag_lower, released_by, locked_until) VALUES ($1, $2, now() + interval '30 days') ON CONFLICT (tag_lower) DO UPDATE SET released_by = EXCLUDED.released_by, locked_until = EXCLUDED.locked_until, released_at = now()", [me.rows[0].tag_lower, sub]);
    }
    await client.query('INSERT INTO players (sub, gamertag, tag_lower) VALUES ($1, $2, $3) ON CONFLICT (sub) DO UPDATE SET gamertag = EXCLUDED.gamertag, tag_lower = EXCLUDED.tag_lower, updated_at = now()', [sub, tag, lower]);
    await client.query('COMMIT');
    return { ok: true, tag };
  } catch (e) {
    try { if (client) await client.query('ROLLBACK'); } catch (e2) {}
    if (e && e.code === '23505') return { ok: false, code: 'taken' };
    console.log('[relay] gamertag claim failed: ' + e.message);
    return { ok: false, code: 'down' };
  } finally { if (client) client.release(); }
}

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

function requestHandler(req, res) {
  let urlPath = '';
  try { urlPath = decodeURIComponent((req.url || '/').split('?')[0]); } catch (e) { urlPath = ''; }
  if (urlPath === '/leaderboard') { leaderboardHandler(req, res).catch((e) => { try { res.writeHead(500); res.end('error'); } catch (e2) {} }); return; }
  staticHandler(req, res);
}

const useTls = !!(process.env.TLS_CERT && process.env.TLS_KEY);
let server;
if (useTls) {
  server = https.createServer({ cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY) }, requestHandler);
} else {
  server = http.createServer(requestHandler);
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
    noteRatedSeatGone(code, 1); /* step 3: the dropped guest can no longer report */
    if (room.host) sendTo(room.host, { type: 'guestLeft' });
  } else if (room.awayHost) {
    room.awayHost = null;
    noteRatedSeatGone(code, 0); /* step 3: the dropped host can no longer report */
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
  if (role === 'host') { room.awayHost = { sub: conn.identity.sub, name: fdName(conn) }; room.host = null; }
  else { room.awayGuest = { sub: conn.identity.sub, name: fdName(conn) }; room.guest = null; }
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
    room.awaySeats[seat] = { sub: conn.identity.sub, name: fdName(conn) };
    broadcastRoom(room, seat, { type: 'peerAway', seat, role: seat === 0 ? 'host' : 'guest', name: fdName(conn), graceMs: REJOIN_GRACE_MS });
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
  noteRatedSeatGone(code, seat); /* step 3: a converted player can no longer report this match */
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
  const recMMR = ratedByRoom.get(code); /* step 3: a rejoining queue player still reports under the same matchId */
  sendTo(conn, { type: 'queue_start', role: conn.role, seat, seats: room.nSeats, room: code, lineup: room.lineup, rejoin: true, ...(recMMR ? { matchId: recMMR.id } : {}) });
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
  pushOnlineCount(); /* a departure may lower the distinct-player count */
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
      finishAuth(conn);
    } else {
      sendTo(conn, { type: 'auth_fail', reason: 'unrecognised token — dev mode accepts dev:<DisplayName>' });
    }
    return;
  }
  conn.authPending = true;
  verifyGoogleToken(token, (info) => {
    if (conn.dead) { conn.authPending = false; conn.deferred = null; return; }
    if (info) {
      conn.identity = info;
      finishAuth(conn);
    } else {
      conn.authPending = false;
      sendTo(conn, { type: 'auth_fail', reason: 'Google sign-in could not be verified' });
      replayDeferred(conn);
    }
  });
}

/* Replay the messages that arrived while an async sign-in (token
   verification, then the profile lookup) was in flight — in order,
   exactly as the pre-accounts relay did after verification. */
function replayDeferred(conn) {
  const deferred = conn.deferred || [];
  conn.deferred = null;
  for (const m of deferred) { if (conn.dead) break; try { routeMessage(conn, m); } catch (e) { console.log('[relay] route error (ignored): ' + e.message); } }
}

/* The post-auth sequence for both modes: with accounts on, the
   player's gamertag profile is loaded BEFORE auth_ok goes out and
   before any deferred message is replayed — the client sends its
   first action (a queue join, a Custom hello/join) back-to-back
   with auth, and the tag gate must already know the answer. The
   connection stays authPending through the lookup so those messages
   defer; the lookup settles either way (a database problem marks
   the profile accountsDown and auth proceeds — sign-in never hangs
   on the database). With accounts off this is the old synchronous
   auth_ok, byte for byte. */
function finishAuth(conn) {
  const complete = () => {
    conn.authPending = false;
    sendTo(conn, { type: 'auth_ok', name: conn.identity.name, picture: conn.identity.picture });
    if (ACCOUNTS_ON) { sendProfile(conn); pushOnlineCount(); }
    console.log('[relay] conn ' + conn.id + ' signed in' + (AUTH_DEV_MODE ? ' (dev)' : '') + ' as ' + conn.identity.name + (ACCOUNTS_ON ? (conn.accountsDown ? ' (accounts unavailable — playing without a gamertag)' : (conn.tag ? ' — gamertag ' + conn.tag : ' (no gamertag yet)')) : ''));
    replayDeferred(conn);
  };
  if (!ACCOUNTS_ON) { complete(); return; }
  conn.authPending = true;
  dbLoadProfile(conn.identity.sub).then((res) => {
    if (conn.dead) { conn.authPending = false; conn.deferred = null; return; }
    conn.profileKnown = true;
    conn.accountsDown = !!res.down;
    conn.tag = res.down ? null : (res.tag || null);
    complete();
  });
}
function sendProfile(conn) {
  sendTo(conn, { type: 'profile', tag: conn.tag || null, needTag: !conn.accountsDown && !conn.tag, accountsDown: !!conn.accountsDown, online: onlineCount() });
}

/* Players online (amendment, Taylor 2026-11-04): DISTINCT signed-in
   players currently connected — two sockets for one player (two
   tabs, a reconnect overlap) count once, because the count is over
   verified subs, not connections. The count rides the profile
   message at sign-in and is re-pushed to every signed-in connection
   whenever it CHANGES (sign-in settling, disconnect). Accounts-only:
   with accounts off nothing is sent, keeping the no-database relay
   byte-for-byte the step-2 behaviour. Pure relay bookkeeping —
   never in the sim or lockstep path. */
function onlineCount() {
  const subs = new Set();
  for (const c of conns) if (c.identity && !c.dead) subs.add(c.identity.sub);
  return subs.size;
}
let lastOnlineSent = -1;
function pushOnlineCount() {
  if (!ACCOUNTS_ON) return;
  const n = onlineCount();
  if (n === lastOnlineSent) return;
  lastOnlineSent = n;
  for (const c of conns) if (c.identity && !c.dead) sendTo(c, { type: 'online', count: n });
}

/* The tag gate: with accounts on and a healthy database, a signed-in
   player with no gamertag claims one before queueing or entering a
   room. Every degradation (no DATABASE_URL, database down, profile
   never loaded) leaves the gate OPEN — games always run. */
function needsTag(conn) { return ACCOUNTS_ON && !!conn.identity && conn.profileKnown && !conn.accountsDown && !conn.tag; }
function tagGate(conn) {
  if (!needsTag(conn)) return false;
  sendTo(conn, { type: 'tag_required', msg: 'Choose a gamertag before playing multiplayer — it is the name other players will see.' });
  return true;
}

/* {type:'tag_claim', tag}: first claim and later changes share this
   one path (dbClaimTag handles the released-name lock on a change).
   Relay-consumed, never forwarded; answers go to the claimer only. */
function handleTagClaim(conn, o) {
  if (!conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
  if (!ACCOUNTS_ON) { sendTo(conn, { type: 'tag_error', msg: 'Accounts are not enabled on this server, so gamertags are unavailable.' }); return; }
  if (conn.tagBusy) return; /* a double-click is one claim */
  const tag = typeof o.tag === 'string' ? o.tag.trim() : '';
  const ferr = tagFormatError(tag);
  if (ferr) { sendTo(conn, { type: 'tag_error', msg: ferr }); return; }
  conn.tagBusy = true;
  dbClaimTag(conn.identity.sub, tag).then((res) => {
    conn.tagBusy = false;
    if (conn.dead) return;
    if (res.ok) {
      conn.tag = res.tag; conn.accountsDown = false; conn.profileKnown = true;
      /* A second tab of the same player follows the change at once. */
      for (const other of conns) if (other !== conn && other.identity && other.identity.sub === conn.identity.sub && other.tag !== res.tag) { other.tag = res.tag; sendProfile(other); }
      sendTo(conn, { type: 'tag_ok', tag: res.tag });
      console.log('[relay] conn ' + conn.id + ' is now gamertag ' + res.tag);
    } else if (res.code === 'taken') sendTo(conn, { type: 'tag_error', msg: 'That gamertag is taken — try another.' });
    else if (res.code === 'locked') sendTo(conn, { type: 'tag_error', msg: 'That name was recently given up by its owner and stays locked for a while, so nobody can snatch it — try another.' });
    else sendTo(conn, { type: 'tag_error', msg: 'Accounts are unavailable right now — try again in a bit.' });
  });
}

/* ---------------- step 3: queue-match records + MMR + leaderboard ----
 * Everything in this section runs OUTSIDE the simulation and the
 * lockstep message path: reports travel client -> relay only, after
 * the match has ended on the reporting client. With accounts off the
 * section is inert — no matchIds are issued, no reports are solicited
 * and any stray one is dropped — so the relay behaves like step 2.
 *
 * The agreement rule (spec section 4): honest clients compute the
 * identical end table from the deterministic sim, so identical
 * reports are the norm. A match is recorded RATED when one report
 * shape collects at least floor(humans/2)+1 identical copies (both
 * reports in a 2-human match, 2 of 3, 3 of 4). When every seat that
 * can still report has either reported or been ruled out (its player
 * converted to AI / the room ended) and no shape reached the bar —
 * or when the settle timer below expires with at least one report in
 * hand — the match is recorded UNRATED from the most-agreed report
 * (ties: the first one received): stats kept, no MMR movement, no
 * games_played credit. With zero reports there is nothing to record
 * and the entry is simply dropped. */
const MMR_K = 32;               /* flat K-factor for v1 (spec) */
const MIN_GAMES_LEADERBOARD = 1; /* spec decision: 1 rated game to appear for now, 5 eventually (the step-3 brief calls this same constant LEADERBOARD_MIN_GAMES) */
const REPORT_SETTLE_MS = parseInt(process.env.SQ_REPORT_SETTLE_MS || '20000', 10); /* backstop: finalise from whatever reports exist this long after the first */
const ratedMatches = new Map(); /* matchId -> record (see registerRatedMatch) */
const ratedByRoom = new Map();  /* room code -> record (seat-gone hooks find it) */
let nextRatedId = 1;

function registerRatedMatch(code, lineup, players) {
  if (!ACCOUNTS_ON) return null;
  const id = 'm' + (nextRatedId++) + '-' + crypto.randomBytes(4).toString('hex');
  const rec = {
    id, code,
    lineup: { teamAnimals: lineup.teamAnimals.slice(), aiTeams: lineup.aiTeams.slice(), aiDifficulty: lineup.aiDifficulty || 'Normal' },
    humans: players.map((p, seat) => ({ seat, sub: p.identity ? p.identity.sub : null, gone: false })),
    reports: new Map(), /* sub -> { hash, report, at } */
    finalized: false, settleTimer: null,
  };
  ratedMatches.set(id, rec);
  ratedByRoom.set(code, rec);
  return rec;
}
function dropRatedMatch(rec) {
  if (rec.settleTimer) { clearTimeout(rec.settleTimer); rec.settleTimer = null; }
  ratedMatches.delete(rec.id);
  if (ratedByRoom.get(rec.code) === rec) ratedByRoom.delete(rec.code);
}
/* A seat whose player can no longer report (converted to AI at the
   grace expiry, or a legacy seat whose grace ran out): rule it out
   and re-evaluate — it may complete the "everyone who can report
   has" condition for an unrated recording. */
function noteRatedSeatGone(code, seat) {
  const rec = ratedByRoom.get(code);
  if (!rec || rec.finalized) return;
  const h = rec.humans.find((x) => x.seat === seat);
  if (h && !h.gone) { h.gone = true; evaluateRated(rec); }
}
function ratedMajority(rec) { return Math.floor(rec.humans.length / 2) + 1; }
function ratedReportShape(report) {
  /* Canonical shape for the agreement comparison: finishing order,
     the frozen placements (seat keys in numeric order), and the
     per-team stat lines. Values arrive already sanitised. */
  const conv = {};
  for (const k of Object.keys(report.conv).sort((a, b) => Number(a) - Number(b))) conv[k] = report.conv[k];
  return JSON.stringify({ places: report.places, conv, stats: report.stats, dur: report.dur });
}
function sanitizeReport(o) {
  if (!o || !Array.isArray(o.places) || o.places.length !== 4) return null;
  const places = o.places.map((v) => (typeof v === 'number' && isFinite(v)) ? Math.round(v) : -1);
  if (places.slice().sort((a, b) => a - b).join(',') !== '0,1,2,3') return null; /* must be a permutation of the four teams */
  const num = (v) => (typeof v === 'number' && isFinite(v) && v >= 0) ? Math.min(Math.round(v), 1000000000) : 0;
  const statsSrc = (o.stats && typeof o.stats === 'object') ? o.stats : {};
  const stats = {};
  for (let t = 0; t < 4; t++) {
    const s = statsSrc[t] || statsSrc[String(t)] || {};
    stats[t] = { dmg: num(s.dmg), cloudFactory: num(s.cloudFactory), cloudKill: num(s.cloudKill), bldBuilt: num(s.bldBuilt), bldDestroyed: num(s.bldDestroyed), planesProduced: num(s.planesProduced), planesLost: num(s.planesLost) };
  }
  const conv = {};
  if (o.conv && typeof o.conv === 'object') {
    for (const k of Object.keys(o.conv)) {
      const seat = Number(k), place = (typeof o.conv[k] === 'number' && isFinite(o.conv[k])) ? Math.round(o.conv[k]) : 0;
      if ((seat === 0 || seat === 1 || seat === 2 || seat === 3) && place >= 1 && place <= 4) conv[seat] = place;
    }
  }
  return { places, conv, stats, dur: num(o.dur) };
}
/* {type:'match_report', matchId, places, conv, stats, dur}: relay-
   consumed, never forwarded. Only a verified identity the relay
   itself seated in this queue match may report it, and only its
   FIRST report counts — duplicates (a second tab, a retry, a forged
   echo on another connection with the same identity) are ignored,
   which is what makes recording idempotent. */
function handleMatchReport(conn, o) {
  if (!ACCOUNTS_ON || !conn.identity || typeof o.matchId !== 'string') return;
  const rec = ratedMatches.get(o.matchId);
  if (!rec || rec.finalized) return;
  const me = rec.humans.find((h) => h.sub === conn.identity.sub);
  if (!me) return; /* not a participant the relay seated */
  if (rec.reports.has(me.sub)) return; /* first report wins */
  const report = sanitizeReport(o);
  if (!report) return;
  rec.reports.set(me.sub, { hash: ratedReportShape(report), report, at: Date.now() });
  if (!rec.settleTimer) {
    rec.settleTimer = setTimeout(() => { rec.settleTimer = null; evaluateRated(rec, true); }, REPORT_SETTLE_MS);
    if (rec.settleTimer.unref) rec.settleTimer.unref();
  }
  evaluateRated(rec, false);
}
function evaluateRated(rec, fromTimer) {
  if (rec.finalized || !ratedMatches.has(rec.id)) return;
  const need = ratedMajority(rec);
  const byHash = new Map();
  for (const entry of rec.reports.values()) {
    const cur = byHash.get(entry.hash);
    if (cur) cur.count++;
    else byHash.set(entry.hash, { count: 1, report: entry.report, at: entry.at });
  }
  let best = null;
  for (const v of byHash.values()) if (!best || v.count > best.count || (v.count === best.count && v.at < best.at)) best = v;
  if (best && best.count >= need) { finalizeRated(rec, best.report, true); return; }
  const everyoneIn = rec.humans.every((h) => h.gone || rec.reports.has(h.sub));
  if (everyoneIn || (fromTimer && rec.reports.size > 0)) {
    if (rec.reports.size > 0) finalizeRated(rec, best.report, false);
    else dropRatedMatch(rec);
  }
}
/* Placements as recorded: a converted player's FROZEN placement
   (Option A — the AI's eventual finish never changes it); everyone
   else's finishing place from the agreed report. */
function recordedPlacements(rec, report) {
  const place = {};
  for (const h of rec.humans) {
    if (Object.prototype.hasOwnProperty.call(report.conv, h.seat)) place[h.sub] = report.conv[h.seat];
    else place[h.sub] = report.places.indexOf(h.seat) + 1;
  }
  return place;
}
/* Pairwise Elo among the humans only. AI seats hold no rating and
   never enter a pair, so where an AI finished cannot move a human's
   number. Deltas are summed over all pairs and rounded once. */
function mmrDeltas(rec, place, before) {
  const deltas = {};
  for (const h of rec.humans) deltas[h.sub] = 0;
  for (let i = 0; i < rec.humans.length; i++) {
    for (let j = i + 1; j < rec.humans.length; j++) {
      const a = rec.humans[i], b = rec.humans[j];
      const ea = 1 / (1 + Math.pow(10, (before[b.sub] - before[a.sub]) / 400));
      const sa = place[a.sub] < place[b.sub] ? 1 : (place[a.sub] > place[b.sub] ? 0 : 0.5);
      deltas[a.sub] += MMR_K * (sa - ea);
      deltas[b.sub] += MMR_K * ((1 - sa) - (1 - ea));
    }
  }
  for (const h of rec.humans) deltas[h.sub] = Math.round(deltas[h.sub]);
  return deltas;
}
/* The single recording write. RATED: one transaction inserts the
   match + one match_players row per human and applies the MMR
   deltas + games_played together — it all lands or none of it does.
   Any database failure (including "the database died before this
   match ended") records NOTHING and is never retried: a match whose
   database is down at the end simply goes unrecorded. On success the
   humans still connected are told their result for the end screen. */
async function finalizeRated(rec, report, rated) {
  if (rec.finalized) return;
  rec.finalized = true;
  if (rec.settleTimer) { clearTimeout(rec.settleTimer); rec.settleTimer = null; }
  ratedMatches.delete(rec.id);
  if (ratedByRoom.get(rec.code) === rec) ratedByRoom.delete(rec.code);
  if (!dbPool || !(await ensureSchema())) { console.log('[relay] match ' + rec.id + ': not recorded (accounts database unavailable)'); return; }
  const place = recordedPlacements(rec, report);
  let client = null;
  try {
    client = await dbPool.connect();
    await client.query('BEGIN');
    const ins = await client.query('INSERT INTO matches (kind, lineup, rated) VALUES ($1, $2, $3) RETURNING id', ['queue', JSON.stringify(rec.lineup), rated]);
    const matchId = ins.rows[0].id;
    const before = {};
    for (const h of rec.humans) {
      await client.query('INSERT INTO players (sub) VALUES ($1) ON CONFLICT (sub) DO NOTHING', [h.sub]);
      const r = await client.query('SELECT mmr FROM players WHERE sub = $1 FOR UPDATE', [h.sub]);
      before[h.sub] = r.rows.length ? r.rows[0].mmr : 1000;
    }
    const deltas = rated ? mmrDeltas(rec, place, before) : {};
    for (const h of rec.humans) {
      const after = rated ? before[h.sub] + deltas[h.sub] : before[h.sub];
      if (rated) await client.query('UPDATE players SET mmr = $2, games_played = games_played + 1, updated_at = now() WHERE sub = $1', [h.sub, after]);
      await client.query('INSERT INTO match_players (match_id, sub, placement, stats, mmr_before, mmr_after, animal) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [matchId, h.sub, place[h.sub], JSON.stringify({ ...(report.stats[h.seat] || {}), dur: report.dur }), before[h.sub], after, rec.lineup.teamAnimals[h.seat] || null]);
    }
    await client.query('COMMIT');
    console.log('[relay] match ' + rec.id + ' recorded ' + (rated ? 'RATED' : 'UNRATED') + ' as match #' + matchId + ' (' + rec.humans.map((h) => 'seat ' + h.seat + ' -> ' + place[h.sub]).join(', ') + ')');
    for (const h of rec.humans) {
      for (const c of conns) {
        if (c.identity && c.identity.sub === h.sub && !c.dead) {
          if (rated) sendTo(c, { type: 'match_result', matchId: rec.id, rated: true, mmrBefore: before[h.sub], mmrAfter: before[h.sub] + deltas[h.sub], delta: deltas[h.sub] });
          else sendTo(c, { type: 'match_result', matchId: rec.id, rated: false });
        }
      }
    }
  } catch (e) {
    try { if (client) await client.query('ROLLBACK'); } catch (e2) {}
    console.log('[relay] match ' + rec.id + ': recording failed (' + e.message + ') — nothing recorded');
  } finally { if (client) client.release(); }
}

/* ---------------- leaderboard page (step 3) ----------------
 * GET /leaderboard: a plain read-only page in privacy.html's style.
 * Gamertags only — never a sub, an email, or a Google name (the
 * query does not even select them). DB trouble answers 503 with the
 * same plain page saying the board is unavailable right now; the
 * choice of 503 (over a 200 with an apology) is deliberate: the page
 * is a live view of the database, and a 503 tells search engines and
 * monitors "temporarily unavailable" instead of caching an apology
 * as if it were the board. */
function lbEscape(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function lbPage(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>Squadrons — ' + lbEscape(title) + '</title>\n<style>\n  body { background:#0d1522; color:#dbe6f5; font-family: Georgia, \'Times New Roman\', serif;\n         margin:0; padding:40px 20px 80px; line-height:1.65; }\n  main { max-width: 680px; margin: 0 auto; }\n  h1 { font-size: 30px; margin: 0 0 4px; color:#fff; }\n  h2 { font-size: 19px; margin: 30px 0 6px; color:#9fc2ee; }\n  .date { color:#8fa6c4; font-size: 14px; margin-bottom: 28px; }\n  a { color:#9fc2ee; }\n  p, li { font-size: 16px; }\n  table { border-collapse: collapse; width: 100%; margin-top: 10px; }\n  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #24344d; font-size: 16px; }\n  th { color:#9fc2ee; font-weight: normal; }\n  td.n, th.n { text-align: right; }\n</style>\n</head>\n<body>\n<main>\n' + inner + '\n</main>\n</body>\n</html>\n';
}
async function leaderboardHandler(req, res) {
  const unavailable = (why) => {
    res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(lbPage('Leaderboard', '<h1>Squadrons — Leaderboard</h1>\n<div class="date">Queue-match ratings</div>\n<p>The leaderboard is unavailable right now (' + lbEscape(why) + '). The game itself is unaffected — ratings live in the accounts database, and matches are only recorded while it is reachable.</p>\n<p><a href="/game.html">Back to the game</a></p>'));
  };
  if (!dbPool || !(await ensureSchema())) { unavailable('accounts database unreachable'); return; }
  try {
    const r = await dbPool.query(
      'SELECT p.gamertag AS tag, p.mmr AS mmr, p.games_played AS games, ' +
      '(SELECT COUNT(*)::int FROM match_players mp JOIN matches m ON m.id = mp.match_id WHERE mp.sub = p.sub AND mp.placement = 1 AND m.rated) AS wins ' +
      'FROM players p WHERE p.gamertag IS NOT NULL AND p.games_played >= $1 ' +
      'ORDER BY p.mmr DESC, p.games_played DESC, p.tag_lower ASC', [MIN_GAMES_LEADERBOARD]);
    /* Per-animal table (amendment): RATED queue matches, HUMAN
       participants only — match_players only ever holds humans, and
       the animal column is the one the relay seated them on. AI
       seats have no rows and so can never enter these numbers.
       Placements are the recorded ones, so a converted player
       counts at their frozen Option A placement. */
    const ra = await dbPool.query(
      'SELECT mp.animal AS animal, COUNT(*)::int AS games, ' +
      'SUM(CASE WHEN mp.placement = 1 THEN 1 ELSE 0 END)::int AS wins, ' +
      'SUM(CASE WHEN mp.placement <= 2 THEN 1 ELSE 0 END)::int AS top2 ' +
      'FROM match_players mp JOIN matches m ON m.id = mp.match_id WHERE m.rated AND mp.animal IS NOT NULL GROUP BY mp.animal');
    const byAnimal = {};
    let totalPlayerGames = 0;
    for (const row of ra.rows) { byAnimal[row.animal] = row; totalPlayerGames += row.games; }
    const pct = (num, den) => den > 0 ? (Math.round((num / den) * 1000) / 10).toFixed(1) + '%' : '—';
    let inner = '<h1>Squadrons — Leaderboard</h1>\n<div class="date">Queue-match ratings — everyone starts at 1000</div>\n';
    inner += '<p>Players online: ' + onlineCount() + '</p>\n';
    if (!r.rows.length) {
      inner += '<p>No rated players yet. Finish a queue match and the first names land here.</p>';
    } else {
      inner += '<table>\n<tr><th class="n">#</th><th>Player</th><th class="n">Rating</th><th class="n">Rated games</th><th class="n">1st places</th></tr>\n';
      r.rows.forEach((row, i) => { inner += '<tr><td class="n">' + (i + 1) + '</td><td>' + lbEscape(row.tag) + '</td><td class="n">' + row.mmr + '</td><td class="n">' + row.games + '</td><td class="n">' + row.wins + '</td></tr>\n'; });
      inner += '</table>\n<p>Ratings move only in queue matches. Custom games and single player are never recorded.</p>\n';
    }
    inner += '<h2>Animal stats</h2>\n<p>Rated queue matches only, human players only — the AI seats are draft leftovers, so their results say nothing about an animal. In a perfectly balanced field each animal would win about 25% of its games and finish in the top two about 50% of the time; judge every rate against the games played beside it.</p>\n';
    inner += '<table>\n<tr><th>Animal</th><th class="n">Games</th><th class="n">Pick rate</th><th class="n">Win rate</th><th class="n">Top-2 rate</th></tr>\n';
    for (const a of ANIMALS) {
      const row = byAnimal[a] || { games: 0, wins: 0, top2: 0 };
      const label = a.charAt(0).toUpperCase() + a.slice(1);
      inner += '<tr><td>' + label + '</td><td class="n">' + row.games + '</td><td class="n">' + pct(row.games, totalPlayerGames) + '</td><td class="n">' + pct(row.wins, row.games) + '</td><td class="n">' + pct(row.top2, row.games) + '</td></tr>\n';
    }
    inner += '</table>\n';
    inner += '<p><a href="/game.html">Back to the game</a></p>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(lbPage('Leaderboard', inner));
  } catch (e) { console.log('[relay] leaderboard query failed: ' + e.message); unavailable('accounts database unreachable'); }
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

/* The name OTHER players see. Once accounts are on this is the
   gamertag — or "Player" for someone without one (tag not claimed
   yet, or the database is down): a Google display name is never
   broadcast to another client again. With accounts off it is the
   pre-accounts behaviour verbatim. */
function fdName(conn) { if (ACCOUNTS_ON) return conn.tag || 'Player'; return (conn.identity && conn.identity.name) || 'Player'; }
function fdInPool(conn) { return queuePool.indexOf(conn) >= 0; }
function fdRemoveFromPool(conn) { const i = queuePool.indexOf(conn); if (i >= 0) queuePool.splice(i, 1); if (queuePool.length < 2 && fillTimer) { clearTimeout(fillTimer); fillTimer = null; } /* a dissolved group must not leave a stale deadline that matches the NEXT pair early */ }
function fdRequeueFront(conns) {
  const alive = conns.filter((c) => c && !c.dead && !c.fdMatch && !fdInPool(c));
  if (alive.length) queuePool.unshift(...alive);
}

function queueJoin(conn) {
  if (!conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
  if (tagGate(conn)) return;
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
  /* Step 3: a QUEUE match is a rated-match candidate. The relay
     registers it (accounts on only) and its id rides queue_start, so
     the end-of-match reports quote an id the relay itself issued —
     never one a client invented. Custom launches never register. */
  const ratedRec = registerRatedMatch(code, lineup, players);
  const ratedField = ratedRec ? { matchId: ratedRec.id } : {};
  if (players.length === 2) {
    /* Two humans keep the proven Stage B seating exactly: one host +
       one guest in the legacy room shape, so every pre-Stage-C flow
       (seat grace, rejoin, pairwise forwarding) behaves byte-for-byte
       as before. The seat/seats fields in queue_start are additive —
       older clients ignore them. */
    rooms.set(code, { host: players[0], guest: players[1], started: true }); /* Fix E: a seated queue match is live — seat grace applies */
    players[0].role = 'host'; players[0].room = code;
    players[1].role = 'guest'; players[1].room = code;
    sendTo(players[0], { type: 'queue_start', role: 'host', seat: 0, seats: 2, room: code, lineup, ...ratedField });
    sendTo(players[1], { type: 'queue_start', role: 'guest', seat: 1, seats: 2, room: code, lineup, ...ratedField });
  } else {
    /* Stage C: 3-4 humans get a seated room (see the Stage C room
       section above): seat i plays team i, traffic fans out, drops
       are held per seat, a no-return seat converts to AI. */
    const room = { queueRoom: true, seats: players.slice(), nSeats: players.length, started: true, awaySeats: {}, convSeats: {}, seatTimers: {}, tickHint: {}, lineup };
    rooms.set(code, room);
    players.forEach((p, i) => {
      p.role = i === 0 ? 'host' : 'guest'; p.room = code; p.seat = i;
      sendTo(p, { type: 'queue_start', role: p.role, seat: i, seats: players.length, room: code, lineup, ...ratedField });
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
  if (o.type === 'tag_claim') { handleTagClaim(conn, o); return; }
  if (o.type === 'match_report') { handleMatchReport(conn, o); return; }
  if (o.type === 'ready') { matchReady(conn); return; }
  if (o.type === 'draft_pick') { draftPick(conn, o); return; }
  if (!conn.role) {
    if (o.type === 'hello' && o.role === 'host') {
      if (!AUTH_DEV_MODE && !conn.identity) { sendTo(conn, { type: 'auth_required', msg: 'Please sign in first' }); return; }
      /* Accounts: a FRESH room needs a gamertag first; a reclaim
         (hello WITH a code) is never gated — it resumes a match the
         player was already in. */
      if (!(typeof o.code === 'string' && o.code) && tagGate(conn)) return;
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
      /* Accounts: a fresh join needs a gamertag first. A reclaim
         join is unaffected in practice — the seat holder's tag is
         already loaded on this connection, so the gate stays open. */
      if (tagGate(conn)) return;
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
      if (conn.identity) o.name = fdName(conn); /* the host's lobby slot shows the guest's display name (gamertag once accounts are on) */
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
    const conn = { id: nextId++, sock, buf: Buffer.alloc(0), role: null, room: null, seat: null, seatRace: null, build: null, dead: false, lastSeen: Date.now(), rate: [], identity: null, authPending: false, deferred: null, fdMatch: null, tag: null, profileKnown: false, accountsDown: false, tagBusy: false };
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
