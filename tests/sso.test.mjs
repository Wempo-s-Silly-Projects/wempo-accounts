// The phase-2 handshake routes (the Accounts side, the sign-off's §2):
// POST /api/sso/ticket (the browser's own return flow — same-origin,
// login-tier limiter, a live wa_sso_sessions session, the EXACT-MATCH
// origin allowlist, one hashed 60-second ticket) and POST /api/sso/redeem
// (the service-binding lane — the relay token as the whole auth, the stored
// hash compared, ONE guarded UPDATE as the only proof of redeem, a
// read-only identity answer). Same fakeDb + pinned-SQL style.
import test from "node:test";
import assert from "node:assert/strict";

import { dispatch, fakeDb, ORIGIN, sha256Hex, limiters } from "./harness.mjs";
import { nowSeconds } from "../api/core/crypto.mjs";
import { SSO_RETURN_ALLOWLIST, SSO_TICKET_TTL_SECONDS } from "../constants.mjs";

const RELAY_TOKEN = "relay-test-token";
const TICKET_GONE = "This sign-in ticket is no longer valid. Please sign in again.";

// The canonical ticket fixtures: the browser's cookie token (the session
// that mints tickets) and the wa_sso_sessions row it reads back through.
async function liveSession() {
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
  const row = {
    token_hash: await sha256Hex(token),
    user_id: 7,
    csrf_token: "csrf-token-abcdefghijklmnopqrstuvwxyz0123",
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    username: "wempos",
    role: "moderator",
    totp_enabled: 0,
  };
  return { row, headers: { Cookie: "wempo_account_session=" + token } };
}

function envForSession(sessionRow) {
  const env = { ...limiters() };
  env.GOOBER_DB = fakeDb([
    // The pinned session read (readSession): the expiry predicate is part of
    // the SQL, so the fake honors bound[1] — an expired row answers null.
    {
      test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      first: async (bound) =>
        sessionRow && Number(sessionRow.expires_at) > Number(bound[1]) ? sessionRow : null,
    },
    { test: (sql) => sql.includes("INSERT INTO wa_login_tickets") },
    { test: (sql) => sql.includes("DELETE FROM wa_login_tickets") },
  ]);
  return env;
}

function ticketRequest(returnOrigin, overrides = {}) {
  return new Request(ORIGIN + "/api/sso/ticket", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, ...overrides },
    body: JSON.stringify({ return: returnOrigin }),
  });
}

function redeemEnv({ changes = 1, user = null } = {}) {
  const env = { ...limiters() };
  env.RELAY_TOKEN = RELAY_TOKEN;
  env.GOOBER_DB = fakeDb([
    { test: (sql) => sql.startsWith("UPDATE wa_login_tickets"), run: async () => ({ changes }) },
    { test: (sql) => sql.includes("JOIN users u"), first: async () => user },
  ]);
  return env;
}

function redeemRequest(code, overrides = {}) {
  return new Request(ORIGIN + "/api/sso/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Relay-Token": RELAY_TOKEN, ...overrides },
    body: JSON.stringify({ code }),
  });
}

// --- POST /api/sso/ticket (the browser's lane) ---------------------------------

test("a signed-in ticket mint: hashed 60-second row + the site's own ?wt= redirect", async () => {
  for (const returnOrigin of SSO_RETURN_ALLOWLIST) {
    const { row, headers } = await liveSession();
    const env = envForSession(row);
    const t0 = nowSeconds();
    const response = await dispatch(ticketRequest(returnOrigin, headers), env);

    assert.equal(response.status, 200);
    const { redirect } = await response.json();
    assert.ok(
      redirect.startsWith(returnOrigin + "/?wt="),
      "the redirect answers the SAME allowlisted origin with the code: " + redirect,
    );
    const code = new URL(redirect).searchParams.get("wt");
    assert.match(code, /^[0-9a-f]{64}$/, "the ticket code is 32 bytes of lowercase hex");

    // Exactly one INSERT — and it stores the HASH alone: the raw code never
    // rides any bound value, the row is the logged-in member's, the return
    // site is the exact allowlisted origin, and expiry is ≤60s past mint.
    const inserts = env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO wa_login_tickets"));
    assert.equal(inserts.length, 1);
    assert.match(
      inserts[0].sql,
      /INSERT INTO wa_login_tickets \(code_hash, user_id, return_site, expires_at\) VALUES \(\?, \?, \?, \?\)/,
      "the stored form is code_hash — never a raw-column list",
    );
    assert.equal(inserts[0].bound[0], await sha256Hex(code), "the stored form IS the sha256 of the shown code");
    assert.equal(inserts[0].bound[1], 7, "the ticket belongs to the signed-in member");
    assert.equal(inserts[0].bound[2], returnOrigin, "the return site rides the row");
    const lifetime = Number(inserts[0].bound[3]) - t0;
    assert.ok(lifetime >= SSO_TICKET_TTL_SECONDS - 1 && lifetime <= SSO_TICKET_TTL_SECONDS, "expiry ≤ 60s past mint");
    assert.ok(inserts[0].bound.every((value) => value !== code), "the raw code is never stored");
    assert.ok(
      env.GOOBER_DB.executed.some((e) => e.sql.startsWith("DELETE FROM wa_login_tickets WHERE expires_at <= ?")),
      "the expired-ticket sweep rides the mint",
    );
  }
});

test("no live session → the shared 401 (no cookie, and an EXPIRED row via the SQL's own predicate)", async () => {
  const ghost = await dispatch(ticketRequest(SSO_RETURN_ALLOWLIST[0]), envForSession(null));
  assert.equal(ghost.status, 401);
  assert.deepEqual(await ghost.json(), { error: "Please sign in to do that." });

  const { row, headers } = await liveSession();
  const expired = { ...row, expires_at: nowSeconds() - 1 };
  const expiredResponse = await dispatch(ticketRequest(SSO_RETURN_ALLOWLIST[0], headers), envForSession(expired));
  assert.equal(expiredResponse.status, 401, "the pinned read's expires_at predicate decides liveness");
  assert.ok(
    !envForSession(expired).GOOBER_DB.executed.some((e) => e.sql.includes("INSERT INTO wa_login_tickets")),
    "no ticket mint ever rides a dead session",
  );
});

test("non-allowlisted returns are the shared 403 — the exact-match pin (suffix, path, case, scheme, contains near-misses)", async () => {
  const { row, headers } = await liveSession();
  const env = envForSession(row);
  // Each near-miss is what a looser predicate would admit: a subdomain-ish
  // suffix, a same-host path, a case fold, a plain/scheme downgrade, and a
  // query-soup that CONTAINS an allowlisted origin without EQUALING one.
  const nearMisses = [
    "https://wempos-forum.itswempo.workers.dev.evil.example",
    "https://wempos-forum.itswempo.workers.dev/",
    "HTTPS://WEMPOS-FORUM.ITSWEMPO.WORKERS.DEV",
    "http://wempos-forum.itswempo.workers.dev",
    "https://goobercord.itswempo.workers.dev.evil.example/?x=https://goobercord.itswempo.workers.dev",
    "https://wempos-forum.itswempo.workers.dev https://goobercord.itswempo.workers.dev",
  ];
  for (const bad of nearMisses) {
    const response = await dispatch(ticketRequest(bad, headers), env);
    assert.equal(response.status, 403, "an off-allowlist origin never mints: " + bad);
    assert.deepEqual(await response.json(), { error: "This sign-in destination is not allowed." });
  }
  assert.equal(
    env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO wa_login_tickets")).length,
    0,
    "no ticket row is ever written for a refused origin",
  );
});

test("the ticket route is the browser's flow: same-origin is a gate (missing or foreign Origin → 403)", async () => {
  const { row, headers } = await liveSession();
  const env = envForSession(row);
  for (const origin of [null, "https://else.example"]) {
    const headerBag = { ...headers, "Content-Type": "application/json" };
    if (origin) headerBag.Origin = origin;
    const response = await dispatch(
      new Request(ORIGIN + "/api/sso/ticket", {
        method: "POST",
        headers: headerBag,
        body: JSON.stringify({ return: SSO_RETURN_ALLOWLIST[1] }),
      }),
      env,
    );
    assert.equal(response.status, 403, "an unverifiable origin is refused, with and without the header");
    assert.equal(
      env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO wa_login_tickets")).length,
      0,
      "no mint rides an unverifiable origin",
    );
  }
});

// --- POST /api/sso/redeem (the service-binding lane) ---------------------------

test("a live redeem: ONE guarded UPDATE, identity read from the users row, never written", async () => {
  const user = { id: 7, username: "wempos", role: "moderator" };
  const env = redeemEnv({ changes: 1, user });
  const t0 = nowSeconds();
  // The sites' workers echo the literal code; the normalize (trim + lowercase)
  // pins here too — an honest paste with padding and case folds still hashes
  // to the canonical stored form.
  const code = "  " + "ab".repeat(32).toUpperCase() + "  ";
  const response = await dispatch(
    redeemRequest(code, { "X-Relay-Worker": "wempos-forum" }),
    env,
  );

  assert.equal(response.status, 200, "no browser gates (Origin is expected absent on the binding lane)");
  assert.deepEqual(await response.json(), { userId: 7, username: "wempos", role: "admin" },
    "the stored tier renders through publicRole, identity columns only");

  const updates = env.GOOBER_DB.executed.filter((e) => e.sql.startsWith("UPDATE wa_login_tickets"));
  assert.equal(updates.length, 1);
  assert.match(
    updates[0].sql,
    /UPDATE wa_login_tickets SET redeemed_at = \?, redeemed_by = \? WHERE code_hash = \? AND redeemed_at IS NULL AND expires_at > \?/,
    "the one-time/expiry predicates ride the SAME UPDATE's WHERE — changes==1 is the only proof",
  );
  assert.equal(updates[0].bound[0] >= t0, true, "redeemed_at is the redeem moment");
  assert.equal(updates[0].bound[1], "wempos-forum", "the calling worker's stamp rides the row");
  assert.equal(updates[0].bound[2], await sha256Hex(code.trim().toLowerCase()), "the comparison key is the stored hash");
  assert.equal(updates[0].bound[3] >= t0, true, "the expiry predicate binds the redeem moment");

  const identities = env.GOOBER_DB.executed.filter((e) => e.sql.includes("JOIN users u"));
  assert.equal(identities.length, 1, "exactly one identity read, after the guarded update");
  assert.match(identities[0].sql, /SELECT u\.id, u\.username, u\.role/, "identity columns only");
});

test("a junk/absent worker stamp is stored as 'unknown' — the header shape is all it is trusted for", async () => {
  const user = { id: 9, username: "goober", role: "member" };
  for (const stamp of ["../etc/passwd", "x".repeat(65), "", undefined]) {
    const env = redeemEnv({ changes: 1, user });
    const overrides = {};
    if (stamp !== undefined) overrides["X-Relay-Worker"] = stamp;
    const response = await dispatch(redeemRequest("ab".repeat(32), overrides), env);
    assert.equal(response.status, 200);
    const updates = env.GOOBER_DB.executed.filter((e) => e.sql.startsWith("UPDATE wa_login_tickets"));
    assert.equal(updates[0].bound[1], "unknown", "a non-slug stamp never enters the row as-is");
  }
});

test("the guard refusing (expired OR already-redeemed OR unknown code) is the shared 410 — and the identity is never read", async () => {
  for (const why of ["expired", "double-redeem"]) {
    const env = redeemEnv({ changes: 0, user: { id: 7, username: "wempos", role: "moderator" } });
    const response = await dispatch(redeemRequest("ab".repeat(32)), env);
    assert.equal(response.status, 410, why + " answers 410");
    assert.deepEqual(await response.json(), { error: TICKET_GONE }, "one shared copy, no oracle for which");
    assert.equal(
      env.GOOBER_DB.executed.filter((e) => e.sql.includes("JOIN users u")).length,
      0,
      "the identity read never rides a refused redeem: " + why,
    );
  }
});

test("the relay token is the whole redeem auth: wrong, missing, or unconfigured → 401, storage untouched", async () => {
  for (const token of ["wrong-token", "", undefined]) {
    const env = redeemEnv({ changes: 1, user: { id: 7, username: "wempos", role: "moderator" } });
    const overrides = {};
    if (token !== undefined) overrides["X-Relay-Token"] = token;
    else delete overrides["X-Relay-Token"];
    if (token === "") env.RELAY_TOKEN = "";
    if (token === undefined) delete env.RELAY_TOKEN;
    const response = await dispatch(redeemRequest("ab".repeat(32), overrides), env);
    assert.equal(response.status, 401, "the presented token must equal the shared secret exactly");
    assert.deepEqual(await response.json(), { error: "Relay refused." });
    assert.equal(env.GOOBER_DB.executed.length, 0, "no statement rides an unauthenticated lane");
  }
});

test("a malformed code is a shape 400 before any storage question (and unrouted /api/sso paths still 404)", async () => {
  for (const bad of ["", "abc", "ab".repeat(31) + "a", "ab".repeat(32) + "g", "z".repeat(64)]) {
    const env = redeemEnv({});
    const response = await dispatch(redeemRequest(bad), env);
    assert.equal(response.status, 400, "non-32-byte-hex input is a 400: " + JSON.stringify(bad));
    assert.deepEqual(await response.json(), { error: "That sign-in ticket is not valid." });
    assert.equal(env.GOOBER_DB.executed.length, 0, "no statement rides a malformed code");
  }

  // Non-string bodies answer the same 400 (the normalize never sees them).
  const env = redeemEnv({});
  const numeric = new Request(ORIGIN + "/api/sso/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Relay-Token": RELAY_TOKEN },
    body: JSON.stringify({ code: 123456 }),
  });
  assert.equal((await dispatch(numeric, env)).status, 400);

  // The route space is POST-only: a GET is not an endpoint.
  const readBack = await dispatch(new Request(ORIGIN + "/api/sso/redeem"), redeemEnv({}));
  assert.equal(readBack.status, 404);
});

// --- the storage/source discipline pins -----------------------------------------

test("source pin: tickets are stored hash-only and users is a read-only FK target in the handshake", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../api/sso.mjs", import.meta.url), "utf8");

  // The raw code never has a column: the INSERT lists code_hash first and
  // the redeem keys on it; the shown bytes exist only in the redirect answer.
  assert.match(source, /INSERT INTO wa_login_tickets \(code_hash, user_id, return_site, expires_at\)/);
  assert.match(source, /WHERE code_hash = \? AND redeemed_at IS NULL AND expires_at > \?/);
  assert.ok(source.includes("sha256Hex(code)"), "every storage key is built from the hash");

  // No user data is ever concat'd into SQL: the statements are plain quoted
  // literals (no template literals anywhere in the module), the code enters
  // only as a bound hash, and users appears only in a read-only JOIN.
  assert.doesNotMatch(source, /`/, "no template literal — no interpolation can build SQL");
  assert.doesNotMatch(source, /(INSERT INTO|UPDATE|DELETE FROM)\s+users/i, "users is never written");
  assert.match(source, /JOIN users u ON u\.id = t\.user_id/, "the identity read is a JOIN over users");

  // Exactly three writes, all on Accounts' own table: the mint, the sweep,
  // and the guarded single redeem — nothing else.
  const writes = source.match(/(?:"(?:INSERT|UPDATE|DELETE)[^"]*")/g) || [];
  assert.equal(writes.length, 3, "one INSERT + one sweep DELETE + one guarded UPDATE, nothing else");
  for (const write of writes) {
    assert.ok(write.includes("wa_login_tickets"), "every write targets Accounts' own table: " + write);
  }
  assert.equal(writes[2].startsWith('"UPDATE wa_login_tickets SET redeemed_at = ?'), true, "the redeem is THE guarded one");
});

test("the allowlist constants: exactly the two member-site origins, frozen, with the 60s ticket cap", async () => {
  assert.deepEqual([...SSO_RETURN_ALLOWLIST], [
    "https://wempos-forum.itswempo.workers.dev",
    "https://goobercord.itswempo.workers.dev",
  ]);
  assert.ok(Object.isFrozen(SSO_RETURN_ALLOWLIST), "the allowlist cannot be mutated at runtime");
  assert.equal(SSO_TICKET_TTL_SECONDS, 60, "the ticket lifetime cap is 60 seconds");
});
