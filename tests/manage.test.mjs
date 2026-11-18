// Copyright 2026 ItsWempo
//
// This file is part of Wempo Accounts.
//
// Wempo Accounts is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the
// GNU Affero General Public License along with this program.  If not,
// see <https://www.gnu.org/licenses/>

// The account-management routes (the owner-approved "new account
// management" section): POST /api/password/change (the relayed two-leg
// change — verify then set, each leg strictly validated, both strict
// limiter tiers BEFORE any relay call), GET /api/sessions (the caller's
// own rows, hashed tokens never leave the worker, the current one
// flagged), POST /api/sessions/revoke (the calling row behaves exactly
// like logout) and POST /api/sessions/revoke-all (the TRUE everywhere:
// the forum relay leg deletes the member sites' shared `sessions` rows
// FIRST — fail-closed 503 on any degraded answer — then the accounts'
// own rows go, calling row included, with the still-pending tickets in
// the same breath). Same fakeDb + pinned-SQL style; the forum fake is
// harness's relayWorker (the mock FORUM_WORKER binding).
import test from "node:test";
import assert from "node:assert/strict";

import { dispatch, fakeDb, limiters, ORIGIN, relayWorker, sha256Hex } from "./harness.mjs";
import { nowSeconds } from "../api/core/crypto.mjs";

const RELAY_UNAVAILABLE = /temporarily unavailable/;
const OLD_PASSWORD = "the-old-password-1";
const NEW_PASSWORD = "the-new-password-2";

// The canonical calling-session fixtures, with the migration-0002
// per-row id (32 lowercase hex) the management answer/revocations key on.
async function liveSession(overrides = {}) {
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
  const csrfToken = "csrf-token-abcdefghijklmnopqrstuvwxyz0123";
  const sessionId = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
  const row = {
    session_id: sessionId,
    token_hash: await sha256Hex(token),
    user_id: 7,
    csrf_token: csrfToken,
    created_at: nowSeconds() - 300,
    expires_at: nowSeconds() + 3600,
    username: "wempos",
    role: "moderator",
    totp_enabled: 0,
    ...overrides,
  };
  return { token, csrfToken, sessionId, row, headers: { Cookie: "wempo_account_session=" + token } };
}

function envForSession(sessionRow, relay, extraRoutes = []) {
  const env = { ...limiters() };
  env.RELAY_TOKEN = relay.token;
  env.FORUM_WORKER = relay;
  env.GOOBER_DB = fakeDb([
    {
      test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      // The pinned read carries the expiry predicate; the fake honors
      // bound[1] so an expired row really answers null.
      first: async (bound) =>
        sessionRow && sessionRow.token_hash === bound[0] && Number(sessionRow.expires_at) > Number(bound[1])
          ? sessionRow
          : null,
    },
    ...extraRoutes,
  ]);
  return env;
}

function changeRequest(csrfToken, cookieToken) {
  return new Request(ORIGIN + "/api/password/change", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: ORIGIN,
      "X-CSRF-Token": csrfToken || "",
      Cookie: cookieToken ? "wempo_account_session=" + cookieToken : "",
    },
    body: JSON.stringify({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD }),
  });
}

// --- POST /api/password/change --------------------------------------------------

test("the success path: verify leg then set leg, one apiece, in order — and no password ever rides back", async () => {
  const { token, csrfToken, row } = await liveSession();
  const relay = relayWorker();
  const env = envForSession(row, relay);

  const response = await dispatch(changeRequest(csrfToken, token), env);

  assert.equal(response.status, 200);
  // No credential material in the answer, and no wa_ SQL ran at all — the
  // password never touches an Accounts-side table by construction.
  const answerText = await response.text();
  assert.deepEqual(JSON.parse(answerText), { changed: true });
  assert.ok(!answerText.includes(OLD_PASSWORD) && !answerText.includes(NEW_PASSWORD));

  // The legs: exactly two, verify → set, both keyed to the calling account.
  assert.equal(relay.calls.length, 2);
  const [verify, set] = relay.calls;
  assert.equal(new URL(verify.url).pathname, "/api/relay/password-verify");
  assert.deepEqual(verify.body, { username: "wempos", password: OLD_PASSWORD });
  assert.equal(new URL(set.url).pathname, "/api/relay/password-set");
  assert.deepEqual(set.body, { username: "wempos", password: NEW_PASSWORD });

  // No credential material ever rides the answer, and no SESSION WRITE ran —
  // the session join read is the only wa_ SQL the lane touches, and the
  // password never gets near an Accounts-side table by construction.
  assert.equal(env.GOOBER_DB.executed.filter((e) => e.sql.startsWith("SELECT ") && e.sql.includes("users WHERE")).length, 0);
  assert.equal(
    env.GOOBER_DB.executed.filter((e) => e.sql.includes("wa_sso_sessions") && !e.sql.includes("LEFT JOIN users u")).length,
    0,
    "no session write of any kind",
  );
});

test("a wrong current password is a clean 403 — the set leg NEVER fires, nothing changed", async () => {
  const { token, csrfToken, row } = await liveSession();
  const relay = relayWorker({ verify: false }); // the forum's own { valid: false }
  const env = envForSession(row, relay);

  const response = await dispatch(changeRequest(csrfToken, token), env);

  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "The current password is incorrect.");
  assert.equal(relay.calls.length, 1, "only the verify leg ran");
  assert.equal(new URL(relay.calls[0].url).pathname, "/api/relay/password-verify");
});

test("a degraded/refused relay on the SET leg is a fail-closed 503 — the old password stays intact", async () => {
  const { token, csrfToken, row } = await liveSession();
  const rejectedSet = relayWorker({ set: false }); // the forum answers its own 400 → a null set
  const response = await dispatch(changeRequest(csrfToken, token), envForSession(row, rejectedSet));
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, RELAY_UNAVAILABLE);
  assert.equal(rejectedSet.calls.length, 2, "both legs were attempted — the SET leg just refused");

  // An unreachable edge fails the same closed, and earlier — on the verify leg.
  const down = relayWorker({ fail: true });
  const response2 = await dispatch(changeRequest(csrfToken, token), envForSession(row, down));
  assert.equal(response2.status, 503);
  assert.match((await response2.json()).error, RELAY_UNAVAILABLE);
  assert.equal(down.calls.length, 1, "the verify leg was attempted and answered nothing");
  assert.equal(new URL(down.calls[0].url).pathname, "/api/relay/password-verify");
});

test("the strict validation: a VALID verdict naming a DIFFERENT user is never honored — 503, no set leg", async () => {
  const { token, csrfToken, row } = await liveSession();
  const relay = relayWorker({ imposter: true }); // { valid: true, user: { id: 99, ... } }
  const env = envForSession(row, relay);

  const response = await dispatch(changeRequest(csrfToken, token), env);

  assert.equal(response.status, 503, "a relay answer about anyone else is the degraded path");
  assert.match((await response.json()).error, RELAY_UNAVAILABLE);
  assert.equal(relay.calls.length, 1, "the set leg never fired on an unestablished verdict");
});

test("the strict limiter tiers answer BEFORE any relay call (an IP pass and a user-id pass)", async () => {
  const { token, csrfToken, row } = await liveSession();
  const relay = relayWorker();
  const env = envForSession(row, relay);

  // First: a satisfied pair of passes still precedes every relay leg — the
  // two calls (the IP bucket, then user:7) land with nothing asked of the
  // relay until both have answered success.
  await dispatch(changeRequest(csrfToken, token), env);
  assert.equal(env.fakes.password.calls.length, 2, "an IP pass, then a distinct account pass");
  assert.notEqual(env.fakes.password.calls[0], env.fakes.password.calls[1]);
  assert.equal(relay.calls.length, 2, "the relay legs ran only after both tiers answered success");

  // Then: a failed password bucket is a 429 with ZERO relay calls.
  const relay2 = relayWorker();
  const env2 = envForSession(row, relay2);
  env2.WA_PASSWORD_RATE_LIMITER = { async limit() { return { success: false }; } };
  const response = await dispatch(changeRequest(csrfToken, token), env2);
  assert.equal(response.status, 429);
  assert.equal(relay2.calls.length, 0);
});

test("the gate comes first: no CSRF header answers 401/403 with no relay call at all", async () => {
  const { token, row } = await liveSession();
  const relay = relayWorker();

  const noCsrf = await dispatch(changeRequest("", token), envForSession(row, relay));
  assert.ok(noCsrf.status === 401 || noCsrf.status === 403);
  assert.equal(relay.calls.length, 0);
});

// --- GET /api/sessions ----------------------------------------------------------

test("GET /api/sessions lists the caller's own live rows, flags the current one, leaks nothing secret", async () => {
  const { sessionId, row, headers } = await liveSession();
  const other = {
    session_id: "b2c3d4e5f60718293a4b5c6d7e8f90aa",
    created_at: nowSeconds() - 999,
    expires_at: row.expires_at + 60,
  };
  const malformed = { session_id: "not-a-real-id", created_at: nowSeconds() - 5, expires_at: row.expires_at + 60 };
  const env = envForSession(row, relayWorker(), [
    {
      test: (sql) => sql.startsWith("SELECT session_id, created_at, expires_at FROM wa_sso_sessions"),
      all: async (bound) => {
        assert.equal(Number(bound[0]), 7, "the list is keyed to the CALLING user only");
        return [malformed, other, row];
      },
    },
  ]);

  const response = await dispatch(new Request(ORIGIN + "/api/sessions", { headers }), env);

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.sessions.length, 2, "the row without a minted id is page-invisible (revoke-all's lane)");
  const current = body.sessions.filter((s) => s.current);
  assert.equal(current.length, 1, "exactly one row is flagged — the calling one");
  assert.equal(current[0].id, sessionId);
  const others = body.sessions.filter((s) => !s.current);
  assert.equal(others.length, 1);
  assert.equal(others[0].id, other.session_id);
  // Token hashes and CSRF tokens never leave the worker.
  const payload = JSON.stringify(body);
  assert.ok(!payload.includes(row.token_hash) && !payload.includes(row.csrf_token));
});

// --- POST /api/sessions/revoke --------------------------------------------------

function revokeRequest(sessionId, csrfToken, cookieToken) {
  return new Request(ORIGIN + "/api/sessions/revoke", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: ORIGIN,
      "X-CSRF-Token": csrfToken || "",
      Cookie: cookieToken ? "wempo_account_session=" + cookieToken : "",
    },
    body: JSON.stringify({ sessionId }),
  });
}

test("revoking the CALLING session behaves exactly like logout: the row goes, the cookie expires", async () => {
  const { token, sessionId, csrfToken, row, headers } = await liveSession();
  const env = envForSession(row, relayWorker(), [
    {
      test: (sql) => sql.startsWith("SELECT token_hash FROM wa_sso_sessions WHERE session_id"),
      first: async (bound) => {
        assert.equal(bound[0], sessionId);
        assert.equal(Number(bound[1]), 7);
        assert.ok(Number(bound[2]) >= Math.floor(Date.now() / 1000) - 1, "an expiry bound rides the WHERE");
        return { token_hash: row.token_hash };
      },
    },
    { test: (sql) => sql.startsWith("DELETE FROM wa_sso_sessions WHERE session_id") },
  ]);

  const response = await dispatch(revokeRequest(sessionId, csrfToken, token), env);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { revoked: true, signedOut: true });
  const cookie = response.headers.get("Set-Cookie");
  assert.match(cookie, /^wempo_account_session=;/);
  for (const pin of ["Max-Age=0", "HttpOnly", "SameSite=Lax"]) {
    assert.ok(cookie.includes(pin), "the expired cookie carries " + pin);
  }
  void headers;
});

test("revoking a DIFFERENT session keeps the caller signed in, keyed to the caller's own user", async () => {
  const { token, csrfToken, row, headers } = await liveSession();
  const otherId = "b2c3d4e5f60718293a4b5c6d7e8f90aa";
  const deletes = [];
  const env = envForSession(row, relayWorker(), [
    {
      test: (sql) => sql.startsWith("SELECT token_hash FROM wa_sso_sessions WHERE session_id"),
      first: async (bound) => (bound[0] === otherId ? { token_hash: "someone-elses-hash" } : null),
    },
    {
      test: (sql) => sql.startsWith("DELETE FROM wa_sso_sessions WHERE session_id"),
      run: async (bound) => {
        deletes.push(bound);
        return { changes: 1 };
      },
    },
  ]);

  const response = await dispatch(revokeRequest(otherId, csrfToken, token), env);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { revoked: true, signedOut: false });
  assert.equal(response.headers.get("Set-Cookie"), null, "no cookie expiry — the caller's row survives");
  assert.deepEqual(deletes[0], [otherId, 7], "the delete binds the row's id AND the caller's user_id");

  // A foreign/expired id is the shared "already gone" answer.
  const gone = await dispatch(revokeRequest("c".repeat(32), csrfToken, token), env);
  assert.equal(gone.status, 404);
  void headers;
});

test("revoke is shape-gated (a malformed id never reaches storage) and CSRF-gated", async () => {
  const { token, sessionId, csrfToken, row, headers } = await liveSession();
  const env = envForSession(row, relayWorker(), [
    {
      test: (sql) => sql.startsWith("DELETE") || sql.startsWith("SELECT token_hash"),
      run: async () => { throw new Error("storage must not be touched"); },
      first: async () => { throw new Error("storage must not be touched"); },
    },
  ]);

  const malformed = await dispatch(revokeRequest("z".repeat(32), csrfToken, token), env);
  assert.equal(malformed.status, 400, "the 32-hex shape gate answers before any storage question");

  const noCsrf = await dispatch(revokeRequest(sessionId, "", token), env);
  assert.ok(noCsrf.status === 401 || noCsrf.status === 403);
  void headers;
});

// --- POST /api/sessions/revoke-all ----------------------------------------------

function revokeAllRequest(csrfToken, cookieToken) {
  return new Request(ORIGIN + "/api/sessions/revoke-all", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: ORIGIN,
      "X-CSRF-Token": csrfToken || "",
      Cookie: cookieToken ? "wempo_account_session=" + cookieToken : "",
    },
    body: JSON.stringify({}),
  });
}

test("revoke-all is the TRUE everywhere: relay leg FIRST, accounts rows next (calling one included), pending tickets last", async () => {
  const { token, csrfToken, row, headers } = await liveSession();
  const order = [];
  const relay = relayWorker({ revokeAll: 2 });
  const env = envForSession(row, relay, [
    {
      test: (sql) => sql.includes("DELETE FROM wa_sso_sessions WHERE user_id = ?") && !sql.includes("token_hash <> ?"),
      run: async (bound) => {
        order.push("wa_sso_sessions");
        assert.equal(relay.calls.length, 1, "the member-sites relay leg ran BEFORE any local delete");
        assert.deepEqual(bound, [7], "user_id alone — no token_hash exemption, the calling row INCLUDED");
        return { changes: 3 };
      },
    },
    {
      test: (sql) => sql.includes("DELETE FROM wa_login_tickets WHERE user_id = ? AND redeemed_at IS NULL"),
      run: async (bound) => {
        order.push("wa_login_tickets");
        assert.deepEqual(bound, [7], "only the CALLING user's pending tickets");
        return { changes: 1 };
      },
    },
    // Any OTHER delete statement is a defect — this route never runs one.
    {
      test: (sql) => sql.startsWith("DELETE"),
      run: async () => { throw new Error("an unscoped delete must never run"); },
    },
  ]);

  const response = await dispatch(revokeAllRequest(csrfToken, token), env);

  assert.equal(response.status, 200);
  assert.deepEqual(
    await response.json(),
    { revoked: 3, sites: 2, tickets: 1, signedOut: true },
    "accounts rows + member-site rows + pending tickets, and the caller signed out",
  );
  const cookie = response.headers.get("Set-Cookie");
  assert.match(cookie, /^wempo_account_session=;/);
  for (const pin of ["Max-Age=0", "HttpOnly", "SameSite=Lax"]) {
    assert.ok(cookie.includes(pin), "the expired cookie carries " + pin);
  }
  // The relay leg: exactly one call, user_id-keyed body, before the locals.
  assert.equal(relay.calls.length, 1);
  assert.equal(new URL(relay.calls[0].url).pathname, "/api/relay/session-revoke-all");
  assert.deepEqual(relay.calls[0].body, { userId: 7 });
  assert.deepEqual(order, ["wa_sso_sessions", "wa_login_tickets"], "accounts rows, then the ticket sweep");
  void headers;
});

test("a degraded/refused relay leg fails revoke-all CLOSED (503) — nothing was deleted, no partial success", async () => {
  const { token, csrfToken, row, headers } = await liveSession();
  for (const relay of [relayWorker({ fail: true }), relayWorker({ revokeRefuse: true })]) {
    const env = envForSession(row, relay, [
      {
        test: (sql) => sql.startsWith("DELETE"),
        run: async () => { throw new Error("storage must not be touched"); },
        first: async () => { throw new Error("storage must not be touched"); },
      },
    ]);
    const response = await dispatch(revokeAllRequest(csrfToken, token), env);
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /Signing out everywhere is temporarily unavailable/);
    assert.equal(relay.calls.length, 1, "the relay leg was attempted — it just refused");
    assert.deepEqual(relay.calls[0].body, { userId: 7 });
  }
  void headers;
});

test("revoke-all is gated like every other management POST (CSRF off → no relay call, nothing deleted)", async () => {
  const { token, row, headers } = await liveSession();
  const relay = relayWorker();
  const env = envForSession(row, relay, [
    {
      test: (sql) => sql.startsWith("DELETE"),
      run: async () => { throw new Error("storage must not be touched"); },
    },
  ]);
  const response = await dispatch(revokeAllRequest("", ""), env);
  assert.ok(response.status === 401 || response.status === 403);
  assert.equal(relay.calls.length, 0, "the gate answers before any relay leg is attempted");
  void headers;
});
