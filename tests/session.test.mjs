// Copyright 2026 YourLocalGoober
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

// Session machinery: the wempo_account_session cookie ↔ wa_sso_sessions row
// pair (GET /api/me), the CSRF/same-origin gate on POST /api/logout, and the
// dispatch loop's edges (unknown API paths, the asset fallback). Same fakeDb
// + pinned-SQL style; session fixtures carry the real token/hash pair.
import test from "node:test";
import assert from "node:assert/strict";

import { fakeDb, dispatch, sha256Hex, ORIGIN } from "./harness.mjs";

// The canonical session fixture: the raw token (what the cookie carries)
// plus the stored row (what wa_sso_sessions holds — hashes only).
async function sessionFixtures(username, overrides = {}) {
  const token = Buffer.from(new Uint8Array(32).map(() => (Math.random() * 256) | 0)).toString("base64url");
  const csrfToken = "csrf-token-abcdefghijklmnopqrstuvwxyz0123";
  const row = {
    token_hash: await sha256Hex(token),
    user_id: 7,
    csrf_token: csrfToken,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    username,
    role: "admin",
    totp_enabled: 0,
    ...overrides,
  };
  return { token, csrfToken, row, headers: { Cookie: "wempo_account_session=" + token } };
}

function limitStub() {
  return { async limit() { return { success: true }; } };
}

function envFor(sessionRow = null) {
  return {
    GOOBER_DB: fakeDb([
      {
        test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
        // The pinned read carries the expiry predicate (token_hash = ? AND
        // expires_at > ?); the fake honors bound[1] so the expired-row case
        // really exercises the SQL's own semantics.
        first: async (bound) =>
          sessionRow && Number(sessionRow.expires_at) > Number(bound[1]) ? sessionRow : null,
      },
    ]),
    WA_READ_RATE_LIMITER: limitStub(),
    WA_WRITE_RATE_LIMITER: limitStub(),
    WA_LOGIN_RATE_LIMITER: limitStub(),
    WA_TOTP_RATE_LIMITER: limitStub(),
  };
}

test("GET /api/me answers the session's identity + csrf from the wa_ join", async () => {
  const { csrfToken, row, headers } = await sessionFixtures("wempos");
  const response = await dispatch(
    new Request(ORIGIN + "/api/me", { headers }),
    envFor(row),
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(
    { ...body.user },
    { id: 7, username: "wempos", role: "owner", totpEnabled: false },
    "the stored owner tier ('admin') renders through publicRole",
  );
  assert.equal(body.csrfToken, csrfToken);
});

test("GET /api/me is 401 without a session (no cookie, expired row, bad token shape)", async () => {
  const noCookie = await dispatch(new Request(ORIGIN + "/api/me"), envFor(null));
  assert.equal(noCookie.status, 401);

  const { row, headers } = await sessionFixtures("wempos", { expires_at: Math.floor(Date.now() / 1000) - 1 });
  const expired = await dispatch(new Request(ORIGIN + "/api/me", { headers }), envFor(row));
  assert.equal(expired.status, 401, "the expires_at predicate is part of the pinned read");

  const malformed = await dispatch(
    new Request(ORIGIN + "/api/me", { headers: { Cookie: "wempo_account_session=too-short" } }),
    envFor(null),
  );
  assert.equal(malformed.status, 401, "a token outside the base64url length band never reaches the DB");
});

test("POST /api/logout deletes the row and expires the cookie — behind same-origin + CSRF", async () => {
  const { row, csrfToken, headers } = await sessionFixtures("wempos");
  const env = envFor(row);

  const response = await dispatch(
    new Request(ORIGIN + "/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "X-CSRF-Token": csrfToken, ...headers },
      body: JSON.stringify({}),
    }),
    env,
  );

  assert.equal(response.status, 204);
  const cookie = response.headers.get("Set-Cookie");
  assert.match(cookie, /^wempo_account_session=;/);
  for (const pin of ["Max-Age=0", "HttpOnly", "SameSite=Lax"]) {
    assert.ok(cookie.includes(pin), "the expired cookie carries " + pin);
  }
  const deletes = env.GOOBER_DB.executed.filter((e) => e.sql.startsWith("DELETE FROM wa_sso_sessions"));
  assert.equal(deletes.length, 1);
  assert.equal(deletes[0].bound[0], row.token_hash, "the delete keys on the session's own token hash");
});

test("logout without the CSRF header is 401/403 — a stolen-origin post deletes nothing", async () => {
  const { row, csrfToken, headers } = await sessionFixtures("wempos");

  // A present-but-wrong token is the CSRF gate's 403.
  const missing = await dispatch(
    new Request(ORIGIN + "/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: ORIGIN, ...headers },
      body: JSON.stringify({}),
    }),
    envFor(row),
  );
  assert.equal(missing.status, 403, "empty header ≠ the row's CSRF token → the gate's 403");

  const wrong = await dispatch(
    new Request(ORIGIN + "/api/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json", Origin: ORIGIN, "X-CSRF-Token": csrfToken + "x", ...headers,
      },
      body: JSON.stringify({}),
    }),
    envFor(row),
  );
  assert.equal(wrong.status, 403);

  // No session at all → the gate's 401.
  const ghost = await dispatch(
    new Request(ORIGIN + "/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "X-CSRF-Token": csrfToken },
      body: JSON.stringify({}),
    }),
    envFor(null),
  );
  assert.equal(ghost.status, 401);

  // Cross-origin post → 403 before anything reads the session.
  const crossed = await dispatch(
    new Request(ORIGIN + "/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://else.example", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({}),
    }),
    envFor(row),
  );
  assert.equal(crossed.status, 403);
});

function withAssets(env, fetchFn) {
  return {
    ...env,
    ASSETS: {
      async fetch(request) {
        return fetchFn(request);
      },
    },
  };
}

test("the dispatch loop's edges: unknown API paths 404, asset paths ride ASSETS", async () => {
  const env = envFor(null);

  const unknownApi = await dispatch(
    new Request(ORIGIN + "/api/nothing", { headers: { Origin: ORIGIN } }),
    env,
  );
  assert.equal(unknownApi.status, 404);
  assert.deepEqual(await unknownApi.json(), { error: "That API endpoint does not exist." });

  // Unrouted paths still answer the dispatch 404 (the built phase-2 routes
  // are /api/sso/ticket + /api/sso/redeem — anything else does not exist);
  // /login is a non-API path, so it rides ASSETS (whose fake answers 404
  // for the missing page).
  for (const path of ["/api/tickets/redeem", "/api/sso/everywhere-signout"]) {
    const response = await dispatch(new Request(ORIGIN + path), env);
    assert.equal(response.status, 404, path + " is not part of phase 1");
  }
  const login = await dispatch(new Request(ORIGIN + "/login"), withAssets(env, () => new Response("nope", { status: 404 })));
  assert.equal(login.status, 404);

  // Non-API paths fall through to the asset binding (header wrapper applied).
  let assetAsked = null;
  const pageEnv = withAssets(env, (request) => {
    assetAsked = request;
    return new Response("<html></html>", { headers: { "Content-Type": "text/html; charset=utf-8" } });
  });
  const page = await dispatch(new Request(ORIGIN + "/"), pageEnv);
  assert.equal(page.status, 200);
  assert.equal(assetAsked.url, ORIGIN + "/");
  for (const [name, value] of [
    ["Content-Security-Policy", /default-src 'self'/],
    ["X-Content-Type-Options", "nosniff"],
    ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ]) {
    assert.ok(page.headers.get(name)?.match(value), name + " rides the page too");
  }
});

test("the SQL discipline pin: every write in the worker's api/ targets a wa_-prefixed table (the register users-row lane is the ONE documented exception), and no module reads a password column", async () => {
  // The exception (§4b, owner-approved): register.mjs creates the shared
  // users row with the GC-precedent INSERT shape and cleans up its own
  // placeholder row when the relay degrades — the GC register precedent the
  // design doc pins by name. Every OTHER write stays wa_-only.
  const REGISTER_USERS_LANE = /register\.mjs/;
  const { readdirSync, readFileSync } = await import("node:fs");
  for (const dir of ["api", "api/core"]) {
  const files = readdirSync(new URL("../" + dir, import.meta.url));
  for (const file of files) {
    if (!file.endsWith(".mjs")) continue;
    const location = new URL("../" + dir + "/" + file, import.meta.url);
    const source = readFileSync(location, "utf8");
    const literals = source.match(/(?:"(?:SELECT|INSERT|DELETE|UPDATE|CREATE|ALTER)[^"]*")/g) || [];
    for (const literal of literals) {
      const plain = literal.slice(1, -1);
      const excepted = REGISTER_USERS_LANE.test(file) &&
        ((/^\s*INSERT\s+INTO users|^\s*INSERT\s+INTO \(?\s*$/i.test(plain) || /^\s*INSERT\s+INTO users/i.test(plain)) ||
         /^\s*DELETE\s+FROM users WHERE id = \? AND password_hash = \?/i.test(plain));
      if (!excepted) {
        if (/^\s*INSERT\s+INTO|^\s*UPDATE\s+/i.test(plain)) {
          assert.match(plain, /\bwa_/i, file + " writes must target wa_ tables: " + plain);
        }
        if (/^\s*DELETE\s+FROM\s+/i.test(plain)) {
          assert.match(plain, /\bwa_/i, file + " deletes must target wa_ tables: " + plain);
        }
      } else {
        // The exception itself is pinned: it may never READ a password
        // column beyond the placeholder-overwrite cleanup, and never a
        // hash-bearing SELECT.
        assert.doesNotMatch(plain, /SELECT\s+\*.*(salt|hash)/i, file + " never bulk-reads hash columns");
      }
      if (!/password_salt|password_hash/i.test(plain) || !REGISTER_USERS_LANE.test(file)) {
        assert.doesNotMatch(plain, /password_salt|password_hash/, dir + "/" + file + " never reads a password column");
      }
    }
  }
  }
});
