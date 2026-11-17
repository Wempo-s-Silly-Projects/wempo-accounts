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

// POST /api/register — the §4b Make Account lane. Pins: the GC-precedent
// users-row INSERT with the relay overwriting the hash (a degraded relay
// deletes the placeholder and fails the registration closed; a refused set
// is the forum's password rules 400), Turnstile fail-closed on the
// "register" action, the shared username word filter (read-only
// site_settings), the duplicate-username 409, the limiter tiers, and the
// auto-login mint (the page turns the response into the §2 ticket redirect).
import test from "node:test";
import assert from "node:assert/strict";

import { dbFor, dispatch, limiters, registerRequest } from "./harness.mjs";
import { resetFilterCacheForTests } from "../api/register.mjs";

const RELAY_TOKEN = "relay-test-token";

function forumWorker({ verify = true, fail = false } = {}) {
  const calls = [];
  return {
    calls: () => calls,
    async fetch(request) {
      const body = await request.clone().json();
      calls.push({ url: request.url, headers: request.headers, body });
      if (fail) throw new Error("edge down");
      if (request.headers.get("X-Relay-Token") !== RELAY_TOKEN) {
        return new Response(JSON.stringify({ error: "Relay refused." }), { status: 403 });
      }
      if (new URL(request.url).pathname === "/api/relay/password-set") {
        if (!verify) return new Response(JSON.stringify({ error: "Enter a username and a valid password." }), { status: 400 });
        return new Response(JSON.stringify({ changed: true, user: { id: 7, username: body.username } }),
          { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ valid: true }), { status: 200 });
    },
  };
}

function envFor({ forum, limiterFails, turnstile } = {}) {
  const env = { ...limiters(limiterFails) };
  env.GOOBER_DB = dbFor({
    id: 7, username: "wempos", username_key: "wempos", role: "member", totp_enabled: 0,
  }, null);
  env.RELAY_TOKEN = RELAY_TOKEN;
  env.FORUM_WORKER = forum;
  env._turnstileVerify = turnstile === undefined ? async () => {} : turnstile;
  return env;
}

test("a Make Account POST creates the users row, sets the password through the relay, and mints the session", async () => {
  resetFilterCacheForTests();
  const forum = forumWorker();
  const env = envFor({ forum });
  const response = await dispatch(
    registerRequest({ username: "newmember", password: "a-fine-12-char-pass" }),
    env,
  );

  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.user.username, "wempos", "the returned projection mirrors the login shape");
  assert.match(body.csrfToken, /^[A-Za-z0-9_-]{20,}/);
  const cookie = response.headers.get("Set-Cookie");
  assert.ok(cookie && cookie.includes("wempo_account_session="), "the auto-login mint rides success");

  // The users row: the GC-precedent INSERT with placeholder credential
  // columns, then the relay overwrite (username/password ride to the forum
  // with the shared token).
  const inserted = env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO users"));
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].bound[4], "member", "the stored role is the member tier");
  const relayCall = forum.calls().find((call) => new URL(call.url).pathname === "/api/relay/password-set");
  assert.ok(relayCall, "the forum relay wrote the hash");
  assert.equal(relayCall.headers.get("X-Relay-Token"), RELAY_TOKEN);
  assert.deepEqual(relayCall.body, { username: "wempos", password: "a-fine-12-char-pass" });

  // The session mint writes Accounts' own table only.
  const sessionWrite = env.GOOBER_DB.executed.find((e) => e.sql.includes("INSERT INTO wa_sso_sessions"));
  assert.ok(sessionWrite, "the session lands in wa_sso_sessions");
});

test("a degraded relay deletes the placeholder row and registration fails closed", async () => {
  resetFilterCacheForTests();
  const forum = forumWorker({ fail: true });
  const env = envFor({ forum });
  const response = await dispatch(
    registerRequest({ username: "newmember", password: "a-fine-12-char-pass" }),
    env,
  );
  assert.equal(response.status, 503);
  const deletes = env.GOOBER_DB.executed.filter((e) =>
    e.sql.startsWith("DELETE FROM users WHERE id = ? AND password_hash = ?"));
  assert.equal(deletes.length, 1, "the just-inserted row does not survive a degraded relay");
  const bound = deletes[0].bound;
  assert.equal(bound[0], 7, "the cleanup matches the minted row's id");
  assert.equal(bound[1], "0".repeat(64), "and only the placeholder-hash row");
  // No session for an account whose password could never verify.
  assert.equal(
    env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO wa_sso_sessions")).length,
    0,
  );
});

test("a relay set the forum refused (400 over the binding) is the same fail-closed 503 with the row cleaned up", async () => {
  resetFilterCacheForTests();
  const forum = forumWorker({ verify: false });
  const env = envFor({ forum });
  const response = await dispatch(
    registerRequest({ username: "newmember", password: "a-fine-12-char-pass" }),
    env,
  );
  assert.equal(response.status, 503);
  assert.ok(env.GOOBER_DB.executed.some((e) =>
    e.sql.startsWith("DELETE FROM users WHERE id = ? AND password_hash = ?")),
  "the placeholder row is gone either way");
});

test("no Turnstile verdict (or a missing secret) is a 403 BEFORE any D1 write", async () => {
  resetFilterCacheForTests();
  const forum = forumWorker();
  const env = envFor({ forum, turnstile: async () => {
    throw new (await import("../api/core/http.mjs")).HttpError(403, "Human verification is required.");
  } });
  const response = await dispatch(
    registerRequest({ username: "newmember", password: "a-fine-12-char-pass" }),
    env,
  );
  assert.equal(response.status, 403);
  assert.equal(env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO users")).length, 0);
  assert.equal(forum.calls().length, 0, "no credential call rides an unverified request");
});

test("the shared username word filter refuses a filtered username with the GC copy", async () => {
  const forum = forumWorker();
  const env = envFor({ forum });
  env.GOOBER_DB = dbFor({ id: 7, username: "wempos", username_key: "wempos", role: "member", totp_enabled: 0 },
    null, { filterWords: new Map([["filtered_words", "noob"]]) });
  resetFilterCacheForTests();
  const response = await dispatch(
    registerRequest({ username: "a_noob_here", password: "a-fine-12-char-pass" }),
    env,
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "That username isn't allowed.");
  assert.equal(env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO users")).length, 0);
});

test("the duplicate-username INSERT failure is the shared 409 and no relay call happens", async () => {
  resetFilterCacheForTests();
  const forum = forumWorker();
  const env = envFor({ forum });
  // The duplicate diagnosis route: the username read answers an existing row
  // after the unique-index insert failure.
  const { dbFor: originalDbFor } = await import("./harness.mjs");
  const failFirst = ["INSERT INTO users"];
  env.GOOBER_DB = {
    prepare(sql) {
      if (failFirst.some((needle) => sql.includes(needle))) {
        return {
          bind: () => ({ run: async () => { throw new Error("UNIQUE constraint failed: users.username_key"); } }),
        };
      }
      return originalDbFor.call(null).prepare(sql);
    },
    batch: () => [],
  };
  const response = await dispatch(
    registerRequest({ username: "wempos", password: "a-fine-12-char-pass" }),
    env,
  );
  assert.equal(response.status, 409);
  assert.equal(forum.calls().length, 0, "no hash write for a name that was taken");
  void originalDbFor;
});
