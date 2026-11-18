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

// POST /api/login — the phase-1 credential path. Pins: relay wiring (the
// password verdict is the FORUM worker's; a degraded relay fails closed),
// Turnstile fail-closed, the shared 401s, the TOTP gate (200 ask → verify →
// one shared 401), the strict limiter tiers, request-shape and same-origin
// gates, and the session mint (cookie + CSRF + wa_-only writes).
import test from "node:test";
import assert from "node:assert/strict";

import { dbFor, dispatch, limiters, loginRequest, usersRow } from "./harness.mjs";
import { HttpError } from "../api/core/http.mjs";
import { base32Encode, totpAt } from "../api/core/totp.mjs";
import { nowSeconds } from "../api/core/crypto.mjs";

const RELAY_TOKEN = "relay-test-token";
const REAL_PASSWORD = "the-password-we-know";

// A 160-bit secret, base32 — the shape the forum stores and BOTH workers'
// verify modules decode verbatim.
function freshTotpSecret() {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

// The mock forum worker: it answers password-verify exactly like the real
// relay route — redacted rows, `valid:false` for wrong credentials, its own
// dummy burn for unknown usernames.
function forumWorker(validFor, { fail = false } = {}) {
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
      const known = validFor[body.username.toLowerCase()];
      const valid = Boolean(known) && known === body.password;
      return new Response(
        JSON.stringify(valid ? { valid: true, user: { id: 7, username: "wempos" } } : { valid: false }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    },
  };
}

function envFor(user, { forum, limiterFails, turnstile } = {}) {
  const env = { ...limiters(limiterFails) };
  env.GOOBER_DB = dbFor(user);
  env.RELAY_TOKEN = RELAY_TOKEN;
  env.FORUM_WORKER = forum;
  // Tests that pin the credential/TOTP path get the approving seam by
  // default; `turnstile: null` deliberately installs NO seam so the test
  // drives the vendored (fail-closed) requireTurnstile instead, exactly
  // like a production deployment with the secret unset.
  env._turnstileVerify = turnstile === undefined ? async () => {} : turnstile;
  return env;
}

test("a verified password mints a wa_sso_sessions row: 200 + cookie + csrf", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });
  const env = envFor(usersRow(), { forum });
  const response = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    env,
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(
    { ...body.user },
    { id: 7, username: "wempos", role: "admin", totpEnabled: false },
    "the stored 'moderator' renders through publicRole; identity columns only",
  );
  assert.match(body.csrfToken, /^[A-Za-z0-9_-]{20,}/);

  const cookie = response.headers.get("Set-Cookie");
  assert.ok(cookie, "a session cookie rides success");
  for (const pin of ["wempo_account_session=", "HttpOnly", "SameSite=Lax", "Secure"]) {
    assert.ok(cookie.includes(pin), "cookie carries " + pin + " (https origin → Secure)");
  }

  // Exactly one credential question, asked of the FORUM, with the token.
  assert.equal(forum.calls().length, 1);
  const relayed = forum.calls()[0];
  assert.equal(new URL(relayed.url).pathname, "/api/relay/password-verify");
  assert.equal(relayed.headers.get("X-Relay-Token"), RELAY_TOKEN);
  assert.deepEqual(relayed.body, { username: "wempos", password: REAL_PASSWORD });

  // Session writes: one INSERT (the verified user's token hash + CSRF) and
  // the expiry sweep — both wa_-prefixed, no forum-table write anywhere.
  const inserts = env.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO wa_sso_sessions"));
  assert.equal(inserts.length, 1);
  assert.equal(inserts[0].bound[1], 7, "the minted row is the verified user's");
  const sweep = env.GOOBER_DB.executed.filter((e) => e.sql.includes("DELETE FROM wa_sso_sessions WHERE expires_at"));
  assert.ok(sweep.length, "the expiry sweep runs after the mint");
  for (const write of env.GOOBER_DB.executed.filter((e) => e.sql.startsWith("INSERT") || e.sql.startsWith("DELETE"))) {
    assert.match(write.sql, /wa_sso_sessions/, "every write targets Accounts' own table: " + write.sql);
  }
});

test("a wrong password is the ONE shared credential 401 — no detail, one relay call", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });
  const env = envFor(usersRow(), { forum });
  const response = await dispatch(
    loginRequest({ username: "wempos", password: "wrong-password" }),
    env,
  );

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "The username or password is incorrect." });
  assert.equal(response.headers.get("Set-Cookie"), null);
  assert.equal(forum.calls().length, 1, "the verdict came from the relay");
});

test("an unknown username is the same shared 401 (the forum burns its dummy salt)", async () => {
  const forum = forumWorker({});
  const env = envFor(usersRow(), { forum });
  const response = await dispatch(loginRequest({ username: "ghost", password: REAL_PASSWORD }), env);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "The username or password is incorrect." });
});

test("a degraded relay fails closed — and the forum binding is never asked without the token", async () => {
  for (const token of [undefined, "", 42]) {
    const forum = forumWorker({ wempos: REAL_PASSWORD });
    const env = envFor(usersRow(), { forum });
    if (token === undefined) delete env.RELAY_TOKEN;
    else env.RELAY_TOKEN = token;
    const response = await dispatch(loginRequest({ username: "wempos", password: REAL_PASSWORD }), env);
    assert.equal(response.status, 401, "a token-less relay is a credential 401, never success");
    assert.equal(response.headers.get("Set-Cookie"), null);
    assert.equal(forum.calls().length, 0, "no subrequest rides a missing token");
  }

  // An unreachable forum: the binding throw degrades to null → 401.
  const unreachable = forumWorker({ wempos: REAL_PASSWORD }, { fail: true });
  const unreachableResponse = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    envFor(usersRow(), { forum: unreachable }),
  );
  assert.equal(unreachableResponse.status, 401);

  // A non-2xx relay answer (refused): null → 401.
  const refused = forumWorker({ wempos: REAL_PASSWORD });
  refused.fetch = async () => new Response(JSON.stringify({ error: "Relay refused." }), { status: 403 });
  const refusedResponse = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    envFor(usersRow(), { forum: refused }),
  );
  assert.equal(refusedResponse.status, 401);
});

test("Turnstile is fail-closed: the seam's refusal (or an unset secret) is a 403 BEFORE any relay call", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });

  // The test seam (the GC hook) refuses: the route refuses equally and
  // never reaches the credential step.
  const env = envFor(usersRow(), {
    forum,
    turnstile: () => {
      throw new HttpError(403, "Human verification is required.");
    },
  });
  const body = { username: "wempos", password: REAL_PASSWORD, "cf-turnstile-response": "t" };
  const response = await dispatch(loginRequest(body), env);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "Human verification is required." });
  assert.equal(forum.calls().length, 0, "no password work rides an unverified request");

  // No seam (production-like) and NO configured secret: the vendored check
  // refuses before siteverify is even touched (fail-closed, no network).
  const env2 = envFor(usersRow(), { forum, turnstile: null });
  const response2 = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, "cf-turnstile-response": "t" }),
    env2,
  );
  assert.equal(response2.status, 403);
  assert.deepEqual(await response2.json(), { error: "Human verification is required." });
});

test("a verifying seam lets the login ride (the hook mirrors requireTurnstile's signature)", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });
  const seen = [];
  const env = envFor(usersRow(), {
    forum,
    turnstile: async (request, env, body, action) => {
      seen.push({ action, token: body["cf-turnstile-response"] });
    },
  });
  const response = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, "cf-turnstile-response": "tok" }),
    env,
  );
  assert.equal(response.status, 200);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].action, "login");
});

test("request-shape and same-origin gates: 400 on a malformed body, 403 without a same origin", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });
  const env = envFor(usersRow(), { forum });

  const badShape = await dispatch(loginRequest({ username: "x", password: "" }), env);
  assert.equal(badShape.status, 400, "too-short username with an empty password is a shape 400");

  const noOrigin = new Request(ORIGIN_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "wempos", password: REAL_PASSWORD }),
  });
  const crossOrigin = new Request(ORIGIN_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://else.example" },
    body: JSON.stringify({ username: "wempos", password: REAL_PASSWORD }),
  });
  for (const request of [noOrigin, crossOrigin]) {
    const response = await dispatch(request, env);
    assert.equal(response.status, 403, "origin unverifiable or foreign = 403");
  }
  assert.equal(forum.calls().length, 0, "no credential work rides a gate refusal");
});

const ORIGIN_PATH = "https://accounts.itswempo.workers.dev/api/login";

test("the strict login tier: a missing limiter is 503, a throttled tier is 429", async () => {
  const forum = forumWorker({ wempos: REAL_PASSWORD });

  const noLimiter = envFor(usersRow(), { forum });
  delete noLimiter.WA_LOGIN_RATE_LIMITER;
  const response = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    noLimiter,
  );
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "Rate limiting is not configured for this endpoint." });

  const throttled = envFor(usersRow(), { forum, limiterFails: { login: true } });
  const throttledResponse = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    throttled,
  );
  assert.equal(throttledResponse.status, 429);
  assert.equal(throttledResponse.headers.get("Retry-After"), "60");
});

test("the TOTP gate: no code asks (200, no cookie), a wrong code is ONE shared 401, the right code mints", async () => {
  const secret = freshTotpSecret();
  const user = usersRow({ totp_enabled: 1, totp_secret: secret });
  const forum = forumWorker({ wempos: REAL_PASSWORD });

  // Step one: no code yet → the ask, with NO session work and NO cookie.
  const askEnv = envFor(user, { forum });
  const ask = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD }),
    askEnv,
  );
  assert.equal(ask.status, 200);
  assert.deepEqual(await ask.json(), { totpRequired: true });
  assert.equal(ask.headers.get("Set-Cookie"), null);
  assert.equal(
    askEnv.GOOBER_DB.executed.filter((e) => e.sql.includes("INSERT INTO")).length,
    0,
    "no session rides the ask",
  );

  // A wrong code: the shared 401 (same copy regardless of the garbage).
  const wrongEnv = envFor(user, { forum });
  const wrong = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, totp: "000000" }),
    wrongEnv,
  );
  assert.equal(wrong.status, 401);
  assert.deepEqual(await wrong.json(), { error: "That code is not correct." });

  // The right code (±1-step window, as the module verifies): mint.
  const code = await totpAt(secret, nowSeconds());
  const mintEnv = envFor(user, { forum });
  const mint = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, totp: code }),
    mintEnv,
  );
  assert.equal(mint.status, 200);
  const mintBody = await mint.json();
  assert.equal(mintBody.user.totpEnabled, true);
  assert.match(mint.headers.get("Set-Cookie"), /^wempo_account_session=/);

  // Both code-check passes rode the TOTP limiter (IP pass + user pass).
  const totpLimiter = mintEnv.fakes.totp;
  assert.equal(totpLimiter.calls.length, 2, "IP pass and user pass, both on the strict tier");
});

test("the TOTP tier failing is a 429, and a member with 2FA off ignores a stray code field", async () => {
  const totpSecret = freshTotpSecret();
  const user = usersRow({ totp_enabled: 1, totp_secret: totpSecret });
  const forum = forumWorker({ wempos: REAL_PASSWORD });

  const throttledEnv = envFor(user, { forum, limiterFails: { totp: true } });
  const code = await totpAt(totpSecret, nowSeconds());
  const throttledResponse = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, totp: code }),
    throttledEnv,
  );
  assert.equal(throttledResponse.status, 429);

  // No 2FA: a stray totp value is simply not consulted — a plain mint.
  const env = envFor(usersRow(), { forum });
  const response = await dispatch(
    loginRequest({ username: "wempos", password: REAL_PASSWORD, totp: "123456" }),
    env,
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.user.totpEnabled, false);
  assert.ok(body.csrfToken);
});
