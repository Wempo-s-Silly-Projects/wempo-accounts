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
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>

import test from "node:test";
import assert from "node:assert/strict";
import { dispatch, fakeDb, limiters, ORIGIN, sha256Hex } from "./harness.mjs";
import { decodeJwtPart, publicSigningJwk } from "../api/oauth-crypto.mjs";
import { nowSeconds } from "../api/core/crypto.mjs";

const CLIENT_ID = "client_identifier_1234567890123456";
// Generated per run so no credential-shaped literal lives in the source.
const CLIENT_SECRET = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const REDIRECT_URI = "https://service.example/callback";
const VERIFIER = "A".repeat(43);

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function challenge(value) {
  return base64Url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function signingEnvironment() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(privateJwk),
    OAUTH_SIGNING_KID: "test-oauth-key",
    OAUTH_SUBJECT_SECRET: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"),
    publicKey,
  };
}

async function liveSession() {
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
  const csrfToken = Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString("base64url");
  return {
    token,
    csrfToken,
    row: {
      session_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
      token_hash: await sha256Hex(token),
      user_id: 7,
      csrf_token: csrfToken,
      created_at: nowSeconds() - 120,
      expires_at: nowSeconds() + 3600,
      username: "wempos",
      role: "member",
      totp_enabled: 0,
    },
  };
}

function clientRow(secretHash) {
  return {
    client_id: CLIENT_ID,
    client_secret_hash: secretHash,
    client_name: "Example Service",
    redirect_uris_json: JSON.stringify([REDIRECT_URI]),
    token_endpoint_auth_method: "client_secret_basic",
    scopes_json: JSON.stringify(["openid", "profile"]),
    disabled_at: null,
  };
}

async function makeEnvironment({ sessionRow = null, codeRow = null, signing = null } = {}) {
  const state = { codeRow, tokens: [], authorizationInsert: null };
  const env = { ...limiters() };
  if (signing) Object.assign(env, {
    OAUTH_SIGNING_PRIVATE_JWK: signing.OAUTH_SIGNING_PRIVATE_JWK,
    OAUTH_SIGNING_KID: signing.OAUTH_SIGNING_KID,
    OAUTH_SUBJECT_SECRET: signing.OAUTH_SUBJECT_SECRET,
  });
  env.FORUM_DB = fakeDb([
    {
      test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      first: async (bound) => sessionRow && sessionRow.token_hash === bound[0] &&
        Number(sessionRow.expires_at) > Number(bound[1]) ? sessionRow : null,
    },
    {
      test: (sql) => sql.includes("FROM wa_oauth_clients WHERE client_id = ?"),
      first: async () => clientRow(await sha256Hex(CLIENT_SECRET)),
    },
    {
      test: (sql) => sql.startsWith("INSERT INTO wa_oauth_authorization_codes"),
      run: async (bound) => {
        state.authorizationInsert = bound;
        state.codeRow = {
          code_hash: bound[0],
          client_id: bound[1],
          user_id: bound[2],
          redirect_uri: bound[3],
          scope: bound[4],
          auth_time: bound[5],
          code_challenge: bound[6],
          nonce: bound[7],
          expires_at: bound[8],
          consumed_at: null,
        };
        return { changes: 1 };
      },
    },
    {
      test: (sql) => sql.includes("FROM wa_oauth_authorization_codes WHERE code_hash = ?"),
      first: async () => state.codeRow,
    },
    {
      test: (sql) => sql.startsWith("UPDATE wa_oauth_authorization_codes SET consumed_at = ?"),
      run: async (bound) => {
        if (!state.codeRow || state.codeRow.consumed_at !== null ||
            state.codeRow.code_hash !== bound[1] || state.codeRow.client_id !== bound[2]) return { changes: 0 };
        state.codeRow.consumed_at = bound[0];
        return { changes: 1 };
      },
    },
    {
      test: (sql) => sql.includes("SELECT id, username FROM users WHERE id = ? LIMIT 1"),
      first: async () => ({ id: 7, username: "wempos" }),
    },
    {
      test: (sql) => sql.startsWith("INSERT INTO wa_oauth_access_tokens"),
      run: async (bound) => {
        state.tokens.push({
          token_hash: bound[0],
          client_id: bound[1],
          user_id: bound[2],
          scope: bound[3],
          created_at: bound[4],
          expires_at: bound[5],
          revoked_at: null,
        });
        return { changes: 1 };
      },
    },
    {
      test: (sql) => sql.includes("SELECT t.client_id, t.user_id, t.scope, u.username"),
      first: async (bound) => {
        const row = state.tokens.find((token) => token.token_hash === bound[0] &&
          token.revoked_at === null && token.expires_at > bound[1]);
        return row ? { ...row, username: "wempos" } : null;
      },
    },
    {
      test: (sql) => sql.startsWith("UPDATE wa_oauth_access_tokens SET revoked_at = ?") &&
        sql.includes("created_at >= ?"),
      run: async (bound) => {
        let changes = 0;
        for (const token of state.tokens) {
          if (token.client_id === bound[1] && token.user_id === bound[2] &&
              token.created_at >= bound[3] && token.revoked_at === null) {
            token.revoked_at = bound[0];
            changes += 1;
          }
        }
        return { changes };
      },
    },
    {
      test: (sql) => sql.startsWith("UPDATE wa_oauth_access_tokens SET revoked_at = ?"),
      run: async (bound) => {
        const row = state.tokens.find((token) => token.token_hash === bound[1] && token.client_id === bound[2]);
        if (!row || row.revoked_at !== null) return { changes: 0 };
        row.revoked_at = bound[0];
        return { changes: 1 };
      },
    },
  ]);
  return { env, state };
}

function sessionRequest(path, method, body, session) {
  return new Request(ORIGIN + path, {
    method,
    headers: {
      Origin: ORIGIN,
      Cookie: "wempo_account_session=" + session.token,
      "X-CSRF-Token": session.csrfToken,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function authorizationParams(codeChallenge) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile",
    state: "state-from-client",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    nonce: "nonce-from-client",
  });
  return params;
}

test("OIDC discovery publishes the exact issuer and Authorization Code + PKCE capabilities", async () => {
  const { env } = await makeEnvironment();
  const response = await dispatch(new Request(ORIGIN + "/.well-known/openid-configuration"), env);
  assert.equal(response.status, 200);
  const metadata = await response.json();
  assert.equal(metadata.issuer, ORIGIN);
  assert.equal(metadata.authorization_endpoint, ORIGIN + "/oauth2/authorize");
  assert.equal(metadata.token_endpoint, ORIGIN + "/oauth2/token");
  assert.equal(metadata.jwks_uri, ORIGIN + "/.well-known/jwks.json");
  assert.deepEqual(metadata.response_types_supported, ["code"]);
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(metadata.subject_types_supported, ["pairwise"]);
  assert.ok(!metadata.grant_types_supported.includes("implicit"));
});

test("JWKS exposes only the configured public RSA key", async () => {
  const signing = await signingEnvironment();
  const { env } = await makeEnvironment({ signing });
  const response = await dispatch(new Request(ORIGIN + "/.well-known/jwks.json"), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { keys: [publicSigningJwk(env)] });
});

test("authorization validates the registered redirect and sends signed-out users through login", async () => {
  const { env } = await makeEnvironment();
  const query = authorizationParams(await challenge(VERIFIER));
  const request = new Request(ORIGIN + "/oauth2/authorize?" + query);
  const response = await dispatch(request, env);
  assert.equal(response.status, 302);
  const login = new URL(response.headers.get("Location"));
  assert.equal(login.origin, ORIGIN);
  assert.equal(login.pathname, "/");
  assert.equal(login.searchParams.get("oauth_request"), request.url);

  query.set("redirect_uri", "https://attacker.example/callback");
  const rejected = await dispatch(new Request(ORIGIN + "/oauth2/authorize?" + query), env);
  assert.equal(rejected.status, 400);
  assert.equal((await rejected.json()).error, "invalid_request");
});

test("signed-in authorization serves the consent page only after request validation", async () => {
  const session = await liveSession();
  const { env } = await makeEnvironment({ sessionRow: session.row });
  env.ASSETS = { fetch: async (request) => {
    assert.equal(new URL(request.url).pathname, "/oauth-consent.html");
    return new Response("consent page", { headers: { "Content-Type": "text/html" } });
  } };
  const query = authorizationParams(await challenge(VERIFIER));
  const response = await dispatch(new Request(ORIGIN + "/oauth2/authorize?" + query, {
    headers: { Cookie: "wempo_account_session=" + session.token },
  }), env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "consent page");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});

test("consent creates a hashed, short-lived, single-use code bound to client, user, redirect, state and PKCE", async () => {
  const session = await liveSession();
  const { env, state } = await makeEnvironment({ sessionRow: session.row });
  const query = authorizationParams(await challenge(VERIFIER));
  const body = Object.fromEntries(query.entries());
  body.approved = true;
  const response = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  assert.equal(response.status, 200);
  const result = await response.json();
  const redirect = new URL(result.redirect);
  assert.equal(redirect.origin, "https://service.example");
  assert.equal(redirect.pathname, "/callback");
  assert.equal(redirect.searchParams.get("state"), "state-from-client");
  assert.equal(redirect.searchParams.get("iss"), ORIGIN);
  const code = redirect.searchParams.get("code");
  assert.equal(typeof code, "string");
  assert.notEqual(state.authorizationInsert[0], code);
  assert.equal(state.authorizationInsert[1], CLIENT_ID);
  assert.equal(state.authorizationInsert[2], 7);
  assert.equal(state.authorizationInsert[3], REDIRECT_URI);
  assert.equal(state.authorizationInsert[4], "openid profile");
  assert.equal(state.authorizationInsert[5], session.row.created_at);
  assert.equal(state.authorizationInsert[6], await challenge(VERIFIER));
  assert.equal(state.codeRow.consumed_at, null);
});

test("token exchange requires client authentication and matching PKCE, then issues an RS256 ID token and opaque access token", async () => {
  const session = await liveSession();
  const signing = await signingEnvironment();
  const { env, state } = await makeEnvironment({ sessionRow: session.row, signing });
  const query = authorizationParams(await challenge(VERIFIER));
  const body = Object.fromEntries(query.entries());
  body.approved = true;
  const consent = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  const code = new URL((await consent.json()).redirect).searchParams.get("code");

  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: VERIFIER,
  });
  const basic = "Basic " + btoa(CLIENT_ID + ":" + CLIENT_SECRET);
  const bad = await dispatch(new Request(ORIGIN + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basic },
    body: new URLSearchParams({ ...Object.fromEntries(form), code_verifier: "B".repeat(43) }),
  }), env);
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error, "invalid_grant");
  assert.equal(state.codeRow.consumed_at, null);

  const response = await dispatch(new Request(ORIGIN + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: basic },
    body: form,
  }), env);
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.token_type, "Bearer");
  assert.equal(result.expires_in, 3600);
  assert.equal(result.scope, "openid profile");
  assert.equal(typeof result.access_token, "string");
  assert.equal(state.tokens.length, 1);
  assert.equal(state.tokens[0].token_hash, await sha256Hex(result.access_token));
  assert.equal(state.codeRow.consumed_at > 0, true);

  const [headerPart, payloadPart, signaturePart] = result.id_token.split(".");
  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);
  assert.equal(header.alg, "RS256");
  assert.equal(header.kid, "test-oauth-key");
  assert.equal(payload.iss, ORIGIN);
  assert.equal(payload.aud, CLIENT_ID);
  assert.equal(payload.nonce, "nonce-from-client");
  assert.equal(payload.auth_time, session.row.created_at);
  assert.equal(payload.preferred_username, "wempos");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    signing.publicKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  assert.equal(await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    Buffer.from(signaturePart, "base64url"),
    new TextEncoder().encode(headerPart + "." + payloadPart),
  ), true);
});

test("userinfo returns only the pairwise subject and explicitly requested profile claims", async () => {
  const session = await liveSession();
  const signing = await signingEnvironment();
  const { env, state } = await makeEnvironment({ sessionRow: session.row, signing });
  const query = authorizationParams(await challenge(VERIFIER));
  const body = Object.fromEntries(query.entries());
  body.approved = true;
  const consent = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  const code = new URL((await consent.json()).redirect).searchParams.get("code");
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER });
  const response = await dispatch(new Request(ORIGIN + "/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + btoa(CLIENT_ID + ":" + CLIENT_SECRET),
    },
    body: form,
  }), env);
  const tokens = await response.json();
  const userinfo = await dispatch(new Request(ORIGIN + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + tokens.access_token },
  }), env);
  assert.equal(userinfo.status, 200);
  const claims = await userinfo.json();
  assert.equal(typeof claims.sub, "string");
  assert.equal(claims.preferred_username, "wempos");
  assert.equal(claims.name, "wempos");
  assert.ok(!("email" in claims));
  assert.equal(state.tokens.length, 1);
});

test("revocation is client-bound and removes the bearer token from userinfo", async () => {
  const session = await liveSession();
  const signing = await signingEnvironment();
  const { env, state } = await makeEnvironment({ sessionRow: session.row, signing });
  const query = authorizationParams(await challenge(VERIFIER));
  const body = Object.fromEntries(query.entries());
  body.approved = true;
  const consent = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  const code = new URL((await consent.json()).redirect).searchParams.get("code");
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER });
  const tokenResponse = await dispatch(new Request(ORIGIN + "/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + btoa(CLIENT_ID + ":" + CLIENT_SECRET),
    },
    body: form,
  }), env);
  const token = (await tokenResponse.json()).access_token;

  const revoked = await dispatch(new Request(ORIGIN + "/oauth2/revoke", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + btoa(CLIENT_ID + ":" + CLIENT_SECRET),
    },
    body: new URLSearchParams({ token, token_type_hint: "access_token" }),
  }), env);
  assert.equal(revoked.status, 200);
  assert.equal(await revoked.text(), "");

  const userinfo = await dispatch(new Request(ORIGIN + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + token },
  }), env);
  assert.equal(userinfo.status, 401);
  assert.equal(state.tokens[0].revoked_at > 0, true);
});

test("members can list and revoke only their own connected OAuth applications", async () => {
  const session = await liveSession();
  const updates = [];
  const env = { ...limiters() };
  env.FORUM_DB = fakeDb([
    {
      test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      first: async (bound) => session.row.token_hash === bound[0] &&
        Number(session.row.expires_at) > Number(bound[1]) ? session.row : null,
    },
    {
      test: (sql) => sql.includes("FROM wa_oauth_access_tokens t JOIN wa_oauth_clients c"),
      all: async () => [{
        client_id: CLIENT_ID,
        client_name: "Example Service",
        token_count: 2,
        latest_expiry: nowSeconds() + 1800,
      }],
    },
    {
      test: (sql) => sql.startsWith("UPDATE wa_oauth_access_tokens SET revoked_at = ?"),
      run: async (bound) => {
        updates.push({ table: "tokens", bound });
        return { changes: 2 };
      },
    },
    {
      test: (sql) => sql.startsWith("UPDATE wa_oauth_authorization_codes SET consumed_at = ?"),
      run: async (bound) => {
        updates.push({ table: "codes", bound });
        return { changes: 1 };
      },
    },
  ]);

  const listed = await dispatch(sessionRequest("/api/oauth/grants", "GET", undefined, session), env);
  assert.equal(listed.status, 200);
  const data = await listed.json();
  assert.equal(data.applications[0].client_id, CLIENT_ID);
  assert.equal(data.applications[0].client_name, "Example Service");
  assert.equal(data.applications[0].active_tokens, 2);

  const revoked = await dispatch(sessionRequest("/api/oauth/grants/revoke", "POST", {
    client_id: CLIENT_ID,
  }, session), env);
  assert.equal(revoked.status, 200);
  assert.deepEqual(await revoked.json(), { revoked_tokens: 2, invalidated_codes: 1 });
  assert.deepEqual(updates.map((item) => item.table), ["tokens", "codes"]);
  for (const item of updates) {
    assert.equal(item.bound[1], CLIENT_ID);
    assert.equal(item.bound[2], 7);
  }
});

test("a replayed authorization code is refused and revokes the tokens it already issued", async () => {
  const session = await liveSession();
  const signing = await signingEnvironment();
  const { env, state } = await makeEnvironment({ sessionRow: session.row, signing });
  const body = Object.fromEntries(authorizationParams(await challenge(VERIFIER)).entries());
  body.approved = true;
  const consent = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  const code = new URL((await consent.json()).redirect).searchParams.get("code");
  const exchange = () => dispatch(new Request(ORIGIN + "/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + btoa(CLIENT_ID + ":" + CLIENT_SECRET),
    },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER }),
  }), env);

  assert.equal((await exchange()).status, 200);
  assert.equal(state.tokens[0].revoked_at, null);
  const replay = await exchange();
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "invalid_grant");
  assert.equal(state.tokens.length, 1);
  assert.ok(state.tokens[0].revoked_at > 0, "the first exchange's token is revoked");
});

test("denying consent returns access_denied with state and issuer to the registered redirect", async () => {
  const session = await liveSession();
  const { env, state } = await makeEnvironment({ sessionRow: session.row });
  const body = Object.fromEntries(authorizationParams(await challenge(VERIFIER)).entries());
  body.approved = false;
  const response = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
  assert.equal(response.status, 200);
  const redirect = new URL((await response.json()).redirect);
  assert.equal(redirect.origin + redirect.pathname, REDIRECT_URI);
  assert.equal(redirect.searchParams.get("error"), "access_denied");
  assert.equal(redirect.searchParams.get("state"), "state-from-client");
  assert.equal(redirect.searchParams.get("iss"), ORIGIN);
  assert.equal(redirect.searchParams.get("code"), null);
  assert.equal(state.authorizationInsert, null);
});

test("authorization rejects control characters in state and requests without openid", async () => {
  const session = await liveSession();
  const { env } = await makeEnvironment({ sessionRow: session.row });
  const query = authorizationParams(await challenge(VERIFIER));
  for (const [key, value] of [["state", "bad\u0007state"], ["scope", "profile"], ["code_challenge_method", "plain"]]) {
    const body = Object.fromEntries(query.entries());
    body[key] = value;
    body.approved = true;
    const response = await dispatch(sessionRequest("/api/oauth/authorize", "POST", body, session), env);
    assert.equal(response.status, 400, key + " must be rejected");
  }
});
