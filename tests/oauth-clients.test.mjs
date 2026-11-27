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
import { nowSeconds } from "../api/core/crypto.mjs";

async function liveSession(role = "admin") {
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
  const csrfToken = "csrf-token-abcdefghijklmnopqrstuvwxyz0123";
  return {
    token,
    csrfToken,
    row: {
      session_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
      token_hash: await sha256Hex(token),
      user_id: 7,
      csrf_token: csrfToken,
      created_at: nowSeconds() - 300,
      expires_at: nowSeconds() + 3600,
      username: "wempos",
      role,
      totp_enabled: 0,
    },
  };
}

function oauthEnv(sessionRow, { clientRows = [], insert = () => ({ changes: 1 }), updates = [] } = {}) {
  const env = { ...limiters() };
  env.FORUM_DB = fakeDb([
    {
      test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      first: async (bound) => sessionRow && sessionRow.token_hash === bound[0] &&
        Number(sessionRow.expires_at) > Number(bound[1]) ? sessionRow : null,
    },
    { test: (sql) => sql.startsWith("INSERT INTO wa_oauth_clients"), run: async (bound) => {
      insert(bound);
      return { changes: 1 };
    } },
    { test: (sql) => sql.includes("FROM wa_oauth_clients ORDER BY created_at"),
      all: async () => clientRows },
    { test: (sql) => sql.startsWith("UPDATE wa_oauth_clients"), run: async () => ({ changes: 1 }) },
    { test: (sql) => sql.startsWith("UPDATE wa_oauth_access_tokens"), run: async () => {
      updates.push("tokens");
      return { changes: 1 };
    } },
    { test: (sql) => sql.startsWith("UPDATE wa_oauth_authorization_codes"), run: async () => {
      updates.push("codes");
      return { changes: 1 };
    } },
  ]);
  return env;
}

function request(path, method, body, session, extraHeaders = {}) {
  return new Request(ORIGIN + path, {
    method,
    headers: {
      Origin: ORIGIN,
      Cookie: "wempo_account_session=" + (session?.token || ""),
      "X-CSRF-Token": session?.csrfToken || "",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...extraHeaders,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

test("owner can register a confidential client; secret is returned once and only its hash is stored", async () => {
  const session = await liveSession("admin");
  let inserted;
  const env = oauthEnv(session.row, { insert: (bound) => { inserted = bound; } });
  const response = await dispatch(request("/api/oauth/clients", "POST", {
    client_name: "Example service",
    redirect_uris: ["https://example.com/oauth/callback"],
    scopes: ["openid", "profile"],
    token_endpoint_auth_method: "client_secret_basic",
  }, session), env);

  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.client_name, "Example service");
  assert.match(result.client_id, /^[A-Za-z0-9_-]{32,80}$/);
  assert.equal(typeof result.client_secret, "string");
  assert.equal(inserted[0], result.client_id);
  assert.equal(inserted[1], await sha256Hex(result.client_secret));
  assert.notEqual(inserted[1], result.client_secret);
  assert.equal(inserted[2], "Example service");
  assert.deepEqual(JSON.parse(inserted[3]), ["https://example.com/oauth/callback"]);
  assert.equal(inserted[4], "client_secret_basic");
  assert.deepEqual(JSON.parse(inserted[5]), ["openid", "profile"]);
  assert.equal(inserted[6], 7);
});

test("public clients can register with loopback redirects and receive no client secret", async () => {
  const session = await liveSession();
  const response = await dispatch(request("/api/oauth/clients", "POST", {
    client_name: "Local development client",
    redirect_uris: ["http://127.0.0.1:4321/callback"],
    token_endpoint_auth_method: "none",
    scopes: ["openid"],
  }, session), oauthEnv(session.row));
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.token_endpoint_auth_method, "none");
  assert.equal("client_secret" in result, false);
});

test("member sessions cannot register OAuth clients", async () => {
  const session = await liveSession("moderator");
  const response = await dispatch(request("/api/oauth/clients", "POST", {
    client_name: "Not allowed",
    redirect_uris: ["https://example.com/callback"],
  }, session), oauthEnv(session.row));
  assert.equal(response.status, 403);
});

test("OAuth client registration rejects non-HTTPS remote redirects and unsupported scopes", async () => {
  const session = await liveSession();
  for (const body of [
    { client_name: "Bad redirect", redirect_uris: ["http://example.com/callback"] },
    { client_name: "Bad scope", redirect_uris: ["https://example.com/callback"], scopes: ["openid", "email"] },
    { client_name: "Wildcard", redirect_uris: ["https://*.example.com/callback"] },
  ]) {
    const response = await dispatch(request("/api/oauth/clients", "POST", body, session), oauthEnv(session.row));
    assert.equal(response.status, 400);
  }
});

test("client listing never exposes stored client-secret hashes", async () => {
  const session = await liveSession();
  const env = oauthEnv(session.row, {
    clientRows: [{
      client_id: "client_identifier_1234567890123456",
      client_name: "Example",
      redirect_uris_json: '["https://example.com/callback"]',
      token_endpoint_auth_method: "client_secret_basic",
      scopes_json: '["openid"]',
      created_at: nowSeconds(),
      disabled_at: null,
      client_secret_hash: "never-return-this",
    }],
  });
  const response = await dispatch(request("/api/oauth/clients", "GET", undefined, session), env);
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.ok(!text.includes("never-return-this"));
  assert.ok(!text.includes("client_secret"));
  assert.equal(JSON.parse(text).clients[0].client_name, "Example");
});

test("disabling a client revokes its access tokens and consumes pending codes", async () => {
  const session = await liveSession();
  const updates = [];
  const env = oauthEnv(session.row, { updates });
  const response = await dispatch(request(
    "/api/oauth/clients/client_identifier_1234567890123456",
    "DELETE",
    undefined,
    session,
  ), env);
  assert.equal(response.status, 204);
  assert.deepEqual(updates.sort(), ["codes", "tokens"]);
});

test("OAuth client mutations require same-origin and a valid CSRF token", async () => {
  const session = await liveSession();
  const env = oauthEnv(session.row);
  const response = await dispatch(request("/api/oauth/clients", "POST", {
    client_name: "Example",
    redirect_uris: ["https://example.com/callback"],
  }, session, { "X-CSRF-Token": "wrong" }), env);
  assert.equal(response.status, 403);
});
