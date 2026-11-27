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

import { requireCsrf, readSession } from "./core/auth.mjs";
import { nowSeconds, randomToken, sha256Hex } from "./core/crypto.mjs";
import { HttpError, json, readJson, securityHeaders } from "./core/http.mjs";

const SUPPORTED_SCOPES = new Set(["openid", "profile"]);
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{32,80}$/;

function ownerOnly(session) {
  if (!session?.user) throw new HttpError(401, "Please sign in to manage OAuth applications.");
  if (session.user.role !== "owner") throw new HttpError(403, "Only the account owner can manage OAuth applications.");
}

function validRedirectUri(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048 || value.includes("#")) return false;
  try {
    const url = new URL(value);
    if (url.username || url.password || url.hash) return false;
    if (url.protocol === "https:") return true;
    if (url.protocol !== "http:") return false;
    return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  } catch {
    return false;
  }
}

function clientScopes(value) {
  if (value === undefined) return ["openid", "profile"];
  if (!Array.isArray(value) || value.length === 0 || value.length > SUPPORTED_SCOPES.size) return null;
  const scopes = [...new Set(value)];
  if (scopes.length !== value.length || scopes.some((scope) => !SUPPORTED_SCOPES.has(scope)) ||
      !scopes.includes("openid")) return null;
  return scopes.sort();
}

function publicClient(row) {
  let redirectUris = [];
  let scopes = [];
  try {
    redirectUris = JSON.parse(row.redirect_uris_json);
    scopes = JSON.parse(row.scopes_json);
  } catch {
    // A malformed stored row is not returned as a usable client.
  }
  return {
    client_id: row.client_id,
    client_name: row.client_name,
    redirect_uris: Array.isArray(redirectUris) ? redirectUris : [],
    token_endpoint_auth_method: row.token_endpoint_auth_method,
    scope: Array.isArray(scopes) ? scopes.join(" ") : "",
    created_at: Number(row.created_at),
    disabled: row.disabled_at !== null,
  };
}

async function listClients(request, env) {
  const session = await readSession(request, env);
  ownerOnly(session);
  const result = await env.FORUM_DB.prepare(
    "SELECT client_id, client_name, redirect_uris_json, token_endpoint_auth_method, " +
      "scopes_json, created_at, disabled_at FROM wa_oauth_clients ORDER BY created_at DESC LIMIT 100",
  ).all();
  return json({ clients: (result.results || []).map(publicClient) });
}

async function createClient(request, env) {
  const session = await requireCsrf(request, env);
  ownerOnly(session);
  const body = await readJson(request);
  const name = typeof body.client_name === "string" ? body.client_name.trim() : "";
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  const authMethod = body.token_endpoint_auth_method === undefined
    ? "client_secret_basic"
    : body.token_endpoint_auth_method;
  const scopes = clientScopes(body.scopes);

  if (!name || name.length > 80 || redirectUris.length < 1 || redirectUris.length > 20 ||
      redirectUris.some((uri) => !validRedirectUri(uri)) ||
      new Set(redirectUris).size !== redirectUris.length ||
      !["client_secret_basic", "none"].includes(authMethod) || !scopes) {
    throw new HttpError(400, "Provide a name, unique HTTPS or loopback redirect URIs, a supported client authentication method, and supported scopes.");
  }

  const clientId = randomToken(24);
  const clientSecret = authMethod === "client_secret_basic" ? randomToken(48) : null;
  const clientSecretHash = clientSecret ? await sha256Hex(clientSecret) : null;
  const now = nowSeconds();
  await env.FORUM_DB.prepare(
    "INSERT INTO wa_oauth_clients " +
      "(client_id, client_secret_hash, client_name, redirect_uris_json, token_endpoint_auth_method, scopes_json, created_by, created_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(
    clientId,
    clientSecretHash,
    name,
    JSON.stringify(redirectUris),
    authMethod,
    JSON.stringify(scopes),
    Number(session.user.id),
    now,
  ).run();

  return json({
    client_id: clientId,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
    client_name: name,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: authMethod,
    scope: scopes.join(" "),
    created_at: now,
  }, 201);
}

async function disableClient(request, env, clientId) {
  const session = await requireCsrf(request, env);
  ownerOnly(session);
  await rateLimit(request, env, "write");
  if (!CLIENT_ID_PATTERN.test(clientId)) throw new HttpError(404, "OAuth application not found.");
  const now = nowSeconds();
  const result = await env.FORUM_DB.prepare(
    "UPDATE wa_oauth_clients SET disabled_at = ? WHERE client_id = ? AND disabled_at IS NULL",
  ).bind(now, clientId).run();
  if (Number(result.meta?.changes) !== 1) throw new HttpError(404, "OAuth application not found.");
  await env.FORUM_DB.batch([
    env.FORUM_DB.prepare(
      "UPDATE wa_oauth_access_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL",
    ).bind(now, clientId),
    env.FORUM_DB.prepare(
      "UPDATE wa_oauth_authorization_codes SET consumed_at = ? WHERE client_id = ? AND consumed_at IS NULL",
    ).bind(now, clientId),
  ]);
  return new Response(null, { status: 204, headers: securityHeaders(new Headers({ "Cache-Control": "no-store" })) });
}

export async function handleOAuthClientRoutes(request, env, path, method) {
  if (path === "/api/oauth/clients" && method === "GET") return listClients(request, env);
  if (path === "/api/oauth/clients" && method === "POST") return createClient(request, env);
  const match = path.match(/^\/api\/oauth\/clients\/([A-Za-z0-9_-]+)$/);
  if (match && method === "DELETE") return disableClient(request, env, match[1]);
  return undefined;
}
