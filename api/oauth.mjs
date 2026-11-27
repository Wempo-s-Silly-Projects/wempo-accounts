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
import { equalConstantTime, nowSeconds, randomToken, sha256Hex } from "./core/crypto.mjs";
import { HttpError, json, rateLimit, readJson, readLimitedBody, securityHeaders } from "./core/http.mjs";
import { pairwiseSubject, publicSigningJwk, signJwt } from "./oauth-crypto.mjs";

const ISSUER = "https://accounts.wempos-forum.com";
const AUTH_CODE_TTL_SECONDS = 300;
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const SUPPORTED_SCOPES = new Set(["openid", "profile"]);
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{32,80}$/;
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const encoder = new TextEncoder();

function oauthError(error, description, status = 400, headers = {}) {
  return json({
    error,
    ...(description ? { error_description: description } : {}),
  }, status, headers);
}

function oauthNoContent(status = 200) {
  return new Response(null, {
    status,
    headers: securityHeaders(new Headers({ "Cache-Control": "no-store" })),
  });
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function readForm(request) {
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("application/x-www-form-urlencoded")) {
    throw new HttpError(415, "Use application/x-www-form-urlencoded.");
  }
  const bytes = await readLimitedBody(request, 16 * 1024);
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new HttpError(400, "The form body is not valid UTF-8.");
  }
  return new URLSearchParams(decoded);
}

async function clientById(env, clientId) {
  if (typeof clientId !== "string" || !CLIENT_ID_PATTERN.test(clientId)) return null;
  const row = await env.FORUM_DB.prepare(
    "SELECT client_id, client_secret_hash, client_name, redirect_uris_json, " +
      "token_endpoint_auth_method, scopes_json, disabled_at " +
      "FROM wa_oauth_clients WHERE client_id = ? AND disabled_at IS NULL LIMIT 1",
  ).bind(clientId).first();
  if (!row) return null;
  try {
    row.redirectUris = JSON.parse(row.redirect_uris_json);
    row.scopes = JSON.parse(row.scopes_json);
  } catch {
    return null;
  }
  if (!Array.isArray(row.redirectUris) || !Array.isArray(row.scopes)) return null;
  return row;
}

function authorizationRequest(params, client) {
  const redirectUri = params.get("redirect_uri") || "";
  const requestedScope = params.get("scope") || "";
  const scopes = requestedScope.split(" ").filter(Boolean);
  const state = params.get("state") || "";
  const codeChallenge = params.get("code_challenge") || "";
  const nonce = params.get("nonce") || null;

  if (params.get("response_type") !== "code") {
    throw new HttpError(400, "Only the authorization code response type is supported.");
  }
  if (!client || !client.redirectUris.includes(redirectUri)) {
    throw new HttpError(400, "The OAuth client or redirect URI is not registered.");
  }
  if (!scopes.length || scopes.length !== new Set(scopes).size ||
      scopes.some((scope) => !SUPPORTED_SCOPES.has(scope) || !client.scopes.includes(scope)) ||
      !scopes.includes("openid")) {
    throw new HttpError(400, "The requested scopes are not supported by this application.");
  }
  if (!state || state.length > 512 || /[\u0000-\u001f\u007f]/.test(state)) {
    throw new HttpError(400, "A valid state parameter is required.");
  }
  if (params.get("code_challenge_method") !== "S256" ||
      !CODE_CHALLENGE_PATTERN.test(codeChallenge)) {
    throw new HttpError(400, "PKCE with the S256 challenge method is required.");
  }
  if (nonce !== null && (nonce.length < 1 || nonce.length > 256)) {
    throw new HttpError(400, "The nonce parameter is not valid.");
  }
  return {
    clientId: client.client_id,
    clientName: client.client_name,
    redirectUri,
    scopes,
    scope: scopes.join(" "),
    state,
    codeChallenge,
    nonce,
  };
}

async function authorizePage(request, env) {
  await rateLimit(request, env, "read");
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id") || "";
  const client = await clientById(env, clientId);
  let authorization;
  try {
    authorization = authorizationRequest(url.searchParams, client);
  } catch (error) {
    return oauthError("invalid_request", error.message, 400);
  }

  const session = await readSession(request, env);
  if (!session?.user) {
    if (url.href.length > 4096) return oauthError("invalid_request", "The authorization request is too long.");
    const loginUrl = new URL("/", ISSUER);
    loginUrl.searchParams.set("oauth_request", url.href);
    return Response.redirect(loginUrl.toString(), 302);
  }
  if (!env.ASSETS) return oauthError("server_error", "The consent page is unavailable.", 503);
  const assetUrl = new URL("/oauth-consent.html", ISSUER);
  const response = await env.ASSETS.fetch(new Request(assetUrl));
  const headers = securityHeaders(response.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function authorizeInfo(request, env) {
  const session = await readSession(request, env);
  if (!session?.user) throw new HttpError(401, "Please sign in to continue.");
  const url = new URL(request.url);
  const client = await clientById(env, url.searchParams.get("client_id") || "");
  const authorization = authorizationRequest(url.searchParams, client);
  return json({
    client_name: authorization.clientName,
    scopes: authorization.scopes,
  });
}

async function authorizeDecision(request, env) {
  const session = await requireCsrf(request, env);
  if (!session?.user) throw new HttpError(401, "Please sign in to continue.");
  const body = await readJson(request);
  const params = new URLSearchParams();
  for (const key of ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "nonce"]) {
    if (typeof body[key] === "string") params.set(key, body[key]);
  }
  const client = await clientById(env, params.get("client_id") || "");
  const authorization = authorizationRequest(params, client);
  const redirect = new URL(authorization.redirectUri);
  if (body.approved !== true) {
    redirect.searchParams.set("error", "access_denied");
    redirect.searchParams.set("state", authorization.state);
    return json({ redirect: redirect.toString() });
  }

  const code = randomToken(32);
  const codeHash = await sha256Hex(code);
  const now = nowSeconds();
  await env.FORUM_DB.prepare(
    "INSERT INTO wa_oauth_authorization_codes " +
      "(code_hash, client_id, user_id, redirect_uri, scope, auth_time, code_challenge, nonce, expires_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(
    codeHash,
    authorization.clientId,
    Number(session.user.id),
    authorization.redirectUri,
    authorization.scope,
    Math.floor(Number(session.createdAt) || now),
    authorization.codeChallenge,
    authorization.nonce,
    now + AUTH_CODE_TTL_SECONDS,
  ).run();

  redirect.searchParams.set("code", code);
  redirect.searchParams.set("state", authorization.state);
  return json({ redirect: redirect.toString() });
}

function decodeBasicCredentials(header) {
  if (typeof header !== "string" || !header.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6));
    const separator = decoded.indexOf(":");
    if (separator < 1) return null;
    const decodeFormValue = (value) => decodeURIComponent(value.replace(/\+/g, " "));
    return {
      clientId: decodeFormValue(decoded.slice(0, separator)),
      clientSecret: decodeFormValue(decoded.slice(separator + 1)),
    };
  } catch {
    return null;
  }
}

async function authenticateClient(request, form, env) {
  const basic = decodeBasicCredentials(request.headers.get("Authorization"));
  let clientId;
  if (basic) {
    if (form.has("client_id") || form.has("client_secret")) return null;
    clientId = basic.clientId;
  } else {
    if (request.headers.has("Authorization") || form.has("client_secret")) return null;
    clientId = form.get("client_id") || "";
  }
  const client = await clientById(env, clientId);
  if (!client) return null;

  if (client.token_endpoint_auth_method === "none") {
    return basic ? null : client;
  }
  if (!basic || typeof client.client_secret_hash !== "string") return null;
  const presentedHash = await sha256Hex(basic.clientSecret);
  return equalConstantTime(presentedHash, client.client_secret_hash) ? client : null;
}

async function tokenEndpoint(request, env) {
  await rateLimit(request, env, "write");
  let form;
  try {
    form = await readForm(request);
  } catch (error) {
    return oauthError("invalid_request", error.message, error.status || 400);
  }
  const grantType = form.get("grant_type");
  if (grantType !== "authorization_code") {
    return oauthError("unsupported_grant_type", "Only authorization_code is supported.");
  }
  const client = await authenticateClient(request, form, env);
  if (!client) return oauthError("invalid_client", "Client authentication failed.", 401, {
    "WWW-Authenticate": 'Basic realm="wempo-accounts"',
  });

  const code = form.get("code") || "";
  const redirectUri = form.get("redirect_uri") || "";
  const verifier = form.get("code_verifier") || "";
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(code) ||
      !CODE_VERIFIER_PATTERN.test(verifier) ||
      !client.redirectUris.includes(redirectUri)) {
    return oauthError("invalid_grant", "The authorization code or PKCE verifier is not valid.");
  }

  const codeHash = await sha256Hex(code);
  const stored = await env.FORUM_DB.prepare(
    "SELECT code_hash, client_id, user_id, redirect_uri, scope, auth_time, code_challenge, nonce, expires_at, consumed_at " +
      "FROM wa_oauth_authorization_codes WHERE code_hash = ? AND client_id = ? LIMIT 1",
  ).bind(codeHash, client.client_id).first();
  const now = nowSeconds();
  if (!stored || stored.consumed_at !== null || Number(stored.expires_at) <= now ||
      stored.redirect_uri !== redirectUri) {
    return oauthError("invalid_grant", "The authorization code is expired or already used.");
  }

  const verifierHash = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
  if (!equalConstantTime(verifierHash, stored.code_challenge)) {
    return oauthError("invalid_grant", "The PKCE verifier does not match.");
  }

  const user = await env.FORUM_DB.prepare(
    "SELECT id, username FROM users WHERE id = ? LIMIT 1",
  ).bind(Number(stored.user_id)).first();
  if (!user) return oauthError("invalid_grant", "The account for this authorization code no longer exists.");

  let idToken;
  let accessToken;
  let accessTokenHash;
  try {
    const subject = await pairwiseSubject(env, client.client_id, Number(user.id));
    idToken = await signJwt(env, {
      iss: ISSUER,
      sub: subject,
      aud: client.client_id,
      exp: now + ACCESS_TOKEN_TTL_SECONDS,
      iat: now,
      auth_time: Number(stored.auth_time),
      ...(stored.nonce ? { nonce: stored.nonce } : {}),
      ...(stored.scope.split(" ").includes("profile") ? {
        preferred_username: user.username,
        name: user.username,
      } : {}),
    });
    accessToken = randomToken(32);
    accessTokenHash = await sha256Hex(accessToken);
  } catch (error) {
    console.error("OAuth signing configuration failed:", error && error.name ? error.name : "UnknownError");
    return oauthError("server_error", "The identity provider is not configured.", 503);
  }

  const consumed = await env.FORUM_DB.prepare(
    "UPDATE wa_oauth_authorization_codes SET consumed_at = ? " +
      "WHERE code_hash = ? AND client_id = ? AND consumed_at IS NULL AND expires_at > ?",
  ).bind(now, codeHash, client.client_id, now).run();
  if (Number(consumed.meta?.changes) !== 1) {
    return oauthError("invalid_grant", "The authorization code is expired or already used.");
  }

  const expiresAt = now + ACCESS_TOKEN_TTL_SECONDS;
  await env.FORUM_DB.prepare(
    "INSERT INTO wa_oauth_access_tokens (token_hash, client_id, user_id, scope, created_at, expires_at) " +
      "VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(accessTokenHash, client.client_id, Number(user.id), stored.scope, now, expiresAt).run();

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope: stored.scope,
    id_token: idToken,
  });
}

async function userinfoEndpoint(request, env) {
  await rateLimit(request, env, "read");
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{40,60})$/);
  if (!match) {
    return oauthError("invalid_token", "A valid bearer access token is required.", 401, {
      "WWW-Authenticate": 'Bearer error="invalid_token"',
    });
  }
  const tokenHash = await sha256Hex(match[1]);
  const row = await env.FORUM_DB.prepare(
    "SELECT t.client_id, t.user_id, t.scope, u.username " +
      "FROM wa_oauth_access_tokens t JOIN users u ON u.id = t.user_id " +
      "WHERE t.token_hash = ? AND t.revoked_at IS NULL AND t.expires_at > ? LIMIT 1",
  ).bind(tokenHash, nowSeconds()).first();
  if (!row || !String(row.scope).split(" ").includes("openid")) {
    return oauthError("invalid_token", "The access token is invalid or expired.", 401, {
      "WWW-Authenticate": 'Bearer error="invalid_token"',
    });
  }
  const claims = {
    sub: await pairwiseSubject(env, row.client_id, Number(row.user_id)),
  };
  if (String(row.scope).split(" ").includes("profile")) {
    claims.preferred_username = row.username;
    claims.name = row.username;
  }
  return json(claims);
}

async function revocationEndpoint(request, env) {
  await rateLimit(request, env, "write");
  let form;
  try {
    form = await readForm(request);
  } catch (error) {
    return oauthError("invalid_request", error.message, error.status || 400);
  }
  const client = await authenticateClient(request, form, env);
  if (!client) return oauthError("invalid_client", "Client authentication failed.", 401);
  const token = form.get("token") || "";
  if (!token || token.length > 256) return oauthError("invalid_request", "A token is required.");
  const tokenHash = await sha256Hex(token);
  await env.FORUM_DB.prepare(
    "UPDATE wa_oauth_access_tokens SET revoked_at = ? " +
      "WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL",
  ).bind(nowSeconds(), tokenHash, client.client_id).run();
  return oauthNoContent();
}

function authorizationServerMetadata() {
  return {
    issuer: ISSUER,
    authorization_endpoint: ISSUER + "/oauth2/authorize",
    token_endpoint: ISSUER + "/oauth2/token",
    userinfo_endpoint: ISSUER + "/oauth2/userinfo",
    revocation_endpoint: ISSUER + "/oauth2/revoke",
    jwks_uri: ISSUER + "/.well-known/jwks.json",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["pairwise"],
    scopes_supported: ["openid", "profile"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["RS256"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username", "name"],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  };
}

async function jwksEndpoint(env) {
  try {
    return json({ keys: [publicSigningJwk(env)] });
  } catch {
    return oauthError("server_error", "The signing key is not configured.", 503);
  }
}

async function listUserGrants(request, env) {
  const session = await readSession(request, env);
  if (!session?.user) throw new HttpError(401, "Please sign in to manage connected applications.");
  const result = await env.FORUM_DB.prepare(
    "SELECT c.client_id, c.client_name, COUNT(*) AS token_count, MAX(t.expires_at) AS latest_expiry " +
      "FROM wa_oauth_access_tokens t JOIN wa_oauth_clients c ON c.client_id = t.client_id " +
      "WHERE t.user_id = ? AND t.revoked_at IS NULL AND t.expires_at > ? " +
      "GROUP BY c.client_id, c.client_name ORDER BY c.client_name LIMIT 100",
  ).bind(Number(session.user.id), nowSeconds()).all();
  return json({
    applications: (result.results || []).map((row) => ({
      client_id: row.client_id,
      client_name: row.client_name,
      active_tokens: Number(row.token_count) || 0,
      latest_expiry: Number(row.latest_expiry) || 0,
    })),
  });
}

async function revokeUserGrant(request, env) {
  const session = await requireCsrf(request, env);
  if (!session?.user) throw new HttpError(401, "Please sign in to manage connected applications.");
  const body = await readJson(request);
  const clientId = typeof body.client_id === "string" ? body.client_id : "";
  if (!CLIENT_ID_PATTERN.test(clientId)) throw new HttpError(400, "Choose a valid connected application.");
  const now = nowSeconds();
  const tokens = await env.FORUM_DB.prepare(
    "UPDATE wa_oauth_access_tokens SET revoked_at = ? " +
      "WHERE client_id = ? AND user_id = ? AND revoked_at IS NULL",
  ).bind(now, clientId, Number(session.user.id)).run();
  const codes = await env.FORUM_DB.prepare(
    "UPDATE wa_oauth_authorization_codes SET consumed_at = ? " +
      "WHERE client_id = ? AND user_id = ? AND consumed_at IS NULL",
  ).bind(now, clientId, Number(session.user.id)).run();
  return json({
    revoked_tokens: Number(tokens.meta?.changes) || 0,
    invalidated_codes: Number(codes.meta?.changes) || 0,
  });
}

export async function handleOAuthApiRoutes(request, env, path, method) {
  if (path === "/api/oauth/authorize-info" && method === "GET") return authorizeInfo(request, env);
  if (path === "/api/oauth/authorize" && method === "POST") return authorizeDecision(request, env);
  if (path === "/api/oauth/grants" && method === "GET") return listUserGrants(request, env);
  if (path === "/api/oauth/grants/revoke" && method === "POST") return revokeUserGrant(request, env);
  return undefined;
}

export async function handleOAuthPublicRoutes(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (path === "/.well-known/openid-configuration" ||
      path === "/.well-known/oauth-authorization-server") {
    if (method !== "GET" && method !== "HEAD") return oauthError("invalid_request", "Method not allowed.", 405, { Allow: "GET, HEAD" });
    const metadata = authorizationServerMetadata();
    return json(metadata);
  }
  if (path === "/.well-known/jwks.json") {
    if (method !== "GET" && method !== "HEAD") return oauthError("invalid_request", "Method not allowed.", 405, { Allow: "GET, HEAD" });
    return jwksEndpoint(env);
  }
  if (path === "/oauth2/authorize" && method === "GET") return authorizePage(request, env);
  if (path === "/oauth2/token" && method === "POST") return tokenEndpoint(request, env);
  if (path === "/oauth2/userinfo" && (method === "GET" || method === "POST")) return userinfoEndpoint(request, env);
  if (path === "/oauth2/revoke" && method === "POST") return revocationEndpoint(request, env);
  return undefined;
}
