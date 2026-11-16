// Session and identity machinery for the accounts SITE itself: cookie
// sessions with only SHA-256 token hashes stored (migration 0001's
// wa_sso_sessions — a wa_-prefixed table, never a forum object), the
// same-origin and CSRF gates, and the users-row projection the page reads.
// Vendored in shape from GooberCord's api/core/auth.mjs: the differences are
// the wa_sso_sessions table, the wempo_account_session cookie, and the
// narrower user projection (id/username/role/2FA-state — identity only, no
// profile columns). Forum users rows are read here by contract; the
// credential work itself never happens on this worker.
import { SESSION_COOKIE, SESSION_TTL_SECONDS } from "../../constants.mjs";
import { equalConstantTime, nowSeconds, randomToken, sha256Hex } from "./crypto.mjs";
import { HttpError } from "./http.mjs";
import { publicRole } from "./roles.mjs";

function setCookie(request, token, maxAge = SESSION_TTL_SECONDS) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return SESSION_COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAge + secure;
}

export function expiredCookie(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return SESSION_COOKIE + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" + secure;
}

export function cookieValue(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return null;
}

// The login-shaped users projection, read-only over the SHARED users table —
// identity columns only (the password hash columns are NEVER listed here; not
// even this worker's code touches them, by design).
export async function userByUsernameKey(env, key) {
  return env.GOOBER_DB.prepare(
    "SELECT id, username, username_key, role, totp_enabled " +
      "FROM users WHERE username_key = ? LIMIT 1",
  ).bind(key).first();
}

export function publicUser(row) {
  return {
    id: Number(row.id),
    username: row.username,
    role: publicRole(row.role),
    totpEnabled: Number(row.totp_enabled) === 1,
  };
}

export async function readSession(request, env) {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || !/^[A-Za-z0-9_-]{40,50}$/.test(token)) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.GOOBER_DB.prepare(
    "SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, " +
      "u.username, u.role, u.totp_enabled " +
      "FROM wa_sso_sessions s LEFT JOIN users u ON u.id = s.user_id " +
      "WHERE s.token_hash = ? AND s.expires_at > ? LIMIT 1",
  ).bind(tokenHash, nowSeconds()).first();
  if (!row) return null;

  let user = null;
  if (row.user_id !== null && row.username !== null) {
    user = {
      id: Number(row.user_id),
      username: row.username,
      role: publicRole(row.role),
      totpEnabled: Number(row.totp_enabled) === 1,
    };
  }
  return { tokenHash: row.token_hash, csrfToken: row.csrf_token, expiresAt: Number(row.expires_at), user };
}

export async function createSession(request, env, userId) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const csrfToken = randomToken(24);
  const now = nowSeconds();
  const expiresAt = now + SESSION_TTL_SECONDS;
  await env.GOOBER_DB.prepare(
    "INSERT INTO wa_sso_sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(tokenHash, Number(userId), csrfToken, now, expiresAt).run();
  // Housekeeping as a write to Accounts' OWN table only: expired rows leave.
  await env.GOOBER_DB.prepare("DELETE FROM wa_sso_sessions WHERE expires_at <= ?").bind(now).run();
  return { tokenHash, csrfToken, setCookie: setCookie(request, token) };
}

export function assertSameOrigin(request) {
  const origin = request.headers.get("Origin");
  const expected = new URL(request.url).origin;
  if (!origin || origin !== expected) {
    throw new HttpError(403, "This request was blocked because its origin could not be verified.");
  }
}

export async function requireCsrf(request, env) {
  assertSameOrigin(request);
  const session = await readSession(request, env);
  if (!session) throw new HttpError(401, "Your session has expired. Reload the page and sign in again.");
  const supplied = request.headers.get("X-CSRF-Token") || "";
  if (!equalConstantTime(supplied, session.csrfToken)) {
    throw new HttpError(403, "Your security token is out of date. Reload the page and try again.");
  }
  return session;
}
