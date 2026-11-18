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

// Accounts routes (phase 1: scaffold + login): POST /api/login (password +
// Turnstile + the TOTP second step), GET /api/me, POST /api/logout. The
// route/shape/status-code handling mirrors GooberCord's api/accounts.mjs
// (itself the forum's session.mjs ordering: same-origin → rate limit → body
// → TOTP branch → session mint), with three deliberate substitutions:
//   • The password question is never answered here — the RELAY is. Accounts
//     reads only identity/2FA columns of the shared users table; the pepper
//     and the hashes stay forum-side, so there is no local dummy-salt burn
//     (the forum's relay burns its own for unknown usernames).
//   • The TOTP second step is the { username, password, totp } RE-SUBMISSION
//     shape: the forum's pepper-keyed challenge token cannot exist here (the
//     pepper must never ride this worker), so step two re-proofs the
//     password through the relay and then verifies the freshly read code.
//     A failed code is ONE shared 401 no matter its content.
//   • Sessions live in wa_sso_sessions (migration 0001) with the
//     wempo_account_session cookie; forum tables are read-only here, and
//     no ban gate runs at this login — the forum answers bans at its own
//     sign-in, and phase 2's handshake inherits that decision.
import { assertSameOrigin, createSession, requireCsrf, readSession, expiredCookie } from "./core/auth.mjs";
import { nowSeconds } from "./core/crypto.mjs";
import { HttpError, json, rateLimit, readJson, requireTurnstile, securityHeaders } from "./core/http.mjs";
import { verifyTotpCode } from "./core/totp.mjs";
import { userByUsernameKey, publicUser } from "./core/auth.mjs";
import { relayVerify } from "./relay.mjs";
import { handleRegisterRoute } from "./register.mjs";
import { handleSsoRoutes } from "./sso.mjs";
import { handleManageRoutes } from "./manage.mjs";
import { isValidUsername } from "./usernames.mjs";

// Test seam (the GooberCord pattern): real deployments always run the
// vendored requireTurnstile, which calls Cloudflare's siteverify endpoint.
// Tests inject `env._turnstileVerify` — a function with the same
// (request, env, body, expectedAction) signature — so tests never touch the
// network. Production paths are unchanged (no override exists there).
async function requireLoginTurnstile(request, env, body) {
  if (typeof env._turnstileVerify === "function") {
    await env._turnstileVerify(request, env, body, "login");
    return;
  }
  await requireTurnstile(request, env, body, "login");
}

// One answer shape for the code prompt: trimmed so a stray space can't fail
// an honest paste; an empty/absent string means "no code given".
function codeAnswer(value) {
  return typeof value === "string" && value.length <= 128 ? value.trim() : "";
}

async function handleLoginRoute(request, env) {
  assertSameOrigin(request);
  await rateLimit(request, env, "login");
  const body = await readJson(request);
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const code = codeAnswer(body.totp);
  if (!isValidUsername(username) || password.length < 1 || password.length > 128) {
    throw new HttpError(400, "Enter your username and password.");
  }
  // The account-keyed pass bounds hammering one username from rotating IPs.
  await rateLimit(request, env, "login", "account:" + username.toLowerCase());
  // Fail-closed human verification BEFORE any credential work (no relay call
  // on an unverified request).
  await requireLoginTurnstile(request, env, body);

  // The password verdict is the forum's (see relay.mjs). An unverified or
  // unreachable relay answers null/false and this route fails closed with
  // the ONE shared credential 401 — identical copy for wrong password and
  // unknown username (the relay burns the forum dummy salt for the latter).
  const relayed = await relayVerify(env, username, password);
  if (!relayed || relayed.valid !== true) {
    throw new HttpError(401, "The username or password is incorrect.");
  }
  // Valid credentials: read ONLY the identity/2FA columns of the shared
  // users row (the relay's user payload is not trusted for the projection —
  // this read is the single source).
  const user = await userByUsernameKey(env, username.toLowerCase());
  if (!user) throw new HttpError(401, "The username or password is incorrect.");

  // Two-factor sits between the password and the session mint. Without a
  // code: ask for one (200, no cookie, the form moves to its 2FA step).
  // With one: both limiter passes ride the check (IP, then the account) —
  // a code guess still had to ride a verified password, and the strict
  // tiers keep the guessing math bounded. Any failed code is ONE shared 401.
  if (Number(user.totp_enabled) === 1 && user.totp_secret) {
    if (!code) {
      return json({ totpRequired: true }, 200);
    }
    await rateLimit(request, env, "totp", "");
    await rateLimit(request, env, "totp", "user:" + Number(user.id));
    if (!(await verifyTotpCode(user.totp_secret, code, nowSeconds()))) {
      throw new HttpError(401, "That code is not correct.");
    }
  }

  const session = await createSession(request, env, Number(user.id));
  return json({ user: publicUser(user), csrfToken: session.csrfToken }, 200, {
    "Set-Cookie": session.setCookie,
  });
}

async function handleMeRoute(request, env) {
  await rateLimit(request, env, "read");
  const session = await readSession(request, env);
  if (!session || !session.user) throw new HttpError(401, "Please sign in to do that.");
  return json({ user: session.user, csrfToken: session.csrfToken });
}

async function handleLogoutRoute(request, env) {
  await rateLimit(request, env, "write");
  const session = await requireCsrf(request, env);
  await env.GOOBER_DB.prepare(
    "DELETE FROM wa_sso_sessions WHERE token_hash = ?",
  ).bind(session.tokenHash).run();
  return new Response(null, {
    status: 204,
    headers: securityHeaders(new Headers({
      "Cache-Control": "no-store",
      "Set-Cookie": expiredCookie(request),
    })),
  });
}

export async function handleAccountRoutes(request, env, url, path, method, ctx) {
  // ctx (the worker's execution context) is accepted to complete the
  // dispatch loop's handler signature; these routes schedule no background.
  // The phase-2 handshake (GET /?return=… is the page's client-side read;
  // the two POST /api/sso/* routes) lives in sso.mjs.
  void url;
  void ctx;

  if (path === "/api/login" && method === "POST") {
    return handleLoginRoute(request, env);
  }
  if (path === "/api/register" && method === "POST") {
    return handleRegisterRoute(request, env);
  }
  if (path === "/api/me" && method === "GET") {
    return handleMeRoute(request, env);
  }
  if (path === "/api/logout" && method === "POST") {
    return handleLogoutRoute(request, env);
  }
  const ssoRoute = await handleSsoRoutes(request, env, path, method);
  if (ssoRoute) return ssoRoute;
  // The account-management routes (the signed-in page's lanes: the relayed
  // password change + the wa_sso_sessions revocation lane) live in manage.mjs.
  const manageRoute = await handleManageRoutes(request, env, path, method);
  if (manageRoute) return manageRoute;
  return undefined;
}
