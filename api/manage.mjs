// Account management routes (owner-approved design section "new account
// management"): the signed-in page's lanes, behind requireCsrf (same-origin +
// live session + X-CSRF-Token) exactly like logout:
//
//   POST /api/password/change  { currentPassword, newPassword }
//     The password change through the CREDENTIAL RELAY. The current password
//     is re-proofed with /api/relay/password-verify, the new one is stored by
//     the forum with /api/relay/password-set (the Make Account verb). Accounts
//     never sees a pepper, stores no hash material, logs nothing, and answers
//     with no password material. A wrong current password is a clean 403 that
//     touches nothing; a degraded/refused relay on either leg fails closed
//     503 — and because the set leg is one atomic UPDATE forum-side (register
//     pins its contract), the old password stays untouched by construction.
//
//   GET  /api/sessions
//     The caller's OWN wa_sso_sessions rows, live ones only (expires_at in
//     the WHERE), the current one flagged. Row identity is the non-secret
//     session_id (migration 0002); the SHA-256 token hashes and the CSRF
//     tokens never leave the worker.
//
//   POST /api/sessions/revoke  { sessionId }
//     Deletes that one row for the caller's user. Revoking the CALLING row
//     behaves exactly like logout: the answer expires the wempo_account_session
//     cookie (and tells the page with signedOut: true).
//
//   POST /api/sessions/revoke-all
//     The TRUE sign-out-everywhere: the member-sites leg runs FIRST through
//     the forum's token-gated /api/relay/session-revoke-all (GC's
//     goober_session and the forum's wempo_session share the one `sessions`
//     table — one user_id-scoped DELETE there signs the member out of every
//     member site; accounts never writes `sessions` directly), then the
//     accounts' OWN rows go (the calling one INCLUDED — signedOut: true +
//     the expired cookie), then every still-pending wa_login_ticket (the
//     ≤60s re-entry hole). A null/degraded relay answer is a fail-closed
//     503 with nothing deleted — no partial success, ever.
//
// Rate limits: the global write/read tiers run in worker.mjs's dispatch (the
// logout pattern); the password lane adds its own strict WA_PASSWORD tier as
// an IP pass then an account pass, BOTH before any relay call (constants.mjs).
// TOTP is deliberately absent — the owner gates TOTP writes (forum columns).
import { expiredCookie, readSession, requireCsrf } from "./core/auth.mjs";
import { nowSeconds } from "./core/crypto.mjs";
import { HttpError, json, readJson, rateLimit } from "./core/http.mjs";
import { relayRevokeAll, relaySet, relayVerify } from "./relay.mjs";

// The shared fail-closed copy for every relay leg that could not establish
// its fact (unreachable, refused token, non-ok, a shape we can't trust).
// A 503 here never claims success and never distinguishes the fault.
const RELAY_UNAVAILABLE =
  "Password changes are temporarily unavailable, so nothing was changed. " +
  "Try again in a moment.";

// The sign-out-everywhere leg's own fail-closed copy (same shared tone, the
// right fact: NOTHING was deleted if the relay leg could not establish it —
// no partial success, ever).
const RELAY_SESSION_UNAVAILABLE =
  "Signing out everywhere is temporarily unavailable, so nothing was " +
  "changed. Try again in a moment.";

// The session_id shape mint.ts mints (16 bytes, lowercase hex). A malformed
// id is a shape 400 before any storage question is asked — sso.mjs's
// 64-hex lesson, one size down.
const SESSION_ID_PATTERN = /^[0-9a-f]{32}$/;

// Strict response validation (the login/register style, one step further):
// a password-verify answer is trusted only when EVERY field it leans on is
// the field it expects — the verdict is a real true, and the user payload
// matches the CALLING session exactly (right row, right account, no relay
// answer about anyone else is ever honored). A well-formed { valid: false }
// is the forum's clean wrong-password verdict; anything else — including a
// 200-with-wrong-shape — is the degraded path, not a credential answer.
function verifyEstablished(answer, session) {
  return Boolean(
    answer &&
      answer.valid === true &&
      answer.user &&
      typeof answer.user === "object" &&
      Number(answer.user.id) === Number(session.user.id) &&
      answer.user.username === session.user.username,
  );
}

// The 12–128 new-password rule, register's validateNewCredentials rule and
// copy exactly (api/register.mjs) — the same public shape the relay will
// re-check under the forum's own isValidPassword before storing anything.
function passwordShape(body) {
  const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
  const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
  if (currentPassword.length < 1 || currentPassword.length > 128 || newPassword.length === 0) {
    throw new HttpError(400, "Enter your current and new password.");
  }
  if (newPassword.length < 12 || newPassword.length > 128) {
    throw new HttpError(400, "Password must be 12–128 characters long.");
  }
  return { currentPassword, newPassword };
}

async function handlePasswordChangeRoute(request, env) {
  const session = await requireCsrf(request, env);
  if (!session.user) throw new HttpError(401, "Please sign in to do that.");
  // The strict tiers BEFORE the body is even read, and before any relay
  // call ever happens: the IP pass, then the account pass (the totp
  // keyed-by-id pattern — one username cannot be hammered through this
  // lane from rotating IPs), the login route's gate ordering.
  await rateLimit(request, env, "password");
  await rateLimit(request, env, "password", "user:" + Number(session.user.id));
  const body = await readJson(request);
  const { currentPassword, newPassword } = passwordShape(body);

  // Leg 1 — the current password is re-proofed by the forum (the pepper
  // never rides this worker). null (degraded/unrefused) is NOT a wrong
  // password: a config fault answers 503 and touches nothing. Only the
  // forum's own { valid: false } is the clean 403.
  const verdict = await relayVerify(env, session.user.username, currentPassword);
  if (verdict === null) throw new HttpError(503, RELAY_UNAVAILABLE);
  if (verdict.valid !== true) throw new HttpError(403, "The current password is incorrect.");
  if (!verifyEstablished(verdict, session)) throw new HttpError(503, RELAY_UNAVAILABLE);

  // Leg 2 — the forum writes the new hash in ONE atomic UPDATE (username-
  // keyed; register pins the answer contract). A refused/degraded set leaves
  // the old password untouched: nothing was written, nothing is cleaned up,
  // and the caller learns the same shared-toned 503.
  const answer = await relaySet(env, session.user.username, newPassword);
  if (!answer || answer.changed !== true) throw new HttpError(503, RELAY_UNAVAILABLE);

  // No password material in any answer — not the new one, not the old one.
  return json({ changed: true });
}

async function handleSessionsListRoute(request, env) {
  const session = await readSession(request, env);
  if (!session || !session.user) throw new HttpError(401, "Please sign in to do that.");
  // The caller's own rows, live ones only; the expiry predicate rides the
  // WHERE exactly like the session-boot read. Only the non-secret
  // session_id + the two timestamps ever leave the worker.
  const list = await env.GOOBER_DB.prepare(
    "SELECT session_id, created_at, expires_at FROM wa_sso_sessions " +
      "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC, session_id DESC",
  ).bind(Number(session.user.id), nowSeconds()).all();
  const rows = list && Array.isArray(list.results) ? list.results : [];
  return json({
    sessions: rows
      // A row without a minted id (only possible across a missed migration)
      // is not revocable one-by-one — it stays for revoke-all, never the page.
      .filter((row) => typeof row.session_id === "string" && SESSION_ID_PATTERN.test(row.session_id))
      .map((row) => ({
        id: row.session_id,
        createdAt: Number(row.created_at),
        expiresAt: Number(row.expires_at),
        current: row.session_id === session.sessionId,
      })),
  });
}

async function handleSessionRevokeRoute(request, env) {
  const session = await requireCsrf(request, env);
  if (!session.user) throw new HttpError(401, "Please sign in to do that.");
  const body = await readJson(request);
  const sessionId = typeof body.sessionId === "string" ? body.sessionId.toLowerCase() : "";
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    throw new HttpError(400, "That session is not valid.");
  }
  // The row must be the CALLING user's own and still live — a foreign or
  // expired id is the same "already gone" answer (no oracle for which).
  const row = await env.GOOBER_DB.prepare(
    "SELECT token_hash FROM wa_sso_sessions " +
      "WHERE session_id = ? AND user_id = ? AND expires_at > ? LIMIT 1",
  ).bind(sessionId, Number(session.user.id), nowSeconds()).first();
  if (!row) throw new HttpError(404, "That session is already gone.");
  await env.GOOBER_DB.prepare(
    "DELETE FROM wa_sso_sessions WHERE session_id = ? AND user_id = ?",
  ).bind(sessionId, Number(session.user.id)).run();

  // Revoking the CALLING session behaves exactly like logout: the answer
  // expires the cookie (and the page drops to the sign-in form).
  const signedOut = row.token_hash === session.tokenHash;
  if (!signedOut) {
    return json({ revoked: true, signedOut: false });
  }
  // json() already rides the security-header set + no-store; the cookie is
  // the expired one (the logout answer's Set-Cookie, manage-shaped).
  return json({ revoked: true, signedOut: true }, 200, {
    "Set-Cookie": expiredCookie(request),
  });
}

async function handleSessionRevokeAllRoute(request, env) {
  const session = await requireCsrf(request, env);
  if (!session.user) throw new HttpError(401, "Please sign in to do that.");
  const userId = Number(session.user.id);

  // Leg 0 — the member sites. GC's goober_session and the forum's
  // wempo_session hash into the SAME `sessions` table on the shared D1, so
  // the FORUM's token-gated relay route (a single user_id-scoped DELETE)
  // signs the member out of every member site at once. Accounts never
  // touches `sessions` directly (the wa_-only discipline stands; the relay
  // leg is the point). THE RELAY LEG RUNS FIRST and a null/degraded answer
  // is a fail-closed 503 with NOTHING deleted — a "sign out everywhere"
  // that only half-worked must never exist: no partial success, ever.
  const sites = await relayRevokeAll(env, userId);
  if (!sites || typeof sites.revoked !== "number") {
    throw new HttpError(503, RELAY_SESSION_UNAVAILABLE);
  }

  // Leg 1 — the accounts SITE's own rows, the CALLING ONE INCLUDED (the
  // token_hash <> ? exclusion is gone: "everywhere" is literally true, so
  // the caller's answer below carries signedOut: true + the expired cookie,
  // exactly like the calling-row revoke above).
  const result = await env.GOOBER_DB.prepare(
    "DELETE FROM wa_sso_sessions WHERE user_id = ?",
  ).bind(userId).run();

  // Leg 2 — the handshake's re-entry hole: a minted-but-unredeemed ticket
  // (up to SSO_TICKET_TTL_SECONDS of life) would let a stale tab hop right
  // back to a member site AFTER the everywhere press. Those go too —
  // redeemed ones are already spent, so only the pending lane is deleted.
  const tickets = await env.GOOBER_DB.prepare(
    "DELETE FROM wa_login_tickets WHERE user_id = ? AND redeemed_at IS NULL",
  ).bind(userId).run();

  const revoked = Number(result && result.meta && result.meta.changes) || 0;
  const pendingTickets = Number(tickets && tickets.meta && tickets.meta.changes) || 0;
  // json() rides the security-header set + no-store; the cookie is the
  // expired one (the calling-row answer's Set-Cookie, manage-shaped).
  return json({ revoked, sites: sites.revoked, tickets: pendingTickets, signedOut: true }, 200, {
    "Set-Cookie": expiredCookie(request),
  });
}

export async function handleManageRoutes(request, env, path, method) {
  if (path === "/api/password/change" && method === "POST") {
    return handlePasswordChangeRoute(request, env);
  }
  if (path === "/api/sessions" && method === "GET") {
    return handleSessionsListRoute(request, env);
  }
  if (path === "/api/sessions/revoke" && method === "POST") {
    return handleSessionRevokeRoute(request, env);
  }
  if (path === "/api/sessions/revoke-all" && method === "POST") {
    return handleSessionRevokeAllRoute(request, env);
  }
  return undefined;
}
