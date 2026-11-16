// The phase-2 handshake (the sign-off's §2): Accounts' side of the redirect
// flow the member sites drive. Two routes, two lanes, never mixed:
//
//   POST /api/sso/ticket  — the BROWSER's own flow, behind the login limiter:
//     same-origin + a live wa_sso_sessions session (the member just logged
//     in here) + a 'return' that EXACTLY equals one of the allowlisted site
//     origins (constants.mjs — an equality probe, no contains, no regex; the
//     unanchored-regex advisory's lesson). Success mints a ONE-TIME ticket
//     code the browser sees exactly once and answers { redirect }.
//
//   POST /api/sso/redeem  — the SERVICE-BINDING-ONLY lane: the member sites'
//     workers call this through their bindings during the ticket hand-back;
//     it is never a browser API. A site's worker proves itself with the
//     shared X-Relay-Token (the same token the credential relay uses), the
//     code is compared against the STORED sha256 hash (no raw code is ever
//     written, and no user data is ever concat'd into SQL), and the
//     redeem-in-fact happens in ONE guarded UPDATE whose WHERE carries the
//     one-time/expiry predicates — the row changes exactly once or not at
//     all. Answer: read-only identity columns of the users row (users stays
//     a read-only FK target, never a write).
//
// No CSRF token is carried by the ticket route, deliberately: the browser's
// Origin header IS the gate here (a foreign site cannot send a same-origin
// POST on the member's behalf), and the route mints no lasting authority —
// the 60-second one-time ticket is only worth holding between its answers.
import { assertSameOrigin, readSession } from "./core/auth.mjs";
import { equalConstantTime, hex, nowSeconds, sha256Hex } from "./core/crypto.mjs";
import { HttpError, json, rateLimit, readJson } from "./core/http.mjs";
import { publicRole } from "./core/roles.mjs";
import { SSO_RETURN_ALLOWLIST, SSO_TICKET_TTL_SECONDS } from "../constants.mjs";

// The ticket code shown to the browser once: 32 bytes of CSPRNG as lowercase
// hex (the only form it takes anywhere — the table stores its hash alone).
function randomTicketCode() {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}

// The redeem stamp: the calling site's worker name rides an X-Relay-Worker
// header and is stored ONLY if it is a plain slug — anything else (or an
// absent header) is just "unknown". Never trusted beyond that shape.
const redeemStamp = (request) => {
  const name = request.headers.get("X-Relay-Worker") || "";
  return /^[A-Za-z0-9-]{1,64}$/.test(name) ? name : "unknown";
};

// The shared 410: no row, an expired row, or an already-redeemed row are the
// same non-credentialed answer (no oracle for which of the three it was).
const TICKET_GONE = "This sign-in ticket is no longer valid. Please sign in again.";

async function handleTicketRoute(request, env) {
  // The browser's own flow, so the browser's gates: same origin (the login
  // page POSTs), then the same strict tier the login itself rides.
  assertSameOrigin(request);
  await rateLimit(request, env, "login");

  const body = await readJson(request);
  const session = await readSession(request, env);
  if (!session || !session.user) throw new HttpError(401, "Please sign in to do that.");

  // The exact-match allowlist: the return must BE one of the site origins,
  // letter for letter — no suffix games, no substring rides, no case folds.
  const returnOrigin = typeof body.return === "string" ? body.return : "";
  if (returnOrigin.length > 2048 || SSO_RETURN_ALLOWLIST.indexOf(returnOrigin) < 0) {
    throw new HttpError(403, "This sign-in destination is not allowed.");
  }

  // The one-time ticket: raw code to the browser ONCE (it rides the redirect
  // URL back to the site), the hash is the only stored form, ≤60s lifetime.
  const now = nowSeconds();
  const code = randomTicketCode();
  const codeHash = await sha256Hex(code);
  await env.GOOBER_DB.prepare(
    "INSERT INTO wa_login_tickets (code_hash, user_id, return_site, expires_at) VALUES (?, ?, ?, ?)",
  ).bind(codeHash, session.user.id, returnOrigin, now + SSO_TICKET_TTL_SECONDS).run();
  // Housekeeping mirrors createSession's expiry sweep — Accounts' own table.
  await env.GOOBER_DB.prepare("DELETE FROM wa_login_tickets WHERE expires_at <= ?").bind(now).run();

  return json({ redirect: returnOrigin + "/?wt=" + code });
}

async function handleRedeemRoute(request, env) {
  // NOT a browser API: absent Origin is expected on the service-binding lane
  // (assertSameOrigin is deliberately NOT called here). The relay token is
  // the whole auth — compared constant-time, read only as env.X, never
  // printed or logged anywhere.
  const presented = request.headers.get("X-Relay-Token") || "";
  if (!env.RELAY_TOKEN || typeof env.RELAY_TOKEN !== "string" || !equalConstantTime(presented, env.RELAY_TOKEN)) {
    throw new HttpError(401, "Relay refused.");
  }

  const body = await readJson(request);
  const rawCode = typeof body.code === "string" ? body.code : "";
  const code = rawCode.trim().toLowerCase();
  // 32-byte hex or nothing: a malformed/short value is a shape 400 before
  // any storage question is asked (and no user data ever reaches this SQL —
  // the code only enters it as its sha256 hash).
  if (!/^[0-9a-f]{64}$/.test(code)) {
    throw new HttpError(400, "That sign-in ticket is not valid.");
  }
  const codeHash = await sha256Hex(code);
  const now = nowSeconds();

  // The guarded single statement: a ticket redeems exactly once. The row's
  // own state (NULL redeemed_at, live expiry) rides the WHERE, so the
  // changes==1 answer is the only proof either lane ever accepts.
  const redeem = await env.GOOBER_DB.prepare(
    "UPDATE wa_login_tickets SET redeemed_at = ?, redeemed_by = ? " +
      "WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?",
  ).bind(now, redeemStamp(request), codeHash, now).run();
  if (Number(redeem && redeem.meta && redeem.meta.changes) !== 1) {
    throw new HttpError(410, TICKET_GONE);
  }

  // Read-only identity answer: the FK target is READ here, never written.
  const row = await env.GOOBER_DB.prepare(
    "SELECT u.id, u.username, u.role FROM wa_login_tickets t " +
      "JOIN users u ON u.id = t.user_id WHERE t.code_hash = ? LIMIT 1",
  ).bind(codeHash).first();
  if (!row) throw new HttpError(410, TICKET_GONE);
  return json({ userId: Number(row.id), username: row.username, role: publicRole(row.role) });
}

export async function handleSsoRoutes(request, env, path, method) {
  if (path === "/api/sso/ticket" && method === "POST") {
    return handleTicketRoute(request, env);
  }
  if (path === "/api/sso/redeem" && method === "POST") {
    return handleRedeemRoute(request, env);
  }
  return undefined;
}
