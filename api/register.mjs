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

// The Make Account route (§4b): POST /api/register — the accounts front
// door's create-account lane. The users row is created with the GC-precedent
// INSERT shape (GooberCord api/accounts.mjs storeUser verbatim column list),
// and the password hash is written by the FORUM through the credential relay
// (/api/relay/password-set) — accounts never sees a pepper and stores no
// hash material of its own. The placeholder salt/hash the INSERT carries is
// overwritten by the relay's answer before the member signs in; a degraded
// relay DELETES the just-inserted row and fails the registration closed (a
// row whose hash no worker can verify must never survive).
//
// The ordering mirrors the login route and GC's register exactly:
//   same-origin → rate limits (IP then account-keyed) → Turnstile
//   ("register" action, fail-closed) → username shape → the SHARED username
//   word filter (site_settings, read-only here; api/filter.mjs is the
//   verbatim vendor of GC's) → duplicate-username 409 → the INSERT →
//   relaySet → auto-login (wa_sso_sessions) → the response, which the page
//   turns into the §2 ticket redirect through its finishLogin flow.
//
// Register is NOT the GC route's /api/auth/register path — accounts' own
// lane is /api/register (the §4b "the sites keep their own plumbing" rule;
// no path collision with anything the sites expose).
import { assertSameOrigin, createSession, userByUsernameKey, publicUser } from "./core/auth.mjs";
import { nowSeconds } from "./core/crypto.mjs";
import { HttpError, json, rateLimit, readJson, requireTurnstile } from "./core/http.mjs";
import { ROLE_MEMBER_DB } from "./core/roles.mjs";
import { relaySet } from "./relay.mjs";
import { applyWordFilter, containsFilteredWord, normalizeUsernameForFilter } from "./filter.mjs";
import { isValidUsername } from "./usernames.mjs";

// Test seam (the GooberCord registration pattern): production always runs
// the vendored requireTurnstile; tests inject env._turnstileVerify.
async function requireRegisterTurnstile(request, env, body) {
  if (typeof env._turnstileVerify === "function") {
    await env._turnstileVerify(request, env, body, "register");
    return;
  }
  await requireTurnstile(request, env, body, "register");
}

// The shared username word filter: the desk-stored list lives in D1's
// site_settings under the same key the forum desk writes. Accounts only ever
// READS it (forum tables are read-only here); a failed read means an EMPTY
// effective list, exactly like an empty desk list reads at GC — the two
// filter passes become strict no-ops, never a register refusal.
//
// A cache matters because register is a hot anonymous route: one shared
// isolation-level row read per 30s, the same shape as the forum store.
const FILTER_KEY = "filtered_words";
const FILTER_CACHE_TTL_MS = 30_000;
let filterCache = { loaded: false, raw: "", at: 0 };

export async function registerFilterWords(env) {
  if (filterCache.loaded && Date.now() - filterCache.at < FILTER_CACHE_TTL_MS) {
    return filterCache.raw;
  }
  try {
    const row = await env.GOOBER_DB.prepare(
      "SELECT value, updated_at FROM site_settings WHERE key = ? LIMIT 1",
    ).bind(FILTER_KEY).first();
    if (row) {
      filterCache = { loaded: true, raw: String(row.value ?? ""), at: Date.now() };
    }
  } catch (error) {
    // No site_settings yet: the empty list applies (a strict no-op — never a
    // register refusal). The failure itself is worth one line in the logs,
    // since a silently-empty list also silently skips the word filter.
    console.warn(
      "Username-filter site_settings read failed:",
      error && error.name ? error.name : "UnknownError",
    );
  }
  return filterCache.loaded ? filterCache.raw : "";
}

export function resetFilterCacheForTests() {
  filterCache = { loaded: false, raw: "", at: 0 };
}

// New credential shape (GooberCord validateNewCredentials verbatim, minus the
// pepper-module password check — the length rule IS the password's public
// shape; the relay re-validates strength with the forum's own isValidPassword
// before it stores anything).
function validateNewCredentials(body) {
  const username = typeof body.username === "string" ? body.username.trim() : "";
  if (!isValidUsername(username)) {
    throw new HttpError(400, "Username must be 3–24 characters and use only letters, numbers, and underscores.");
  }
  const password = typeof body.password === "string" ? body.password : "";
  if (password.length < 12 || password.length > 128) {
    throw new HttpError(400, "Password must be 12–128 characters long.");
  }
  return { username, usernameKey: username.toLowerCase(), password };
}

// The GC-precedent INSERT, with the credential columns as placeholders the
// relay overwrites (verified below) — a member row must always exist before
// the forum's password-set can UPDATE it.
const PLACEHOLDER_SALT = "00000000000000000000000000000000";
const PLACEHOLDER_HASH = "0".repeat(64);

async function storeUser(env, credentials) {
  const now = nowSeconds();
  try {
    const result = await env.GOOBER_DB.prepare(
      "INSERT INTO users (username, username_key, password_salt, password_hash, role, bio, created_at) " +
        "VALUES (?, ?, ?, ?, ?, '', ?)",
    ).bind(credentials.username, credentials.usernameKey, PLACEHOLDER_SALT, PLACEHOLDER_HASH, ROLE_MEMBER_DB, now).run();
    return await env.GOOBER_DB.prepare(
      "SELECT id, username, username_key, password_salt, password_hash, role, bio, " +
        "avatar_status, avatar_mime, avatar_updated_at, avatar_version, totp_enabled " +
        "FROM users WHERE id = ? LIMIT 1",
    ).bind(Number(result.meta.last_row_id)).first();
  } catch (error) {
    // Same duplicate-username diagnosis as the forum/GC pair: the unique
    // index on username_key fails the insert, and the pre-existing row (if
    // any) turns it into a user-facing 409 instead of a 500.
    const existing = await userByUsernameKey(env, credentials.usernameKey);
    if (existing) throw new HttpError(409, "That username is already taken.");
    throw error;
  }
}

// The relay's hash write is NOT best-effort here: register answers 201 only
// after the row's password verifies under the forum pepper. A degraded or
// refused relay deletes the placeholder row (only ever its own, matched on
// the freshly minted id) so no unverifiable account survives, and the
// registration fails closed.
async function writePasswordThroughRelay(env, user, password) {
  const answer = await relaySet(env, user.username, password);
  if (answer && answer.changed === true) return;
  await env.GOOBER_DB.prepare(
    "DELETE FROM users WHERE id = ? AND password_hash = ?",
  ).bind(Number(user.id), PLACEHOLDER_HASH).run();
  // The relay's non-ok and unreachable paths both answer null — a refused
  // password-set is a config-level fault here (the length shape was already
  // validated), so the ONE fail-closed 503 covers both.
  throw new HttpError(503, "Account creation is temporarily unavailable. Try again in a moment.");
}

export async function handleRegisterRoute(request, env) {
  assertSameOrigin(request);
  await rateLimit(request, env, "register");
  const body = await readJson(request);
  const { username, usernameKey, password } = validateNewCredentials(body);
  // The account-keyed pass bounds one username's churn across rotating IPs.
  await rateLimit(request, env, "register", "account:" + usernameKey);
  // Fail-closed human verification BEFORE any credential work.
  await requireRegisterTurnstile(request, env, body);
  // Username word filter — identity, never prose (the GC-parity check at the
  // GC-parity spot: right after the shape validation).
  const words = await registerFilterWords(env);
  if (
    applyWordFilter(username, words) !== username ||
    containsFilteredWord(normalizeUsernameForFilter(username), words)
  ) {
    throw new HttpError(400, "That username isn't allowed.");
  }
  // The row INSERT: the unique index on username_key carries the same 409
  // diagnosis the siblings answer.
  const user = await storeUser(env, { username, usernameKey, password });
  // The forum's pepper is the truth for the hash; the relay writes it.
  await writePasswordThroughRelay(env, user, password);
  // Auto-login (the §4b flow): the accounts-site session mints here, and the
  // page's finishLogin turns the response into the §2 ticket redirect.
  const session = await createSession(request, env, Number(user.id));
  return json({ user: publicUser(user), csrfToken: session.csrfToken }, 201, {
    "Set-Cookie": session.setCookie,
  });
}
