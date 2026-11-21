# Wempo Accounts architecture

Wempo Accounts (<https://accounts.wempos-forum.com>) is the account home for
Wempo's Forum (<https://wempos-forum.com>). It is the only place members make
accounts and sign in; the forum trusts it through a one-time ticket handoff.

## Pieces

| Piece | Where | Role |
| --- | --- | --- |
| Worker entry | `worker.mjs` | Routes `/api/*` to `api/accounts.mjs`; everything else is served from `public/` with the same security headers. |
| Sign-in, register, session | `api/accounts.mjs`, `api/register.mjs`, `api/core/auth.mjs` | `POST /api/login`, `POST /api/register`, `GET /api/me`, `POST /api/logout`. |
| Single sign-on | `api/sso.mjs` | `POST /api/sso/ticket` (browser), `POST /api/sso/redeem` (forum worker only). |
| Account management | `api/manage.mjs` | `POST /api/password/change`, `GET /api/sessions`, `POST /api/sessions/revoke`, `POST /api/sessions/revoke-all`. |
| Credential relay client | `api/relay.mjs` | Calls the forum worker for password verify, password set, and revoke-all-sessions. |
| Page | `public/index.html`, `public/js/accounts.js` | One page with three states: sign in, make account, manage account. |

## Data

Accounts shares the forum's D1 database.

- **Reads:** the forum's `users` table (identity, role, two-factor state) and
  the username word filter in `site_settings`.
- **Owns:** `wa_sso_sessions` (Accounts sessions: token hash, CSRF token,
  public `session_id`, expiry) and `wa_login_tickets` (ticket hash, user,
  `return_site`, expiry, redeemed time and redeeming worker). See
  `migrations/0001_wa_sessions.sql` and `migrations/0002_wa_session_ids.sql`.
- **Never touches:** password hashes or the password pepper. Those live only
  in the forum worker.

The one exception to "read only" on `users` is account creation: `POST
/api/register` inserts the new `users` row with a placeholder password, then
asks the forum to set the real hash. If the forum can't be reached, the new
row is deleted and registration fails.

## Credentials stay in the forum

Every password question goes to the forum worker over the `FORUM_WORKER`
service binding with the shared `RELAY_TOKEN`:

- `/api/relay/password-verify` — is this username and password correct?
  The answer carries no hash or salt.
- `/api/relay/password-set` — store this password (account creation and
  password change).
- `/api/relay/session-revoke-all` — end all of this user's forum sessions.

If the token is missing or the forum doesn't answer, the call returns
nothing and the action fails closed.

## Sign-in

1. Same-origin check, then the sign-in rate limits (by IP and by account).
2. Turnstile check.
3. Password check through the relay.
4. If the account has two-factor turned on, the page re-submits with the
   6-digit code, which Accounts checks against the stored TOTP secret
   (with its own rate limit).
5. A new `wa_sso_sessions` row and the `wempo_account_session` cookie
   (HttpOnly, SameSite=Lax, 30 days).

Two-factor setup and backup codes are not part of Accounts today.

## Single sign-on to the forum

1. The forum links to `/?return=https://wempos-forum.com`.
2. After sign-in, the page posts that `return` to `/api/sso/ticket`. The
   value must exactly equal an entry in `SSO_RETURN_ALLOWLIST`
   (`constants.mjs`).
3. Accounts mints a random 32-byte ticket, stores only its SHA-256 hash with
   a 60-second expiry, and redirects to `<return>/?wt=<ticket>`.
4. The forum worker calls `/api/sso/redeem` over its service binding with
   the relay token and an `X-Relay-Worker` header naming itself. One guarded
   `UPDATE` marks the ticket redeemed only if it is unused, unexpired, and
   was minted for that worker's site. Every failure is the same `410`.
5. The redeem answers `{ userId, username, role }` and the forum starts its
   own session.

Signing out of the forum sends the browser to `/?signout=1`, which ends the
Accounts session and shows the sign-in form without redirecting back.

## Sessions and sign-out everywhere

- `GET /api/sessions` lists the caller's live Accounts sessions by
  `session_id`; token hashes never leave the worker.
- `POST /api/sessions/revoke` ends one session (ending the current one
  signs you out).
- `POST /api/sessions/revoke-all` first ends every forum session through
  the relay, then deletes all of the user's Accounts sessions and unused
  tickets. If the relay fails, nothing is deleted.

All management routes require the session cookie, a same-origin request,
and the `X-CSRF-Token` header.

## Rate limits

Each tier is a Workers rate limiter declared in `wrangler.toml` and mapped
in `constants.mjs`:

| Tier | Limit | Used by |
| --- | --- | --- |
| login | 10 / min | sign-in, ticket minting |
| register | 10 / min | account creation |
| totp | 10 / min | two-factor codes |
| password | 10 / min | password change |
| redeem | 30 / min | ticket redeem, keyed by calling worker |
| read | 180 / min | every GET |
| write | 45 / min | every other request |
