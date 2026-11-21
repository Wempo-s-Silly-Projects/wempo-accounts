-- 0001: Wempo Accounts phase 1 — the account worker's own session/ticket
-- tables on the SHARED wempo-forum-data D1 (the owner's explicit call: no
-- second account registry ever exists; accounts rides the forum database).
--
-- The migration-scoping contract: every object here is
-- wa_-prefixed and INDEPENDENT of every other migration — the file applies
-- cleanly in any order and is idempotent (IF NOT EXISTS per the shared
-- ledger's re-apply convention). The forum's `users` table is referenced
-- ONLY as a read-only FK target (a target, not a write); password verify/set
-- never happens on this worker (the FORUM_WORKER relay owns it) and this
-- migration never reads its columns. Owner-run against the remote
-- database — the worker never applies migrations itself.
--
-- wa_login_tickets is the ONE-TIME ticket-code table for the phase-2
-- handshake (the sign-off's redirect flow): a site's "Sign in with Wempo
-- Accounts" lands on /login?return=<site-url>, accounts authenticates, and
-- the ticket code rides the redirect back. The table EXISTS FROM PHASE 1
-- (the ledger lands with the scaffold) even though no route writes it yet,
-- and nothing else lives here — no profile data. The route-side contract
-- the phase-2 writers must keep (documented here, enforced in code then):
-- `code` is stored ONLY as its SHA-256 hash, expires_at is at most 60s past
-- mint, and a ticket redeems exactly once (redeemed_at/redeemed_by NULL
-- until then; the redeeming worker's own name is the consumer stamp).
CREATE TABLE IF NOT EXISTS wa_login_tickets (
  code_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  return_site TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  redeemed_at INTEGER NULL,
  redeemed_by TEXT NULL
);

-- wa_sso_sessions = the sessions of the accounts SITE itself (what
-- "sign out everywhere" revokes in phase 2). Same shape and rules as the
-- forum session table: only the SHA-256 of the cookie token is stored
-- (the raw token rides the Set-Cookie header exactly once), the CSRF token
-- rides the row, and the cookie (wempo_account_session) stays on the
-- accounts host — each member site keeps its OWN local session.
CREATE TABLE IF NOT EXISTS wa_sso_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Session reads walk by token hash (the PRIMARY KEY already answers those);
-- this index is the expiry sweep ("DELETE ... WHERE expires_at <= ?", the
-- createSession housekeeping) plus any phase-2 "sign out everywhere" scan.
CREATE INDEX IF NOT EXISTS idx_wa_sessions_expiry ON wa_sso_sessions(expires_at);
