-- 0002: Wempo Accounts — per-row revocable session ids for the account
-- management page's session list (GET /api/sessions + POST /api/sessions/revoke
-- + POST /api/sessions/revoke-all). The SHA-256 token hashes stay the row
-- identities in storage and NEVER leave the worker (the management page's
-- contract), so each row also carries ONE non-secret random id the caller's
-- own browser may hold: session_id. The raw login token and its hash can be
-- derived from nothing here — session_id is generated fresh at mint time
-- (api/core/auth.mjs createSession) and revocations are keyed on it together
-- with user_id, so a guessed id revokes nothing it does not own.
--
-- Same contract as 0001: every statement targets a wa_-prefixed object on the
-- SHARED wempo-forum-data D1; the forum's users table is never named except
-- through nothing at all (not even the FK here — an added column carries no
-- constraint). This file applies exactly once through the migrations ledger
-- (apply-remote.sh): a bare ALTER TABLE is intentionally NOT re-apply-safe —
-- run it via wrangler d1 migrations apply, never re-run by hand.
ALTER TABLE wa_sso_sessions ADD COLUMN session_id TEXT;

-- The backfill: pre-0002 rows (any session minted before this column existed)
-- get their own random id, so a session surviving the deploy stays revocable.
UPDATE wa_sso_sessions
  SET session_id = lower(hex(randomblob(16)))
  WHERE session_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_wa_sessions_id
  ON wa_sso_sessions(session_id) WHERE session_id IS NOT NULL;
