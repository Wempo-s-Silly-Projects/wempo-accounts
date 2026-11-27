-- 0003: Wempo Accounts OAuth 2.0 / OpenID Connect provider.
-- Every object is wa_-prefixed because Accounts shares the forum D1 database.
-- Client secrets, authorization codes, and access tokens are stored only as
-- SHA-256 hashes. Authorization codes are single-use and PKCE is mandatory.

CREATE TABLE IF NOT EXISTS wa_oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT NULL,
  client_name TEXT NOT NULL,
  redirect_uris_json TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'none')),
  scopes_json TEXT NOT NULL,
  created_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER NULL
);

CREATE TABLE IF NOT EXISTS wa_oauth_authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES wa_oauth_clients(client_id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  auth_time INTEGER NOT NULL,
  code_challenge TEXT NOT NULL,
  nonce TEXT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NULL
);

CREATE INDEX IF NOT EXISTS idx_wa_oauth_codes_expiry
  ON wa_oauth_authorization_codes(expires_at);

CREATE TABLE IF NOT EXISTS wa_oauth_access_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES wa_oauth_clients(client_id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER NULL
);

CREATE INDEX IF NOT EXISTS idx_wa_oauth_tokens_expiry
  ON wa_oauth_access_tokens(expires_at);
