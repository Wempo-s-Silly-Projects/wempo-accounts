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

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const migration = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations",
  "0003_wa_oauth_provider.sql",
);
const sql = readFileSync(migration, "utf8").replace(/--[^\\n]*/g, "");

test("migration 0003 creates only wa_-prefixed OAuth objects", () => {
  const statements = sql.split(";").map((part) => part.trim()).filter(Boolean);
  assert.equal(statements.length, 5);
  for (const statement of statements) {
    if (/^CREATE TABLE/i.test(statement)) {
      assert.match(statement, /^CREATE TABLE IF NOT EXISTS wa_oauth_[a-z_]+/i);
    } else {
      assert.match(statement, /^CREATE INDEX IF NOT EXISTS idx_wa_oauth_[a-z_]+\\s+ON wa_oauth_[a-z_]+/i);
    }
  }
  assert.doesNotMatch(sql, /\\b(DROP|ALTER|PRAGMA)\\b/i);
});

test("OAuth tables store hashes and enforce expiry, one-time codes, and client ownership", () => {
  assert.match(sql, /client_secret_hash TEXT NULL/i);
  assert.match(sql, /code_hash TEXT PRIMARY KEY/i);
  assert.match(sql, /token_hash TEXT PRIMARY KEY/i);
  assert.match(sql, /consumed_at INTEGER NULL/i);
  assert.match(sql, /revoked_at INTEGER NULL/i);
  assert.match(sql, /REFERENCES users\\(id\\)/i);
  assert.match(sql, /CHECK \\(token_endpoint_auth_method IN \\('client_secret_basic', 'none'\\)\\)/i);
});
