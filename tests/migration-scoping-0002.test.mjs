// Copyright 2026 YourLocalGoober
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

// Migration 0002 scoping pin: the per-row revocable session_id the account
// management page's lanes key on. Same STRICT contract as the 0001 pin —
// every statement must positively classify as one of the three allowed
// forms, and each must target a wa_-prefixed object on the SHARED
// wempo-forum-data D1. The forum's users table is never named at all (an
// added column carries no constraint).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const MIGRATION = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations",
  "0002_wa_session_ids.sql",
);

const sql = readFileSync(MIGRATION, "utf8");

// -- comments stripped; three statements, each ending at its semicolon.
const statements = sql
  .replace(/--[^\n]*/g, "")
  .split(";")
  .map((part) => part.trim())
  .filter(Boolean);

test("migration 0002 is exactly three statements, each targeting wa_sso_sessions", () => {
  assert.equal(statements.length, 3);
  for (const statement of statements) {
    assert.match(statement, /wa_sso_sessions/, "every statement targets the accounts' own table");
  }
});

test("the three statements are the pinned forms: the ALTER, the NULL-only backfill, the partial unique index", () => {
  assert.match(statements[0], /^ALTER TABLE wa_sso_sessions ADD COLUMN session_id TEXT$/);

  // The backfill touches ONLY rows the new column left NULL — re-running the
  // ledger can never mint a second id over an existing one — and mints the
  // SAME non-secret shape createSession does: 16 random bytes, lowercase hex.
  assert.match(statements[1], /^UPDATE wa_sso_sessions\s+SET session_id = lower\(hex\(randomblob\(16\)\)\)\s+WHERE session_id IS NULL$/);

  // The lookup index is unique, IF NOT EXISTS, and skips still-unbackfilled rows.
  assert.match(
    statements[2],
    /^CREATE UNIQUE INDEX IF NOT EXISTS idx_wa_sessions_id\s+ON wa_sso_sessions\(session_id\) WHERE session_id IS NOT NULL$/,
  );
});

test("0002 has no DROP, PRAGMA, DELETE, or INSERT — and never names the forum's users table", () => {
  const stripped = sql.replace(/--[^\n]*/g, "");
  assert.doesNotMatch(stripped, /\bDROP\b/i);
  assert.doesNotMatch(stripped, /\bPRAGMA\b/i);
  assert.doesNotMatch(stripped, /\bDELETE\s+FROM\b/i);
  assert.doesNotMatch(stripped, /\bINSERT\s+INTO\b/i);
  assert.doesNotMatch(stripped, /\busers\b/, "the shared users table is never named here");
});
