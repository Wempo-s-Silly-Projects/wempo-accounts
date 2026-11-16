// Migration 0001 scoping pin: the Wempo Accounts phase-1 D1 surface
// (wa_login_tickets + wa_sso_sessions) on the SHARED wempo-forum-data D1.
// Same contract as the GooberCord 0006/0007/0008 pins, with the accounts
// prefix: every statement targets a wa_-prefixed object; `users` is never
// created, altered, or written (it is only ever a read-only FK target —
// a target, not a write). The parser below is STRICT by design: any
// statement it cannot positively classify as targeting a wa_* object is a
// FAILURE, not a pass.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const MIGRATION = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations",
  "0001_wa_sessions.sql",
);

const sql = readFileSync(MIGRATION, "utf8");

function stripQuotes(name) {
  return name.replace(/^"(.*)"$/, "$1");
}

// Strip -- line comments; statements close on a semicolon whose BEGIN/END
// balance is even (no triggers in this file, but the rule costs nothing).
function statementsOf(text) {
  const withoutComments = text.replace(/--[^\n]*/g, "");
  const parts = withoutComments.split(";");
  const statements = [];
  let buf = [];
  const count = (s, word) => (s.match(new RegExp(`\\b${word}\\b`, "gi")) || []).length;
  for (const part of parts) {
    buf.push(part);
    const candidate = buf.join(";");
    if (count(candidate, "begin") === count(candidate, "end")) {
      const trimmed = candidate.trim();
      if (trimmed) statements.push(trimmed);
      buf = [];
    }
  }
  const tail = buf.join(";").trim();
  if (tail) statements.push(tail);
  return statements;
}

// Same classify shape the GC pins use (this migration ships only the two
// statement forms the shared ledger's idempotent re-apply needs).
function classify(statement) {
  const plain = statement.replace(/--[^\n]*/g, "").trim();
  if (!plain) return { form: "comment-only" };

  let m = /^CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?([\w"'.]+)/i.exec(plain);
  if (m) return { form: "CREATE TABLE", name: stripQuotes(m[2]), target: stripQuotes(m[2]), ifNotExists: Boolean(m[1]) };

  m = /^CREATE\s+(?:UNIQUE\s+)?INDEX\s+UNIQUE\s*(?:IF\s+NOT\s+EXISTS\s+)?([\w"'.]+)/i.exec(plain)
    || /^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w"'.]+)\s+ON\s+([\w"'.]+)/is.exec(plain);
  if (m) {
    return { form: "CREATE INDEX", name: stripQuotes(m[1]), target: stripQuotes(m[2]), ifNotExists: true };
  }

  return { form: "unrecognized" };
}

const wa = (value) => /^wa_/.test(String(value || "").replace(/^"(.*)"$/, "$1"));

test("migration 0001 only targets wa_-prefixed objects with known statement forms", () => {
  const statements = statementsOf(sql);
  const offenders = statements
    .map(classify)
    .filter((c) =>
      c.form === "unrecognized" ||
      !wa(c.target) ||
      (c.form === "CREATE INDEX" ? !/^idx_wa_/.test(c.name) : !wa(c.name)))
    .map((c) => c.form + " " + (c.name || ""));

  assert.ok(statements.length > 0, "parsed at least one statement");
  assert.deepEqual(offenders, []);
});

test("0001 has no DROP, PRAGMA, UPDATE, DELETE, or INSERT statements", () => {
  const stripped = sql.replace(/--[^\n]*/g, "");
  assert.doesNotMatch(stripped, /\bDROP\b/i);
  assert.doesNotMatch(stripped, /\bPRAGMA\b/i);
  assert.doesNotMatch(stripped, /\bUPDATE\b/i);
  assert.doesNotMatch(stripped, /\bDELETE\s+FROM\b/i);
  assert.doesNotMatch(stripped, /\bINSERT\s+INTO\b/i);
  // users is NEVER created or altered here — only a read-only FK target.
  const statements = statementsOf(sql);
  for (const c of statements.map(classify)) {
    assert.equal(c.form === "ALTER TABLE", false, "no ALTERs land on the shared ledger");
  }
});

test("0001 creates the two phase-1 tables with the phase-2 ticket contract", () => {
  const statements = statementsOf(sql);
  const tableNames = statements.map(classify).filter((c) => c.form === "CREATE TABLE").map((c) => c.name);
  assert.ok(tableNames.includes("wa_login_tickets"), "wa_login_tickets exists from phase 1");
  assert.ok(tableNames.includes("wa_sso_sessions"), "wa_sso_sessions exists from phase 1");
  // Token-hash PKs: raw codes/tokens are stored ONLY as SHA-256 hashes, so
  // neither table can ever carry a printable secret column.
  assert.match(sql, /CREATE TABLE IF NOT EXISTS wa_login_tickets \(\s*\n\s*code_hash TEXT PRIMARY KEY,/i);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS wa_sso_sessions \(\s*\n\s*token_hash TEXT PRIMARY KEY,/i);
  // The ticket row carries its one redeemer stamp: redeemed_at/redeemed_by
  // are NULL until the phase-2 redeem runs (a ticket is one-time).
  assert.match(sql, /redeemed_at\s+INTEGER\s+NULL/i);
  assert.match(sql, /redeemed_by\s+TEXT\s+NULL/i);
  // The return-site is the phase-2 handshake's only per-ticket payload.
  assert.match(sql, /return_site\s+TEXT\s+NOT\s+NULL/i);
  // The sso-session row carries the CSRF token, and expiry windows too —
  // both tables time out (tickets ≤60s at mint; sessions carry the sweep).
  assert.match(sql, /csrf_token\s+TEXT\s+NOT\s+NULL/i);
  assert.match(sql, /expires_at\s+INTEGER\s+NOT\s+NULL/i);
  assert.match(sql, /created_at\s+INTEGER\s+NOT\s+NULL/i);
  // Read-only FK targets: users(id) is referenced, never written.
  assert.match(
    sql,
    /user_id\s+INTEGER\s+NOT\s+NULL\s+REFERENCES\s+users\(id\)\s+ON\s+DELETE\s+CASCADE/i,
  );
});

test("0001 ships exactly one lookup index (the expiry sweep) and is independent", () => {
  const indexes = statementsOf(sql).map(classify).filter((c) => c.form === "CREATE INDEX");
  assert.equal(indexes.length, 1, "the PK covers token reads; only the sweep needs an index");
  assert.equal(indexes[0].name, "idx_wa_sessions_expiry");
  assert.equal(indexes[0].target, "wa_sso_sessions");
  assert.ok(indexes[0].ifNotExists, "the shared ledger needs CREATE INDEX IF NOT EXISTS");
  // Order independence and cross-prefix hygiene: the file references NO
  // object outside the wa_ family and the read-only users FK — no gc_*
  // table, no forum session/ban/totp object is ever named as its own target.
  const stripped = sql.replace(/--[^\n]*/g, "");
  assert.equal(/\bgc_/i.test(stripped), false, "no GooberCord object is referenced");
  const statements = statementsOf(sql);
  const targets = [...new Set(statements.map((s) => classify(s).target || "").filter(Boolean))];
  assert.deepEqual(
    targets.filter((name) => !wa(name)),
    [],
    "every concrete target is wa_-prefixed",
  );
});
