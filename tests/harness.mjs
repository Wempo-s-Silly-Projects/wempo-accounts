// Shared test harness (the GooberCord fakeDb + pinned-SQL house style): a
// statement-routing fake D1, fake rate limiters, a canonical users row, and
// a dispatch helper that drives Accounts' worker entrypoint exactly as
// workerd would (same origin, real Response objects — no network).
import worker from "../worker.mjs";
import { nowSeconds, sha256Hex } from "../api/core/crypto.mjs";

const ORIGIN = "https://accounts.itswempo.workers.dev";

// fakeDb routes by SQL text; each route may answer `first` (a row read) or
// rely on the default run() result. Every statement that ever ran stays in
// `executed` so tests can PIN the SQL (the wa_-only / read-only-users
// discipline asserts against it).
export function fakeDb(routes) {
  const find = (sql) => routes.find((route) => route.test(sql));
  const executed = [];
  const db = {
    executed,
    prepare(sql) {
      const statement = { sql, bound: [] };
      statement.bind = (...values) => {
        statement.bound = values;
        return statement;
      };
      statement.first = async () => {
        executed.push({ sql, bound: statement.bound });
        const route = find(sql);
        return route && route.first ? await route.first(statement.bound) : null;
      };
      statement.run = async () => {
        executed.push({ sql, bound: statement.bound });
        const route = find(sql);
        return route && route.run ? { meta: await route.run(statement.bound) } : { meta: { changes: 1 } };
      };
      statement.all = async () => {
        executed.push({ sql, bound: statement.bound });
        return { results: [] };
      };
      return statement;
    },
    async batch(statements) {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      return results;
    },
  };
  return db;
}

// The WA_* limiter fakes: every limit() call is counted with its identity
// (the test pins who got throttled); `fail` answers { success: false }.
export function fakeLimiter(fail = false) {
  const calls = [];
  return {
    calls,
    async limit({ key }) {
      calls.push(key);
      return { success: !fail };
    },
  };
}

export function limiters(fails = {}) {
  const env = {};
  const fakes = {};
  for (const name of ["LOGIN", "REGISTER", "TOTP", "READ", "WRITE"]) {
    const fake = fakeLimiter(Boolean(fails[name.toLowerCase()]));
    env["WA_" + name + "_RATE_LIMITER"] = fake;
    fakes[name.toLowerCase()] = fake;
  }
  env.fakes = fakes;
  return env;
}

// The canonical forum users row (identity + 2FA columns ONLY — the login
// projection never selects a password column; test data mirrors that).
export function usersRow(overrides = {}) {
  return {
    id: 7,
    username: "wempos",
    username_key: "wempos",
    role: "moderator", // stored vocabulary — publicRole renders 'admin'
    totp_enabled: 0,
    totp_secret: null,
    ...overrides,
  };
}

// The users read routes: identity by username_key, the session join.
export function dbFor(user = usersRow(), sessionRow = null, { filterWords } = {}) {
  const filteredWords = filterWords instanceof Map ? filterWords : new Map();
  return fakeDb([
    { test: (sql) => sql.includes("FROM users WHERE username_key = ?"),
      first: async () => user },
    { test: (sql) => sql.includes("FROM users WHERE id = ? LIMIT 1"),
      first: async (bound) => (Number(bound[0]) === user.id ? user : null) },
    { test: (sql) => sql.startsWith("INSERT INTO users"),
      run: async () => ({ changes: 1, last_row_id: user.id }) },
    { test: (sql) => sql.includes("FROM wa_sso_sessions s LEFT JOIN users u"),
      first: async () => sessionRow },
    // The shared username-filter list (register's read-only site_settings
    // lookup): an empty desk list applies — the two filter passes are no-ops.
    { test: (sql) => sql.includes("FROM site_settings WHERE key = ?"),
      first: async (bound) => (filteredWords.has(String(bound[0])) ?
        { value: filteredWords.get(String(bound[0])), updated_at: nowSeconds } : null) },
  ]);
}

export function registerRequest(body, overrides = {}) {
  return new Request(ORIGIN + "/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, ...overrides },
    body: JSON.stringify(body),
  });
}

export function loginRequest(body, overrides = {}) {
  return new Request(ORIGIN + "/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: ORIGIN,
      ...overrides,
    },
    body: JSON.stringify(body),
  });
}

export async function dispatch(request, env) {
  return worker.fetch(request, env, undefined);
}

export { ORIGIN, sha256Hex, nowSeconds };
