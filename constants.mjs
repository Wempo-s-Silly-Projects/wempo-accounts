// Wempo Accounts constants: the rate-limit scope → binding map (the WA_*
// limiters in wrangler.toml, ids in a fresh range) and the Cloudflare
// Turnstile siteverify URL (mirrs GooberCord's constants.mjs — the same
// vendored http.mjs shape reads it).
export const RATE_LIMIT_BINDINGS = Object.freeze({
  login: "WA_LOGIN_RATE_LIMITER",
  totp: "WA_TOTP_RATE_LIMITER",
  read: "WA_READ_RATE_LIMITER",
  write: "WA_WRITE_RATE_LIMITER",
});

export const TURNSTILE_SITEVERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";

// The accounts-site session table and cookie: sessions live ONLY in
// wa_sso_sessions (migration 0001) and the cookie stays on the accounts
// host — each member site keeps its own local session (the sign-off's
// per-site cookie decision).
export const SESSION_COOKIE = "wempo_account_session";
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
