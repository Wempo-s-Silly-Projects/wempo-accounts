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

// Request/response glue — the typed error, JSON responses, the security-
// header set, rate limiting, TURNSTILE verification, bounded JSON reading.
// Vendored from GooberCord's api/core/http.mjs with Accounts' substitutions:
// the WA_* limiter map (constants.mjs) and a login-specific expected action.
import { RATE_LIMIT_BINDINGS, TURNSTILE_SITEVERIFY_URL } from "../../constants.mjs";
import { sha256Hex } from "./crypto.mjs";

export const MAX_JSON_BYTES = 16 * 1024;
const TURNSTILE_TOKEN_MAX_LENGTH = 2048;

export class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.headers = headers;
  }
}

export function securityHeaders(headers = new Headers()) {
  const result = new Headers(headers);
  result.set("X-Content-Type-Options", "nosniff");
  result.set("Strict-Transport-Security", "max-age=31536000");
  result.set("X-Frame-Options", "DENY");
  result.set("Referrer-Policy", "strict-origin-when-cross-origin");
  result.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  result.set("Cross-Origin-Resource-Policy", "same-origin");
  result.set("Cross-Origin-Opener-Policy", "same-origin");
  // The login page is script-src 'self'; challenges.cloudflare.com is
  // allowed ONLY for the Turnstile widget (script/frame/connect).
  result.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; " +
    "img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; " +
    "frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; " +
    "form-action 'self'; frame-ancestors 'none'",
  );
  return result;
}

export function json(data, status = 200, headers = {}) {
  const resultHeaders = securityHeaders(new Headers(headers));
  resultHeaders.set("Content-Type", "application/json; charset=utf-8");
  resultHeaders.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(data), { status, headers: resultHeaders });
}

export async function rateLimit(request, env, scope, actor = "") {
  const bindingName = RATE_LIMIT_BINDINGS[scope];
  const limiter = bindingName ? env[bindingName] : null;
  if (!limiter || typeof limiter.limit !== "function") {
    throw new HttpError(503, "Rate limiting is not configured for this endpoint.");
  }
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const identity = actor ? scope + ":" + actor : scope + ":" + ip;
  const key = await sha256Hex(identity);
  const { success } = await limiter.limit({ key });
  if (!success) {
    throw new HttpError(429, "Too many requests. Please wait a little and try again.", {
      "Retry-After": "60",
    });
  }
}

// Fail-closed human verification, exactly GooberCord's shape: an absent
// secret, no configured hostnames, or a missing/oversized token is a 403
// BEFORE any siteverify call; a siteverify error is a 403 too — the route
// never degrades to allowing a request through. The hostname check matches
// the TURNSTILE_HOSTNAMES allowlist (a `*.suffix` entry admits its children).
export async function requireTurnstile(request, env, body, expectedAction) {
  const secret = env.TURNSTILE_SECRET;
  const hostnames = String(env.TURNSTILE_HOSTNAMES || "")
    .split(",")
    .map((hostname) => hostname.trim())
    .filter(Boolean);
  const token = typeof body["cf-turnstile-response"] === "string" ? body["cf-turnstile-response"] : "";
  if (!secret || hostnames.length === 0 || !token || token.length > TURNSTILE_TOKEN_MAX_LENGTH) {
    throw new HttpError(403, "Human verification is required.");
  }
  let result;
  try {
    const response = await fetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      signal: AbortSignal.timeout(10_000),
      body: new URLSearchParams({
        secret,
        response: token,
        remoteip: request.headers.get("CF-Connecting-IP") || "",
      }),
    });
    if (!response.ok) throw new Error("siteverify responded with " + response.status);
    result = await response.json();
  } catch (error) {
    if (error instanceof HttpError) throw error;
    console.error("Turnstile siteverify request failed:", error && error.name ? error.name : "UnknownError");
    throw new HttpError(403, "Human verification could not be completed. Please try again.");
  }
  const verifiedHostname = typeof result.hostname === "string" ? result.hostname.trim().toLowerCase() : "";
  const hostnameAllowed = hostnames.some((configured) => {
    const expected = configured.toLowerCase();
    if (expected.startsWith("*.")) {
      const suffix = expected.slice(1);
      return verifiedHostname.length > suffix.length && verifiedHostname.endsWith(suffix);
    }
    return verifiedHostname === expected;
  });
  if (!result.success || result.action !== expectedAction || !hostnameAllowed) {
    throw new HttpError(403, "Human verification failed. Please try again.");
  }
}

export async function readLimitedBody(request, maximum) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > maximum) throw new HttpError(413, "That upload is too large.");
  const reader = request.body && request.body.getReader ? request.body.getReader() : null;
  if (!reader) return new Uint8Array();
  const chunks = [];
  let total = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > maximum) {
      try {
        await reader.cancel();
      } catch (cancelError) {
        console.warn(
          "Request body cancellation failed:",
          cancelError && cancelError.name ? cancelError.name : "UnknownError",
        );
      }
      throw new HttpError(413, "That upload is too large.");
    }
    chunks.push(part.value);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

export async function readJson(request, maxBytes = MAX_JSON_BYTES) {
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new HttpError(415, "Send this form as JSON.");
  }
  const bytes = await readLimitedBody(request, maxBytes);
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new HttpError(400, "The request body is not valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "The request body must be a JSON object.");
  }
  return value;
}
