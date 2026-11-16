// Wempo Accounts — worker entrypoint. All handler logic lives under api/;
// worker.mjs owns only the dispatch loop:
//   /api/* → the Accounts routes (login, me, logout + the phase-2 handshake
//            routes: POST /api/sso/ticket for the browser's return flow,
//            POST /api/sso/redeem for the member sites' service bindings)
//   else   → the ASSETS binding (the login page; run_worker_first, so the
//            page still rides the security-header wrapper below)
// The sign-out-everywhere lane (revoking tickets + the SSO session) is the
// handshake's remaining piece, phase 3.
import { handleAccountRoutes } from "./api/accounts.mjs";
import { HttpError, json, rateLimit, securityHeaders } from "./api/core/http.mjs";

export { requireTurnstile, rateLimit, readJson } from "./api/core/http.mjs";
export { createSession } from "./api/core/auth.mjs";
export { relayVerify, relaySet } from "./api/relay.mjs";
export { verifyTotpCode, totpAt } from "./api/core/totp.mjs";
export { isValidUsername } from "./api/usernames.mjs";

function secureResponse(response) {
  const headers = securityHeaders(response.headers);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function apiError(error) {
  if (error instanceof HttpError) {
    return json({ error: error.message }, error.status, error.headers);
  }
  console.error("Accounts request failed:", error);
  return json({ error: "Something went wrong. Please try again." }, 500);
}

async function routeApi(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  if (!env.GOOBER_DB) throw new HttpError(503, "The accounts database is not configured.");

  // The global tier (the GC shape): GETs ride the read limiter, everything
  // else the write limiter; the strict per-route tiers (login, totp) stack
  // on top inside the handlers.
  await rateLimit(request, env, method === "GET" || method === "HEAD" ? "read" : "write");

  const response = await handleAccountRoutes(request, env, url, path, method, ctx);
  if (response) return response;

  if (path.startsWith("/api/")) throw new HttpError(404, "That API endpoint does not exist.");
  throw new HttpError(404, "Not found.");
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await routeApi(request, env, ctx);
      } catch (error) {
        return apiError(error);
      }
    }
    if (!env.ASSETS) return json({ error: "Static assets are not configured." }, 503);
    try {
      // The asset answers keep the same security-header set (CSP included)
      // as the API: one discipline for every byte this worker emits.
      return secureResponse(await env.ASSETS.fetch(request));
    } catch (error) {
      console.error("Static asset request failed:", error);
      return json({ error: "The requested page could not be loaded." }, 500);
    }
  },
};
