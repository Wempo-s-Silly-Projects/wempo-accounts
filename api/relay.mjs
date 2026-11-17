// Credential relay client: Accounts' password pepper NEVER exists on this
// worker — the pepper lives ONLY on the forum worker as a wrangler secret,
// and the shared users table stores hashes only the FORUM can verify. So
// every credential question rides the forum worker's token-gated relay
// (wempos-forum's api/relay.mjs), through a service binding (client copy
// of GooberCord's api/relay.mjs, the same contract, one new consumer):
//   relayVerify     → "are these credentials correct under the forum pepper?"
//   relaySet        → "store this new password under the forum pepper" (the
//                     change-password lane — register pins the contract)
//   relayRevokeAll  → "sign this user out of every member site" (phase 3:
//                     ONE user_id-scoped DELETE on the SHARED `sessions`
//                     table — GC's goober_session and the forum's
//                     wempo_session hash into the same table — answered with
//                     a count only, no existence oracle)
// relayVerify answers REDACTED (ids, usernames, roles — no salt/hash
// material) and burns the forum's own dummy salt for unknown usernames, so
// a token holder gets no existence oracle. The token is the whole auth
// (RELAY_TOKEN secret on BOTH workers); every call degrades gracefully: an
// unconfigured token or an unreachable forum returns null and callers fail
// their credential path closed.
const RELAY_ORIGIN = "https://wempos-forum.itswempo.workers.dev";
const RELAY_TIMEOUT_MS = 10_000;
// Same-zone subrequests to a SIBLING workers.dev script 404 at the edge
// without entering the forum worker (the GC↔forum lesson), so THIS absolute
// URL rides inside a service binding fetch only.
const RELAY_INTERNAL_ORIGIN = "https://relay.internal";

async function relayCall(env, path, body) {
  if (!env.RELAY_TOKEN || typeof env.RELAY_TOKEN !== "string") return null;

  const request = new Request(RELAY_INTERNAL_ORIGIN + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Relay-Token": env.RELAY_TOKEN,
      // The calling worker's convenience stamp: the forum keys its shared
      // throttle buckets per-worker on this slug. NOT an auth boundary — the
      // token above is the whole auth; the slug never picks up authority.
      "X-Relay-Worker": "accounts",
    },
    body: JSON.stringify(body),
  });

  let response;
  try {
    const binding = env.FORUM_WORKER;
    if (binding && typeof binding.fetch === "function") {
      // Production: direct worker-to-worker invocation, no edge routing.
      response = await binding.fetch(request, {
        signal: AbortSignal.timeout(RELAY_TIMEOUT_MS),
      });
    } else {
      // Dev without the binding: plain internet fetch to the forum.
      response = await fetch(RELAY_ORIGIN + path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Relay-Token": env.RELAY_TOKEN,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(RELAY_TIMEOUT_MS),
      });
    }
  } catch {
    return null; // forum unreachable — the credential path fails closed
  }

  if (!response.ok) return null;

  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function relayVerify(env, username, password) {
  return relayCall(env, "/api/relay/password-verify", { username, password });
}

export async function relaySet(env, username, password) {
  return relayCall(env, "/api/relay/password-set", { username, password });
}

export async function relayRevokeAll(env, userId) {
  return relayCall(env, "/api/relay/session-revoke-all", { userId: Number(userId) });
}
