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

// Relay wiring tests (mock FORUM_WORKER): the credential relay client rides
// the forum relay contract — service-bound
// POST to https://relay.internal/api/relay/*, the X-Relay-Token header as
// the whole auth, redacted JSON back, and a graceful null on every
// degraded path (unconfigured token, unfetchable forum, non-2xx, bad JSON).
import test from "node:test";
import assert from "node:assert/strict";

import { relayVerify, relaySet, relayRevokeAll } from "../api/relay.mjs";

const TOKEN = "relay-test-token-abc123";

// The mock binding: records every request and answers from a canned map.
function mockBinding(responder) {
  const calls = [];
  return {
    calls,
    async fetch(request) {
      calls.push(request);
      return responder(request);
    },
  };
}

function jsonBinding(body, status = 200) {
  return mockBinding(() => new Response(JSON.stringify(body), { status }));
}

function envWith(binding) {
  return { RELAY_TOKEN: TOKEN, FORUM_WORKER: binding };
}

test("relayVerify asks the forum worker over the service binding with the token header", async () => {
  const binding = jsonBinding({ valid: true, user: { id: 7, username: "wempos", role: "admin" } });
  const answer = await relayVerify(envWith(binding), "wempos", "letmein-please");

  assert.equal(answer.valid, true);
  assert.equal(answer.user.username, "wempos");

  assert.equal(binding.calls.length, 1, "exactly one subrequest");
  const request = binding.calls[0];
  const url = new URL(request.url);
  assert.equal(url.origin, "https://relay.internal", "the sibling-workers.dev lane is the binding, not the edge");
  assert.equal(url.pathname, "/api/relay/password-verify");
  assert.equal(request.headers.get("X-Relay-Token"), TOKEN, "the token is the whole relay auth");
  assert.equal(request.headers.get("Content-Type"), "application/json");
  assert.deepEqual(await request.json(), { username: "wempos", password: "letmein-please" });
});

test("relaySet rides the same lane (the phase-3 password lane, wired today)", async () => {
  const binding = jsonBinding({ changed: true, user: { id: 7, username: "wempos" } });
  const answer = await relaySet(envWith(binding), "wempos", "brand-new-password");

  assert.equal(answer.changed, true);
  assert.equal(new URL(binding.calls[0].url).pathname, "/api/relay/password-set");
});

test("relayRevokeAll rides the same lane (the true sign-out-everywhere leg, count-only answer)", async () => {
  const binding = jsonBinding({ revoked: 3 });
  const answer = await relayRevokeAll(envWith(binding), 7);

  assert.deepEqual(answer, { revoked: 3 });
  assert.equal(new URL(binding.calls[0].url).pathname, "/api/relay/session-revoke-all");
  assert.deepEqual(await binding.calls[0].clone().json(), { userId: 7 });
});

test("an unconfigured RELAY_TOKEN is a null answer with NO subrequest (fail closed)", async () => {
  const binding = jsonBinding({ valid: true });
  for (const token of [undefined, "", 42]) {
    const env = { RELAY_TOKEN: token, FORUM_WORKER: binding };
    assert.equal(await relayVerify(env, "wempos", "x"), null);
  }
  assert.equal(binding.calls.length, 0, "the forum worker is never asked without the token");
});

test("a non-2xx relay answer is a null, a thrown fetch is a null", async () => {
  const rejecting = await relayVerify(
    envWith(mockBinding(() => { throw new Error("edge down"); })),
    "wempos",
    "x",
  );
  assert.equal(rejecting, null, "an unreachable forum must never surface as an error");

  const erroring = await relayVerify(
    envWith(jsonBinding({ error: "Relay refused." }, 403)),
    "wempos",
    "x",
  );
  assert.equal(erroring, null);
});

test("a non-JSON relay answer is a null (the caller keeps its failure path)", async () => {
  const binding = mockBinding(() => new Response("<html>502</html>", { status: 200 }));
  assert.equal(await relayVerify(envWith(binding), "wempos", "x"), null);
});

test("credential material never rides back: a hash-bearing answer is not this client's problem — responses are read as JSON only, and no password set/verify happens on this worker", async () => {
  // The structural pin: the relay client module contains NO SQL, no D1, and
  // no pepper reading — the forum side owns every secret.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../api/relay.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /prepare\(|PASSWORD_PEPPER|password_hash/);
});
