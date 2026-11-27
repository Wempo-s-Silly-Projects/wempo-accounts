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
import { decodeJwtPart, pairwiseSubject, publicSigningJwk, signJwt } from "../api/oauth-crypto.mjs";

async function signingEnv() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    env: {
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(privateJwk),
      OAUTH_SIGNING_KID: "test-key-1",
      OAUTH_SUBJECT_SECRET: "0123456789abcdef0123456789abcdef",
    },
    publicKey,
  };
}

test("RS256 JWTs use the configured key id and verify", async () => {
  const { env, publicKey } = await signingEnv();
  const token = await signJwt(env, { iss: "https://accounts.wempos-forum.com", sub: "subject-1" }, "oauth-id-jag+jwt");
  const [headerPart, payloadPart, signaturePart] = token.split(".");
  assert.equal(decodeJwtPart(headerPart).kid, "test-key-1");
  assert.equal(decodeJwtPart(headerPart).typ, "oauth-id-jag+jwt");
  assert.equal(decodeJwtPart(payloadPart).sub, "subject-1");
  const imported = await crypto.subtle.importKey(
    "jwk",
    publicKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const input = headerPart + "." + payloadPart;
  const signature = Uint8Array.from(atob(signaturePart.replace(/-/g, "+").replace(/_/g, "/") + "=="), c => c.charCodeAt(0));
  assert.equal(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", imported, signature, new TextEncoder().encode(input)), true);
  assert.deepEqual(publicSigningJwk(env), {
    kty: "RSA", n: publicKey.n, e: publicKey.e, use: "sig", alg: "RS256", kid: "test-key-1",
  });
});

test("pairwise subjects are stable per client and distinct across clients", async () => {
  const { env } = await signingEnv();
  const first = await pairwiseSubject(env, "client-a", 7);
  assert.equal(first, await pairwiseSubject(env, "client-a", 7));
  assert.notEqual(first, await pairwiseSubject(env, "client-b", 7));
});
