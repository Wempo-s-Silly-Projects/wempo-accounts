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

const encoder = new TextEncoder();
const RS256 = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\\+/g, "-").replace(/\\//g, "_");
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function signingJwk(env) {
  if (typeof env.OAUTH_SIGNING_PRIVATE_JWK !== "string" ||
      typeof env.OAUTH_SIGNING_KID !== "string" ||
      !/^[A-Za-z0-9._-]{1,80}$/.test(env.OAUTH_SIGNING_KID)) {
    throw new Error("OAuth signing key is not configured.");
  }
  let jwk;
  try {
    jwk = JSON.parse(env.OAUTH_SIGNING_PRIVATE_JWK);
  } catch {
    throw new Error("OAuth signing key configuration is invalid.");
  }
  if (!jwk || jwk.kty !== "RSA" || typeof jwk.n !== "string" ||
      typeof jwk.e !== "string" || typeof jwk.d !== "string") {
    throw new Error("OAuth signing key must be an RSA private JWK.");
  }
  return jwk;
}

export async function signJwt(env, payload, typ = "JWT") {
  const jwk = signingJwk(env);
  const key = await crypto.subtle.importKey("jwk", jwk, RS256, false, ["sign"]);
  const header = { alg: "RS256", kid: env.OAUTH_SIGNING_KID, typ };
  const encodedHeader = base64Url(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64Url(encoder.encode(JSON.stringify(payload)));
  const signingInput = encodedHeader + "." + encodedPayload;
  const signature = new Uint8Array(await crypto.subtle.sign(RS256, key, encoder.encode(signingInput)));
  return signingInput + "." + base64Url(signature);
}

export function publicSigningJwk(env) {
  const jwk = signingJwk(env);
  return {
    kty: "RSA",
    n: jwk.n,
    e: jwk.e,
    use: "sig",
    alg: "RS256",
    kid: env.OAUTH_SIGNING_KID,
  };
}

export async function pairwiseSubject(env, clientId, userId) {
  if (typeof env.OAUTH_SUBJECT_SECRET !== "string" || env.OAUTH_SUBJECT_SECRET.length < 32) {
    throw new Error("OAuth pairwise subject secret is not configured.");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.OAUTH_SUBJECT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(String(clientId) + ":" + String(userId)),
  );
  return base64Url(new Uint8Array(digest));
}

export function decodeJwtPart(value) {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value)));
}
