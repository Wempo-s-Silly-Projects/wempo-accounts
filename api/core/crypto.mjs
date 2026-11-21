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

// The crypto primitives everything bottoms out on — time, hex/base64url
// codecs, random tokens, SHA-256, constant-time string comparison. Kept
// identical to the forum's api/core/crypto.mjs character for character (imports
// nothing; Web Crypto + TextEncoder only) so both workers' session/token
// machinery stays provably identical.
const encoder = new TextEncoder();

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function hex(bytes) {
  let result = "";
  for (const value of bytes) result += value.toString(16).padStart(2, "0");
  return result;
}

function base64Url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function randomToken(size = 32) {
  return base64Url(crypto.getRandomValues(new Uint8Array(size)));
}

export async function sha256Hex(value) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

export function equalConstantTime(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}
