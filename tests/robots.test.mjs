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
// along with this program. If not, see <https://www.gnu.org/licenses/>

// RFC 9309 crawler policy: public site pages remain crawlable while account
// API routes stay out of crawler indexes. The endpoint bypasses D1 entirely.
import test from "node:test";
import assert from "node:assert/strict";

import { dispatch, ORIGIN } from "./harness.mjs";

test("GET /robots.txt serves the crawler policy as plain text without database access", async () => {
  const response = await dispatch(new Request(ORIGIN + "/robots.txt"), {});

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^text\/plain(?:;|$)/i);
  assert.equal(await response.text(), "User-agent: *\nAllow: /\nDisallow: /api/\n");
  assert.match(response.headers.get("Cache-Control") || "", /public/);
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
});

test("HEAD /robots.txt returns the same metadata without a response body", async () => {
  const response = await dispatch(new Request(ORIGIN + "/robots.txt", { method: "HEAD" }), {});

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^text\/plain(?:;|$)/i);
  assert.equal(await response.text(), "");
});
