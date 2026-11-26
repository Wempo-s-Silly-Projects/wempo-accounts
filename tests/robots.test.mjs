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

import { dispatch, fakeDb, ORIGIN } from "./harness.mjs";

function assertPublicCachePolicy(response) {
  const directives = new Set((response.headers.get("Cache-Control") || "")
    .split(",")
    .map((directive) => directive.trim().toLowerCase()));
  assert.ok(directives.has("public"), "Cache-Control must include public");
  assert.ok(directives.has("max-age=3600"), "Cache-Control must include max-age=3600");
  assert.ok(!directives.has("no-store"), "Cache-Control must not include no-store");
  assert.ok(!directives.has("no-cache"), "Cache-Control must not include no-cache");
  assert.ok(!directives.has("private"), "Cache-Control must not include private");
}

function assertDiscoveryMetadataMatches(getResponse, headResponse) {
  for (const name of ["Content-Type", "Cache-Control", "X-Content-Type-Options"]) {
    assert.equal(headResponse.headers.get(name), getResponse.headers.get(name),
      `HEAD must preserve ${name} from GET`);
  }
}

test("GET /robots.txt serves the crawler policy as plain text without database access", async () => {
  const db = fakeDb([]);
  const response = await dispatch(new Request(ORIGIN + "/robots.txt"), { FORUM_DB: db });

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^text\/plain(?:;|$)/i);
  assert.equal(await response.text(), "User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://accounts.wempos-forum.com/sitemap.xml\n");
  assertPublicCachePolicy(response);
  assert.deepEqual(db.executed, [], "robots.txt must not execute D1 statements");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
});

test("HEAD /robots.txt returns the same metadata without a response body", async () => {
  const getResponse = await dispatch(new Request(ORIGIN + "/robots.txt"), {});
  const response = await dispatch(new Request(ORIGIN + "/robots.txt", { method: "HEAD" }), {});

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^text\/plain(?:;|$)/i);
  assert.equal(await response.text(), "");
  assertDiscoveryMetadataMatches(getResponse, response);
});

test("GET /sitemap.xml serves a valid XML sitemap of canonical public pages", async () => {
  const response = await dispatch(new Request(ORIGIN + "/sitemap.xml"), {});

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^application\/xml(?:;|$)/i);
  const body = await response.text();
  assert.match(body, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(body, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.deepEqual([...body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]), [
    "https://accounts.wempos-forum.com/",
  ]);
  assertPublicCachePolicy(response);
});

test("HEAD /sitemap.xml returns sitemap metadata without a response body", async () => {
  const getResponse = await dispatch(new Request(ORIGIN + "/sitemap.xml"), {});
  const response = await dispatch(new Request(ORIGIN + "/sitemap.xml", { method: "HEAD" }), {});

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type") || "", /^application\/xml(?:;|$)/i);
  assert.equal(await response.text(), "");
  assertDiscoveryMetadataMatches(getResponse, response);
});
