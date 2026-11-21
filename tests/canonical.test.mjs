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

// The domain move: every workers.dev request answers a 301 to the canonical
// accounts origin (path + query preserved) BEFORE any routing; the canonical
// host itself is never redirected.
import test from "node:test";
import assert from "node:assert/strict";
import worker from "../worker.mjs";

const CANONICAL = "https://accounts.wempos-forum.com";

test("a workers.dev request is a 301 to the canonical origin with path and query preserved", async () => {
  const response = await worker.fetch(
    new Request("https://accounts.legacy.workers.dev/api/me?return=x&y=1"),
    {},
    {},
  );
  assert.equal(response.status, 301);
  assert.equal(response.headers.get("Location"), CANONICAL + "/api/me?return=x&y=1");
});

test("the workers.dev redirect runs before routing: a page path redirects even without ASSETS", async () => {
  const response = await worker.fetch(new Request("https://anything.example.workers.dev/"), {}, {});
  assert.equal(response.status, 301);
  assert.equal(response.headers.get("Location"), CANONICAL + "/");
});

test("the canonical host is not redirected", async () => {
  const response = await worker.fetch(new Request(CANONICAL + "/"), {}, {});
  assert.notEqual(response.status, 301);
  assert.equal(response.headers.get("Location"), null);
});
