import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import { cacheKeyForDigest, cacheObjectDirectory } from "../src/acquire/cache.ts";

test("cache keys accept only sha256 digests", () => {
  assert.equal(cacheKeyForDigest("a".repeat(64)), `sha256/${"a".repeat(64)}`);
  assert.equal(cacheKeyForDigest("A".repeat(64)), `sha256/${"a".repeat(64)}`);
  assert.throws(() => cacheKeyForDigest("not-a-digest"), /expected sha256 digest/);
});

test("cache object directory rejects unsupported algorithms and malformed digests", () => {
  const root = "/tmp/pfs-cache";

  assert.equal(cacheObjectDirectory(root, `sha256/${"b".repeat(64)}`), path.join(root, "sha256", "b".repeat(64)));
  assert.throws(() => cacheObjectDirectory(root, `md5/${"b".repeat(64)}`), /unsupported cache key algorithm/);
  assert.throws(() => cacheObjectDirectory(root, "sha256/not-a-digest"), /expected sha256 digest/);
  assert.throws(() => cacheObjectDirectory(root, "sha256"), /expected sha256 digest/);
});
