import test from "node:test";
import assert from "node:assert/strict";

import { isGitHubHttpsSource, parseGitHubSource } from "../src/acquire/github.ts";

test("GitHub source parser canonicalizes public HTTPS repository URLs", () => {
  const parsed = parseGitHubSource("https://github.com/Owner/repo.git#main");
  assert.equal(parsed.owner, "Owner");
  assert.equal(parsed.repo, "repo");
  assert.equal(parsed.requestedRef, "main");
  assert.equal(parsed.canonicalUrl, "https://github.com/Owner/repo");
});

test("GitHub source parser rejects embedded credentials", () => {
  assert.throws(
    () => parseGitHubSource("https://token@github.com/owner/repo"),
    /embedded credentials/
  );
});

test("GitHub source detection is narrow", () => {
  assert.equal(isGitHubHttpsSource("https://github.com/owner/repo"), true);
  assert.equal(isGitHubHttpsSource("git@github.com:owner/repo.git"), false);
  assert.equal(isGitHubHttpsSource("https://example.com/owner/repo"), false);
});
