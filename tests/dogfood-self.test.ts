import test from "node:test";
import assert from "node:assert/strict";

import { SCHEMA_VERSION } from "../src/schema.ts";
import { runSelfDogfood, shouldUseLocalSelfDogfoodFallback } from "../scripts/dogfood-self.ts";

test("self dogfood falls back to local checkout outside CI when public GitHub source is unavailable", async () => {
  const attempts: string[] = [];
  let output = "";

  const exitCode = await runSelfDogfood(["--pin-current"], {
    currentRevision: () => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    env: {},
    publicUrl: "https://github.com/owner/repo",
    root: "/workspace/current",
    writeOutput: (value) => {
      output = value;
    },
    async attemptDogfood(sourceInput) {
      attempts.push(sourceInput);
      if (attempts.length === 1) {
        throw new Error("GitHub API request failed: HTTP 404");
      }
      return fakeAttempt();
    }
  });

  const parsed = JSON.parse(output);

  assert.equal(exitCode, 0);
  assert.deepEqual(attempts, [
    "https://github.com/owner/repo#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "/workspace/current"
  ]);
  assert.equal(parsed.sourceMode, "local-fallback");
  assert.equal(parsed.publicSourceAvailable, false);
  assert.equal(parsed.fallbackSource, "/workspace/current");
  assert.equal(parsed.fallbackReason, "GitHub API request failed: HTTP 404");
  assert.equal(parsed.pinnedRevision, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(parsed.policyDecision, "ALLOW");
});

test("self dogfood keeps public-source failures strict in CI by default", () => {
  assert.equal(
    shouldUseLocalSelfDogfoodFallback(new Error("GitHub API request failed: HTTP 404"), { CI: "true" }),
    false
  );
  assert.equal(
    shouldUseLocalSelfDogfoodFallback(new Error("GitHub API request failed: HTTP 404"), {
      CI: "true",
      PREFLIGHTSEAL_SELF_DOGFOOD_ALLOW_LOCAL_FALLBACK: "1"
    }),
    true
  );
});

function fakeAttempt() {
  const startedAt = "2026-01-01T00:00:00.000Z";
  return {
    inspected: {
      source: {
        schemaVersion: SCHEMA_VERSION.SOURCE,
        kind: "local",
        originalInput: "/workspace/current",
        canonical: "/workspace/current",
        canonicalIdentity: "/workspace/current",
        resolvedRevision: "local-content-digest",
        contentDigest: "local-content-digest",
        retrievedAt: startedAt
      },
      inventoryDigest: "local-content-digest",
      analyzerEvidenceDigest: "evidence-digest",
      sourceRoot: "/workspace/current",
      analyzerResults: [{
        schemaVersion: SCHEMA_VERSION.ANALYZER_RESULT,
        providerId: "native-install-boundary",
        status: "PASS" as const,
        startedAt,
        finishedAt: startedAt,
        reportDigest: "native-report-digest",
        findings: []
      }]
    },
    plan: {
      operations: [],
      seal: "test-plan-seal"
    }
  };
}
