import test from "node:test";
import assert from "node:assert/strict";

import { defaultPolicy, evaluatePolicy } from "../src/policy.ts";
import { normalizeFinding } from "../src/findings.ts";
import type { AnalyzerResult } from "../src/types.ts";

function analyzer(findings: AnalyzerResult["findings"], status: AnalyzerResult["status"] = "FINDINGS"): AnalyzerResult {
  return {
    providerId: "native-install-boundary",
    status,
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:00.000Z",
    reportDigest: "digest",
    findings
  };
}

test("WARN findings require explicit scoped acceptance", () => {
  const policy = defaultPolicy();
  const warning = {
    id: "PFS-CODEX-INSTRUCTIONS",
    title: "instructions",
    decision: "WARN" as const,
    severity: "medium" as const,
    evidence: "instruction file",
    recommendation: "accept if reviewed"
  };
  const normalizedWarning = normalizeFinding(warning, "native-install-boundary");

  assert.equal(evaluatePolicy(policy, [analyzer([normalizedWarning])]).decision, "WARN");
  assert.equal(evaluatePolicy(policy, [analyzer([normalizedWarning])], [normalizedWarning.fingerprint]).decision, "ALLOW");
  assert.equal(evaluatePolicy(policy, [analyzer([normalizedWarning])], ["PFS-CODEX-INSTRUCTIONS"]).decision, "WARN");
});

test("required scanner failure is inconclusive, not allow", () => {
  const policy = defaultPolicy();
  assert.equal(evaluatePolicy(policy, [analyzer([], "TIMEOUT")]).decision, "INCONCLUSIVE");
});

test("block findings override warning acceptance", () => {
  const policy = defaultPolicy();
  const blocking = {
    id: "PFS-CURL-BASH",
    title: "remote shell",
    decision: "BLOCK" as const,
    severity: "critical" as const,
    evidence: "curl | bash",
    recommendation: "refuse"
  };
  const normalizedBlocking = normalizeFinding(blocking, "native-install-boundary");
  assert.equal(evaluatePolicy(policy, [analyzer([normalizedBlocking])], [normalizedBlocking.fingerprint]).decision, "BLOCK");
});
