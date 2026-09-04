import test from "node:test";
import assert from "node:assert/strict";

import { defaultPolicy, evaluatePolicy } from "../src/policy.ts";
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

  assert.equal(evaluatePolicy(policy, [analyzer([warning])]).decision, "WARN");
  assert.equal(evaluatePolicy(policy, [analyzer([warning])], ["PFS-CODEX-INSTRUCTIONS"]).decision, "ALLOW");
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
  assert.equal(evaluatePolicy(policy, [analyzer([blocking])], ["PFS-CURL-BASH"]).decision, "BLOCK");
});
