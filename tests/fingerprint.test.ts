import test from "node:test";
import assert from "node:assert/strict";

import { fingerprintFinding, normalizeFinding } from "../src/findings.ts";
import { defaultPolicy, evaluatePolicy } from "../src/policy.ts";
import type { AnalyzerResult, Finding } from "../src/types.ts";

test("same warning fingerprint is deterministic", () => {
  const finding = warningFinding({ path: "AGENTS.md", evidence: "instruction files influence future agent behavior" });

  assert.equal(fingerprintFinding(finding), fingerprintFinding({ ...finding }));
});

test("warning evidence changes fingerprint", () => {
  const base = warningFinding({ path: "AGENTS.md", evidence: "mode 755" });
  const changed = warningFinding({ path: "AGENTS.md", evidence: "mode 644" });

  assert.notEqual(fingerprintFinding(base), fingerprintFinding(changed));
});

test("warning path changes fingerprint", () => {
  const base = warningFinding({ path: "AGENTS.md", evidence: "instruction file" });
  const changed = warningFinding({ path: "nested/AGENTS.md", evidence: "instruction file" });

  assert.notEqual(fingerprintFinding(base), fingerprintFinding(changed));
});

test("warning rule and severity changes fingerprint", () => {
  const base = warningFinding({ id: "PFS-CODEX-INSTRUCTIONS", severity: "medium" });
  const changedRule = warningFinding({ id: "PFS-AGENT-SKILL", severity: "medium" });
  const changedSeverity = warningFinding({ id: "PFS-CODEX-INSTRUCTIONS", severity: "high" });

  assert.notEqual(fingerprintFinding(base), fingerprintFinding(changedRule));
  assert.notEqual(fingerprintFinding(base), fingerprintFinding(changedSeverity));
});

test("volatile evidence fields do not alter finding fingerprint", () => {
  const base = warningFinding({
    evidence: "scanner failed at /Users/alina/private/tmp/run pid=123 elapsed 50ms"
  });
  const changedVolatile = warningFinding({
    evidence: "scanner failed at /Users/other/private/tmp/run pid=456 elapsed 92ms"
  });

  assert.equal(fingerprintFinding(base), fingerprintFinding(changedVolatile));
});

test("tampered fingerprint does not satisfy warning acceptance", () => {
  const warning = normalizeFinding(warningFinding({ path: "AGENTS.md" }), "native-install-boundary");
  const evaluation = evaluatePolicy(defaultPolicy(), [analyzer([warning])], [
    `pfs1:sha256:${"0".repeat(64)}`
  ]);

  assert.equal(evaluation.decision, "WARN");
  assert.deepEqual(evaluation.warningFingerprints, [warning.fingerprint]);
});

test("accepting one warning does not accept another warning with same rule", () => {
  const first = normalizeFinding(warningFinding({ path: "AGENTS.md" }), "native-install-boundary");
  const second = normalizeFinding(warningFinding({ path: "nested/AGENTS.md" }), "native-install-boundary");

  const evaluation = evaluatePolicy(defaultPolicy(), [analyzer([first, second])], [first.fingerprint]);

  assert.equal(evaluation.decision, "WARN");
  assert.deepEqual(evaluation.warningIds, ["PFS-CODEX-INSTRUCTIONS"]);
  assert.deepEqual(evaluation.warningFingerprints, [second.fingerprint]);
});

test("finding normalization derives stable categories and handles empty or unsafe paths", () => {
  const cases = [
    ["PFS-MCP-REGISTRATION", "mcp"],
    ["PFS-HOOK-REGISTRATION", "hooks"],
    ["PFS-NPM-LIFECYCLE", "package"],
    ["PFS-SOURCE-CHANGED", "source"],
    ["PFS-AGENT-SKILL", "agent-runtime"],
    ["SNYK-AGENT-SCAN-DEMO", "external-analyzer"],
    ["PFS-OTHER", "install-boundary"]
  ];

  for (const [id, category] of cases) {
    assert.equal(normalizeFinding(warningFinding({ id, category: undefined }), "native-install-boundary").category, category);
  }

  assert.equal(normalizeFinding(warningFinding({ path: "" }), "native-install-boundary").path, undefined);
  assert.equal(fingerprintFinding(warningFinding({ path: "." })), fingerprintFinding(warningFinding({ path: undefined })));
  assert.equal(normalizeFinding(warningFinding({ path: "/tmp/preflightseal/demo/AGENTS.md" }), "native-install-boundary").path, "AGENTS.md");
});

function warningFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "PFS-CODEX-INSTRUCTIONS",
    title: "Agent instruction file changes runtime behavior",
    decision: "WARN",
    severity: "medium",
    path: "AGENTS.md",
    evidence: "instruction files influence future agent behavior",
    recommendation: "Accept this warning only for reviewed instruction content.",
    providerId: "native-install-boundary",
    category: "agent-runtime",
    fingerprint: "",
    schemaVersion: "preflightseal.finding.v1",
    ...overrides
  };
}

function analyzer(findings: Finding[]): AnalyzerResult {
  return {
    schemaVersion: "preflightseal.analyzer-result.v1",
    providerId: "native-install-boundary",
    status: "FINDINGS",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:00.000Z",
    reportDigest: "digest",
    findings
  };
}
