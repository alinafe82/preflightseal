import type { AnalyzerResult, DecisionState, Finding, Policy, PolicyEvaluation } from "./types.ts";
import { fingerprintFinding } from "./findings.ts";
import { SCHEMA_VERSION } from "./schema.ts";
import { sha256Json } from "./util/crypto.ts";

export function defaultPolicy(): Policy {
  return {
    id: "preflightseal-default",
    version: "0.1.0",
    requiredAnalyzers: ["native-install-boundary"],
    warnRequiresAcceptance: true,
    blockedFindingIds: []
  };
}

export function digestPolicy(policy: Policy): string {
  return sha256Json(policy);
}

export function evaluatePolicy(
  policy: Policy,
  analyzerResults: AnalyzerResult[],
  acceptedWarningFingerprints: string[] = []
): PolicyEvaluation {
  const accepted = new Set(acceptedWarningFingerprints);
  const findings = analyzerResults.flatMap((result) => result.findings);
  const missingRequired = policy.requiredAnalyzers.filter((id) => !analyzerResults.some((result) => result.providerId === id));
  const inconclusiveProviderIds = analyzerResults
    .filter((result) => policy.requiredAnalyzers.includes(result.providerId))
    .filter((result) => ["ERROR", "TIMEOUT", "UNAVAILABLE", "NOT_RUN", "PARTIAL"].includes(result.status))
    .map((result) => result.providerId);
  inconclusiveProviderIds.push(...missingRequired);

  const blockingFindings = findings.filter((finding) => isBlockingFinding(finding, policy));
  const warningFindings = findings.filter((finding) => finding.decision === "WARN");
  const unacceptedWarnings = warningFindings.filter((finding) => !accepted.has(findingFingerprint(finding)));

  const reasons: string[] = [];
  let decision: DecisionState = "ALLOW";

  if (inconclusiveProviderIds.length > 0 || findings.some((finding) => finding.decision === "INCONCLUSIVE")) {
    decision = "INCONCLUSIVE";
    reasons.push("required evidence is missing, failed, partial, or inconclusive");
  }

  if (blockingFindings.length > 0) {
    decision = "BLOCK";
    reasons.push("one or more findings violate policy");
  }

  if (decision === "ALLOW" && policy.warnRequiresAcceptance && unacceptedWarnings.length > 0) {
    decision = "WARN";
    reasons.push("one or more understood risks require scoped acceptance");
  }

  if (decision === "ALLOW") {
    reasons.push("required evidence completed and no unaccepted policy findings remain");
  }

  return {
    schemaVersion: SCHEMA_VERSION.POLICY_EVALUATION,
    decision,
    reasons,
    warningIds: uniqueStrings(unacceptedWarnings.map((finding) => finding.id)),
    warningFingerprints: uniqueStrings(unacceptedWarnings.map(findingFingerprint)),
    blockingIds: [...new Set(blockingFindings.map((finding) => finding.id))],
    blockingFingerprints: uniqueStrings(blockingFindings.map(findingFingerprint)),
    inconclusiveProviderIds: [...new Set(inconclusiveProviderIds)]
  };
}

function isBlockingFinding(finding: Finding, policy: Policy): boolean {
  return finding.decision === "BLOCK"
    || finding.severity === "critical"
    || policy.blockedFindingIds.includes(finding.id);
}

function findingFingerprint(finding: Finding): string {
  return finding.fingerprint ?? fingerprintFinding(finding);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)].sort();
}
