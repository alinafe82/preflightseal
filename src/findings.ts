import path from "node:path";

import type { Finding } from "./types.ts";
import { SCHEMA_VERSION } from "./schema.ts";
import { sha256Json } from "./util/crypto.ts";
import { validateRelativePath } from "./util/path.ts";

export const FINDING_FINGERPRINT_PATTERN = /^pfs1:sha256:[a-f0-9]{64}$/;

export function fingerprintFinding(finding: Finding): string {
  const digest = sha256Json({
    schemaVersion: "preflightseal.finding-fingerprint.v1",
    ruleId: finding.id,
    category: finding.category ?? categoryForFinding(finding),
    decision: finding.decision,
    severity: finding.severity,
    path: normalizeFindingPath(finding.path),
    evidence: normalizeFingerprintEvidence(finding.evidence),
    operationIdentity: finding.operationIdentity ?? null,
    providerId: finding.providerId ?? null
  });
  return `pfs1:sha256:${digest}`;
}

export function normalizeFinding(finding: Finding, providerId: string): Finding {
  const normalizedPath = finding.path ? normalizeFindingPath(finding.path) : null;
  const normalized: Finding = {
    ...finding,
    schemaVersion: SCHEMA_VERSION.FINDING,
    category: finding.category ?? categoryForFinding(finding),
    evidence: normalizeStoredEvidence(finding.evidence),
    path: normalizedPath ?? undefined,
    providerId: finding.providerId ?? providerId
  };
  return {
    ...normalized,
    fingerprint: fingerprintFinding(normalized)
  };
}

export function normalizeFindings(findings: Finding[], providerId: string): Finding[] {
  return findings.map((finding) => normalizeFinding(finding, providerId));
}

export function assertFindingFingerprint(value: string): void {
  if (!FINDING_FINGERPRINT_PATTERN.test(value)) {
    throw new Error(`PFS_INSTALL_UNSUPPORTED: installation requires finding fingerprint acceptance: ${value}`);
  }
}

function categoryForFinding(finding: Finding): string {
  if (finding.id.startsWith("SNYK-AGENT-SCAN")) {
    return "external-analyzer";
  }
  if (finding.id.includes("MCP")) {
    return "mcp";
  }
  if (finding.id.includes("HOOK")) {
    return "hooks";
  }
  if (finding.id.includes("NPM") || finding.id.includes("PACKAGE")) {
    return "package";
  }
  if (finding.id.includes("SOURCE") || finding.id.includes("INVENTORY") || finding.id.includes("ARCHIVE")) {
    return "source";
  }
  if (finding.id.includes("CODEX") || finding.id.includes("AGENT") || finding.id.includes("SKILL")) {
    return "agent-runtime";
  }
  return "install-boundary";
}

function normalizeFindingPath(input?: string): string | null {
  if (!input) {
    return null;
  }
  const withPosixSeparators = input.replace(/\\/g, "/").trim();
  if (!withPosixSeparators || withPosixSeparators === ".") {
    return null;
  }
  try {
    return validateRelativePath(withPosixSeparators);
  } catch {
    return normalizeVolatilePath(withPosixSeparators);
  }
}

function normalizeStoredEvidence(input: string): string {
  return input.replace(/\s+/g, " ").trim();
}

function normalizeFingerprintEvidence(input: string): string {
  return normalizeStoredEvidence(input)
    .replace(/\bpid\s*[:=]\s*\d+\b/gi, "pid=<pid>")
    .replace(/\bprocess\s+\d+\b/gi, "process <pid>")
    .replace(/\b\d+(?:\.\d+)?\s*ms\b/gi, "<duration>")
    .replace(/\b(?:started|finished|elapsed)(?:At| at)?\s*[:=]\s*[-:.TZ0-9]+\b/gi, "<time>")
    .replace(/\/private\/var\/folders\/[^\s"'`]+/g, "<tmp>")
    .replace(/\/var\/folders\/[^\s"'`]+/g, "<tmp>")
    .replace(/\/tmp\/[^\s"'`]+/g, "<tmp>")
    .replace(/\/Users\/[^/\s"'`]+/g, "<home>")
    .replace(/\/home\/[^/\s"'`]+/g, "<home>");
}

function normalizeVolatilePath(input: string): string {
  const parsed = path.posix.parse(input);
  const base = parsed.base || input;
  return normalizeFingerprintEvidence(base);
}
