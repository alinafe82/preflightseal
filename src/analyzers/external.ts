import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";

import type { AnalyzerResult, Finding, Inventory } from "../types.ts";
import { normalizeFindings } from "../findings.ts";
import { SCHEMA_VERSION } from "../schema.ts";
import { sha256Json } from "../util/crypto.ts";
import { isInside } from "../util/path.ts";
import { sanitizeEvidence } from "../util/text.ts";

export interface ScanContext {
  sourceRoot: string;
  inventory: Inventory;
  timeoutMs: number;
}

export interface ScannerProvider {
  id: string;
  version(): Promise<string>;
  scan(context: ScanContext): Promise<AnalyzerResult>;
}

export const SNYK_AGENT_SCAN_VERSION = "0.5.17";

export function snykAgentScanProvider(): ScannerProvider {
  return {
    id: "snyk-agent-scan",
    async version() {
      return SNYK_AGENT_SCAN_VERSION;
    },
    async scan(context: ScanContext): Promise<AnalyzerResult> {
      const startedAt = new Date().toISOString();
      const skillFiles = context.inventory.entries
        .filter((entry) => entry.type === "file" && path.posix.basename(entry.path) === "SKILL.md")
        .map((entry) => path.join(context.sourceRoot, entry.path));

      if (skillFiles.length === 0) {
        return result("snyk-agent-scan", "NOT_APPLICABLE", startedAt, [], "No SKILL.md files found.");
      }
      const executable = process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;
      if (!executable) {
        return result("snyk-agent-scan", "UNAVAILABLE", startedAt, [], "PREFLIGHTSEAL_SNYK_AGENT_SCAN must point to a trusted scanner executable.");
      }
      if (!path.isAbsolute(executable)) {
        return result("snyk-agent-scan", "UNAVAILABLE", startedAt, [], "PREFLIGHTSEAL_SNYK_AGENT_SCAN must be an absolute executable path.");
      }
      if (!process.env.SNYK_TOKEN) {
        return result("snyk-agent-scan", "UNAVAILABLE", startedAt, [], "SNYK_TOKEN is not set.");
      }

      const findings: Finding[] = [];
      const rawReports: unknown[] = [];
      const analyzerHome = await mkdtemp(path.join(os.tmpdir(), "preflightseal-analyzer-"));
      try {
        for (const skillFile of skillFiles) {
          const run = await spawnBounded(executable, [
            "scan",
            skillFile,
            "--json",
            "--no-bootstrap"
          ], context.timeoutMs, analyzerEnvironment(analyzerHome));

          if (run.timedOut) {
            return result("snyk-agent-scan", "TIMEOUT", startedAt, findings, `Timed out after ${context.timeoutMs} ms.`);
          }
          if (run.spawnError) {
            return result("snyk-agent-scan", "UNAVAILABLE", startedAt, findings, run.spawnError);
          }

          let parsed: unknown;
          try {
            parsed = JSON.parse(run.stdout);
          } catch {
            return result(
              "snyk-agent-scan",
              "ERROR",
              startedAt,
              findings,
              `Scanner emitted malformed JSON: ${sanitizeEvidence(run.stderr || run.stdout)}`
            );
          }
          rawReports.push(parsed);
          findings.push(...normalizeSnykFindings(parsed, path.relative(context.sourceRoot, skillFile), context.sourceRoot));

          if (run.exitCode !== 0 && findings.length === 0) {
            return result(
              "snyk-agent-scan",
              "ERROR",
              startedAt,
              findings,
              `Scanner exited ${run.exitCode}: ${sanitizeEvidence(run.stderr)}`
            );
          }
        }
      } finally {
        await rm(analyzerHome, { recursive: true, force: true }).catch(() => undefined);
      }

      const normalizedFindings = normalizeFindings(dedupe(findings), "snyk-agent-scan");
      const finishedAt = new Date().toISOString();
      return {
        schemaVersion: SCHEMA_VERSION.ANALYZER_RESULT,
        providerId: "snyk-agent-scan",
        status: normalizedFindings.length > 0 ? "FINDINGS" : "PASS",
        startedAt,
        finishedAt,
        version: SNYK_AGENT_SCAN_VERSION,
        reportDigest: sha256Json({ findings: normalizedFindings, rawReports }),
        findings: normalizedFindings
      };
    }
  };
}

async function spawnBounded(command: string, args: string[], timeoutMs: number, env: Record<string, string>): Promise<{
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnError?: string;
}> {
  return await new Promise((resolve) => {
    const child = spawn(command, args, {
      shell: false,
      env,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      settled = true;
      child.kill("SIGKILL");
      resolve({ exitCode: null, stdout, stderr, timedOut: true });
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
      if (stdout.length > 5 * 1024 * 1024) {
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
      if (stderr.length > 1024 * 1024) {
        child.kill("SIGKILL");
      }
    });
    child.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode: null, stdout, stderr, timedOut: false, spawnError: error.message });
    });
    child.on("close", (exitCode) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ exitCode, stdout, stderr, timedOut: false });
    });
  });
}

function analyzerEnvironment(home: string): Record<string, string> {
  return {
    HOME: home,
    PATH: "/usr/bin:/bin",
    SNYK_TOKEN: process.env.SNYK_TOKEN ?? ""
  };
}

function normalizeSnykFindings(report: unknown, relativePath: string, sourceRoot: string): Finding[] {
  const findings: Finding[] = [];
  const stack: unknown[] = [report];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== "object") {
      continue;
    }
    if (Array.isArray(current)) {
      stack.push(...current);
      continue;
    }
    const record = current as Record<string, unknown>;
    const title = firstString(record.title, record.message, record.name, record.ruleId, record.id);
    const severity = normalizeSeverity(firstString(record.severity, record.level, record.priority));
    if (title && (record.severity || record.ruleId || record.id || record.message)) {
      findings.push({
        id: `SNYK-AGENT-SCAN-${sanitizeEvidence(firstString(record.ruleId, record.id) || "FINDING", 60).toUpperCase()}`,
        title,
        decision: severity === "critical" || severity === "high" ? "WARN" : "WARN",
        severity,
        path: normalizeScannerPath(firstString(record.path, record.file), sourceRoot) || relativePath,
        evidence: sanitizeEvidence(firstString(record.description, record.message, record.summary) || title),
        recommendation: "Review scanner evidence and require scoped acceptance before installation."
      });
    }
    stack.push(...Object.values(record));
  }
  return dedupe(findings);
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

function normalizeSeverity(value?: string): Finding["severity"] {
  const lowered = value?.toLocaleLowerCase("en-US");
  if (lowered === "critical" || lowered === "high" || lowered === "medium" || lowered === "low" || lowered === "info") {
    return lowered;
  }
  return "medium";
}

function result(
  providerId: string,
  status: AnalyzerResult["status"],
  startedAt: string,
  findings: Finding[],
  error?: string
): AnalyzerResult {
  const normalizedFindings = normalizeFindings(findings, providerId);
  return {
    schemaVersion: SCHEMA_VERSION.ANALYZER_RESULT,
    providerId,
    status,
    startedAt,
    finishedAt: new Date().toISOString(),
    version: SNYK_AGENT_SCAN_VERSION,
    reportDigest: sha256Json({ status, findings: normalizedFindings, error }),
    findings: normalizedFindings,
    error
  };
}

function normalizeScannerPath(value: string | undefined, sourceRoot: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const absolute = path.isAbsolute(value) ? value : path.resolve(sourceRoot, value);
  if (isInside(sourceRoot, absolute)) {
    return path.relative(sourceRoot, absolute).split(path.sep).join("/");
  }
  return value.split(path.sep).join("/");
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const output: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}\0${finding.path ?? ""}\0${finding.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      output.push(finding);
    }
  }
  return output;
}
