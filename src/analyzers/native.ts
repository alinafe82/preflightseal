import path from "node:path";
import { readFile } from "node:fs/promises";

import type { AnalyzerResult, Finding, Inventory } from "../types.ts";
import { normalizeFindings } from "../findings.ts";
import { SCHEMA_VERSION } from "../schema.ts";
import { sha256Json } from "../util/crypto.ts";
import { sanitizeEvidence } from "../util/text.ts";

const lifecycleScriptNames = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepack",
  "postpack"
]);

const sourcePolicyFileNames = new Set([
  "preflightseal.yaml",
  "preflightseal.yml",
  "policy.json",
  "agent-vet.yaml",
  "agent-vet.yml",
  "security-policy.yaml",
  "security-policy.yml"
]);

const riskyTextRules: Array<{
  id: string;
  title: string;
  decision: "WARN" | "BLOCK";
  severity: "medium" | "high" | "critical";
  pattern: RegExp;
  recommendation: string;
}> = [
  {
    id: "PFS-CURL-BASH",
    title: "Remote shell execution pattern",
    decision: "BLOCK",
    severity: "critical",
    pattern: /\b(curl|wget)\b[\s\S]{0,160}\|\s*(sh|bash|zsh)\b/i,
    recommendation: "Do not install from plans that require piping remote bytes into a shell."
  },
  {
    id: "PFS-REMOTE-POWERSHELL",
    title: "Remote PowerShell execution pattern",
    decision: "BLOCK",
    severity: "critical",
    pattern: /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[\s\S]{0,180}\|\s*(iex|invoke-expression)\b/i,
    recommendation: "Do not install from plans that require executing remote PowerShell."
  },
  {
    id: "PFS-EVAL-EXEC",
    title: "Dynamic code execution pattern",
    decision: "WARN",
    severity: "high",
    pattern: /\b(eval|exec)\s*\(|\b(node\s+-e|python(?:3)?\s+-c)\b/i,
    recommendation: "Review dynamic execution manually and require scoped acceptance."
  },
  {
    id: "PFS-MUTABLE-RUNNER",
    title: "Mutable package runner",
    decision: "WARN",
    severity: "high",
    pattern: /\b(npx\s+[^&|;\n]*@latest|pnpm\s+dlx\b|bunx\b)/i,
    recommendation: "Pin package versions and avoid mutable command runners."
  },
  {
    id: "PFS-GLOBAL-NPM-INSTALL",
    title: "Global npm installation",
    decision: "WARN",
    severity: "medium",
    pattern: /\bnpm\s+(install|i)\s+-g\b/i,
    recommendation: "Avoid global package installation from untrusted agent repositories."
  },
  {
    id: "PFS-AGENT-CONFIG-MUTATION",
    title: "Agent configuration mutation",
    decision: "WARN",
    severity: "high",
    pattern: /(~\/\.(codex|claude)|\$HOME\/\.(codex|claude))/i,
    recommendation: "Require explicit operation planning for agent runtime configuration changes."
  },
  {
    id: "PFS-GIT-HOOK-MUTATION",
    title: "Git hook mutation",
    decision: "WARN",
    severity: "high",
    pattern: /(\.git\/hooks|core\.hooksPath|git\s+config\s+[^&|;\n]*hooksPath)/i,
    recommendation: "Do not authorize hook installation without a dedicated hook plan."
  },
  {
    id: "PFS-PERSISTENCE-MECHANISM",
    title: "Persistence mechanism",
    decision: "WARN",
    severity: "high",
    pattern: /(crontab|LaunchAgents|launchctl|systemd|schtasks|Scheduled\s+Task)/i,
    recommendation: "Review persistence changes as privileged operations."
  },
  {
    id: "PFS-DESTRUCTIVE-DELETE",
    title: "Destructive deletion pattern",
    decision: "WARN",
    severity: "high",
    pattern: /\brm\s+-rf\b|\bRemove-Item\b[\s\S]{0,80}\b-Recurse\b/i,
    recommendation: "Require a narrow, reviewed deletion plan before accepting."
  },
  {
    id: "PFS-ENV-DUMP",
    title: "Environment dumping pattern",
    decision: "WARN",
    severity: "high",
    pattern: /\b(printenv|env\s*>|process\.env|Get-ChildItem\s+Env:)/i,
    recommendation: "Review whether secrets can be exposed by this behavior."
  }
];

export async function runNativeAnalyzer(sourceRoot: string, inventory: Inventory): Promise<AnalyzerResult> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [...inventory.findings];

  for (const entry of inventory.entries) {
    if (entry.type !== "file") {
      continue;
    }
    if (entry.executable) {
      findings.push({
        id: "PFS-EXECUTABLE-FILE",
        title: "Executable file present",
        decision: "WARN",
        severity: "medium",
        path: entry.path,
        evidence: `mode ${entry.mode.toString(8)}`,
        recommendation: "Review executable files before accepting installation."
      });
    }

    if (entry.artifactKinds.includes("hook-configuration")) {
      findings.push({
        id: "PFS-HOOK-REGISTRATION",
        title: "Hook configuration present",
        decision: "WARN",
        severity: "high",
        path: entry.path,
        evidence: "hook configuration can cause future command execution",
        recommendation: "Require explicit scoped acceptance before installing hook configuration."
      });
    }

    if (entry.artifactKinds.includes("mcp-configuration") || looksLikeMcpPath(entry.path)) {
      findings.push({
        id: "PFS-MCP-REGISTRATION",
        title: "MCP configuration present",
        decision: "WARN",
        severity: "high",
        path: entry.path,
        evidence: "MCP configuration can register executable or remote tools",
        recommendation: "Require explicit scoped acceptance and non-executing scanner evidence."
      });
    }

    if (entry.artifactKinds.includes("agent-instructions")) {
      findings.push({
        id: "PFS-CODEX-INSTRUCTIONS",
        title: "Agent instruction file changes runtime behavior",
        decision: "WARN",
        severity: "medium",
        path: entry.path,
        evidence: "instruction files influence future agent behavior",
        recommendation: "Accept this warning only for reviewed instruction content."
      });
    }
    if (entry.artifactKinds.includes("agent-skill")) {
      findings.push({
        id: "PFS-AGENT-SKILL",
        title: "Agent skill changes runtime behavior",
        decision: "WARN",
        severity: "medium",
        path: entry.path,
        evidence: "skill files influence future agent behavior",
        recommendation: "Accept this warning only for reviewed skill content and assets."
      });
    }

    if (sourcePolicyFileNames.has(path.posix.basename(entry.path).toLocaleLowerCase("en-US"))) {
      findings.push({
        id: "PFS-SOURCE-SUPPLIED-POLICY",
        title: "Source-supplied policy file",
        decision: "WARN",
        severity: "high",
        path: entry.path,
        evidence: "policy-like files in the inspected source are untrusted content",
        recommendation: "Use an operator-controlled policy instead of trusting policy files from the source."
      });
    }

    const absolute = path.join(sourceRoot, entry.path);
    if (entry.path.endsWith("package.json")) {
      findings.push(...await analyzePackageJson(absolute, entry.path));
    }
    if (isInstallBoundaryTextCandidate(entry, entry.size)) {
      const text = await readFile(absolute, "utf8").catch(() => "");
      findings.push(...analyzeText(entry.path, text));
    }
  }

  const unique = normalizeFindings(dedupeFindings(findings), "native-install-boundary");
  const finishedAt = new Date().toISOString();
  return {
    schemaVersion: SCHEMA_VERSION.ANALYZER_RESULT,
    providerId: "native-install-boundary",
    status: unique.length > 0 ? "FINDINGS" : "PASS",
    startedAt,
    finishedAt,
    version: "0.1.0",
    reportDigest: sha256Json(unique),
    findings: unique
  };
}

async function analyzePackageJson(absolute: string, relative: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const parsed = JSON.parse(await readFile(absolute, "utf8")) as { scripts?: Record<string, unknown> };
    const scripts = parsed.scripts ?? {};
    for (const [name, value] of Object.entries(scripts)) {
      if (lifecycleScriptNames.has(name)) {
        findings.push({
          id: "PFS-NPM-LIFECYCLE",
          title: "npm lifecycle script",
          decision: "WARN",
          severity: "high",
          path: relative,
          evidence: `${name}: ${sanitizeEvidence(String(value))}`,
          recommendation: "Do not execute package installation before reviewing lifecycle behavior."
        });
      }
    }
  } catch (error) {
    findings.push({
      id: "PFS-PACKAGE-JSON-PARSE",
      title: "package.json could not be parsed",
      decision: "INCONCLUSIVE",
      severity: "medium",
      path: relative,
      evidence: String((error as Error).message),
      recommendation: "Fix or quarantine malformed package metadata before installation."
    });
  }
  return findings;
}

function analyzeText(relative: string, text: string): Finding[] {
  const findings: Finding[] = [];
  for (const rule of riskyTextRules) {
    const match = text.match(rule.pattern);
    if (match) {
      findings.push({
        id: rule.id,
        title: rule.title,
        decision: rule.decision,
        severity: rule.severity,
        path: relative,
        evidence: sanitizeEvidence(match[0]),
        recommendation: rule.recommendation
      });
    }
  }
  if (/mcpServers|"mcp_servers"|\[mcp_servers/i.test(text)) {
    findings.push({
      id: "PFS-MCP-REGISTRATION",
      title: "MCP server registration",
      decision: "WARN",
      severity: "high",
      path: relative,
      evidence: "MCP server configuration key detected",
      recommendation: "Review command, args, environment, and network authority before accepting."
    });
  }
  return findings;
}

function isInstallBoundaryTextCandidate(entry: Inventory["entries"][number], size: number): boolean {
  if (size > 1024 * 1024) {
    return false;
  }
  if (entry.artifactKinds.some((kind) => [
    "agent-instructions",
    "agent-skill",
    "codex-configuration",
    "hook-configuration",
    "mcp-configuration",
    "npm-manifest",
    "python-manifest",
    "python-requirements",
    "executable-instructions"
  ].includes(kind))) {
    return true;
  }
  return /(^|\/)(README|INSTALL|SETUP|QUICKSTART)\.(md|txt)$/i.test(entry.path);
}

function looksLikeMcpPath(relative: string): boolean {
  return /(^|\/)(mcp|mcpServers|mcp_servers)(\/|\.|$)/i.test(relative);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const output: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}\0${finding.path ?? ""}\0${finding.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      output.push(finding);
    }
  }
  return output.sort((a, b) => `${a.id}:${a.path ?? ""}`.localeCompare(`${b.id}:${b.path ?? ""}`));
}
