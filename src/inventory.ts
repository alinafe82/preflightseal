import path from "node:path";
import { readdir, readlink, realpath, lstat } from "node:fs/promises";

import type { Finding, Inventory, InventoryEntry } from "./types.ts";
import { sha256File, sha256Json } from "./util/crypto.ts";
import { assertNoNormalizedCollisions, validateRelativePath } from "./util/path.ts";

export interface InventoryLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxDepth: number;
}

export const defaultInventoryLimits: InventoryLimits = {
  maxFiles: 5000,
  maxFileBytes: 10 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxDepth: 40
};

const ignoredDirectoryNames = new Set([".git", "node_modules", ".preflightseal"]);

export async function createInventory(rootInput: string, limits = defaultInventoryLimits): Promise<Inventory> {
  const root = await realpath(rootInput);
  const entries: InventoryEntry[] = [];
  const findings: Finding[] = [];
  let totalBytes = 0;

  async function walk(absoluteDir: string, relativeDir: string, depth: number): Promise<void> {
    if (depth > limits.maxDepth) {
      findings.push({
        id: "PFS-INVENTORY-DEPTH",
        title: "Inventory depth limit exceeded",
        decision: "INCONCLUSIVE",
        severity: "high",
        path: relativeDir,
        evidence: `maximum depth ${limits.maxDepth} exceeded`,
        recommendation: "Inspect a smaller artifact or raise limits explicitly."
      });
      return;
    }

    const names = (await readdir(absoluteDir)).sort((a, b) => a.localeCompare(b));
    for (const name of names) {
      if (ignoredDirectoryNames.has(name)) {
        continue;
      }
      const absolute = path.join(absoluteDir, name);
      const relative = relativeDir ? `${relativeDir}/${name}` : name;
      validateRelativePath(relative);
      const stat = await lstat(absolute);
      const mode = stat.mode & 0o7777;

      if (stat.isSymbolicLink()) {
        const target = await readlink(absolute);
        entries.push({
          path: relative,
          type: "symlink",
          mode,
          size: stat.size,
          symlinkTarget: target,
          artifactKinds: classifyArtifact(relative, "symlink")
        });
        findings.push({
          id: "PFS-SYMLINK-SOURCE",
          title: "Source contains a symlink",
          decision: "WARN",
          severity: "medium",
          path: relative,
          evidence: "symlink entries are not followed during inspection",
          recommendation: "Review the symlink target before accepting installation."
        });
        continue;
      }

      if (stat.isDirectory()) {
        entries.push({
          path: relative,
          type: "directory",
          mode,
          size: 0,
          artifactKinds: classifyArtifact(relative, "directory")
        });
        await walk(absolute, relative, depth + 1);
        continue;
      }

      if (!stat.isFile()) {
        findings.push({
          id: "PFS-SPECIAL-FILE",
          title: "Source contains a special file",
          decision: "INCONCLUSIVE",
          severity: "high",
          path: relative,
          evidence: "non-file, non-directory, non-symlink entry",
          recommendation: "Remove or quarantine the special file before inspection."
        });
        continue;
      }

      if (stat.size > limits.maxFileBytes) {
        findings.push({
          id: "PFS-LARGE-FILE",
          title: "Source file exceeds maximum file size",
          decision: "INCONCLUSIVE",
          severity: "medium",
          path: relative,
          evidence: `${stat.size} bytes exceeds ${limits.maxFileBytes}`,
          recommendation: "Inspect a smaller artifact or raise limits explicitly."
        });
        continue;
      }

      totalBytes += stat.size;
      if (totalBytes > limits.maxTotalBytes) {
        findings.push({
          id: "PFS-LARGE-SOURCE",
          title: "Source exceeds maximum total size",
          decision: "INCONCLUSIVE",
          severity: "high",
          path: relative,
          evidence: `${totalBytes} bytes exceeds ${limits.maxTotalBytes}`,
          recommendation: "Inspect a smaller artifact or raise limits explicitly."
        });
        continue;
      }

      entries.push({
        path: relative,
        type: "file",
        mode,
        size: stat.size,
        sha256: await sha256File(absolute),
        executable: Boolean(mode & 0o111),
        artifactKinds: classifyArtifact(relative, "file")
      });
      if (entries.length > limits.maxFiles) {
        findings.push({
          id: "PFS-FILE-COUNT",
          title: "Source exceeds maximum file count",
          decision: "INCONCLUSIVE",
          severity: "high",
          path: relative,
          evidence: `${entries.length} entries exceeds ${limits.maxFiles}`,
          recommendation: "Inspect a smaller artifact or raise limits explicitly."
        });
        return;
      }
    }
  }

  await walk(root, "", 0);
  assertNoNormalizedCollisions(entries.map((entry) => entry.path));
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const digest = sha256Json(entries.map((entry) => ({
    artifactKinds: entry.artifactKinds,
    executable: entry.executable ?? false,
    mode: entry.mode,
    path: entry.path,
    sha256: entry.sha256 ?? null,
    size: entry.size,
    symlinkTarget: entry.symlinkTarget ?? null,
    type: entry.type
  })));

  return { root, entries, digest, findings };
}

export async function assertInventoryStable(rootInput: string, expectedDigest: string): Promise<Inventory> {
  const inventory = await createInventory(rootInput);
  if (inventory.digest !== expectedDigest) {
    inventory.findings.push({
      id: "PFS-SOURCE-CHANGED",
      title: "Source changed after inspection",
      decision: "INCONCLUSIVE",
      severity: "critical",
      evidence: `expected inventory digest ${expectedDigest}, got ${inventory.digest}`,
      recommendation: "Re-run inspect and plan on the changed source."
    });
  }
  return inventory;
}

export function classifyArtifact(relativePath: string, entryType: InventoryEntry["type"]): string[] {
  const kinds = new Set<string>();
  const base = path.posix.basename(relativePath);
  const lower = relativePath.toLocaleLowerCase("en-US");

  if (base === "AGENTS.md" || base === "AGENTS.override.md" || base === "CLAUDE.md") {
    kinds.add("agent-instructions");
  }
  if (base === "SKILL.md") {
    kinds.add("agent-skill");
  }
  if (lower.startsWith(".codex/")) {
    kinds.add("codex-configuration");
  }
  if (lower.includes("/hooks/") || lower.endsWith("/hooks") || lower.includes("hooks.json")) {
    kinds.add("hook-configuration");
  }
  if (lower.includes("mcp") && (lower.endsWith(".json") || lower.endsWith(".toml") || lower.endsWith(".yaml") || lower.endsWith(".yml"))) {
    kinds.add("mcp-configuration");
  }
  if (base === "package.json") {
    kinds.add("npm-manifest");
  }
  if (base === "package-lock.json") {
    kinds.add("npm-lockfile");
  }
  if (base === "pyproject.toml" || base === "setup.py") {
    kinds.add("python-manifest");
  }
  if (/requirements.*\.txt$/i.test(base)) {
    kinds.add("python-requirements");
  }
  if (/\.(sh|bash|zsh|fish|ps1|cmd|bat)$/i.test(base) || base === "Makefile" || base === "Dockerfile") {
    kinds.add("executable-instructions");
  }
  if (entryType === "symlink") {
    kinds.add("symlink");
  }
  if (relativePath.startsWith(".")) {
    kinds.add("hidden-file");
  }
  return [...kinds].sort();
}
