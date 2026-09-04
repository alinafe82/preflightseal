#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKIPPED_DIRS = new Set([".git", "node_modules", "coverage", ".preflightseal", ".specs"]);
const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".cts",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".mts",
  ".ts",
  ".txt",
  ".yaml",
  ".yml"
]);

const SECRET_PATTERNS = [
  { name: "private key block", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "OpenAI-style API key", pattern: /sk-[A-Za-z0-9_-]{30,}/ },
  { name: "GitHub token", pattern: /gh[pousr]_[A-Za-z0-9_]{30,}/ },
  { name: "npm token", pattern: /npm_[A-Za-z0-9]{30,}/ },
  { name: "Slack token", pattern: /xox[baprs]-[A-Za-z0-9-]{20,}/ },
  { name: "Snyk token", pattern: /snyk_[A-Za-z0-9]{30,}/ }
];

async function main(): Promise<number> {
  const findings: string[] = [];
  for (const filePath of await walk(ROOT)) {
    if (!isTextFile(filePath)) {
      continue;
    }
    const relative = path.relative(ROOT, filePath);
    const lines = (await readFile(filePath, "utf8").catch(() => "")).split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.pattern.test(line) && !isAllowedFixture(relative, line)) {
          findings.push(`${relative}:${index + 1}: ${pattern.name}`);
        }
      }
    });
  }

  if (findings.length > 0) {
    console.error(`secret-scan: ${findings.length} potential secrets found`);
    for (const finding of findings) {
      console.error(finding);
    }
    return 1;
  }
  console.log("secret-scan: 0 potential secrets");
  return 0;
}

async function walk(root: string): Promise<string[]> {
  const output: string[] = [];
  for (const name of await readdir(root)) {
    if (SKIPPED_DIRS.has(name)) {
      continue;
    }
    const full = path.join(root, name);
    const info = await stat(full);
    if (info.isDirectory()) {
      output.push(...await walk(full));
    } else if (info.isFile()) {
      output.push(full);
    }
  }
  return output;
}

function isTextFile(filePath: string): boolean {
  return TEXT_EXTENSIONS.has(path.extname(filePath)) || path.basename(filePath) === "LICENSE";
}

function isAllowedFixture(relative: string, line: string): boolean {
  return relative.startsWith("tests/") && /test|fixture|example|dummy|redacted/i.test(line);
}

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
