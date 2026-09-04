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

const PROHIBITED = [
  { name: "local user codex home", pattern: new RegExp(["/Users/amatenda", "/.codex"].join("")) },
  { name: "local user agents home", pattern: new RegExp(["/Users/amatenda", "/.agents"].join("")) },
  { name: "internal gate skill name", pattern: new RegExp(["repo", "architecture", "gate"].join("-"), "i") },
  { name: "internal loop skill name", pattern: new RegExp(["autonomous", "development", "loop"].join("-"), "i") },
  { name: "private harness wording", pattern: new RegExp(["private", "engineering", "harness"].join("\\s+"), "i") }
];

async function main(): Promise<number> {
  const findings: string[] = [];
  for (const filePath of await walk(ROOT)) {
    if (!isTextFile(filePath)) {
      continue;
    }
    const relative = path.relative(ROOT, filePath);
    const text = await readFile(filePath, "utf8").catch(() => "");
    for (const probe of PROHIBITED) {
      if (probe.pattern.test(text)) {
        findings.push(`${relative}: ${probe.name}`);
      }
    }
  }

  if (findings.length > 0) {
    console.error(`contamination-check: ${findings.length} prohibited references found`);
    for (const finding of findings) {
      console.error(finding);
    }
    return 1;
  }

  console.log("contamination-check: 0 prohibited references");
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

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
