#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OVERALL_MINIMUM = 80;
const SECURITY_CRITICAL_BRANCH_MINIMUM = 90;

const SECURITY_CRITICAL_MODULES = new Map<string, string>([
  ["cache.ts", "src/acquire/cache.ts"],
  ["github.ts", "src/acquire/github.ts"],
  ["local.ts", "src/acquire/local.ts"],
  ["tar.ts", "src/acquire/tar.ts"],
  ["external.ts", "src/analyzers/external.ts"],
  ["native.ts", "src/analyzers/native.ts"],
  ["findings.ts", "src/findings.ts"],
  ["inventory.ts", "src/inventory.ts"],
  ["plan.ts", "src/plan.ts"],
  ["policy.ts", "src/policy.ts"],
  ["codex.ts", "src/target/codex.ts"],
  ["transaction.ts", "src/install/transaction.ts"],
  ["crypto.ts", "src/util/crypto.ts"],
  ["json.ts", "src/util/json.ts"],
  ["path.ts", "src/util/path.ts"],
  ["text.ts", "src/util/text.ts"]
]);

interface CoverageRow {
  line: number;
  branch: number;
}

async function main(): Promise<number> {
  const testFiles = (await readdir(path.join(ROOT, "tests")))
    .filter((file) => file.endsWith(".test.ts"))
    .sort()
    .map((file) => path.join("tests", file));

  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "preflightseal-coverage-cache-"));
  const result = await runNodeCoverage(testFiles, cacheDir);
  await rm(cacheDir, { recursive: true, force: true });

  process.stdout.write(result.output);
  process.stderr.write(result.errorOutput);

  if (result.exitCode !== 0) {
    return result.exitCode;
  }

  const coverage = parseCoverage(result.output + result.errorOutput);
  const overall = coverage.get("all files");
  if (!overall) {
    console.error("coverage: could not parse overall coverage row");
    return 1;
  }

  const criticalRows = [...SECURITY_CRITICAL_MODULES.entries()].map(([basename, module]) => {
    const row = coverage.get(basename);
    if (!row) {
      throw new Error(`coverage: missing security-critical module coverage for ${module}`);
    }
    return { module, ...row };
  });

  const securityCriticalBranch = average(criticalRows.map((row) => row.branch));
  const below = criticalRows.filter((row) => row.branch < SECURITY_CRITICAL_BRANCH_MINIMUM);

  console.log("");
  console.log("Security-critical branch coverage");
  console.log("Module                                      Branch Coverage");
  console.log("----------------------------------------------------------");
  for (const row of criticalRows) {
    console.log(`${row.module.padEnd(43)} ${row.branch.toFixed(2)}%`);
  }
  console.log(`Overall line coverage: ${overall.line.toFixed(2)}%`);
  console.log(`Overall branch coverage: ${overall.branch.toFixed(2)}%`);
  console.log(`Security-critical branch coverage: ${securityCriticalBranch.toFixed(2)}%`);
  console.log(`Security-critical modules below 90%: ${below.length === 0 ? "none" : below.map((row) => row.module).join(", ")}`);

  if (overall.line < OVERALL_MINIMUM || overall.branch < OVERALL_MINIMUM) {
    console.error(`coverage: overall coverage is below ${OVERALL_MINIMUM}%`);
    return 1;
  }
  if (securityCriticalBranch < SECURITY_CRITICAL_BRANCH_MINIMUM) {
    console.error(`coverage: security-critical branch coverage is below ${SECURITY_CRITICAL_BRANCH_MINIMUM}%`);
    return 1;
  }
  return 0;
}

function runNodeCoverage(testFiles: string[], cacheDir: string): Promise<{
  exitCode: number;
  output: string;
  errorOutput: string;
}> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--test", "--experimental-test-coverage", ...testFiles], {
      cwd: ROOT,
      env: {
        ...process.env,
        PREFLIGHTSEAL_CACHE_DIR: cacheDir
      },
      stdio: ["ignore", "pipe", "pipe"]
    });

    let output = "";
    let errorOutput = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      errorOutput += chunk;
    });
    child.on("close", (code) => {
      resolve({
        exitCode: code ?? 1,
        output,
        errorOutput
      });
    });
  });
}

function parseCoverage(output: string): Map<string, CoverageRow> {
  const rows = new Map<string, CoverageRow>();
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/(?:^| )([A-Za-z0-9_.-]+\.ts|all files)\s+\|\s+([0-9.]+)\s+\|\s+([0-9.]+)/);
    if (!match) {
      continue;
    }
    rows.set(match[1], {
      line: Number(match[2]),
      branch: Number(match[3])
    });
  }
  return rows;
}

function average(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
