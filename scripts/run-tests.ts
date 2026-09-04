#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main(): Promise<number> {
  const testFiles = (await readdir(path.join(ROOT, "tests")))
    .filter((file) => file.endsWith(".test.ts"))
    .sort()
    .map((file) => path.join("tests", file));
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "preflightseal-test-cache-"));
  try {
    return await runNodeTests(testFiles, cacheDir);
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
}

function runNodeTests(testFiles: string[], cacheDir: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--test", ...testFiles], {
      cwd: ROOT,
      env: {
        ...process.env,
        PREFLIGHTSEAL_CACHE_DIR: cacheDir
      },
      stdio: "inherit"
    });
    child.on("close", (code) => {
      resolve(code ?? 1);
    });
  });
}

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
