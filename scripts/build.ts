#!/usr/bin/env node
import { spawn } from "node:child_process";
import { rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main(): Promise<number> {
  await rm(path.join(ROOT, "dist"), { recursive: true, force: true });
  return runTsc();
}

function runTsc(): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(process.platform === "win32" ? "tsc.cmd" : "tsc", ["-p", "tsconfig.build.json"], {
      cwd: ROOT,
      stdio: "inherit"
    });
    child.on("close", (code) => resolve(code ?? 1));
  });
}

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
