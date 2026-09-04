#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CHECK_DIRS = ["src", "scripts", "tests"];

async function main(): Promise<number> {
  const files = (await Promise.all(CHECK_DIRS.map((dir) => walk(path.join(ROOT, dir)))))
    .flat()
    .filter((file) => file.endsWith(".ts"))
    .sort();

  for (const file of files) {
    const code = await checkFile(file);
    if (code !== 0) {
      return code;
    }
  }
  console.log(`syntax-check: ${files.length} TypeScript files checked`);
  return 0;
}

async function walk(root: string): Promise<string[]> {
  const output: string[] = [];
  for (const name of await readdir(root)) {
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

function checkFile(file: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--check", file], {
      cwd: ROOT,
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
