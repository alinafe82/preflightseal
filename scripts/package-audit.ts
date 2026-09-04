#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROHIBITED_PREFIXES = [
  ".git/",
  ".github/",
  ".preflightseal/",
  ".specs/",
  "coverage/",
  "node_modules/",
  "scripts/",
  "src/",
  "tests/"
];

async function main(): Promise<number> {
  const packageJson = JSON.parse(await readFile(path.join(ROOT, "package.json"), "utf8")) as {
    bin?: Record<string, string>;
  };
  const cliBin = packageJson.bin?.preflightseal;
  if (cliBin !== "dist/cli.js") {
    console.error("package-audit: bin.preflightseal must point to dist/cli.js");
    return 1;
  }

  const result = await npmPackJson();
  process.stdout.write(result.output);
  process.stderr.write(result.errorOutput);
  if (result.exitCode !== 0) {
    return result.exitCode;
  }

  const parsed = JSON.parse(result.output) as Array<{ files: Array<{ path: string }> }>;
  const files = parsed.flatMap((entry) => entry.files.map((file) => file.path));
  const prohibited = files.filter((file) => PROHIBITED_PREFIXES.some((prefix) => file === prefix.slice(0, -1) || file.startsWith(prefix)));
  if (prohibited.length > 0) {
    console.error("package-audit: prohibited package entries:");
    for (const file of prohibited) {
      console.error(file);
    }
    return 1;
  }
  if (!files.includes("schemas/preflight-plan.v1.schema.json")) {
    console.error("package-audit: schema files are missing from package");
    return 1;
  }
  if (!files.includes(cliBin)) {
    console.error("package-audit: CLI bin is missing from package");
    return 1;
  }
  const cliSource = await readFile(path.join(ROOT, cliBin), "utf8");
  if (!cliSource.startsWith("#!/usr/bin/env node\n")) {
    console.error("package-audit: CLI bin is missing the node shebang");
    return 1;
  }
  console.log(`package-audit: reviewed ${files.length} package entries`);
  return 0;
}

function npmPackJson(): Promise<{ exitCode: number; output: string; errorOutput: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.platform === "win32" ? "npm.cmd" : "npm", ["pack", "--dry-run", "--json"], {
      cwd: ROOT,
      env: {
        ...process.env,
        npm_config_cache: path.join(ROOT, ".preflightseal", "npm-cache")
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

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
