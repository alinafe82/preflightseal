import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { createPlan } from "../src/plan.ts";
import { installPlan, rollbackReceipt, verifyReceipt } from "../src/install/transaction.ts";

test("sealed plan installs, verifies, and rolls back reviewed bytes", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# Reviewed guidance\n");

  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });
  assert.equal(plan.evaluation.decision, "WARN");
  assert.deepEqual(plan.evaluation.warningIds, ["PFS-CODEX-INSTRUCTIONS"]);
  assert.equal(plan.operations.length, 1);

  await assert.rejects(
    installPlan(plan, { acceptedWarnings: [] }),
    /requires scoped acceptance/
  );

  const { receipt } = await installPlan(plan, { acceptedWarnings: ["PFS-CODEX-INSTRUCTIONS"] });
  assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# Reviewed guidance\n");
  assert.equal((await verifyReceipt(receipt)).ok, true);
  assert.equal((await rollbackReceipt(receipt)).ok, true);
  await assert.rejects(stat(path.join(target, "AGENTS.md")), /ENOENT/);
});

test("install refuses if an installed source file changes after planning", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# v1\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  await writeFile(path.join(source, "AGENTS.md"), "# v2\n");

  await assert.rejects(
    installPlan(plan, { acceptedWarnings: ["PFS-CODEX-INSTRUCTIONS"] }),
    /source changed after planning/
  );
});

test("install refuses if any source inventory entry changes after planning", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# v1\n");
  await writeFile(path.join(source, "README.md"), "notes\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  await writeFile(path.join(source, "README.md"), "changed\n");

  await assert.rejects(
    installPlan(plan, { acceptedWarnings: ["PFS-CODEX-INSTRUCTIONS"] }),
    /source changed after planning/
  );
});

test("rollback refuses to destroy later user changes", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# planned\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });
  const { receipt } = await installPlan(plan, { acceptedWarnings: ["PFS-CODEX-INSTRUCTIONS"] });

  await writeFile(path.join(target, "AGENTS.md"), "# user edit\n");

  const result = await rollbackReceipt(receipt);
  assert.equal(result.ok, false);
  assert.deepEqual(result.conflicts, ["AGENTS.md"]);
  assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# user edit\n");
});

test("rollback treats a swapped symlink parent as a conflict", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# skill\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });
  const { receipt } = await installPlan(plan, { acceptedWarnings: ["PFS-AGENT-SKILL"] });

  await mkdir(path.join(outside, "demo"));
  await writeFile(path.join(outside, "demo", "SKILL.md"), "# skill\n");
  await rm(path.join(target, ".codex", "skills", "demo"), { recursive: true });
  await symlink(path.join(outside, "demo"), path.join(target, ".codex", "skills", "demo"));

  const result = await rollbackReceipt(receipt);

  assert.equal(result.ok, false);
  assert.deepEqual(result.conflicts, [".codex/skills/demo/SKILL.md"]);
  assert.equal(await readFile(path.join(outside, "demo", "SKILL.md"), "utf8"), "# skill\n");
});
