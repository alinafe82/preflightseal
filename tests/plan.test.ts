import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { createPlan, verifyPlanSeal } from "../src/plan.ts";

test("sealed plan carries reviewable analyzer evidence", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");

  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  assert.equal(plan.analyzerResults.length, 1);
  assert.equal(plan.analyzerResults[0].providerId, "native-install-boundary");
  assert.ok(plan.analyzerResults[0].findings.some((finding) => finding.id === "PFS-CODEX-INSTRUCTIONS"));
});

test("plan verification rejects tampered analyzer evidence", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.analyzerResults[0].findings = [];

  assert.throws(() => verifyPlanSeal(plan), /analyzer evidence digest mismatch/);
});
