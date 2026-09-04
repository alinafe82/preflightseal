import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { computePlanSeal, createPlan, inspectLocalSource, inspectSource, readPlan, verifyPlanSeal } from "../src/plan.ts";
import type { PreflightPlan } from "../src/types.ts";

test("sealed plan carries reviewable analyzer evidence", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");

  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  assert.equal(plan.analyzerResults.length, 1);
  assert.equal(plan.analyzerResults[0].providerId, "native-install-boundary");
  assert.ok(plan.analyzerResults[0].findings.some((finding) => finding.id === "PFS-CODEX-INSTRUCTIONS"));
});

test("inspectLocalSource freezes local bytes and includes optional scanner evidence", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# reviewed\n");
  delete process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const result = await inspectLocalSource(source, ["snyk-agent-scan"]);

    assert.equal(result.source.kind, "local");
    assert.match(result.source.cacheKey ?? "", /^sha256\/[a-f0-9]{64}$/);
    assert.equal(result.analyzerResults.length, 2);
    assert.equal(result.analyzerResults[1].status, "UNAVAILABLE");
  } finally {
    restoreScannerEnv(env);
  }
});

test("inspectSource and createPlan include optional scanner evidence", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# reviewed\n");
  delete process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inspected = await inspectSource(source, ["snyk-agent-scan"]);
    const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: ["snyk-agent-scan"] });

    assert.equal(inspected.analyzerResults.length, 2);
    assert.equal(plan.analyzerResults.length, 2);
    assert.equal(plan.analyzerResults[1].providerId, "snyk-agent-scan");
  } finally {
    restoreScannerEnv(env);
  }
});

test("plan verification rejects tampered analyzer evidence", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.analyzerResults[0].findings = [];

  assert.throws(() => verifyPlanSeal(plan), /analyzer evidence digest mismatch/);
});

test("plan verification rejects warning fingerprint tampering", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.warningFingerprints = [];

  assert.throws(() => verifyPlanSeal(plan), /warning fingerprints/);
});

test("plan verification rejects policy digest mismatch", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.policyDigest = "0".repeat(64);

  assert.throws(() => verifyPlanSeal(plan), /policy digest mismatch/);
});

test("plan verification rejects policy evaluation mismatch", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.evaluation.decision = "ALLOW";

  assert.throws(() => verifyPlanSeal(plan), /policy evaluation does not match/);
});

test("plan verification rejects raw seal mismatch", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });

  plan.seal = "0".repeat(64);

  assert.throws(() => verifyPlanSeal(plan), /plan seal mismatch/);
});

test("plan reader rejects unsupported major schema version", async () => {
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-plan-"));
  const planPath = path.join(planDir, "plan.json");
  await writeFile(planPath, JSON.stringify({ schemaVersion: "preflightseal.plan.v2" }));

  await assert.rejects(readPlan(planPath), /unsupported plan schema/);
});

test("plan seal ignores volatile timestamps and covers security material", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const plan = await createPlan(source, { target: "codex", targetRoot: target, scanners: [] });
  const { seal: _seal, ...base } = plan;

  const changedTimestamp = clonePlanLike(base);
  changedTimestamp.source.retrievedAt = "2030-01-01T00:00:00.000Z";
  changedTimestamp.createdAt = "2030-01-01T00:00:00.000Z";
  assert.equal(computePlanSeal(base), computePlanSeal(changedTimestamp));

  const changedDestination = clonePlanLike(base);
  changedDestination.operations[0].targetPath = "AGENTS.override.md";
  assert.notEqual(computePlanSeal(base), computePlanSeal(changedDestination));

  const changedSourceDigest = clonePlanLike(base);
  changedSourceDigest.source.contentDigest = "0".repeat(64);
  assert.notEqual(computePlanSeal(base), computePlanSeal(changedSourceDigest));

  const changedPolicy = clonePlanLike(base);
  changedPolicy.policy.version = "changed";
  changedPolicy.policyDigest = "0".repeat(64);
  assert.notEqual(computePlanSeal(base), computePlanSeal(changedPolicy));
});

function clonePlanLike(planLike: Omit<PreflightPlan, "seal">): Omit<PreflightPlan, "seal"> {
  return JSON.parse(JSON.stringify(planLike));
}

function preserveScannerEnv(): { executable?: string; token?: string } {
  return {
    executable: process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN,
    token: process.env.SNYK_TOKEN
  };
}

function restoreScannerEnv(env: { executable?: string; token?: string }): void {
  if (env.executable === undefined) {
    delete process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;
  } else {
    process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = env.executable;
  }
  if (env.token === undefined) {
    delete process.env.SNYK_TOKEN;
  } else {
    process.env.SNYK_TOKEN = env.token;
  }
}
