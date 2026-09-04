import path from "node:path";
import { mkdir, realpath, readFile, writeFile } from "node:fs/promises";

import { acquireGitHubSource, isGitHubHttpsSource } from "./acquire/github.ts";
import { runNativeAnalyzer } from "./analyzers/native.ts";
import { snykAgentScanProvider } from "./analyzers/external.ts";
import { createInventory } from "./inventory.ts";
import { defaultPolicy, digestPolicy, evaluatePolicy } from "./policy.ts";
import { planCodexOperations } from "./target/codex.ts";
import type { AnalyzerResult, PreflightPlan, SourceIdentity } from "./types.ts";
import { sha256Json } from "./util/crypto.ts";
import { parseJsonObject } from "./util/json.ts";

export interface PlanOptions {
  target: "codex";
  targetRoot: string;
  out?: string;
  scanners: string[];
}

export async function inspectLocalSource(sourceInput: string, scanners: string[] = []): Promise<{
  source: SourceIdentity;
  inventoryDigest: string;
  analyzerEvidenceDigest: string;
  analyzerResults: AnalyzerResult[];
  sourceRoot: string;
}> {
  const sourceRoot = await realpath(sourceInput);
  const inventory = await createInventory(sourceRoot);
  const source: SourceIdentity = {
    kind: "local",
    originalInput: sourceInput,
    canonical: sourceRoot,
    resolvedRevision: inventory.digest,
    contentDigest: inventory.digest,
    retrievedAt: new Date().toISOString()
  };
  const analyzerResults: AnalyzerResult[] = [await runNativeAnalyzer(sourceRoot, inventory)];
  if (scanners.includes("snyk-agent-scan")) {
    analyzerResults.push(await snykAgentScanProvider().scan({
      sourceRoot,
      inventory,
      timeoutMs: 30_000
    }));
  }
  return {
    source,
    inventoryDigest: inventory.digest,
    analyzerEvidenceDigest: digestAnalyzerEvidence(analyzerResults),
    analyzerResults,
    sourceRoot
  };
}

export async function inspectSource(sourceInput: string, scanners: string[] = []): Promise<{
  source: SourceIdentity;
  inventoryDigest: string;
  analyzerEvidenceDigest: string;
  analyzerResults: AnalyzerResult[];
  sourceRoot: string;
}> {
  const resolved = await resolveSource(sourceInput);
  const inventory = await createInventory(resolved.sourceRoot);
  const source = {
    ...resolved.source,
    contentDigest: inventory.digest,
    resolvedRevision: resolved.source.kind === "local" ? inventory.digest : resolved.source.resolvedRevision
  };
  const analyzerResults: AnalyzerResult[] = [await runNativeAnalyzer(resolved.sourceRoot, inventory)];
  if (scanners.includes("snyk-agent-scan")) {
    analyzerResults.push(await snykAgentScanProvider().scan({
      sourceRoot: resolved.sourceRoot,
      inventory,
      timeoutMs: 30_000
    }));
  }
  return {
    source,
    inventoryDigest: inventory.digest,
    analyzerEvidenceDigest: digestAnalyzerEvidence(analyzerResults),
    analyzerResults,
    sourceRoot: resolved.sourceRoot
  };
}

export async function createPlan(sourceInput: string, options: PlanOptions): Promise<PreflightPlan> {
  const targetRoot = await ensureTargetRoot(options.targetRoot);
  const resolved = await resolveSource(sourceInput);
  const sourceRoot = resolved.sourceRoot;
  const inventory = await createInventory(sourceRoot);
  const source: SourceIdentity = {
    ...resolved.source,
    contentDigest: inventory.digest,
    resolvedRevision: resolved.source.kind === "local" ? inventory.digest : resolved.source.resolvedRevision
  };
  const analyzerResults: AnalyzerResult[] = [await runNativeAnalyzer(sourceRoot, inventory)];
  if (options.scanners.includes("snyk-agent-scan")) {
    analyzerResults.push(await snykAgentScanProvider().scan({
      sourceRoot,
      inventory,
      timeoutMs: 30_000
    }));
  }
  const policy = defaultPolicy();
  const policyDigest = digestPolicy(policy);
  const { operations, preconditions } = await planCodexOperations(sourceRoot, targetRoot, inventory);
  const evaluation = evaluatePolicy(policy, analyzerResults);
  const planWithoutSeal = {
    schemaVersion: "preflightseal.plan.v1" as const,
    createdAt: new Date().toISOString(),
    source,
    target: {
      runtime: options.target,
      root: targetRoot
    },
    inventoryDigest: inventory.digest,
    analyzerEvidenceDigest: digestAnalyzerEvidence(analyzerResults),
    analyzerResults,
    policy,
    policyDigest,
    evaluation,
    operations,
    preconditions
  };
  const plan: PreflightPlan = {
    ...planWithoutSeal,
    seal: computePlanSeal(planWithoutSeal)
  };
  if (options.out) {
    await mkdir(path.dirname(options.out), { recursive: true });
    await writeFile(options.out, `${JSON.stringify(plan, null, 2)}\n`, { mode: 0o644 });
  }
  return plan;
}

async function resolveSource(sourceInput: string): Promise<{ source: SourceIdentity; sourceRoot: string }> {
  if (isGitHubHttpsSource(sourceInput)) {
    const acquired = await acquireGitHubSource(sourceInput);
    return {
      source: acquired.source,
      sourceRoot: acquired.sourceRoot
    };
  }

  const sourceRoot = await realpath(sourceInput);
  const inventory = await createInventory(sourceRoot);
  return {
    source: {
      kind: "local",
      originalInput: sourceInput,
      canonical: sourceRoot,
      resolvedRevision: inventory.digest,
      contentDigest: inventory.digest,
      retrievedAt: new Date().toISOString()
    },
    sourceRoot
  };
}

export function digestAnalyzerEvidence(results: AnalyzerResult[]): string {
  return sha256Json(results.map((result) => ({
    error: result.error ?? null,
    findings: result.findings,
    providerId: result.providerId,
    reportDigest: result.reportDigest,
    status: result.status,
    version: result.version ?? null
  })));
}

export function computePlanSeal(planLike: Omit<PreflightPlan, "seal">): string {
  return sha256Json({
    schemaVersion: planLike.schemaVersion,
    source: planLike.source,
    target: planLike.target,
    inventoryDigest: planLike.inventoryDigest,
    analyzerEvidenceDigest: planLike.analyzerEvidenceDigest,
    policyDigest: planLike.policyDigest,
    operations: planLike.operations,
    preconditions: planLike.preconditions
  });
}

export async function readPlan(planPath: string): Promise<PreflightPlan> {
  const data = parseJsonObject(await readFile(planPath, "utf8"), "plan");
  if (data.schemaVersion !== "preflightseal.plan.v1") {
    throw new Error("unsupported plan schema");
  }
  const plan = data as unknown as PreflightPlan;
  verifyPlanSeal(plan);
  return plan;
}

export function verifyPlanSeal(plan: PreflightPlan): void {
  const { seal, ...withoutSeal } = plan;
  const evidenceDigest = digestAnalyzerEvidence(plan.analyzerResults);
  if (plan.analyzerEvidenceDigest !== evidenceDigest) {
    throw new Error(`analyzer evidence digest mismatch: expected ${evidenceDigest}, got ${plan.analyzerEvidenceDigest}`);
  }
  const policyDigest = digestPolicy(plan.policy);
  if (plan.policyDigest !== policyDigest) {
    throw new Error(`policy digest mismatch: expected ${policyDigest}, got ${plan.policyDigest}`);
  }
  const evaluation = evaluatePolicy(plan.policy, plan.analyzerResults);
  if (JSON.stringify(evaluation) !== JSON.stringify(plan.evaluation)) {
    throw new Error("policy evaluation does not match analyzer evidence");
  }
  const expected = computePlanSeal(withoutSeal);
  if (seal !== expected) {
    throw new Error(`plan seal mismatch: expected ${expected}, got ${seal}`);
  }
}

async function ensureTargetRoot(targetRootInput: string): Promise<string> {
  await mkdir(targetRootInput, { recursive: true, mode: 0o755 });
  return await realpath(targetRootInput);
}
