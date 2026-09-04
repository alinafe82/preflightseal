#!/usr/bin/env node
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createPlan, inspectSource } from "../src/plan.ts";
import { defaultPolicy, evaluatePolicy } from "../src/policy.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

interface Target {
  name: string;
  url: string;
  purpose: string[];
}

async function main(argv: string[]): Promise<number> {
  const live = process.env.PREFLIGHTSEAL_LIVE_DOGFOOD === "1" || argv.includes("--live");
  if (!live) {
    console.log("dogfood: live public repository run skipped; set PREFLIGHTSEAL_LIVE_DOGFOOD=1 or pass --live");
    console.log("dogfood: running deterministic fixture dogfood through npm run dogfood:fixtures is required in CI");
    return 0;
  }

  const manifest = JSON.parse(await readFile(path.join(ROOT, "dogfood", "targets.json"), "utf8")) as { targets: Target[] };
  const workspace = await mkdtemp(path.join(os.tmpdir(), "preflightseal-live-dogfood-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = path.join(workspace, "cache");

  try {
    const results = [];
    for (const target of manifest.targets) {
      const inspected = await inspectSource(target.url);
      const evaluation = evaluatePolicy(defaultPolicy(), inspected.analyzerResults);
      const planResult = await attemptPlan(target.url, path.join(workspace, "targets", target.name));
      results.push({
        target: target.name,
        requestedUrl: target.url,
        purpose: target.purpose,
        resolvedRevision: inspected.source.resolvedRevision,
        archiveSha256: inspected.source.archiveSha256 ?? null,
        contentDigest: inspected.source.contentDigest,
        nativeAnalyzerStatus: inspected.analyzerResults.find((result) => result.providerId === "native-install-boundary")?.status ?? "NOT_RUN",
        optionalAnalyzerStatus: inspected.analyzerResults.filter((result) => result.providerId !== "native-install-boundary").map((result) => `${result.providerId}:${result.status}`),
        decision: evaluation.decision,
        blockingFindings: evaluation.blockingIds,
        warnings: evaluation.warningIds,
        installModelingStatus: planResult.status,
        operations: planResult.operations,
        planSeal: planResult.planSeal
      });
    }
    console.log(JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2));
    return 0;
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

async function attemptPlan(source: string, targetRoot: string): Promise<{ status: string; operations: number; planSeal: string | null }> {
  try {
    const plan = await createPlan(source, {
      target: "codex",
      targetRoot,
      scanners: []
    });
    return {
      status: plan.operations.length > 0 ? "SUPPORTED" : "NO_SUPPORTED_OPERATIONS",
      operations: plan.operations.length,
      planSeal: plan.seal
    };
  } catch (error) {
    return {
      status: `INCONCLUSIVE: ${(error as Error).message}`,
      operations: 0,
      planSeal: null
    };
  }
}

function currentGitCommit(): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return null;
  }
}

if (process.argv.includes("--pin-current")) {
  const commit = currentGitCommit();
  if (commit) {
    process.env.PREFLIGHTSEAL_SELF_DOGFOOD_REF = commit;
  }
}

process.exitCode = await main(process.argv.slice(2)).catch((error) => {
  console.error((error as Error).message);
  return 1;
});
