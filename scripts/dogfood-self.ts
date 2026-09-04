#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createPlan, inspectSource } from "../src/plan.ts";
import { defaultPolicy, evaluatePolicy } from "../src/policy.ts";
import type { PreflightPlan } from "../src/types.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_PUBLIC_URL = "https://github.com/alinafe82/preflightseal";

type InspectedSource = Awaited<ReturnType<typeof inspectSource>>;

interface DogfoodAttempt {
  inspected: InspectedSource;
  plan: Pick<PreflightPlan, "operations" | "seal">;
}

interface DogfoodMetadata {
  sourceMode: "github" | "local-fallback";
  requestedUrl: string;
  publicSourceAvailable: boolean;
  fallbackReason?: string;
  fallbackSource?: string;
  pinnedRevision?: string | null;
}

interface SelfDogfoodOptions {
  attemptDogfood?: (sourceInput: string, targetRoot: string) => Promise<DogfoodAttempt>;
  currentRevision?: () => string | null;
  env?: NodeJS.ProcessEnv;
  publicUrl?: string;
  root?: string;
  writeOutput?: (output: string) => void;
}

export async function runSelfDogfood(argv: string[], options: SelfDogfoodOptions = {}): Promise<number> {
  const env = options.env ?? process.env;
  const root = options.root ?? ROOT;
  const publicUrl = env.PREFLIGHTSEAL_SELF_DOGFOOD_URL || options.publicUrl || DEFAULT_PUBLIC_URL;
  const pinCurrent = argv.includes("--pin-current") || env.PREFLIGHTSEAL_DOGFOOD_PIN_CURRENT === "1" || env.CI === "true";
  const ref = env.PREFLIGHTSEAL_SELF_DOGFOOD_REF || (pinCurrent ? (options.currentRevision ?? (() => currentGitCommit(root)))() : null);
  const requestedUrl = ref ? `${publicUrl}#${ref}` : publicUrl;
  const workspace = await mkdtemp(path.join(os.tmpdir(), "preflightseal-self-dogfood-"));
  const previousCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const attemptDogfood = options.attemptDogfood ?? defaultDogfoodAttempt;
  const writeOutput = options.writeOutput ?? ((output) => console.log(output));
  process.env.PREFLIGHTSEAL_CACHE_DIR = path.join(workspace, "cache");

  try {
    const result = await summarizeDogfoodAttempt(attemptDogfood, requestedUrl, path.join(workspace, "fake-codex-target"), {
      sourceMode: "github",
      requestedUrl,
      publicSourceAvailable: true,
      pinnedRevision: ref
    });
    writeOutput(JSON.stringify(result, null, 2));
    return 0;
  } catch (error) {
    if (!shouldUseLocalSelfDogfoodFallback(error, env)) {
      throw error;
    }
    const result = await summarizeDogfoodAttempt(attemptDogfood, root, path.join(workspace, "fake-codex-target"), {
      sourceMode: "local-fallback",
      requestedUrl,
      publicSourceAvailable: false,
      fallbackReason: errorMessage(error),
      fallbackSource: root,
      pinnedRevision: ref
    });
    writeOutput(JSON.stringify(result, null, 2));
    return 0;
  } finally {
    if (previousCacheDir === undefined) {
      delete process.env.PREFLIGHTSEAL_CACHE_DIR;
    } else {
      process.env.PREFLIGHTSEAL_CACHE_DIR = previousCacheDir;
    }
    await rm(workspace, { recursive: true, force: true });
  }
}

export function shouldUseLocalSelfDogfoodFallback(error: unknown, env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.PREFLIGHTSEAL_SELF_DOGFOOD_DISABLE_LOCAL_FALLBACK === "1") {
    return false;
  }
  if (env.CI === "true" && env.PREFLIGHTSEAL_SELF_DOGFOOD_ALLOW_LOCAL_FALLBACK !== "1") {
    return false;
  }
  return isPublicSourceUnavailable(errorMessage(error));
}

async function defaultDogfoodAttempt(sourceInput: string, targetRoot: string): Promise<DogfoodAttempt> {
  const inspected = await inspectSource(sourceInput);
  const plan = await createPlan(sourceInput, {
    target: "codex",
    targetRoot,
    scanners: []
  });
  return { inspected, plan };
}

async function summarizeDogfoodAttempt(
  attemptDogfood: (sourceInput: string, targetRoot: string) => Promise<DogfoodAttempt>,
  sourceInput: string,
  targetRoot: string,
  metadata: DogfoodMetadata
): Promise<Record<string, unknown>> {
  const { inspected, plan } = await attemptDogfood(sourceInput, targetRoot);
  const evaluation = evaluatePolicy(defaultPolicy(), inspected.analyzerResults);
  return {
    ...metadata,
    resolvedRevision: inspected.source.resolvedRevision,
    archiveSha256: inspected.source.archiveSha256 ?? null,
    contentDigest: inspected.source.contentDigest,
    nativeAnalyzerStatus: inspected.analyzerResults.find((analyzer) => analyzer.providerId === "native-install-boundary")?.status ?? "NOT_RUN",
    externalAnalyzerStatus: inspected.analyzerResults.filter((analyzer) => analyzer.providerId !== "native-install-boundary").map((analyzer) => `${analyzer.providerId}:${analyzer.status}`),
    policyDecision: evaluation.decision,
    installModelingStatus: plan.operations.length > 0 ? "SUPPORTED" : "NO_SUPPORTED_OPERATIONS",
    operations: plan.operations.length,
    planSeal: plan.seal
  };
}

function currentGitCommit(root: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return null;
  }
}

function isPublicSourceUnavailable(message: string): boolean {
  return /GitHub API request failed: HTTP 404/.test(message) || /fetch failed/i.test(message);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMainModule(): boolean {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
}

if (isMainModule()) {
  process.exitCode = await runSelfDogfood(process.argv.slice(2)).catch((error) => {
    console.error(errorMessage(error));
    return 1;
  });
}
