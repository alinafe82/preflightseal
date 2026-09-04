#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";

import { inspectSource, createPlan, readPlan } from "./plan.ts";
import { installPlan, readReceipt, rollbackReceipt, verifyReceipt } from "./install/transaction.ts";
import { defaultPolicy, evaluatePolicy } from "./policy.ts";

interface ParsedArgs {
  command?: string;
  positional: string[];
  flags: Map<string, string[]>;
}

async function main(argv: string[]): Promise<number> {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printHelp();
    return 0;
  }
  const parsed = parseArgs(argv);
  if (!parsed.command || parsed.command === "help" || parsed.flags.has("help") || parsed.flags.has("h")) {
    printHelp();
    return 0;
  }

  try {
    switch (parsed.command) {
      case "inspect":
        return await cmdInspect(parsed);
      case "plan":
        return await cmdPlan(parsed);
      case "install":
        return await cmdInstall(parsed);
      case "verify":
        return await cmdVerify(parsed);
      case "rollback":
        return await cmdRollback(parsed);
      case "explain":
        return await cmdExplain(parsed);
      default:
        throw new Error(`unknown command: ${parsed.command}`);
    }
  } catch (error) {
    const message = (error as Error).message;
    if (parsed.flags.has("json")) {
      console.log(JSON.stringify({ ok: false, error: message }, null, 2));
    } else {
      console.error(`preflightseal: ${message}`);
    }
    return 1;
  }
}

async function cmdInspect(parsed: ParsedArgs): Promise<number> {
  const source = requiredPositional(parsed, 0, "source");
  const scanners = flagList(parsed, "scanner");
  const result = await inspectSource(source, scanners);
  const evaluation = evaluatePolicy(defaultPolicy(), result.analyzerResults);
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify({ ...result, evaluation }, null, 2));
  } else {
    console.log(`source: ${result.source.canonical}`);
    console.log(`content digest: ${result.source.contentDigest}`);
    for (const analyzer of result.analyzerResults) {
      console.log(`${analyzer.providerId}: ${analyzer.status} (${analyzer.findings.length} findings)`);
    }
    console.log(`decision: ${evaluation.decision}`);
  }
  return statusCode(evaluation.decision);
}

async function cmdPlan(parsed: ParsedArgs): Promise<number> {
  const source = requiredPositional(parsed, 0, "source");
  const target = firstFlag(parsed, "target") || "codex";
  if (target !== "codex") {
    throw new Error(`unsupported target: ${target}`);
  }
  const targetRoot = firstFlag(parsed, "target-root") || process.cwd();
  const out = firstFlag(parsed, "out");
  const plan = await createPlan(source, {
    target,
    targetRoot,
    out,
    scanners: flagList(parsed, "scanner")
  });
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify(plan, null, 2));
  } else {
    console.log(`decision: ${plan.evaluation.decision}`);
    console.log(`seal: ${plan.seal}`);
    console.log(`operations: ${plan.operations.length}`);
    if (out) {
      console.log(`plan: ${path.resolve(out)}`);
    }
    if (plan.evaluation.warningIds.length > 0) {
      console.log(`warnings: ${plan.evaluation.warningIds.join(", ")}`);
    }
    if (plan.evaluation.blockingIds.length > 0) {
      console.log(`blocking: ${plan.evaluation.blockingIds.join(", ")}`);
    }
  }
  return statusCode(plan.evaluation.decision);
}

async function cmdInstall(parsed: ParsedArgs): Promise<number> {
  const planPath = requiredPositional(parsed, 0, "plan path");
  const plan = await readPlan(planPath);
  const { receiptPath } = await installPlan(plan, {
    acceptedWarnings: flagList(parsed, "accept-warning")
  });
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify({ ok: true, receiptPath }, null, 2));
  } else {
    console.log(`installed: ${receiptPath}`);
  }
  return 0;
}

async function cmdVerify(parsed: ParsedArgs): Promise<number> {
  const receipt = await readReceipt(requiredPositional(parsed, 0, "receipt path"));
  const result = await verifyReceipt(receipt);
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(result.ok ? "verify: OK" : `verify: CONFLICT ${result.conflicts.join(", ")}`);
  }
  return result.ok ? 0 : 5;
}

async function cmdRollback(parsed: ParsedArgs): Promise<number> {
  const receipt = await readReceipt(requiredPositional(parsed, 0, "receipt path"));
  const result = await rollbackReceipt(receipt);
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(result.ok ? "rollback: OK" : `rollback: CONFLICT ${result.conflicts.join(", ")}`);
  }
  return result.ok ? 0 : 5;
}

async function cmdExplain(parsed: ParsedArgs): Promise<number> {
  const filePath = requiredPositional(parsed, 0, "plan or receipt path");
  const data = JSON.parse(await readFile(filePath, "utf8"));
  if (parsed.flags.has("json")) {
    console.log(JSON.stringify(data, null, 2));
    return 0;
  }
  if (data.schemaVersion === "preflightseal.plan.v1") {
    console.log(`plan seal: ${data.seal}`);
    console.log(`decision: ${data.evaluation.decision}`);
    console.log(`target: ${data.target.runtime} at ${data.target.root}`);
    console.log(`operations: ${data.operations.length}`);
    console.log(`reasons: ${data.evaluation.reasons.join("; ")}`);
    return statusCode(data.evaluation.decision);
  }
  if (data.schemaVersion === "preflightseal.receipt.v1") {
    console.log(`receipt digest: ${data.receiptDigest}`);
    console.log(`plan seal: ${data.planSeal}`);
    console.log(`operations: ${data.operations.length}`);
    return 0;
  }
  throw new Error("unsupported file schema");
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags = new Map<string, string[]>();
  const positional: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const item = rest[index];
    if (item.startsWith("--")) {
      const raw = item.slice(2);
      const [key, inlineValue] = raw.split("=", 2);
      let value = inlineValue;
      if (value === undefined && rest[index + 1] && !rest[index + 1].startsWith("--")) {
        value = rest[index + 1];
        index += 1;
      }
      const values = flags.get(key) ?? [];
      values.push(value ?? "true");
      flags.set(key, values);
    } else {
      positional.push(item);
    }
  }
  return { command, positional, flags };
}

function firstFlag(parsed: ParsedArgs, name: string): string | undefined {
  return parsed.flags.get(name)?.[0];
}

function flagList(parsed: ParsedArgs, name: string): string[] {
  return (parsed.flags.get(name) ?? [])
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value && value !== "true");
}

function requiredPositional(parsed: ParsedArgs, index: number, label: string): string {
  const value = parsed.positional[index];
  if (!value) {
    throw new Error(`missing ${label}`);
  }
  return value;
}

function statusCode(decision: string): number {
  switch (decision) {
    case "ALLOW":
      return 0;
    case "WARN":
      return 2;
    case "BLOCK":
      return 3;
    case "INCONCLUSIVE":
      return 4;
    default:
      return 1;
  }
}

function printHelp(): void {
  console.log(`PreflightSeal - Inspect before install. Install only what you inspected.

Usage:
  preflightseal inspect <source> [--json] [--scanner snyk-agent-scan]
  preflightseal plan <source> --target codex --target-root <dir> --out plan.json [--json]
  preflightseal install <plan.json> [--accept-warning ID] [--json]
  preflightseal verify <receipt.json> [--json]
  preflightseal rollback <receipt.json> [--json]
  preflightseal explain <plan-or-receipt.json> [--json]

Decision states:
  ALLOW          install may proceed
  WARN           explicit scoped acceptance required
  BLOCK          installation refused
  INCONCLUSIVE   required evidence is missing or unsafe to interpret
`);
}

const exitCode = await main(process.argv.slice(2));
process.exitCode = exitCode;
