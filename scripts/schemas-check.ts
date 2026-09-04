#!/usr/bin/env node
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runNativeAnalyzer } from "../src/analyzers/native.ts";
import { createInventory } from "../src/inventory.ts";
import { createPlan } from "../src/plan.ts";
import { installPlan, rollbackReceipt, verifyReceipt } from "../src/install/transaction.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_DIR = path.join(ROOT, "schemas");

type JsonSchema = Record<string, unknown>;

interface SchemaSet {
  byFile: Map<string, JsonSchema>;
}

async function main(): Promise<number> {
  const schemas = await loadSchemas();
  const workspace = await mkdtemp(path.join(os.tmpdir(), "preflightseal-schema-check-"));
  const cacheDir = path.join(workspace, "cache");
  process.env.PREFLIGHTSEAL_CACHE_DIR = cacheDir;

  try {
    const source = path.join(workspace, "source");
    const target = path.join(workspace, "target");
    await mkdir(path.join(source, "skills", "demo"), { recursive: true, mode: 0o755 });
    await mkdir(target, { recursive: true, mode: 0o755 });
    await writeFile(path.join(source, "AGENTS.md"), "Use concise, local-only instructions.\n", { mode: 0o644 });
    await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# Demo skill\n\nNo commands are executed during inspection.\n", { mode: 0o644 });

    const inventory = await createInventory(source);
    const analyzer = await runNativeAnalyzer(source, inventory);
    const finding = analyzer.findings[0];
    if (!finding) {
      throw new Error("schema check fixture did not generate an analyzer finding");
    }

    const plan = await createPlan(source, {
      target: "codex",
      targetRoot: target,
      scanners: []
    });
    const { receipt } = await installPlan(plan, {
      acceptedWarningFingerprints: plan.warningFingerprints
    });
    const verification = await verifyReceipt(receipt);
    const rollback = await rollbackReceipt(receipt);

    validateFileSchema(schemas, "source-identity.v1.schema.json", plan.source, "plan.source");
    validateFileSchema(schemas, "finding.v1.schema.json", finding, "analyzer.findings[0]");
    validateFileSchema(schemas, "analyzer-result.v1.schema.json", analyzer, "analyzer");
    validateFileSchema(schemas, "policy-evaluation.v1.schema.json", plan.evaluation, "plan.evaluation");
    validateFileSchema(schemas, "install-operation.v1.schema.json", plan.operations[0], "plan.operations[0]");
    validateFileSchema(schemas, "preflight-plan.v1.schema.json", plan, "plan");
    validateFileSchema(schemas, "install-receipt.v1.schema.json", receipt, "receipt");
    validateFileSchema(schemas, "verification-result.v1.schema.json", verification, "verification");
    validateFileSchema(schemas, "rollback-result.v1.schema.json", rollback, "rollback");

    console.log("schemas: validated real plan, receipt, verification result, rollback result, analyzer result, and finding");
    return 0;
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

async function loadSchemas(): Promise<SchemaSet> {
  const byFile = new Map<string, JsonSchema>();
  const files = (await readdir(SCHEMA_DIR)).filter((file) => file.endsWith(".schema.json")).sort();
  for (const file of files) {
    const schema = JSON.parse(await readFile(path.join(SCHEMA_DIR, file), "utf8")) as JsonSchema;
    if (typeof schema.$id !== "string" || !schema.$id.startsWith("https://preflightseal.dev/schemas/")) {
      throw new Error(`schema ${file} has missing or unstable $id`);
    }
    byFile.set(file, schema);
  }
  return { byFile };
}

function validateFileSchema(schemas: SchemaSet, file: string, value: unknown, label: string): void {
  const schema = schemas.byFile.get(file);
  if (!schema) {
    throw new Error(`schema not found: ${file}`);
  }
  validateSchema(schemas, schema, JSON.parse(JSON.stringify(value)), label, schema);
}

function validateSchema(schemas: SchemaSet, schema: JsonSchema, value: unknown, label: string, rootSchema: JsonSchema): void {
  if (typeof schema.$ref === "string") {
    validateSchema(schemas, resolveRef(schemas, schema.$ref, rootSchema), value, label, rootSchema);
    return;
  }

  if (Object.hasOwn(schema, "const") && value !== schema.const) {
    throw new Error(`${label}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    throw new Error(`${label}: expected one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(value)}`);
  }

  if (typeof schema.type === "string") {
    validateType(schema.type, value, label);
  }

  if (schema.type === "string" && typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      throw new Error(`${label}: string shorter than ${schema.minLength}`);
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) {
      throw new Error(`${label}: string does not match ${schema.pattern}: ${value}`);
    }
    if (schema.format === "date-time" && Number.isNaN(Date.parse(value))) {
      throw new Error(`${label}: invalid date-time: ${value}`);
    }
  }

  if (schema.type === "integer" && typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`${label}: expected integer`);
    }
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      throw new Error(`${label}: expected minimum ${schema.minimum}`);
    }
  }

  if (schema.type === "array" && Array.isArray(value)) {
    const itemSchema = schema.items as JsonSchema | undefined;
    if (itemSchema) {
      value.forEach((item, index) => validateSchema(schemas, itemSchema, item, `${label}[${index}]`, rootSchema));
    }
  }

  if (schema.type === "object" && isRecord(value)) {
    const required = Array.isArray(schema.required) ? schema.required as string[] : [];
    for (const key of required) {
      if (!Object.hasOwn(value, key)) {
        throw new Error(`${label}: missing required property ${key}`);
      }
    }

    const properties = isRecord(schema.properties) ? schema.properties : {};
    for (const [key, propertySchema] of Object.entries(properties)) {
      if (Object.hasOwn(value, key)) {
        validateSchema(schemas, propertySchema as JsonSchema, value[key], `${label}.${key}`, rootSchema);
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) {
          throw new Error(`${label}: unexpected property ${key}`);
        }
      }
    }
  }
}

function resolveRef(schemas: SchemaSet, ref: string, rootSchema: JsonSchema): JsonSchema {
  if (ref.startsWith("#/")) {
    return resolveFragment(rootSchema, ref);
  }
  const [file, fragment] = ref.split("#", 2);
  const schema = schemas.byFile.get(file);
  if (!schema) {
    throw new Error(`schema ref not found: ${ref}`);
  }
  return fragment ? resolveFragment(schema, `#${fragment}`) : schema;
}

function resolveFragment(schema: JsonSchema, fragment: string): JsonSchema {
  const parts = fragment.replace(/^#\//, "").split("/").filter(Boolean);
  let current: unknown = schema;
  for (const part of parts) {
    if (!isRecord(current) || !Object.hasOwn(current, part)) {
      throw new Error(`schema fragment not found: ${fragment}`);
    }
    current = current[part];
  }
  if (!isRecord(current)) {
    throw new Error(`schema fragment is not an object: ${fragment}`);
  }
  return current;
}

function validateType(type: string, value: unknown, label: string): void {
  switch (type) {
    case "object":
      if (!isRecord(value)) {
        throw new Error(`${label}: expected object`);
      }
      return;
    case "array":
      if (!Array.isArray(value)) {
        throw new Error(`${label}: expected array`);
      }
      return;
    case "string":
      if (typeof value !== "string") {
        throw new Error(`${label}: expected string`);
      }
      return;
    case "boolean":
      if (typeof value !== "boolean") {
        throw new Error(`${label}: expected boolean`);
      }
      return;
    case "integer":
      if (typeof value !== "number" || !Number.isInteger(value)) {
        throw new Error(`${label}: expected integer`);
      }
      return;
    case "number":
      if (typeof value !== "number") {
        throw new Error(`${label}: expected number`);
      }
      return;
    default:
      throw new Error(`${label}: unsupported schema type ${type}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

process.exitCode = await main().catch((error) => {
  console.error((error as Error).message);
  return 1;
});
