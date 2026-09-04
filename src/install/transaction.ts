import path from "node:path";
import { constants } from "node:fs";
import { copyFile, lstat, mkdir, open, readFile, realpath, rename, rm, unlink, writeFile } from "node:fs/promises";

import { createInventory } from "../inventory.ts";
import { computePlanSeal, verifyPlanSeal } from "../plan.ts";
import type { FileState, InstallReceipt, PreflightPlan, ReceiptOperation } from "../types.ts";
import { sha256File, sha256Json } from "../util/crypto.ts";
import { parseJsonObject } from "../util/json.ts";
import { ensureSafeParentDirectory, validateDestinationForWrite, validateRelativePath } from "../util/path.ts";

export interface InstallOptions {
  acceptedWarnings: string[];
}

export async function installPlan(plan: PreflightPlan, options: InstallOptions): Promise<{ receipt: InstallReceipt; receiptPath: string }> {
  verifyPlanSeal(plan);
  const sourceRoot = await realpath(plan.source.canonical);
  const targetRoot = await realpath(plan.target.root);

  if (plan.seal !== computePlanSeal(stripSeal(plan))) {
    throw new Error("plan seal is invalid");
  }

  if (plan.evaluation.decision === "BLOCK" || plan.evaluation.decision === "INCONCLUSIVE") {
    throw new Error(`installation refused: ${plan.evaluation.decision} (${plan.evaluation.reasons.join("; ")})`);
  }
  const accepted = new Set(options.acceptedWarnings);
  const missingWarnings = plan.evaluation.warningIds.filter((warningId) => !accepted.has(warningId));
  if (missingWarnings.length > 0) {
    throw new Error(`installation requires scoped acceptance: ${missingWarnings.join(", ")}`);
  }

  await revalidateSourceInventory(sourceRoot, plan);
  await revalidateSourceOperations(sourceRoot, plan);
  await revalidatePreconditions(targetRoot, plan);

  const receiptDir = path.join(targetRoot, ".preflightseal", "receipts");
  const backupDir = path.join(targetRoot, ".preflightseal", "backups", plan.seal);
  await mkdir(receiptDir, { recursive: true, mode: 0o700 });
  await mkdir(backupDir, { recursive: true, mode: 0o700 });

  const receiptOperations: ReceiptOperation[] = [];
  try {
    for (const [index, operation] of plan.operations.entries()) {
      const targetAbsolute = await validateDestinationForWrite(targetRoot, operation.targetPath);
      await ensureSafeParentDirectory(targetRoot, operation.targetPath);
      const before = await readFileState(targetRoot, operation.targetPath);
      let backupPath: string | undefined;
      if (before.kind === "file") {
        backupPath = path.join(".preflightseal", "backups", plan.seal, `${index}.bak`);
        await copyFile(targetAbsolute, path.join(targetRoot, backupPath), constants.COPYFILE_EXCL);
      }

      const sourceAbsolute = path.join(sourceRoot, validateRelativePath(operation.sourcePath));
      const tempPath = `${targetAbsolute}.preflightseal-${process.pid}-${index}.tmp`;
      const handle = await open(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, operation.mode || 0o644);
      try {
        await handle.writeFile(await readFile(sourceAbsolute));
      } finally {
        await handle.close();
      }
      await rename(tempPath, targetAbsolute);
      const after = await readFileState(targetRoot, operation.targetPath);
      if (after.kind !== "file" || after.sha256 !== operation.sha256) {
        throw new Error(`installed bytes mismatch for ${operation.targetPath}`);
      }
      receiptOperations.push({
        op: "write_file",
        targetPath: operation.targetPath,
        before,
        after,
        backupPath
      });
    }
  } catch (error) {
    await rollbackApplied(targetRoot, receiptOperations);
    throw error;
  }

  const receiptWithoutDigest = {
    schemaVersion: "preflightseal.receipt.v1" as const,
    planSeal: plan.seal,
    installedAt: new Date().toISOString(),
    target: plan.target,
    acceptedWarnings: [...options.acceptedWarnings].sort(),
    operations: receiptOperations
  };
  const receipt: InstallReceipt = {
    ...receiptWithoutDigest,
    receiptDigest: sha256Json(receiptWithoutDigest)
  };
  const receiptPath = path.join(receiptDir, `${plan.seal}.json`);
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  return { receipt, receiptPath };
}

export async function readReceipt(receiptPath: string): Promise<InstallReceipt> {
  const data = parseJsonObject(await readFile(receiptPath, "utf8"), "receipt");
  if (data.schemaVersion !== "preflightseal.receipt.v1") {
    throw new Error("unsupported receipt schema");
  }
  const receipt = data as unknown as InstallReceipt;
  verifyReceiptDigest(receipt);
  return receipt;
}

export async function verifyReceipt(receipt: InstallReceipt): Promise<{ ok: boolean; conflicts: string[] }> {
  verifyReceiptDigest(receipt);
  const targetRoot = await realpath(receipt.target.root);
  const conflicts: string[] = [];
  for (const operation of receipt.operations) {
    try {
      const current = await readFileState(targetRoot, operation.targetPath);
      if (!sameState(current, operation.after)) {
        conflicts.push(operation.targetPath);
      }
    } catch {
      conflicts.push(operation.targetPath);
    }
  }
  return { ok: conflicts.length === 0, conflicts };
}

export async function rollbackReceipt(receipt: InstallReceipt): Promise<{ ok: boolean; conflicts: string[] }> {
  const verification = await verifyReceipt(receipt);
  if (!verification.ok) {
    return verification;
  }
  const targetRoot = await realpath(receipt.target.root);
  await rollbackApplied(targetRoot, [...receipt.operations].reverse());
  return { ok: true, conflicts: [] };
}

async function revalidateSourceOperations(sourceRoot: string, plan: PreflightPlan): Promise<void> {
  for (const operation of plan.operations) {
    const absolute = path.join(sourceRoot, validateRelativePath(operation.sourcePath));
    const currentSha = await sha256File(absolute);
    if (currentSha !== operation.sha256) {
      throw new Error(`source changed after planning: ${operation.sourcePath}`);
    }
  }
}

async function revalidateSourceInventory(sourceRoot: string, plan: PreflightPlan): Promise<void> {
  const inventory = await createInventory(sourceRoot);
  if (inventory.digest !== plan.inventoryDigest) {
    throw new Error(`source changed after planning: expected inventory ${plan.inventoryDigest}, got ${inventory.digest}`);
  }
}

async function revalidatePreconditions(targetRoot: string, plan: PreflightPlan): Promise<void> {
  for (const precondition of plan.preconditions) {
    const current = await readFileState(targetRoot, precondition.targetPath);
    if (!sameState(current, precondition.expected)) {
      throw new Error(`target changed after planning: ${precondition.targetPath}`);
    }
  }
}

async function readFileState(targetRoot: string, targetPath: string): Promise<FileState> {
  const absolute = await validateDestinationForWrite(targetRoot, targetPath);
  try {
    const stat = await lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1) {
      throw new Error(`unsupported file state: ${targetPath}`);
    }
    return {
      kind: "file",
      sha256: await sha256File(absolute),
      size: stat.size,
      mode: stat.mode & 0o777
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { kind: "absent" };
    }
    throw error;
  }
}

async function rollbackApplied(targetRoot: string, operations: ReceiptOperation[]): Promise<void> {
  for (const operation of operations) {
    const targetAbsolute = path.join(targetRoot, validateRelativePath(operation.targetPath));
    const current = await readFileState(targetRoot, operation.targetPath);
    if (!sameState(current, operation.after)) {
      throw new Error(`ROLLBACK_CONFLICT: ${operation.targetPath}`);
    }
    if (operation.before.kind === "absent") {
      await unlink(targetAbsolute).catch((error) => {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      });
    } else {
      if (!operation.backupPath) {
        throw new Error(`missing backup for ${operation.targetPath}`);
      }
      await validateDestinationForWrite(targetRoot, operation.targetPath);
      await copyFile(path.join(targetRoot, validateRelativePath(operation.backupPath)), targetAbsolute);
    }
  }
  await rm(path.join(targetRoot, ".preflightseal"), { recursive: true, force: true }).catch(() => undefined);
}

function sameState(left: FileState, right: FileState): boolean {
  if (left.kind !== right.kind) {
    return false;
  }
  if (left.kind === "absent" || right.kind === "absent") {
    return true;
  }
  return left.sha256 === right.sha256 && left.size === right.size;
}

function verifyReceiptDigest(receipt: InstallReceipt): void {
  const { receiptDigest, ...withoutDigest } = receipt;
  const expected = sha256Json(withoutDigest);
  if (receiptDigest !== expected) {
    throw new Error(`receipt digest mismatch: expected ${expected}, got ${receiptDigest}`);
  }
}

function stripSeal(plan: PreflightPlan): Omit<PreflightPlan, "seal"> {
  const { seal: _seal, ...withoutSeal } = plan;
  return withoutSeal;
}
