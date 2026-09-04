import path from "node:path";
import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { copyFile, lstat, mkdir, open, readFile, realpath, rename, rm, stat, unlink } from "node:fs/promises";

import { resolveCachedGitHubSourceRoot } from "../acquire/github.ts";
import { resolveCachedLocalSourceRoot } from "../acquire/local.ts";
import { createInventory } from "../inventory.ts";
import { verifyPlanSeal } from "../plan.ts";
import { assertFindingFingerprint } from "../findings.ts";
import { SCHEMA_VERSION, assertSupportedSchemaVersion } from "../schema.ts";
import type { FileState, InstallOperation, InstallReceipt, PreflightPlan, ReceiptOperation, RollbackResult, TargetStatePrecondition, VerificationResult } from "../types.ts";
import { sha256Bytes, sha256File, sha256Json } from "../util/crypto.ts";
import { parseJsonObject } from "../util/json.ts";
import { ensureSafeParentDirectory, validateDestinationForWrite, validateRelativePath } from "../util/path.ts";

export interface InstallOptions {
  acceptedWarningFingerprints: string[];
}

interface TransactionJournal {
  schemaVersion: typeof SCHEMA_VERSION.TRANSACTION;
  transactionId: string;
  planSeal: string;
  status: "PREPARED" | "APPLYING" | "COMMITTED" | "ROLLED_BACK";
  appliedOperations: string[];
  updatedAt: string;
  error?: string;
}

export async function installPlan(plan: PreflightPlan, options: InstallOptions): Promise<{ receipt: InstallReceipt; receiptPath: string }> {
  verifyPlanSeal(plan);
  const acceptedFingerprints = validateInstallAuthorization(plan, options);
  validatePlanOperationSet(plan);

  const targetRoot = await realpath(plan.target.root);
  const releaseLock = await acquireTargetLock(targetRoot);
  try {
    const sourceRoot = await resolvePlanSourceRoot(plan);

    await revalidateSourceInventory(sourceRoot, plan);
    await revalidateSourceOperations(sourceRoot, plan);
    await revalidatePreconditions(targetRoot, plan);

    const transactionId = randomUUID();
    const receiptId = randomUUID();
    const receiptDir = path.join(targetRoot, ".preflightseal", "receipts");
    const transactionDir = path.join(targetRoot, ".preflightseal", "transactions", transactionId);
    const backupDir = path.join(targetRoot, ".preflightseal", "backups", transactionId);
    await mkdir(receiptDir, { recursive: true, mode: 0o700 });
    await mkdir(transactionDir, { recursive: true, mode: 0o700 });
    await mkdir(backupDir, { recursive: true, mode: 0o700 });

    const journalPath = path.join(transactionDir, "journal.json");
    const receiptOperations: ReceiptOperation[] = [];
    await writeJournal(journalPath, {
      schemaVersion: SCHEMA_VERSION.TRANSACTION,
      transactionId,
      planSeal: plan.seal,
      status: "PREPARED",
      appliedOperations: [],
      updatedAt: new Date().toISOString()
    });

    const preconditions = preconditionsByTargetPath(plan.preconditions);
    try {
      for (const [index, operation] of plan.operations.entries()) {
        const expected = preconditions.get(validateRelativePath(operation.targetPath)) as TargetStatePrecondition["expected"];
        const receiptOperation = await applyWriteFileOperation({
          sourceRoot,
          targetRoot,
          transactionId,
          operation,
          operationIndex: index,
          expected
        });
        receiptOperations.push(receiptOperation);
        await writeJournal(journalPath, {
          schemaVersion: SCHEMA_VERSION.TRANSACTION,
          transactionId,
          planSeal: plan.seal,
          status: "APPLYING",
          appliedOperations: receiptOperations.map((applied) => applied.targetPath),
          updatedAt: new Date().toISOString()
        });
      }
    } catch (error) {
      try {
        await rollbackApplied(targetRoot, [...receiptOperations].reverse());
        await writeJournal(journalPath, {
          schemaVersion: SCHEMA_VERSION.TRANSACTION,
          transactionId,
          planSeal: plan.seal,
          status: "ROLLED_BACK",
          appliedOperations: receiptOperations.map((applied) => applied.targetPath),
          updatedAt: new Date().toISOString(),
          error: String((error as Error).message)
        });
      } catch (rollbackError) {
        throw new Error(`${(error as Error).message}; rollback failed: ${(rollbackError as Error).message}`);
      }
      throw error;
    }

    await writeJournal(journalPath, {
      schemaVersion: SCHEMA_VERSION.TRANSACTION,
      transactionId,
      planSeal: plan.seal,
      status: "COMMITTED",
      appliedOperations: receiptOperations.map((applied) => applied.targetPath),
      updatedAt: new Date().toISOString()
    });

    const receiptWithoutDigest = {
      schemaVersion: SCHEMA_VERSION.RECEIPT,
      receiptId,
      transactionId,
      planSeal: plan.seal,
      installedAt: new Date().toISOString(),
      target: plan.target,
      acceptedWarningFingerprints: acceptedFingerprints,
      operations: receiptOperations
    };
    const receipt: InstallReceipt = {
      ...receiptWithoutDigest,
      receiptDigest: sha256Json(receiptWithoutDigest)
    };
    const receiptPath = path.join(receiptDir, `${receiptId}.json`);
    await writeJsonDurable(receiptPath, receipt, 0o600);
    return { receipt, receiptPath };
  } finally {
    await releaseLock();
  }
}

export async function readReceipt(receiptPath: string): Promise<InstallReceipt> {
  const data = parseJsonObject(await readFile(receiptPath, "utf8"), "receipt");
  assertSupportedSchemaVersion(data.schemaVersion, SCHEMA_VERSION.RECEIPT, "receipt");
  const receipt = data as unknown as InstallReceipt;
  verifyReceiptDigest(receipt);
  return receipt;
}

function normalizeAcceptedWarningFingerprints(options: InstallOptions): string[] {
  const values = options.acceptedWarningFingerprints ?? [];
  const fingerprints = [...new Set(values)].sort();
  for (const fingerprint of fingerprints) {
    assertFindingFingerprint(fingerprint);
  }
  return fingerprints;
}

function validateInstallAuthorization(plan: PreflightPlan, options: InstallOptions): string[] {
  if (plan.evaluation.decision === "BLOCK" || plan.evaluation.decision === "INCONCLUSIVE") {
    throw new Error(`PFS_INSTALL_UNSUPPORTED: installation refused: ${plan.evaluation.decision} (${plan.evaluation.reasons.join("; ")})`);
  }

  const acceptedFingerprints = normalizeAcceptedWarningFingerprints(options);
  const accepted = new Set(acceptedFingerprints);
  const planWarnings = new Set(plan.warningFingerprints);
  const unknownAccepted = acceptedFingerprints.filter((fingerprint) => !planWarnings.has(fingerprint));
  if (unknownAccepted.length > 0) {
    throw new Error(`PFS_INSTALL_UNSUPPORTED: accepted warning fingerprint is not present in this plan: ${unknownAccepted.join(", ")}`);
  }
  const missingWarnings = plan.warningFingerprints.filter((fingerprint) => !accepted.has(fingerprint));
  if (missingWarnings.length > 0) {
    throw new Error(`PFS_INSTALL_UNSUPPORTED: installation requires finding fingerprint acceptance: ${missingWarnings.join(", ")}`);
  }
  return acceptedFingerprints;
}

function validatePlanOperationSet(plan: PreflightPlan): void {
  const preconditions = new Set<string>();
  for (const precondition of plan.preconditions) {
    const targetPath = validateRelativePath(precondition.targetPath);
    if (preconditions.has(targetPath)) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: duplicate target precondition: ${targetPath}`);
    }
    preconditions.add(targetPath);
  }

  const targets = new Set<string>();
  for (const operation of plan.operations) {
    if (operation.op !== "write_file") {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: unsupported install operation: ${String(operation.op)}`);
    }
    validateRelativePath(operation.sourcePath);
    const targetPath = validateRelativePath(operation.targetPath);
    if (targets.has(targetPath)) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: duplicate operation target path: ${targetPath}`);
    }
    targets.add(targetPath);
    if (!/^[a-f0-9]{64}$/i.test(operation.sha256)) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: invalid operation digest for ${targetPath}`);
    }
    if (!Number.isSafeInteger(operation.size) || operation.size < 0) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: invalid operation size for ${targetPath}`);
    }
    if (!Number.isSafeInteger(operation.mode) || operation.mode < 0 || operation.mode > 0o777) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: invalid operation mode for ${targetPath}`);
    }
    if (!preconditions.has(targetPath)) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: missing target precondition for ${targetPath}`);
    }
  }

  for (const targetPath of preconditions) {
    if (!targets.has(targetPath)) {
      throw new Error(`PFS_INSTALL_UNSUPPORTED: precondition has no matching operation: ${targetPath}`);
    }
  }
}

export async function verifyReceipt(receipt: InstallReceipt): Promise<VerificationResult> {
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
  return verificationResult(receipt, conflicts.length === 0, conflicts);
}

export async function rollbackReceipt(receipt: InstallReceipt): Promise<RollbackResult> {
  verifyReceiptDigest(receipt);
  const targetRoot = await realpath(receipt.target.root);
  const releaseLock = await acquireTargetLock(targetRoot);
  try {
    const operationStates: Array<{ operation: ReceiptOperation; needsRollback: boolean }> = [];
    const conflicts: string[] = [];

    for (const operation of receipt.operations) {
      let current: FileState;
      try {
        current = await readFileState(targetRoot, operation.targetPath);
      } catch {
        conflicts.push(operation.targetPath);
        continue;
      }

      if (sameState(current, operation.before)) {
        operationStates.push({ operation, needsRollback: false });
        continue;
      }
      if (!sameState(current, operation.after)) {
        conflicts.push(operation.targetPath);
        continue;
      }
      if (operation.before.kind === "file" && (!operation.backupPath || !await fileExists(path.join(targetRoot, validateRelativePath(operation.backupPath))))) {
        conflicts.push(operation.targetPath);
        continue;
      }
      operationStates.push({ operation, needsRollback: true });
    }

    if (conflicts.length > 0) {
      return rollbackResult(receipt, false, conflicts);
    }

    for (const { operation, needsRollback } of [...operationStates].reverse()) {
      if (needsRollback) {
        await restoreOperation(targetRoot, operation, true);
      }
    }
    const result = rollbackResult(receipt, true, []);
    await writeRollbackEvidence(targetRoot, result);
    await cleanupRolledBackTransactionState(targetRoot, receipt);
    return result;
  } finally {
    await releaseLock();
  }
}

async function resolvePlanSourceRoot(plan: PreflightPlan): Promise<string> {
  if (plan.source.kind === "github") {
    return await resolveCachedGitHubSourceRoot(plan.source);
  }
  return await resolveCachedLocalSourceRoot(plan.source);
}

async function applyWriteFileOperation(input: {
  sourceRoot: string;
  targetRoot: string;
  transactionId: string;
  operation: InstallOperation;
  operationIndex: number;
  expected: TargetStatePrecondition["expected"];
}): Promise<ReceiptOperation> {
  const { sourceRoot, targetRoot, transactionId, operation, operationIndex, expected } = input;
  const targetAbsolute = await validateDestinationForWrite(targetRoot, operation.targetPath);
  await ensureSafeParentDirectory(targetRoot, operation.targetPath);
  const before = await readFileState(targetRoot, operation.targetPath);
  if (!sameState(before, expected)) {
    throw new Error(`PFS_TARGET_CHANGED: target changed after planning: ${operation.targetPath}`);
  }

  let backupPath: string | undefined;
  if (before.kind === "file") {
    backupPath = `.preflightseal/backups/${transactionId}/${operationIndex}.bak`;
    await copyFile(targetAbsolute, path.join(targetRoot, backupPath), constants.COPYFILE_EXCL);
    await syncParentDirectory(path.dirname(path.join(targetRoot, backupPath)));
  }

  const sourceAbsolute = path.join(sourceRoot, validateRelativePath(operation.sourcePath));
  const sourceBytes = await readFile(sourceAbsolute);
  if (sha256Bytes(sourceBytes) !== operation.sha256) {
    throw new Error(`PFS_SOURCE_CHANGED: source changed after planning: ${operation.sourcePath}`);
  }

  const tempPath = `${targetAbsolute}.preflightseal-${process.pid}-${operationIndex}-${randomUUID()}.tmp`;
  let renamed = false;
  try {
    const handle = await open(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      operation.mode || 0o644
    );
    try {
      await handle.writeFile(sourceBytes);
      await syncHandle(handle);
    } finally {
      await handle.close();
    }

    const beforeRename = await readFileState(targetRoot, operation.targetPath);
    if (!sameState(beforeRename, expected)) {
      throw new Error(`PFS_TARGET_CHANGED: target changed during installation: ${operation.targetPath}`);
    }
    await validateDestinationForWrite(targetRoot, operation.targetPath);
    const parent = await ensureSafeParentDirectory(targetRoot, operation.targetPath);
    await rename(tempPath, targetAbsolute);
    renamed = true;
    await syncParentDirectory(parent);
  } catch (error) {
    if (!renamed) {
      await unlink(tempPath).catch((unlinkError) => {
        if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw unlinkError;
        }
      });
    }
    throw error;
  }

  const after = await readFileState(targetRoot, operation.targetPath);
  const receiptOperation: ReceiptOperation = {
    op: "write_file",
    targetPath: operation.targetPath,
    before,
    after,
    backupPath
  };
  if (after.kind !== "file" || after.sha256 !== operation.sha256 || after.size !== operation.size) {
    await rollbackApplied(targetRoot, [receiptOperation]);
    throw new Error(`PFS_TARGET_CHANGED: installed bytes mismatch for ${operation.targetPath}`);
  }
  return receiptOperation;
}

async function revalidateSourceOperations(sourceRoot: string, plan: PreflightPlan): Promise<void> {
  for (const operation of plan.operations) {
    const absolute = path.join(sourceRoot, validateRelativePath(operation.sourcePath));
    const currentSha = await sha256File(absolute);
    if (currentSha !== operation.sha256) {
      throw new Error(`PFS_SOURCE_CHANGED: source changed after planning: ${operation.sourcePath}`);
    }
  }
}

async function revalidateSourceInventory(sourceRoot: string, plan: PreflightPlan): Promise<void> {
  const inventory = await createInventory(sourceRoot);
  if (inventory.digest !== plan.inventoryDigest) {
    throw new Error(`PFS_SOURCE_CHANGED: source changed after planning: expected inventory ${plan.inventoryDigest}, got ${inventory.digest}`);
  }
}

async function revalidatePreconditions(targetRoot: string, plan: PreflightPlan): Promise<void> {
  for (const precondition of plan.preconditions) {
    const current = await readFileState(targetRoot, precondition.targetPath);
    if (!sameState(current, precondition.expected)) {
      throw new Error(`PFS_TARGET_CHANGED: target changed after planning: ${precondition.targetPath}`);
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
    const current = await readFileState(targetRoot, operation.targetPath);
    if (!sameState(current, operation.after)) {
      throw new Error(`PFS_ROLLBACK_CONFLICT: ${operation.targetPath}`);
    }
    await restoreOperation(targetRoot, operation, false);
  }
}

async function restoreOperation(targetRoot: string, operation: ReceiptOperation, allowAlreadyRestored: boolean): Promise<void> {
  const current = await readFileState(targetRoot, operation.targetPath);
  if (allowAlreadyRestored && sameState(current, operation.before)) {
    return;
  }
  if (operation.before.kind === "absent") {
    const targetAbsolute = await validateDestinationForWrite(targetRoot, operation.targetPath);
    await unlink(targetAbsolute).catch((error) => {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    });
    await syncParentDirectory(await ensureSafeParentDirectory(targetRoot, operation.targetPath));
    return;
  }

  if (!operation.backupPath) {
    throw new Error(`PFS_ROLLBACK_CONFLICT: missing backup for ${operation.targetPath}`);
  }
  const backupAbsolute = path.join(targetRoot, validateRelativePath(operation.backupPath));
  const backupBytes = await readFile(backupAbsolute);
  if (sha256Bytes(backupBytes) !== operation.before.sha256) {
    throw new Error(`PFS_ROLLBACK_CONFLICT: backup digest mismatch for ${operation.targetPath}`);
  }
  await replaceFileAtomically(targetRoot, operation.targetPath, backupBytes, operation.before.mode);
  const restored = await readFileState(targetRoot, operation.targetPath);
  if (!sameState(restored, operation.before)) {
    throw new Error(`PFS_ROLLBACK_CONFLICT: restored bytes mismatch for ${operation.targetPath}`);
  }
}

function sameState(left: FileState, right: FileState): boolean {
  if (left.kind !== right.kind) {
    return false;
  }
  if (left.kind === "absent" || right.kind === "absent") {
    return true;
  }
  return left.sha256 === right.sha256 && left.size === right.size && left.mode === right.mode;
}

function verifyReceiptDigest(receipt: InstallReceipt): void {
  const { receiptDigest, ...withoutDigest } = receipt;
  const expected = sha256Json(withoutDigest);
  if (receiptDigest !== expected) {
    throw new Error(`receipt digest mismatch: expected ${expected}, got ${receiptDigest}`);
  }
}

function preconditionsByTargetPath(preconditions: TargetStatePrecondition[]): Map<string, TargetStatePrecondition["expected"]> {
  return new Map(preconditions.map((precondition) => [validateRelativePath(precondition.targetPath), precondition.expected]));
}

async function acquireTargetLock(targetRoot: string): Promise<() => Promise<void>> {
  const locksDir = path.join(targetRoot, ".preflightseal", "locks");
  await mkdir(locksDir, { recursive: true, mode: 0o700 });
  const lockDir = path.join(locksDir, `${sha256Bytes(targetRoot).slice(0, 32)}.lock`);
  try {
    await mkdir(lockDir, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("PFS_TARGET_LOCKED: target is already locked by another transaction");
    }
    throw error;
  }

  try {
    await writeJsonDurable(path.join(lockDir, "owner.json"), {
      schemaVersion: "preflightseal.lock.v1",
      pid: process.pid,
      targetRoot,
      acquiredAt: new Date().toISOString()
    }, 0o600);
  } catch (error) {
    await rm(lockDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }

  return async () => {
    await rm(lockDir, { recursive: true, force: true }).catch(() => undefined);
  };
}

async function replaceFileAtomically(targetRoot: string, targetPath: string, bytes: Buffer, mode: number): Promise<void> {
  const targetAbsolute = await validateDestinationForWrite(targetRoot, targetPath);
  const parent = await ensureSafeParentDirectory(targetRoot, targetPath);
  const tempPath = `${targetAbsolute}.preflightseal-${process.pid}-${randomUUID()}.tmp`;
  let renamed = false;
  try {
    const handle = await open(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      mode || 0o644
    );
    try {
      await handle.writeFile(bytes);
      await syncHandle(handle);
    } finally {
      await handle.close();
    }
    await validateDestinationForWrite(targetRoot, targetPath);
    await rename(tempPath, targetAbsolute);
    renamed = true;
    await syncParentDirectory(parent);
  } catch (error) {
    if (!renamed) {
      await unlink(tempPath).catch((unlinkError) => {
        if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw unlinkError;
        }
      });
    }
    throw error;
  }
}

async function writeJsonDurable(filePath: string, value: unknown, mode: number): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tempPath = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  let renamed = false;
  try {
    const handle = await open(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      mode
    );
    try {
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
      await syncHandle(handle);
    } finally {
      await handle.close();
    }
    await rename(tempPath, filePath);
    renamed = true;
    await syncParentDirectory(path.dirname(filePath));
  } catch (error) {
    if (!renamed) {
      await unlink(tempPath).catch((unlinkError) => {
        if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw unlinkError;
        }
      });
    }
    throw error;
  }
}

async function writeJournal(journalPath: string, journal: TransactionJournal): Promise<void> {
  await writeJsonDurable(journalPath, journal, 0o600);
}

async function writeRollbackEvidence(targetRoot: string, result: RollbackResult): Promise<void> {
  await writeJsonDurable(
    path.join(targetRoot, ".preflightseal", "rollbacks", `${result.receiptId}.json`),
    result,
    0o600
  );
}

function verificationResult(receipt: InstallReceipt, ok: boolean, conflicts: string[]): VerificationResult {
  const withoutDigest = {
    schemaVersion: SCHEMA_VERSION.VERIFICATION_RESULT,
    receiptId: receipt.receiptId,
    transactionId: receipt.transactionId,
    planSeal: receipt.planSeal,
    verifiedAt: new Date().toISOString(),
    ok,
    conflicts: [...conflicts].sort()
  };
  return {
    ...withoutDigest,
    verificationDigest: sha256Json(withoutDigest)
  };
}

function rollbackResult(receipt: InstallReceipt, ok: boolean, conflicts: string[]): RollbackResult {
  const withoutDigest = {
    schemaVersion: SCHEMA_VERSION.ROLLBACK_RESULT,
    receiptId: receipt.receiptId,
    transactionId: receipt.transactionId,
    planSeal: receipt.planSeal,
    rolledBackAt: new Date().toISOString(),
    ok,
    conflicts: [...conflicts].sort(),
    operations: receipt.operations.map((operation) => operation.targetPath).sort()
  };
  return {
    ...withoutDigest,
    rollbackDigest: sha256Json(withoutDigest)
  };
}

async function cleanupRolledBackTransactionState(targetRoot: string, receipt: InstallReceipt): Promise<void> {
  if (receipt.transactionId) {
    await rm(path.join(targetRoot, ".preflightseal", "transactions", receipt.transactionId), { recursive: true, force: true }).catch(() => undefined);
    await rm(path.join(targetRoot, ".preflightseal", "backups", receipt.transactionId), { recursive: true, force: true }).catch(() => undefined);
  }
}

async function syncHandle(handle: Awaited<ReturnType<typeof open>>): Promise<void> {
  await handle.sync();
}

async function syncParentDirectory(parent: string): Promise<void> {
  const handle = await open(parent, "r");
  try {
    await syncHandle(handle);
  } finally {
    await handle.close();
  }
}

async function fileExists(inputPath: string): Promise<boolean> {
  return await stat(inputPath).then(() => true, (error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  });
}
