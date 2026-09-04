import path from "node:path";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readlink, realpath, rename, rm, stat, symlink, writeFile } from "node:fs/promises";

import { createInventory } from "../inventory.ts";
import { SCHEMA_VERSION } from "../schema.ts";
import type { SourceIdentity } from "../types.ts";
import { cacheDirectory, cacheKeyForDigest, cacheObjectDirectory, type FrozenSource } from "./cache.ts";
import { validateRelativePath, isInside } from "../util/path.ts";

export interface LocalFreezeOptions {
  onAfterInitialInventory?: () => Promise<void> | void;
  onBeforeSnapshotInventory?: (stagingSourceRoot: string) => Promise<void> | void;
  onBeforePromote?: (stagingDir: string, cacheObjectDir: string) => Promise<void> | void;
}

export async function acquireLocalSource(input: string, options: LocalFreezeOptions = {}): Promise<FrozenSource> {
  const sourceRoot = await realpath(input);
  const beforeInventory = await createInventory(sourceRoot);
  await options.onAfterInitialInventory?.();

  const cacheRoot = await cacheDirectory();
  const cacheKey = cacheKeyForDigest(beforeInventory.digest);
  const archiveDir = cacheObjectDirectory(cacheRoot, cacheKey);
  const sourceIdentity = localSourceIdentity(input, sourceRoot, beforeInventory.digest, cacheKey);

  try {
    const existing = await readLocalCacheObject(archiveDir, beforeInventory.digest, sourceIdentity);
    await assertSourceUnchanged(sourceRoot, beforeInventory.digest);
    return existing;
  } catch (error) {
    if (await exists(archiveDir)) {
      throw error;
    }
  }

  const tempRoot = path.join(cacheRoot, "tmp");
  await mkdir(tempRoot, { recursive: true, mode: 0o700 });
  await mkdir(path.dirname(archiveDir), { recursive: true, mode: 0o700 });
  const stagingDir = await mkdtemp(path.join(tempRoot, `${beforeInventory.digest}-local-`));
  const stagingSourceRoot = path.join(stagingDir, "source");
  try {
    await mkdir(stagingSourceRoot, { recursive: true, mode: 0o700 });
    await copySnapshot(sourceRoot, stagingSourceRoot, beforeInventory);
    await options.onBeforeSnapshotInventory?.(stagingSourceRoot);
    const snapshotInventory = await createInventory(stagingSourceRoot);
    if (snapshotInventory.digest !== beforeInventory.digest) {
      throw new Error(`PFS_SOURCE_CHANGED: local snapshot digest mismatch: expected ${beforeInventory.digest}, got ${snapshotInventory.digest}`);
    }
    await assertSourceUnchanged(sourceRoot, beforeInventory.digest);
    await writeFile(path.join(stagingDir, "metadata.json"), `${JSON.stringify({
      schemaVersion: SCHEMA_VERSION.CACHE_LOCAL,
      sourceKind: "local",
      originalInput: input,
      canonical: sourceRoot,
      canonicalIdentity: sourceRoot,
      contentDigest: beforeInventory.digest,
      cacheKey,
      createdAt: new Date().toISOString()
    }, null, 2)}\n`, { mode: 0o600 });
    try {
      await options.onBeforePromote?.(stagingDir, archiveDir);
      await rename(stagingDir, archiveDir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" && (error as NodeJS.ErrnoException).code !== "ENOTEMPTY") {
        throw error;
      }
      await rm(stagingDir, { recursive: true, force: true });
    }
  } catch (error) {
    await rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }

  return await readLocalCacheObject(archiveDir, beforeInventory.digest, sourceIdentity);
}

export async function resolveCachedLocalSourceRoot(source: SourceIdentity): Promise<string> {
  if (source.kind !== "local") {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: source identity is not local");
  }
  const expectedCacheKey = cacheKeyForDigest(source.contentDigest);
  if (source.cacheKey && source.cacheKey !== expectedCacheKey) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: local source cache key does not match content digest");
  }
  if (source.immutableLocator && source.immutableLocator !== `preflightseal-cache:${expectedCacheKey}`) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: local source immutable locator does not match content digest");
  }
  const cacheRoot = await cacheDirectory();
  const cacheObject = await readLocalCacheObject(
    cacheObjectDirectory(cacheRoot, expectedCacheKey),
    source.contentDigest,
    source
  );
  return cacheObject.root;
}

async function copySnapshot(sourceRoot: string, destinationRoot: string, inventory: Awaited<ReturnType<typeof createInventory>>): Promise<void> {
  const directories = inventory.entries.filter((entry) => entry.type === "directory");
  const files = inventory.entries.filter((entry) => entry.type === "file");
  const links = inventory.entries.filter((entry) => entry.type === "symlink");

  for (const directory of directories) {
    const relative = validateRelativePath(directory.path);
    await mkdir(path.join(destinationRoot, relative), { recursive: true, mode: directory.mode & 0o777 || 0o755 });
    await chmod(path.join(destinationRoot, relative), directory.mode & 0o777 || 0o755);
  }

  for (const file of files) {
    const relative = validateRelativePath(file.path);
    const sourcePath = path.join(sourceRoot, relative);
    const sourceStat = await lstat(sourcePath);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
      throw new Error(`PFS_SOURCE_CHANGED: source file changed type during freeze: ${relative}`);
    }
    if (sourceStat.nlink > 1) {
      throw new Error(`PFS_SOURCE_CHANGED: source file has multiple hard links: ${relative}`);
    }
    if (sourceStat.size !== file.size) {
      throw new Error(`PFS_SOURCE_CHANGED: source file changed size during freeze: ${relative}`);
    }
    const bytes = await readRegularFileNoFollow(sourcePath, relative, file.size);
    const destinationPath = path.join(destinationRoot, relative);
    await mkdir(path.dirname(destinationPath), { recursive: true, mode: 0o755 });
    const destinationHandle = await open(
      destinationPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      file.mode & 0o777 || 0o644
    );
    try {
      await destinationHandle.writeFile(bytes);
    } finally {
      await destinationHandle.close();
    }
    await chmod(destinationPath, file.mode & 0o777 || 0o644);
  }

  for (const link of links) {
    const relative = validateRelativePath(link.path);
    const sourcePath = path.join(sourceRoot, relative);
    const sourceStat = await lstat(sourcePath);
    if (!sourceStat.isSymbolicLink()) {
      throw new Error(`PFS_SOURCE_CHANGED: source symlink changed type during freeze: ${relative}`);
    }
    const linkTarget = await readlink(sourcePath);
    if (linkTarget !== link.symlinkTarget) {
      throw new Error(`PFS_SOURCE_CHANGED: source symlink changed during freeze: ${relative}`);
    }
    validateSafeSourceSymlink(sourceRoot, relative, linkTarget);
    await mkdir(path.dirname(path.join(destinationRoot, relative)), { recursive: true, mode: 0o755 });
    await symlink(linkTarget, path.join(destinationRoot, relative));
  }
}

async function readRegularFileNoFollow(sourcePath: string, relative: string, expectedSize: number): Promise<Buffer> {
  const handle = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW).catch((error) => {
    throw new Error(`PFS_SOURCE_CHANGED: source file cannot be safely opened during freeze: ${relative}: ${(error as Error).message}`);
  });
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.isSymbolicLink() || openedStat.nlink > 1) {
      throw new Error(`PFS_SOURCE_CHANGED: source file is not a safe regular file during freeze: ${relative}`);
    }
    if (openedStat.size !== expectedSize) {
      throw new Error(`PFS_SOURCE_CHANGED: source file changed size during freeze: ${relative}`);
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

function validateSafeSourceSymlink(sourceRoot: string, relativePath: string, linkTarget: string): void {
  if (path.isAbsolute(linkTarget) || linkTarget.includes("\0")) {
    throw new Error(`PFS_SOURCE_CHANGED: unsafe absolute or NUL symlink target: ${relativePath}`);
  }
  if (linkTarget.includes("\\")) {
    throw new Error(`PFS_SOURCE_CHANGED: unsafe symlink target uses backslashes: ${relativePath}`);
  }
  const sourceParent = path.dirname(path.join(sourceRoot, relativePath));
  const targetAbsolute = path.resolve(sourceParent, linkTarget);
  if (!isInside(sourceRoot, targetAbsolute)) {
    throw new Error(`PFS_SOURCE_CHANGED: symlink target escapes source root: ${relativePath}`);
  }
}

async function assertSourceUnchanged(sourceRoot: string, expectedDigest: string): Promise<void> {
  const afterInventory = await createInventory(sourceRoot);
  if (afterInventory.digest !== expectedDigest) {
    throw new Error(`PFS_SOURCE_CHANGED: local source changed during freeze: expected inventory ${expectedDigest}, got ${afterInventory.digest}`);
  }
}

function localSourceIdentity(input: string, sourceRoot: string, contentDigest: string, cacheKey: string): SourceIdentity {
  return {
    schemaVersion: SCHEMA_VERSION.SOURCE,
    kind: "local",
    originalInput: input,
    canonical: sourceRoot,
    canonicalIdentity: sourceRoot,
    resolvedRevision: contentDigest,
    contentDigest,
    cacheKey,
    immutableLocator: `preflightseal-cache:${cacheKey}`,
    retrievedAt: new Date().toISOString()
  };
}

async function readLocalCacheObject(archiveDir: string, expectedContentDigest: string, source: SourceIdentity): Promise<FrozenSource> {
  const sourceRoot = await realpath(path.join(archiveDir, "source")).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("PFS_FROZEN_SOURCE_MISSING: cached local source tree is missing");
    }
    throw error;
  });
  const inventory = await createInventory(sourceRoot);
  if (inventory.digest !== expectedContentDigest) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: cached local source digest mismatch");
  }
  return {
    kind: "local",
    contentDigest: inventory.digest,
    cacheKey: cacheKeyForDigest(inventory.digest),
    root: sourceRoot,
    metadata: {
      ...source,
      contentDigest: inventory.digest,
      resolvedRevision: inventory.digest,
      cacheKey: cacheKeyForDigest(inventory.digest),
      immutableLocator: `preflightseal-cache:${cacheKeyForDigest(inventory.digest)}`
    }
  };
}

async function exists(inputPath: string): Promise<boolean> {
  return await stat(inputPath).then(() => true, (error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  });
}
