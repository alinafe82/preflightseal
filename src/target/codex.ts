import path from "node:path";
import { lstat } from "node:fs/promises";

import type { InstallOperation, Inventory, TargetStatePrecondition } from "../types.ts";
import { sha256File } from "../util/crypto.ts";
import { validateDestinationForWrite, validateRelativePath } from "../util/path.ts";

const allowedInstructionFiles = new Set(["AGENTS.md", "AGENTS.override.md"]);

export async function planCodexOperations(
  sourceRoot: string,
  targetRoot: string,
  inventory: Inventory
): Promise<{ operations: InstallOperation[]; preconditions: TargetStatePrecondition[] }> {
  const operations: InstallOperation[] = [];
  const preconditions: TargetStatePrecondition[] = [];

  for (const entry of inventory.entries) {
    if (entry.type !== "file" || !entry.sha256) {
      continue;
    }
    const targetPath = targetPathForSource(entry.path);
    if (!targetPath) {
      continue;
    }
    validateRelativePath(targetPath);
    await validateDestinationForWrite(targetRoot, targetPath);
    operations.push({
      op: "write_file",
      sourcePath: entry.path,
      targetPath,
      sha256: entry.sha256,
      size: entry.size,
      mode: entry.mode & 0o777
    });
    preconditions.push({
      targetPath,
      expected: await readTargetState(targetRoot, targetPath)
    });
  }

  return {
    operations: operations.sort((a, b) => a.targetPath.localeCompare(b.targetPath)),
    preconditions: preconditions.sort((a, b) => a.targetPath.localeCompare(b.targetPath))
  };
}

function targetPathForSource(sourcePath: string): string | undefined {
  if (allowedInstructionFiles.has(sourcePath)) {
    return sourcePath;
  }
  const skillMatch = sourcePath.match(/^skills\/([^/]+)\/(.+)$/);
  if (skillMatch) {
    return `.codex/skills/${skillMatch[1]}/${skillMatch[2]}`;
  }
  return undefined;
}

async function readTargetState(targetRoot: string, targetPath: string): Promise<TargetStatePrecondition["expected"]> {
  const absolute = path.join(targetRoot, targetPath);
  try {
    const stat = await lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1) {
      throw new Error(`unsupported target state for ${targetPath}`);
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
