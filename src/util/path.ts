import path from "node:path";
import { constants } from "node:fs";
import { lstat, mkdir, realpath } from "node:fs/promises";

export function validateRelativePath(input: string): string {
  if (!input || input === ".") {
    throw new Error("path must not be empty");
  }
  if (input.includes("\0")) {
    throw new Error("path must not contain NUL bytes");
  }
  if (input.includes("\\")) {
    throw new Error(`path uses backslashes: ${input}`);
  }
  if (path.posix.isAbsolute(input) || /^[A-Za-z]:/.test(input) || input.startsWith("//")) {
    throw new Error(`path escapes the target root: ${input}`);
  }

  const normalizedUnicode = input.normalize("NFC");
  const segments = normalizedUnicode.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`path contains an unsafe segment: ${input}`);
  }

  const normalized = path.posix.normalize(normalizedUnicode);
  if (normalized === "." || normalized.startsWith("../")) {
    throw new Error(`path escapes the target root: ${input}`);
  }
  return normalized;
}

export function assertNoNormalizedCollisions(paths: string[]): void {
  const seen = new Map<string, string>();
  for (const item of paths) {
    const normalized = validateRelativePath(item);
    const key = normalized.normalize("NFC").toLocaleLowerCase("en-US");
    const existing = seen.get(key);
    if (existing && existing !== item) {
      throw new Error(`normalized path collision: ${existing} conflicts with ${item}`);
    }
    seen.set(key, item);
  }
}

export function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export async function validateDestinationForWrite(root: string, relativePath: string): Promise<string> {
  const safeRelative = validateRelativePath(relativePath);
  const rootReal = await realpath(root);
  const absolute = path.resolve(rootReal, safeRelative);
  if (!isInside(rootReal, absolute)) {
    throw new Error(`destination escapes target root: ${relativePath}`);
  }

  let current = rootReal;
  const segments = safeRelative.split("/");
  for (const segment of segments.slice(0, -1)) {
    current = path.join(current, segment);
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) {
        throw new Error(`destination parent is a symlink: ${segment}`);
      }
      if (!stat.isDirectory()) {
        throw new Error(`destination parent is not a directory: ${segment}`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        break;
      }
      throw error;
    }
  }

  try {
    const finalStat = await lstat(absolute);
    if (finalStat.isSymbolicLink()) {
      throw new Error(`destination is a symlink: ${relativePath}`);
    }
    if (!finalStat.isFile()) {
      throw new Error(`destination exists and is not a file: ${relativePath}`);
    }
    if (finalStat.nlink > 1) {
      throw new Error(`destination has multiple hard links: ${relativePath}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }

  return absolute;
}

export async function ensureSafeParentDirectory(root: string, relativePath: string): Promise<string> {
  const safeRelative = validateRelativePath(relativePath);
  const parentRelative = path.posix.dirname(safeRelative);
  const rootReal = await realpath(root);
  const parentAbsolute = parentRelative === "." ? rootReal : path.resolve(rootReal, parentRelative);
  if (!isInside(rootReal, parentAbsolute)) {
    throw new Error(`parent escapes target root: ${relativePath}`);
  }
  await mkdir(parentAbsolute, { recursive: true, mode: 0o755 });
  const parentReal = await realpath(parentAbsolute);
  if (!isInside(rootReal, parentReal)) {
    throw new Error(`parent resolved outside target root: ${relativePath}`);
  }
  return parentReal;
}

export const noFollowWriteFlag = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW;
