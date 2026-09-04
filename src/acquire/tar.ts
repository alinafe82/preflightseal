import path from "node:path";
import { mkdir, open, rm } from "node:fs/promises";

import { sha256Bytes } from "../util/crypto.ts";
import { ensureSafeParentDirectory, validateRelativePath } from "../util/path.ts";

export interface ArchiveLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxDepth: number;
  maxPathLength: number;
}

export const defaultArchiveLimits: ArchiveLimits = {
  maxFiles: 5000,
  maxFileBytes: 10 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxDepth: 40,
  maxPathLength: 1024
};

interface ParsedTarEntry {
  relativePath: string;
  type: "directory" | "file";
  mode: number;
  size: number;
  content?: Buffer;
}

export async function extractGitHubTarBuffer(
  tar: Buffer,
  destinationRoot: string,
  limits = defaultArchiveLimits
): Promise<{ files: number; directories: number; totalBytes: number; digest: string }> {
  const entries = parseTar(tar, limits);
  await mkdir(destinationRoot, { recursive: true, mode: 0o700 });

  let files = 0;
  let directories = 0;
  let totalBytes = 0;
  for (const entry of entries) {
    const absolute = path.join(destinationRoot, entry.relativePath);
    if (entry.type === "directory") {
      await mkdir(absolute, { recursive: true, mode: directoryMode(entry.mode) });
      directories += 1;
      continue;
    }
    await ensureSafeParentDirectory(destinationRoot, entry.relativePath);
    const handle = await open(absolute, "wx", entry.mode || 0o644);
    try {
      await handle.writeFile(entry.content ?? Buffer.alloc(0));
    } finally {
      await handle.close();
    }
    files += 1;
    totalBytes += entry.size;
  }

  return {
    files,
    directories,
    totalBytes,
    digest: sha256Bytes(tar)
  };
}

export async function extractGitHubTarStream(
  input: AsyncIterable<Uint8Array>,
  destinationRoot: string,
  limits = defaultArchiveLimits
): Promise<{ files: number; directories: number; totalBytes: number }> {
  await mkdir(destinationRoot, { recursive: true, mode: 0o700 });

  let buffer = Buffer.alloc(0);
  let files = 0;
  let directories = 0;
  let totalBytes = 0;
  let finished = false;
  const seen = new Map<string, string>();
  let currentFile: {
    relativePath: string;
    remaining: number;
    padding: number;
    handle: Awaited<ReturnType<typeof open>>;
  } | undefined;
  let skipRemaining = 0;

  async function consumeAvailable(flush: boolean): Promise<void> {
    while (!finished) {
      if (skipRemaining > 0) {
        if (buffer.length === 0) {
          if (flush) {
            throw new Error("archive ended before skipped entry content completed");
          }
          return;
        }
        const consumed = Math.min(skipRemaining, buffer.length);
        buffer = buffer.subarray(consumed);
        skipRemaining -= consumed;
        continue;
      }

      if (currentFile) {
        if (currentFile.remaining > 0) {
          if (buffer.length === 0) {
            if (flush) {
              throw new Error(`archive ended before file content completed: ${currentFile.relativePath}`);
            }
            return;
          }
          const writeLength = Math.min(currentFile.remaining, buffer.length);
          const chunk = buffer.subarray(0, writeLength);
          await currentFile.handle.write(chunk);
          buffer = buffer.subarray(writeLength);
          currentFile.remaining -= writeLength;
          continue;
        }

        await currentFile.handle.close();
        files += 1;
        if (currentFile.padding > 0) {
          skipRemaining = currentFile.padding;
        }
        currentFile = undefined;
        continue;
      }

      if (buffer.length < 512) {
        if (flush && buffer.length > 0) {
          throw new Error("archive ended with a partial tar header");
        }
        return;
      }

      const header = buffer.subarray(0, 512);
      buffer = buffer.subarray(512);
      if (isZeroBlock(header)) {
        finished = true;
        return;
      }

      assertChecksum(header);
      const entry = parseTarHeader(header, limits, seen);
      if (!entry) {
        skipRemaining = paddedSize(parseOctal(header, 124, 12));
        continue;
      }

      if (entry.type === "directory") {
        await mkdir(path.join(destinationRoot, entry.relativePath), { recursive: true, mode: directoryMode(entry.mode) });
        directories += 1;
        skipRemaining = paddedSize(entry.size);
        continue;
      }

      if (entry.size > limits.maxFileBytes) {
        throw new Error(`archive entry exceeds maximum file size: ${entry.relativePath}`);
      }
      totalBytes += entry.size;
      if (totalBytes > limits.maxTotalBytes) {
        throw new Error("archive exceeds maximum total size");
      }

      const absolute = path.join(destinationRoot, entry.relativePath);
      await ensureSafeParentDirectory(destinationRoot, entry.relativePath);
      const handle = await open(absolute, "wx", entry.mode || 0o644);
      currentFile = {
        relativePath: entry.relativePath,
        remaining: entry.size,
        padding: paddedSize(entry.size) - entry.size,
        handle
      };
    }
  }

  try {
    for await (const chunk of input) {
      if (finished) {
        break;
      }
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      await consumeAvailable(false);
    }
    await consumeAvailable(true);
    if (currentFile) {
      throw new Error(`archive ended before file content completed: ${currentFile.relativePath}`);
    }
    if (skipRemaining > 0) {
      throw new Error("archive ended before padding completed");
    }
    if (!finished) {
      throw new Error("archive ended before trailer");
    }
  } catch (error) {
    await currentFile?.handle.close().catch(() => undefined);
    await rm(destinationRoot, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }

  return { files, directories, totalBytes };
}

export function parseTar(tar: Buffer, limits = defaultArchiveLimits): ParsedTarEntry[] {
  const entries: ParsedTarEntry[] = [];
  const seen = new Map<string, string>();
  let offset = 0;
  let totalBytes = 0;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    if (isZeroBlock(header)) {
      break;
    }
    assertChecksum(header);

    const parsedHeader = parseTarHeader(header, limits, seen);
    const size = parseOctal(header, 124, 12);

    if (!parsedHeader) {
      offset += paddedSize(size);
      continue;
    }

    if (parsedHeader.type === "directory") {
      entries.push({
        relativePath: parsedHeader.relativePath,
        type: "directory",
        mode: parsedHeader.mode,
        size: 0
      });
      offset += paddedSize(size);
      continue;
    }

    if (size > limits.maxFileBytes) {
      throw new Error(`archive entry exceeds maximum file size: ${parsedHeader.relativePath}`);
    }
    totalBytes += size;
    if (totalBytes > limits.maxTotalBytes) {
      throw new Error("archive exceeds maximum total size");
    }
    entries.push({
      relativePath: parsedHeader.relativePath,
      type: "file",
      mode: parsedHeader.mode,
      size,
      content: tar.subarray(offset, offset + size)
    });
    offset += paddedSize(size);
  }

  return entries;
}

function parseTarHeader(
  header: Buffer,
  limits: ArchiveLimits,
  seen: Map<string, string>
): { relativePath: string; type: "directory" | "file"; mode: number; size: number } | undefined {
  const rawName = tarString(header, 0, 100);
  const mode = parseOctal(header, 100, 8) || 0o644;
  const size = parseOctal(header, 124, 12);
  const typeFlag = tarString(header, 156, 1) || "0";
  const prefix = tarString(header, 345, 155);
  const fullPath = prefix ? `${prefix}/${rawName}` : rawName;
  rejectRawArchivePath(fullPath);
  const relativePath = normalizeGitHubArchivePath(fullPath);

  if (!relativePath) {
    return undefined;
  }

  if (relativePath.split("/").length > limits.maxDepth) {
    throw new Error(`archive entry exceeds maximum depth: ${relativePath}`);
  }
  if (relativePath.length > limits.maxPathLength) {
    throw new Error(`archive entry exceeds maximum path length: ${relativePath}`);
  }

  const collisionKey = relativePath.normalize("NFC").toLocaleLowerCase("en-US");
  const existing = seen.get(collisionKey);
  if (existing) {
    throw new Error(`archive normalized path collision: ${existing} conflicts with ${relativePath}`);
  }
  seen.set(collisionKey, relativePath);

  if (typeFlag === "2" || typeFlag === "1") {
    throw new Error(`archive link entries are not accepted: ${relativePath}`);
  }
  if (typeFlag === "x" || typeFlag === "g") {
    throw new Error(`archive extended headers are not accepted: ${relativePath}`);
  }
  if (typeFlag !== "5" && typeFlag !== "0" && typeFlag !== "\0") {
    throw new Error(`unsupported archive entry type ${JSON.stringify(typeFlag)} for ${relativePath}`);
  }

  if (seen.size > limits.maxFiles) {
    throw new Error("archive exceeds maximum entry count");
  }

  return {
    relativePath,
    type: typeFlag === "5" ? "directory" : "file",
    mode,
    size
  };
}

function normalizeGitHubArchivePath(fullPath: string): string | undefined {
  if (!fullPath || fullPath.includes("\0")) {
    throw new Error("archive path is empty or contains NUL bytes");
  }
  const normalized = fullPath.normalize("NFC");
  const parts = normalized.split("/");
  if (parts.length <= 1) {
    return undefined;
  }
  const stripped = parts.slice(1).join("/").replace(/\/+$/g, "");
  if (!stripped) {
    return undefined;
  }
  return validateRelativePath(stripped);
}

function rejectRawArchivePath(fullPath: string): void {
  if (fullPath.includes("\0")) {
    throw new Error("archive path contains NUL bytes");
  }
  if (fullPath.includes("\\")) {
    throw new Error(`archive path uses backslashes: ${fullPath}`);
  }
  if (fullPath.startsWith("/") || fullPath.startsWith("//") || /^[A-Za-z]:/.test(fullPath)) {
    throw new Error(`archive path is absolute: ${fullPath}`);
  }
}

function paddedSize(size: number): number {
  return Math.ceil(size / 512) * 512;
}

function directoryMode(mode: number): number {
  return (mode || 0o755) | 0o700;
}

function tarString(header: Buffer, start: number, length: number): string {
  const slice = header.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString("utf8").trim();
}

function parseOctal(header: Buffer, start: number, length: number): number {
  const raw = tarString(header, start, length).replace(/\0/g, "").trim();
  if (!raw) {
    return 0;
  }
  const value = Number.parseInt(raw, 8);
  if (!Number.isFinite(value)) {
    throw new Error(`invalid tar octal value: ${raw}`);
  }
  return value;
}

function isZeroBlock(block: Buffer): boolean {
  for (const byte of block) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

function assertChecksum(header: Buffer): void {
  const expected = parseOctal(header, 148, 8);
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (expected !== actual) {
    throw new Error("tar header checksum mismatch");
  }
}
