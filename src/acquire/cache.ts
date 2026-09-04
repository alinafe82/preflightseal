import os from "node:os";
import path from "node:path";
import { mkdir, realpath } from "node:fs/promises";

import type { SourceIdentity } from "../types.ts";

export interface FrozenSource {
  kind: "github" | "local";
  contentDigest: string;
  cacheKey: string;
  root: string;
  metadata: SourceIdentity;
}

export async function cacheDirectory(): Promise<string> {
  const root = process.env.PREFLIGHTSEAL_CACHE_DIR || path.join(os.homedir(), ".preflightseal", "cache");
  await mkdir(root, { recursive: true, mode: 0o700 });
  return await realpath(root);
}

export function cacheKeyForDigest(digest: string): string {
  assertSha256Digest(digest);
  return `sha256/${digest.toLocaleLowerCase("en-US")}`;
}

export function cacheObjectDirectory(cacheRoot: string, cacheKey: string): string {
  const [algorithm, digest] = cacheKey.split("/", 2);
  if (algorithm !== "sha256") {
    throw new Error(`PFS_FROZEN_SOURCE_MISSING: unsupported cache key algorithm: ${cacheKey}`);
  }
  assertSha256Digest(digest);
  return path.join(cacheRoot, algorithm, digest.toLocaleLowerCase("en-US"));
}

export function assertSha256Digest(value: string | undefined): asserts value is string {
  if (!value || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: expected sha256 digest");
  }
}
