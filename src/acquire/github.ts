import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";

import type { SourceIdentity } from "../types.ts";
import { createInventory } from "../inventory.ts";
import { sha256Bytes } from "../util/crypto.ts";
import { extractGitHubTarBuffer } from "./tar.ts";

export interface GitHubSource {
  owner: string;
  repo: string;
  requestedRef: string;
  originalInput: string;
  canonicalUrl: string;
}

export interface AcquiredGitHubSource {
  source: SourceIdentity;
  sourceRoot: string;
  inventoryDigest: string;
  archivePath: string;
  archiveSha256: string;
}

export function parseGitHubSource(input: string, requestedRef = "HEAD"): GitHubSource {
  const url = new URL(input);
  if (url.protocol !== "https:" || url.hostname.toLocaleLowerCase("en-US") !== "github.com") {
    throw new Error("only public GitHub HTTPS repository URLs are supported");
  }
  if (url.username || url.password) {
    throw new Error("GitHub URLs with embedded credentials are rejected");
  }
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error("GitHub URL must include owner and repository");
  }
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, "");
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    throw new Error("GitHub owner or repository contains unsupported characters");
  }
  const ref = url.hash ? decodeURIComponent(url.hash.slice(1)) : requestedRef;
  return {
    owner,
    repo,
    requestedRef: ref || "HEAD",
    originalInput: input,
    canonicalUrl: `https://github.com/${owner}/${repo}`
  };
}

export function isGitHubHttpsSource(input: string): boolean {
  try {
    const url = new URL(input);
    return url.protocol === "https:" && url.hostname.toLocaleLowerCase("en-US") === "github.com";
  } catch {
    return false;
  }
}

export async function acquireGitHubSource(input: string, requestedRef = "HEAD"): Promise<AcquiredGitHubSource> {
  const parsed = parseGitHubSource(input, requestedRef);
  const resolvedCommit = await resolveCommit(parsed);
  const cacheRoot = await cacheDirectory();
  const archiveTemp = path.join(cacheRoot, "downloads", `${resolvedCommit}.tar.gz.tmp`);
  await mkdir(path.dirname(archiveTemp), { recursive: true, mode: 0o700 });
  const download = await downloadTarball(parsed, resolvedCommit, archiveTemp);
  const archiveDir = path.join(cacheRoot, "sha256", download.sha256);
  const archivePath = path.join(archiveDir, "source.tar.gz");
  const extractedRoot = path.join(archiveDir, "source");

  await rm(archiveDir, { recursive: true, force: true });
  await mkdir(archiveDir, { recursive: true, mode: 0o700 });
  await writeFile(archivePath, await readFile(archiveTemp), { mode: 0o600 });
  await rm(archiveTemp, { force: true });

  const gunzipped = await gunzipBuffer(await readFile(archivePath));
  await extractGitHubTarBuffer(gunzipped, extractedRoot);
  const inventory = await createInventory(extractedRoot);
  const sourceRoot = await realpath(extractedRoot);

  return {
    source: {
      kind: "github",
      originalInput: parsed.originalInput,
      canonical: parsed.canonicalUrl,
      resolvedRevision: resolvedCommit,
      contentDigest: inventory.digest,
      retrievedAt: new Date().toISOString(),
      metadata: {
        requestedRef: parsed.requestedRef,
        archiveSha256: download.sha256,
        archiveUrl: download.finalUrl,
        archiveByteLength: download.byteLength
      }
    },
    sourceRoot,
    inventoryDigest: inventory.digest,
    archivePath,
    archiveSha256: download.sha256
  };
}

async function resolveCommit(source: GitHubSource): Promise<string> {
  let ref = source.requestedRef;
  if (ref === "HEAD") {
    const repo = await githubJson(`https://api.github.com/repos/${source.owner}/${source.repo}`);
    ref = stringField(repo, "default_branch");
  }
  const commit = await githubJson(`https://api.github.com/repos/${source.owner}/${source.repo}/commits/${encodeURIComponent(ref)}`);
  const sha = stringField(commit, "sha");
  if (!/^[a-f0-9]{40}$/i.test(sha)) {
    throw new Error(`GitHub returned an invalid commit SHA for ${source.canonicalUrl}`);
  }
  return sha;
}

async function downloadTarball(source: GitHubSource, commit: string, outputPath: string): Promise<{
  sha256: string;
  byteLength: number;
  finalUrl: string;
}> {
  const url = `https://api.github.com/repos/${source.owner}/${source.repo}/tarball/${commit}`;
  const response = await fetch(url, {
    redirect: "follow",
    headers: {
      "accept": "application/vnd.github+json",
      "user-agent": "preflightseal"
    }
  });
  if (!response.ok || !response.body) {
    throw new Error(`GitHub archive download failed: HTTP ${response.status}`);
  }
  const hash = createHash("sha256");
  let byteLength = 0;
  const limit = 50 * 1024 * 1024;
  const stream = Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0]);
  const output = fs.createWriteStream(outputPath, { mode: 0o600 });
  stream.on("data", (chunk) => {
    byteLength += chunk.length;
    if (byteLength > limit) {
      stream.destroy(new Error("GitHub archive exceeds maximum download size"));
      return;
    }
    hash.update(chunk);
  });
  await pipeline(stream, output);
  return {
    sha256: hash.digest("hex"),
    byteLength,
    finalUrl: response.url
  };
}

async function githubJson(url: string): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    headers: {
      "accept": "application/vnd.github+json",
      "user-agent": "preflightseal"
    }
  });
  if (!response.ok) {
    throw new Error(`GitHub API request failed: HTTP ${response.status}`);
  }
  const parsed: unknown = await response.json();
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("GitHub API returned a non-object response");
  }
  return parsed as Record<string, unknown>;
}

async function gunzipBuffer(input: Buffer): Promise<Buffer> {
  const chunks: Buffer[] = [];
  const source = Readable.from(input);
  const gunzip = createGunzip();
  gunzip.on("data", (chunk) => {
    chunks.push(Buffer.from(chunk));
  });
  await pipeline(source, gunzip);
  return Buffer.concat(chunks);
}

async function cacheDirectory(): Promise<string> {
  const root = process.env.PREFLIGHTSEAL_CACHE_DIR || path.join(os.homedir(), ".preflightseal", "cache");
  await mkdir(root, { recursive: true, mode: 0o700 });
  return await realpath(root);
}

function stringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || !value) {
    throw new Error(`GitHub API response did not include string field ${field}`);
  }
  return value;
}

export function archiveIdentityDigest(input: unknown): string {
  return sha256Bytes(JSON.stringify(input));
}
