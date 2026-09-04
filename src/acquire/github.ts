import path from "node:path";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { Readable, Transform } from "node:stream";
import { createGunzip } from "node:zlib";
import { mkdir, mkdtemp, open, realpath, rm, rename, stat, writeFile } from "node:fs/promises";

import type { SourceIdentity } from "../types.ts";
import { createInventory } from "../inventory.ts";
import { SCHEMA_VERSION } from "../schema.ts";
import { sha256Bytes, sha256File } from "../util/crypto.ts";
import { cacheDirectory, cacheKeyForDigest, cacheObjectDirectory } from "./cache.ts";
import { defaultArchiveLimits, extractGitHubTarStream, type ArchiveLimits } from "./tar.ts";

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

interface ResolvedCommit {
  commit: string;
  requestedRef: string;
  resolvedRef: string;
  apiUrl: string;
}

interface DownloadedArchive {
  sha256: string;
  byteLength: number;
  extraction: {
    files: number;
    directories: number;
    totalBytes: number;
  };
  apiUrl: string;
  finalUrl: string;
  redirectChain: Array<{
    status: number;
    from: string;
    to: string;
  }>;
}

interface CacheObject {
  archivePath: string;
  sourceRoot: string;
  inventoryDigest: string;
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
  if (parts.length !== 2) {
    throw new Error("GitHub URL must include exactly owner and repository");
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
  const tempRoot = path.join(cacheRoot, "tmp");
  await mkdir(tempRoot, { recursive: true, mode: 0o700 });
  const stagingDir = await mkdtemp(path.join(tempRoot, `${resolvedCommit.commit}-github-`));
  const stagingArchivePath = path.join(stagingDir, "source.tar.gz");
  const stagingSourceRoot = path.join(stagingDir, "source");

  let download: DownloadedArchive;
  let archiveDir: string;
  let cacheObject: CacheObject;
  try {
    download = await downloadTarball(parsed, resolvedCommit.commit, stagingArchivePath, stagingSourceRoot);
    archiveDir = cacheObjectDirectory(cacheRoot, cacheKeyForArchiveSha(download.sha256));
    cacheObject = await populateOrReuseCacheObject({
      stagingDir,
      archiveDir,
      archiveSha256: download.sha256,
      metadata: {
        sourceKind: "github",
        canonicalUrl: parsed.canonicalUrl,
        requestedRef: resolvedCommit.requestedRef,
        resolvedRef: resolvedCommit.resolvedRef,
        resolvedCommit: resolvedCommit.commit,
        commitApiUrl: resolvedCommit.apiUrl,
        archiveApiUrl: download.apiUrl,
        finalDownloadUrl: download.finalUrl,
        redirectChain: download.redirectChain,
        archiveByteLength: download.byteLength,
        extractedFiles: download.extraction.files,
        extractedDirectories: download.extraction.directories,
        extractedBytes: download.extraction.totalBytes
      }
    });
  } catch (error) {
    await rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
  const cacheKey = cacheKeyForArchiveSha(download.sha256);

  return {
    source: {
      schemaVersion: SCHEMA_VERSION.SOURCE,
      kind: "github",
      originalInput: parsed.originalInput,
      canonical: parsed.canonicalUrl,
      canonicalIdentity: parsed.canonicalUrl,
      requestedRef: resolvedCommit.requestedRef,
      resolvedRevision: resolvedCommit.commit,
      archiveSha256: download.sha256,
      contentDigest: cacheObject.inventoryDigest,
      cacheKey,
      immutableLocator: `preflightseal-cache:${cacheKey}`,
      retrievedAt: new Date().toISOString(),
      metadata: {
        resolvedRef: resolvedCommit.resolvedRef,
        archiveSha256: download.sha256,
        archiveApiUrl: download.apiUrl,
        archiveUrl: download.finalUrl,
        archiveByteLength: download.byteLength,
        redirectChain: download.redirectChain
      }
    },
    sourceRoot: cacheObject.sourceRoot,
    inventoryDigest: cacheObject.inventoryDigest,
    archivePath: cacheObject.archivePath,
    archiveSha256: download.sha256
  };
}

export async function resolveCachedGitHubSourceRoot(source: SourceIdentity): Promise<string> {
  if (source.kind !== "github") {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: source identity is not GitHub");
  }
  const archiveSha256 = source.archiveSha256 ?? stringMetadata(source, "archiveSha256");
  if (!archiveSha256 || !/^[a-f0-9]{64}$/i.test(archiveSha256)) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: GitHub source identity is missing archive digest");
  }
  const expectedCacheKey = cacheKeyForArchiveSha(archiveSha256);
  if (source.cacheKey && source.cacheKey !== expectedCacheKey) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: GitHub source cache key does not match archive digest");
  }
  if (source.immutableLocator && source.immutableLocator !== `preflightseal-cache:${expectedCacheKey}`) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: GitHub source immutable locator does not match archive digest");
  }
  const cacheRoot = await cacheDirectory();
  const cacheObject = await readCacheObject(
    cacheObjectDirectory(cacheRoot, expectedCacheKey),
    archiveSha256,
    source.contentDigest
  );
  return cacheObject.sourceRoot;
}

function cacheKeyForArchiveSha(archiveSha256: string): string {
  return cacheKeyForDigest(archiveSha256);
}

async function resolveCommit(source: GitHubSource): Promise<ResolvedCommit> {
  let ref = source.requestedRef;
  if (ref === "HEAD") {
    const repo = await githubJson(githubApiUrl("repos", source.owner, source.repo));
    ref = stringField(repo, "default_branch");
  }
  const apiUrl = githubApiUrl("repos", source.owner, source.repo, "commits", ref);
  const commit = await githubJson(apiUrl);
  const sha = stringField(commit, "sha");
  if (!/^[a-f0-9]{40}$/i.test(sha)) {
    throw new Error(`GitHub returned an invalid commit SHA for ${source.canonicalUrl}`);
  }
  return {
    commit: sha,
    requestedRef: source.requestedRef,
    resolvedRef: ref,
    apiUrl: apiUrl.toString()
  };
}

async function downloadTarball(source: GitHubSource, commit: string, outputPath: string, sourceRoot: string): Promise<DownloadedArchive> {
  const url = githubApiUrl("repos", source.owner, source.repo, "tarball", commit);
  let currentUrl = url;
  const redirectChain: DownloadedArchive["redirectChain"] = [];
  let response: Response | undefined;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    const requestUrl = validateGitHubArchiveUrl(currentUrl);
    response = await fetch(requestUrl, {
      redirect: "manual",
      headers: githubRequestHeaders(requestUrl)
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      break;
    }
    const location = response.headers.get("location");
    if (!location) {
      throw new Error("GitHub archive redirect did not include a location");
    }
    const nextUrl = validateGitHubArchiveUrl(new URL(location, requestUrl));
    redirectChain.push({ status: response.status, from: requestUrl.toString(), to: nextUrl.toString() });
    currentUrl = nextUrl;
  }
  if (!response || [301, 302, 303, 307, 308].includes(response.status)) {
    throw new Error("GitHub archive redirect limit exceeded");
  }
  if (!response.ok || !response.body) {
    throw new Error(`GitHub archive download failed: HTTP ${response.status}`);
  }
  const stream = Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0]);
  const archive = await extractCompressedGitHubTarball(stream, outputPath, sourceRoot);
  return {
    sha256: archive.sha256,
    byteLength: archive.byteLength,
    extraction: archive.extraction,
    apiUrl: url.toString(),
    finalUrl: response.url || currentUrl.toString(),
    redirectChain
  };
}

async function populateOrReuseCacheObject(input: {
  stagingDir: string;
  archiveDir: string;
  archiveSha256: string;
  metadata: Record<string, unknown>;
}): Promise<CacheObject> {
  if (await exists(input.archiveDir)) {
    await rm(input.stagingDir, { recursive: true, force: true });
    return await readCacheObject(input.archiveDir, input.archiveSha256);
  }

  await mkdir(path.dirname(input.archiveDir), { recursive: true, mode: 0o700 });
  try {
    const inventory = await createInventory(path.join(input.stagingDir, "source"));
    await writeFile(path.join(input.stagingDir, "metadata.json"), `${JSON.stringify({
      ...input.metadata,
      schemaVersion: SCHEMA_VERSION.CACHE_GITHUB,
      cacheKey: cacheKeyForArchiveSha(input.archiveSha256),
      archiveSha256: input.archiveSha256,
      contentDigest: inventory.digest,
      createdAt: new Date().toISOString()
    }, null, 2)}\n`, { mode: 0o600 });
    try {
      await rename(input.stagingDir, input.archiveDir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" && (error as NodeJS.ErrnoException).code !== "ENOTEMPTY") {
        throw error;
      }
      await rm(input.stagingDir, { recursive: true, force: true });
    }
  } catch (error) {
    await rm(input.stagingDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
  return await readCacheObject(input.archiveDir, input.archiveSha256);
}

async function readCacheObject(
  archiveDir: string,
  expectedArchiveSha256: string,
  expectedContentDigest?: string
): Promise<CacheObject> {
  const archivePath = path.join(archiveDir, "source.tar.gz");
  const actualArchiveSha256 = await sha256File(archivePath).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("PFS_FROZEN_SOURCE_MISSING: cached GitHub archive is missing");
    }
    throw error;
  });
  if (actualArchiveSha256 !== expectedArchiveSha256) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: cached GitHub archive digest mismatch");
  }
  const sourceRoot = await realpath(path.join(archiveDir, "source")).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("PFS_FROZEN_SOURCE_MISSING: cached GitHub source tree is missing");
    }
    throw error;
  });
  const inventory = await createInventory(sourceRoot);
  if (expectedContentDigest && inventory.digest !== expectedContentDigest) {
    throw new Error("PFS_FROZEN_SOURCE_MISSING: cached GitHub source digest mismatch");
  }
  return {
    archivePath,
    sourceRoot,
    inventoryDigest: inventory.digest
  };
}

async function githubJson(url: URL): Promise<Record<string, unknown>> {
  const requestUrl = validateGitHubApiUrl(url);
  const response = await fetch(requestUrl, {
    headers: githubRequestHeaders(requestUrl)
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

export async function extractCompressedGitHubTarball(
  input: AsyncIterable<Uint8Array>,
  archivePath: string,
  sourceRoot: string,
  options: {
    limits?: ArchiveLimits;
    maxCompressedBytes?: number;
    maxDecompressedBytes?: number;
  } = {}
): Promise<{
  sha256: string;
  byteLength: number;
  extraction: {
    files: number;
    directories: number;
    totalBytes: number;
  };
}> {
  const limits = options.limits ?? defaultArchiveLimits;
  const maxCompressedBytes = options.maxCompressedBytes ?? defaultMaxCompressedArchiveBytes;
  const maxDecompressedBytes = options.maxDecompressedBytes ?? defaultMaxDecompressedArchiveBytes(limits);
  const hash = createHash("sha256");
  let byteLength = 0;
  const archiveHandle = await open(
    archivePath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600
  );
  let archiveClosed = false;
  const gunzip = createGunzip();
  const decompressedLimiter = new ByteLimitTransform(
    maxDecompressedBytes,
    "PFS_ARCHIVE_LIMIT: archive exceeds maximum decompressed size"
  );
  gunzip.on("error", () => undefined);
  decompressedLimiter.on("error", () => undefined);
  const extractionInput = gunzip.pipe(decompressedLimiter);
  const extractionPromise = extractGitHubTarStream(extractionInput, sourceRoot, limits);

  try {
    for await (const rawChunk of input) {
      const chunk = Buffer.from(rawChunk);
      byteLength += chunk.length;
      if (byteLength > maxCompressedBytes) {
        throw new Error("PFS_ARCHIVE_LIMIT: compressed archive exceeds maximum download size");
      }
      hash.update(chunk);
      await archiveHandle.write(chunk);
      if (!gunzip.write(chunk)) {
        await once(gunzip, "drain");
      }
    }
    gunzip.end();
    await archiveHandle.close();
    archiveClosed = true;
    const extraction = await extractionPromise;
    return {
      sha256: hash.digest("hex"),
      byteLength,
      extraction
    };
  } catch (error) {
    gunzip.destroy(error as Error);
    decompressedLimiter.destroy(error as Error);
    await extractionPromise.catch(() => undefined);
    if (!archiveClosed) {
      await archiveHandle.close().catch(() => undefined);
    }
    throw error;
  }
}

export const defaultMaxCompressedArchiveBytes = 50 * 1024 * 1024;

export function defaultMaxDecompressedArchiveBytes(limits: ArchiveLimits = defaultArchiveLimits): number {
  return limits.maxTotalBytes + (limits.maxFiles * 512) + 1024 * 1024;
}

class ByteLimitTransform extends Transform {
  #seen = 0;
  #maxBytes: number;
  #message: string;

  constructor(maxBytes: number, message: string) {
    super();
    this.#maxBytes = maxBytes;
    this.#message = message;
  }

  _transform(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null, data?: Buffer) => void): void {
    this.#seen += chunk.length;
    if (this.#seen > this.#maxBytes) {
      callback(new Error(this.#message));
      return;
    }
    callback(null, chunk);
  }
}

async function exists(inputPath: string): Promise<boolean> {
  return await stat(inputPath).then(() => true, (error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  });
}

function githubApiUrl(...pathSegments: string[]): URL {
  const url = new URL("https://api.github.com/");
  url.pathname = `/${pathSegments.map((segment) => encodeURIComponent(segment)).join("/")}`;
  return validateGitHubApiUrl(url);
}

function validateGitHubApiUrl(input: string | URL): URL {
  const url = typeof input === "string" ? new URL(input) : input;
  if (url.protocol !== "https:" || url.hostname.toLocaleLowerCase("en-US") !== "api.github.com") {
    throw new Error(`unexpected GitHub API host: ${url.hostname}`);
  }
  return url;
}

function validateGitHubArchiveUrl(input: string | URL): URL {
  const url = typeof input === "string" ? new URL(input) : input;
  const host = url.hostname.toLocaleLowerCase("en-US");
  if (url.protocol !== "https:" || (host !== "api.github.com" && host !== "codeload.github.com")) {
    throw new Error(`unexpected GitHub archive download host: ${url.hostname}`);
  }
  return url;
}

function githubRequestHeaders(url: URL): Record<string, string> {
  const headers: Record<string, string> = {
    "accept": "application/vnd.github+json",
    "user-agent": "preflightseal"
  };
  const token = githubAuthToken();
  if (token && url.hostname.toLocaleLowerCase("en-US") === "api.github.com") {
    headers.authorization = `Bearer ${token}`;
  }
  return headers;
}

function githubAuthToken(): string | null {
  for (const name of ["PREFLIGHTSEAL_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]) {
    const value = process.env[name]?.trim();
    if (value && !/[\r\n]/.test(value)) {
      return value;
    }
  }
  return null;
}

function stringMetadata(source: SourceIdentity, field: string): string | undefined {
  const value = source.metadata?.[field];
  return typeof value === "string" ? value : undefined;
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
