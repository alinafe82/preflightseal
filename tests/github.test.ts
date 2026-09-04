import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { Readable } from "node:stream";

import { acquireGitHubSource, archiveIdentityDigest, extractCompressedGitHubTarball, isGitHubHttpsSource, parseGitHubSource, resolveCachedGitHubSourceRoot } from "../src/acquire/github.ts";
import { installPlan } from "../src/install/transaction.ts";
import { createPlan, inspectSource, readPlan } from "../src/plan.ts";

test("GitHub source parser canonicalizes public HTTPS repository URLs", () => {
  const parsed = parseGitHubSource("https://github.com/Owner/repo.git#main");
  assert.equal(parsed.owner, "Owner");
  assert.equal(parsed.repo, "repo");
  assert.equal(parsed.requestedRef, "main");
  assert.equal(parsed.canonicalUrl, "https://github.com/Owner/repo");
});

test("GitHub source parser rejects embedded credentials", () => {
  assert.throws(
    () => parseGitHubSource("https://token@github.com/owner/repo"),
    /embedded credentials/
  );
});

test("GitHub source parser rejects ambiguous repository paths", () => {
  assert.throws(
    () => parseGitHubSource("https://github.com/owner/repo/tree/main"),
    /exactly owner and repository/
  );
});

test("GitHub source parser rejects non-HTTPS hosts and unsupported owner names", () => {
  assert.throws(() => parseGitHubSource("http://github.com/owner/repo"), /public GitHub HTTPS/);
  assert.throws(() => parseGitHubSource("https://example.com/owner/repo"), /public GitHub HTTPS/);
  assert.throws(() => parseGitHubSource("https://github.com/owner!/repo"), /unsupported characters/);
});

test("GitHub source parser uses explicit requested ref without hash", () => {
  assert.equal(parseGitHubSource("https://github.com/owner/repo", "release").requestedRef, "release");
});

test("GitHub acquisition encodes refs as a single API path segment", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  let requestedEncodedRef = false;

  try {
    const archive = gzipSync(makeTar([
      { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# encoded ref\n" }
    ]));
    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo/commits/feature%2Fhardening") {
        requestedEncodedRef = true;
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      if (url === "https://api.github.com/repos/owner/repo/tarball/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
        return new Response(archive, { status: 200 });
      }
      throw new Error(`unexpected GitHub request: ${url}`);
    };

    const acquired = await acquireGitHubSource("https://github.com/owner/repo#feature%2Fhardening");

    assert.equal(requestedEncodedRef, true);
    assert.equal(acquired.source.requestedRef, "feature/hardening");
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub source detection is narrow", () => {
  assert.equal(isGitHubHttpsSource("https://github.com/owner/repo"), true);
  assert.equal(isGitHubHttpsSource("git@github.com:owner/repo.git"), false);
  assert.equal(isGitHubHttpsSource("https://example.com/owner/repo"), false);
});

test("persisted GitHub plans install the frozen reviewed source without remote access", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-target-"));
  const cache = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  const planDir = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-plan-"));
  const planPath = path.join(planDir, "plan.json");
  process.env.PREFLIGHTSEAL_CACHE_DIR = cache;

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# reviewed from commit a\n" }
      ]))
    });

    await createPlan("https://github.com/owner/repo#main", {
      target: "codex",
      targetRoot: target,
      out: planPath,
      scanners: []
    });
    const persistedPlan = await readPlan(planPath);

    globalThis.fetch = async () => {
      throw new Error("install must not contact GitHub");
    };

    await installPlan(persistedPlan, { acceptedWarningFingerprints: persistedPlan.warningFingerprints });

    assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# reviewed from commit a\n");
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCacheDir === undefined) {
      delete process.env.PREFLIGHTSEAL_CACHE_DIR;
    } else {
      process.env.PREFLIGHTSEAL_CACHE_DIR = originalCacheDir;
    }
  }
});

test("GitHub plan apply keeps the approved frozen bytes after the remote ref changes", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-target-"));
  const cache = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = cache;

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# approved bytes\n" }
      ]))
    });

    const plan = JSON.parse(JSON.stringify(await createPlan("https://github.com/owner/repo#main", {
      target: "codex",
      targetRoot: target,
      scanners: []
    })));

    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      archive: gzipSync(makeTar([
        { name: "owner-repo-bbbbbbbb/AGENTS.md", type: "0", content: "# changed remote bytes\n" }
      ]))
    });

    await installPlan(plan, { acceptedWarningFingerprints: plan.warningFingerprints });

    assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# approved bytes\n");
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCacheDir === undefined) {
      delete process.env.PREFLIGHTSEAL_CACHE_DIR;
    } else {
      process.env.PREFLIGHTSEAL_CACHE_DIR = originalCacheDir;
    }
  }
});

test("GitHub inspect uses the normal remote acquisition path", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# reviewed inspect\n" }
      ]))
    });

    const result = await inspectSource("https://github.com/owner/repo#main");

    assert.equal(result.source.kind, "github");
    assert.equal(result.source.resolvedRevision, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert.equal(result.analyzerResults[0].providerId, "native-install-boundary");
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub plan apply fails closed when the frozen source cache is missing", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-target-"));
  const cache = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = cache;

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# reviewed bytes\n" }
      ]))
    });

    const plan = await createPlan("https://github.com/owner/repo#main", {
      target: "codex",
      targetRoot: target,
      scanners: []
    });
    await rm(path.join(cache, plan.source.cacheKey ?? ""), { recursive: true, force: true });

    await assert.rejects(
      installPlan(plan, { acceptedWarningFingerprints: plan.warningFingerprints }),
      /PFS_FROZEN_SOURCE_MISSING/
    );
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCacheDir === undefined) {
      delete process.env.PREFLIGHTSEAL_CACHE_DIR;
    } else {
      process.env.PREFLIGHTSEAL_CACHE_DIR = originalCacheDir;
    }
  }
});

test("GitHub frozen source resolver rejects wrong identity and cache metadata", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# reviewed bytes\n" }
      ]))
    });
    const acquired = await acquireGitHubSource("https://github.com/owner/repo#main");

    await assert.rejects(resolveCachedGitHubSourceRoot({ ...acquired.source, kind: "local" }), /source identity is not GitHub/);
    await assert.rejects(resolveCachedGitHubSourceRoot({ ...acquired.source, archiveSha256: undefined, metadata: {} }), /missing archive digest/);
    await assert.rejects(resolveCachedGitHubSourceRoot({ ...acquired.source, cacheKey: `sha256/${"0".repeat(64)}` }), /cache key does not match/);
    await assert.rejects(resolveCachedGitHubSourceRoot({ ...acquired.source, immutableLocator: `preflightseal-cache:sha256/${"0".repeat(64)}` }), /immutable locator does not match/);

    const metadataDigestOnly = { ...acquired.source, archiveSha256: undefined };
    assert.equal(await resolveCachedGitHubSourceRoot(metadataDigestOnly), acquired.sourceRoot);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub frozen source resolver rejects corrupted cache archives and content", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const cache = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = cache;

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# reviewed bytes\n" }
      ]))
    });
    const acquired = await acquireGitHubSource("https://github.com/owner/repo#main");
    await writeFile(path.join(cache, acquired.source.cacheKey ?? "", "source.tar.gz"), "corrupted");
    await assert.rejects(resolveCachedGitHubSourceRoot(acquired.source), /archive digest mismatch/);

    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      archive: gzipSync(makeTar([
        { name: "owner-repo-bbbbbbbb/AGENTS.md", type: "0", content: "# reviewed unique bytes\n" }
      ]))
    });
    const acquiredContent = await acquireGitHubSource("https://github.com/owner/repo#main");
    await writeFile(path.join(cache, acquiredContent.source.cacheKey ?? "", "source", "AGENTS.md"), "# corrupted content\n");
    await assert.rejects(resolveCachedGitHubSourceRoot(acquiredContent.source), /source digest mismatch/);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub archive redirects fail closed on unexpected hosts", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-target-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      if (url === "https://api.github.com/repos/owner/repo/commits/main") {
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      if (url === "https://api.github.com/repos/owner/repo/tarball/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
        return new Response(null, {
          status: 302,
          headers: { location: "https://example.com/archive.tar.gz" }
        });
      }
      throw new Error(`unexpected GitHub request: ${url}`);
    };

    await assert.rejects(
      createPlan("https://github.com/owner/repo#main", {
        target: "codex",
        targetRoot: target,
        scanners: []
      }),
      /unexpected GitHub archive download host/
    );
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCacheDir === undefined) {
      delete process.env.PREFLIGHTSEAL_CACHE_DIR;
    } else {
      process.env.PREFLIGHTSEAL_CACHE_DIR = originalCacheDir;
    }
  }
});

test("GitHub acquisition follows codeload redirects and records archive identity", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    const archive = gzipSync(makeTar([
      { name: "owner-repo-aaaaaaaa/AGENTS.md", type: "0", content: "# redirected\n" }
    ]));
    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      if (url === "https://api.github.com/repos/owner/repo/commits/main") {
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      if (url === "https://api.github.com/repos/owner/repo/tarball/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
        return new Response(null, {
          status: 302,
          headers: { location: "https://codeload.github.com/owner/repo/tar.gz/aaaaaaaa" }
        });
      }
      if (url === "https://codeload.github.com/owner/repo/tar.gz/aaaaaaaa") {
        return new Response(archive, { status: 200 });
      }
      throw new Error(`unexpected GitHub request: ${url}`);
    };

    const acquired = await acquireGitHubSource("https://github.com/owner/repo#main");

    assert.equal(acquired.source.resolvedRevision, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert.equal(acquired.source.metadata?.archiveByteLength, archive.length);
    assert.equal(Array.isArray(acquired.source.metadata?.redirectChain), true);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub acquisition rejects invalid API shapes and commit SHAs", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    globalThis.fetch = async () => new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /non-object/);

    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      return jsonResponse({ sha: "not-a-sha" });
    };
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /invalid commit SHA/);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub acquisition rejects archive redirect and HTTP failures", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      if (url === "https://api.github.com/repos/owner/repo/commits/main") {
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      return new Response(null, { status: 302 });
    };
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /redirect did not include a location/);

    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      if (url === "https://api.github.com/repos/owner/repo/commits/main") {
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      return new Response("no", { status: 500 });
    };
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /archive download failed: HTTP 500/);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub acquisition rejects API HTTP failures and archive redirect loops", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  process.env.PREFLIGHTSEAL_CACHE_DIR = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));

  try {
    globalThis.fetch = async () => new Response("no", { status: 500 });
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /API request failed: HTTP 500/);

    globalThis.fetch = async (urlInput: string | URL | Request) => {
      const url = String(urlInput);
      if (url === "https://api.github.com/repos/owner/repo") {
        return jsonResponse({ default_branch: "main" });
      }
      if (url === "https://api.github.com/repos/owner/repo/commits/main") {
        return jsonResponse({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
      }
      return new Response(null, {
        status: 302,
        headers: { location: "https://codeload.github.com/owner/repo/tar.gz/aaaaaaaa" }
      });
    };
    await assert.rejects(acquireGitHubSource("https://github.com/owner/repo"), /redirect limit exceeded/);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("failed GitHub archive validation leaves no promoted cache object", async () => {
  const originalFetch = globalThis.fetch;
  const originalCacheDir = process.env.PREFLIGHTSEAL_CACHE_DIR;
  const cache = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-cache-"));
  process.env.PREFLIGHTSEAL_CACHE_DIR = cache;

  try {
    installMockGitHubFetch({
      defaultBranch: "main",
      commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      archive: gzipSync(makeTar([
        { name: "owner-repo-aaaaaaaa/link", type: "2", content: "" }
      ]))
    });

    await assert.rejects(
      acquireGitHubSource("https://github.com/owner/repo#main"),
      /link entries/
    );
    await assert.rejects(stat(path.join(cache, "sha256")), /ENOENT/);
    assert.deepEqual(await readdir(path.join(cache, "tmp")).catch(() => []), []);
  } finally {
    globalThis.fetch = originalFetch;
    restoreCacheEnv(originalCacheDir);
  }
});

test("GitHub archive decompression enforces an expansion limit", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-stream-"));
  await assert.rejects(
    extractCompressedGitHubTarball(
      Readable.from(gzipSync(makeTar([
        { name: "owner-repo-sha/big.txt", type: "0", content: "x".repeat(2048) }
      ]))),
      path.join(target, "source.tar.gz"),
      path.join(target, "source"),
      { maxDecompressedBytes: 1024 }
    ),
    /PFS_ARCHIVE_LIMIT/
  );
});

test("GitHub archive download enforces a compressed byte limit", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-gh-stream-"));
  await assert.rejects(
    extractCompressedGitHubTarball(
      Readable.from(gzipSync(makeTar([
        { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
      ]))),
      path.join(target, "source.tar.gz"),
      path.join(target, "source"),
      { maxCompressedBytes: 16 }
    ),
    /compressed archive exceeds/
  );
});

test("archive identity digest is deterministic", () => {
  assert.equal(archiveIdentityDigest({ a: 1 }), archiveIdentityDigest({ a: 1 }));
});

function installMockGitHubFetch(input: {
  defaultBranch: string;
  commit: string;
  archive: Buffer;
}): void {
  globalThis.fetch = async (urlInput: string | URL | Request) => {
    const url = String(urlInput);
    if (url === "https://api.github.com/repos/owner/repo") {
      return jsonResponse({ default_branch: input.defaultBranch });
    }
    if (url === `https://api.github.com/repos/owner/repo/commits/${input.defaultBranch}`) {
      return jsonResponse({ sha: input.commit });
    }
    if (url === `https://api.github.com/repos/owner/repo/tarball/${input.commit}`) {
      return new Response(input.archive, {
        status: 200,
        headers: { "content-type": "application/gzip" }
      });
    }
    throw new Error(`unexpected GitHub request: ${url}`);
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}

function restoreCacheEnv(value: string | undefined): void {
  if (value === undefined) {
    delete process.env.PREFLIGHTSEAL_CACHE_DIR;
  } else {
    process.env.PREFLIGHTSEAL_CACHE_DIR = value;
  }
}

function makeTar(entries: Array<{ name: string; type: string; content: string }>): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.content);
    const header = Buffer.alloc(512);
    writeString(header, 0, 100, entry.name);
    writeOctal(header, 100, 8, 0o644);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, content.length);
    writeOctal(header, 136, 12, 0);
    header.fill(" ", 148, 156);
    writeString(header, 156, 1, entry.type);
    writeString(header, 257, 6, "ustar");
    writeString(header, 263, 2, "00");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeOctal(header, 148, 8, checksum);
    chunks.push(header, content, Buffer.alloc(Math.ceil(content.length / 512) * 512 - content.length));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function writeString(buffer: Buffer, offset: number, length: number, value: string): void {
  buffer.write(value, offset, Math.min(length, Buffer.byteLength(value)), "utf8");
}

function writeOctal(buffer: Buffer, offset: number, length: number, value: number): void {
  const raw = value.toString(8).padStart(length - 2, "0");
  buffer.write(`${raw}\0 `, offset, length, "ascii");
}
