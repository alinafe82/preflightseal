import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";

import { extractGitHubTarBuffer, extractGitHubTarStream, parseTar } from "../src/acquire/tar.ts";

test("safe GitHub tar extraction strips the archive root", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-"));
  const archive = makeTar([
    { name: "owner-repo-sha/.github/", type: "5", content: "" },
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
  ]);

  const result = await extractGitHubTarBuffer(archive, target);

  assert.equal(result.files, 1);
  assert.equal(result.directories, 1);
  assert.equal(await readFile(path.join(target, "AGENTS.md"), "utf8"), "# ok\n");
});

test("tar parser rejects traversal entries", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/../escape.txt", type: "0", content: "nope" }
  ]);
  assert.throws(() => parseTar(archive), /unsafe segment|escapes/);
});

test("tar parser rejects symlink entries", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/link", type: "2", content: "" }
  ]);
  assert.throws(() => parseTar(archive), /link entries/);
});

test("tar parser rejects hardlink entries", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/link", type: "1", content: "" }
  ]);
  assert.throws(() => parseTar(archive), /link entries/);
});

test("tar parser rejects unsupported special file entries", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/fifo", type: "6", content: "" }
  ]);
  assert.throws(() => parseTar(archive), /unsupported archive entry type/);
});

test("tar parser rejects extended headers", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/pax", type: "x", content: "" }
  ]);
  assert.throws(() => parseTar(archive), /extended headers/);
});

test("tar parser rejects case-insensitive normalized collisions", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/Readme.md", type: "0", content: "a" },
    { name: "owner-repo-sha/README.md", type: "0", content: "b" }
  ]);
  assert.throws(() => parseTar(archive), /collision/);
});

test("tar parser rejects unicode-normalized path collisions", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/e\u0301.txt", type: "0", content: "a" },
    { name: "owner-repo-sha/\u00e9.txt", type: "0", content: "b" }
  ]);
  assert.throws(() => parseTar(archive), /collision/);
});

test("tar parser rejects duplicate normalized paths even when identical", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/README.md", type: "0", content: "a" },
    { name: "owner-repo-sha/README.md", type: "0", content: "b" }
  ]);
  assert.throws(() => parseTar(archive), /collision/);
});

test("tar parser rejects raw absolute and backslash paths before stripping root", () => {
  assert.throws(() => parseTar(makeTar([
    { name: "/owner-repo-sha/AGENTS.md", type: "0", content: "a" }
  ])), /absolute/);
  assert.throws(() => parseTar(makeTar([
    { name: "owner-repo-sha\\AGENTS.md", type: "0", content: "a" }
  ])), /backslashes/);
});

test("tar parser skips root-only entries and rejects corrupt metadata", () => {
  assert.equal(parseTar(makeTar([
    { name: "owner-repo-sha", type: "5", content: "" },
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
  ])).length, 1);
  assert.equal(parseTar(makeTar([
    { name: "owner-repo-sha/", type: "5", content: "" }
  ])).length, 0);
  assert.throws(() => parseTar(makeTar([
    { name: "", type: "0", content: "x" }
  ])), /empty/);

  const badChecksum = Buffer.from(makeTar([
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
  ]));
  badChecksum[0] = 0x7a;
  assert.throws(() => parseTar(badChecksum), /checksum mismatch/);

  const badOctal = Buffer.from(makeTar([
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
  ]));
  badOctal.write("zzzzzz", 124, 6, "ascii");
  badOctal.fill(" ", 148, 156);
  writeOctal(badOctal, 148, 8, badOctal.subarray(0, 512).reduce((sum, byte) => sum + byte, 0));
  assert.throws(() => parseTar(badOctal), /invalid tar octal/);
});

test("tar parser enforces entry count and normalized path length limits", () => {
  assert.throws(() => parseTar(makeTar([
    { name: "owner-repo-sha/dir-a/", type: "5", content: "" },
    { name: "owner-repo-sha/dir-b/", type: "5", content: "" }
  ]), {
    maxDepth: 40,
    maxFileBytes: 1024,
    maxFiles: 1,
    maxPathLength: 1024,
    maxTotalBytes: 1024
  }), /entry count/);

  assert.throws(() => parseTar(makeTar([
    { name: `owner-repo-sha/${"a".repeat(20)}`, type: "0", content: "x" }
  ]), {
    maxDepth: 40,
    maxFileBytes: 1024,
    maxFiles: 10,
    maxPathLength: 10,
    maxTotalBytes: 1024
  }), /path length/);
});

test("tar parser enforces depth, single-file, and total byte limits", () => {
  assert.throws(() => parseTar(makeTar([
    { name: "owner-repo-sha/a/b/c/file.txt", type: "0", content: "x" }
  ]), {
    maxDepth: 2,
    maxFileBytes: 1024,
    maxFiles: 10,
    maxPathLength: 1024,
    maxTotalBytes: 1024
  }), /maximum depth/);

  assert.throws(() => parseTar(makeTar([
    { name: "owner-repo-sha/big.txt", type: "0", content: "x".repeat(20) }
  ]), {
    maxDepth: 40,
    maxFileBytes: 10,
    maxFiles: 10,
    maxPathLength: 1024,
    maxTotalBytes: 1024
  }), /maximum file size/);

  assert.throws(() => parseTar(makeTar([
    { name: "owner-repo-sha/a.txt", type: "0", content: "12345" },
    { name: "owner-repo-sha/b.txt", type: "0", content: "67890" }
  ]), {
    maxDepth: 40,
    maxFileBytes: 10,
    maxFiles: 10,
    maxPathLength: 1024,
    maxTotalBytes: 8
  }), /maximum total size/);
});

test("streaming tar extraction handles chunked file content without buffering archive", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  const archive = makeTar([
    { name: "owner-repo-sha/dir/", type: "5", content: "" },
    { name: "owner-repo-sha/dir/AGENTS.md", type: "0", content: "# streamed\n" }
  ]);

  const result = await extractGitHubTarStream(chunked(archive, 17), target);

  assert.equal(result.files, 1);
  assert.equal(result.directories, 1);
  assert.equal(await readFile(path.join(target, "dir", "AGENTS.md"), "utf8"), "# streamed\n");
});

test("streaming tar extraction cleans destination on validation failure", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  const archive = makeTar([
    { name: "owner-repo-sha/../escape.txt", type: "0", content: "nope" }
  ]);

  await assert.rejects(
    extractGitHubTarStream(Readable.from(archive), target),
    /unsafe segment|escapes/
  );
  await assert.rejects(stat(target), /ENOENT/);
});

test("streaming tar extraction enforces per-file and total byte limits", async () => {
  const fileTarget = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  await assert.rejects(
    extractGitHubTarStream(Readable.from(makeTar([
      { name: "owner-repo-sha/big.txt", type: "0", content: "x".repeat(20) }
    ])), fileTarget, {
      maxDepth: 40,
      maxFileBytes: 10,
      maxFiles: 10,
      maxPathLength: 1024,
      maxTotalBytes: 1024
    }),
    /maximum file size/
  );

  const totalTarget = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  await assert.rejects(
    extractGitHubTarStream(Readable.from(makeTar([
      { name: "owner-repo-sha/a.txt", type: "0", content: "12345" },
      { name: "owner-repo-sha/b.txt", type: "0", content: "67890" }
    ])), totalTarget, {
      maxDepth: 40,
      maxFileBytes: 10,
      maxFiles: 10,
      maxPathLength: 1024,
      maxTotalBytes: 8
    }),
    /maximum total size/
  );
});

test("streaming tar extraction rejects truncated archives", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  const archive = makeTar([
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# partial\n" }
  ]).subarray(0, 700);

  await assert.rejects(
    extractGitHubTarStream(Readable.from(archive), target),
    /ended before/
  );
});

test("streaming tar extraction rejects header-only file and empty streams", async () => {
  const headerOnlyTarget = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  const headerOnly = makeTar([
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# partial\n" }
  ]).subarray(0, 512);

  await assert.rejects(
    extractGitHubTarStream(Readable.from(headerOnly), headerOnlyTarget),
    /file content completed/
  );

  const emptyTarget = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  await assert.rejects(
    extractGitHubTarStream(Readable.from(Buffer.alloc(0)), emptyTarget),
    /before trailer/
  );
});

test("streaming tar extraction rejects truncated skipped root content", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-stream-"));
  const archive = makeTar([
    { name: "owner-repo-sha", type: "0", content: "root content" }
  ]).subarray(0, 520);

  await assert.rejects(
    extractGitHubTarStream(Readable.from(archive), target),
    /skipped entry content|padding|trailer/
  );
});

function chunked(buffer: Buffer, size: number): AsyncIterable<Buffer> {
  async function* generate(): AsyncIterable<Buffer> {
    for (let offset = 0; offset < buffer.length; offset += size) {
      yield buffer.subarray(offset, offset + size);
    }
  }
  return generate();
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
