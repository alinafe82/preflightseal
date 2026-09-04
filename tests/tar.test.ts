import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { extractGitHubTarBuffer, parseTar } from "../src/acquire/tar.ts";

test("safe GitHub tar extraction strips the archive root", async () => {
  const target = await mkdtemp(path.join(os.tmpdir(), "pfs-tar-"));
  const archive = makeTar([
    { name: "owner-repo-sha/AGENTS.md", type: "0", content: "# ok\n" }
  ]);

  const result = await extractGitHubTarBuffer(archive, target);

  assert.equal(result.files, 1);
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

test("tar parser rejects case-insensitive normalized collisions", () => {
  const archive = makeTar([
    { name: "owner-repo-sha/Readme.md", type: "0", content: "a" },
    { name: "owner-repo-sha/README.md", type: "0", content: "b" }
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
