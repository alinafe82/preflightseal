import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { assertNoNormalizedCollisions, ensureSafeParentDirectory, validateDestinationForWrite, validateRelativePath } from "../src/util/path.ts";
import { createInventory } from "../src/inventory.ts";

test("relative path validation rejects traversal and platform escapes", () => {
  assert.throws(() => validateRelativePath("../AGENTS.md"), /unsafe segment|escapes/);
  assert.throws(() => validateRelativePath("/tmp/AGENTS.md"), /escapes/);
  assert.throws(() => validateRelativePath("C:/Users/name/file"), /escapes/);
  assert.throws(() => validateRelativePath("nested//AGENTS.md"), /unsafe segment/);
  assert.throws(() => validateRelativePath("nested/./AGENTS.md"), /unsafe segment/);
  assert.throws(() => validateRelativePath("bad\u0000path"), /NUL/);
  assert.throws(() => validateRelativePath("nested\\AGENTS.md"), /backslashes/);
  assert.equal(validateRelativePath("nested/AGENTS.md"), "nested/AGENTS.md");
});

test("normalized path collision helper rejects case-fold collisions", () => {
  assert.throws(
    () => assertNoNormalizedCollisions(["Readme.md", "README.md"]),
    /normalized path collision/
  );
});

test("inventory records symlink targets without following linked file contents", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await writeFile(path.join(outside, "secret.txt"), "do-not-read");
  await symlink(path.join(outside, "secret.txt"), path.join(root, "link.txt"));

  const inventory = await createInventory(root);
  const link = inventory.entries.find((entry) => entry.path === "link.txt");

  assert.equal(link?.type, "symlink");
  assert.equal(link?.sha256, undefined);
  assert.equal(link?.symlinkTarget, path.join(outside, "secret.txt"));
});

test("destination validation rejects symlink parents", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await mkdir(path.join(root, "nested"));
  await symlink(outside, path.join(root, "nested", "link"));

  await assert.rejects(
    validateDestinationForWrite(root, "nested/link/AGENTS.md"),
    /symlink/
  );
});

test("destination validation rejects existing symlink, hard link, and directory targets", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await writeFile(path.join(root, "file.txt"), "file\n");
  await mkdir(path.join(root, "dir-target"));
  await symlink(path.join(outside, "file.txt"), path.join(root, "link-target"));
  await writeFile(path.join(root, "hard-a.txt"), "hard\n");
  await fsLink(path.join(root, "hard-a.txt"), path.join(root, "hard-b.txt"));

  await assert.rejects(validateDestinationForWrite(root, "link-target"), /symlink/);
  await assert.rejects(validateDestinationForWrite(root, "hard-a.txt"), /multiple hard links/);
  await assert.rejects(validateDestinationForWrite(root, "dir-target"), /not a file/);
});

test("safe parent creation rejects symlink replacement", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-target-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await symlink(outside, path.join(root, "parent"));

  await assert.rejects(
    ensureSafeParentDirectory(root, "parent/AGENTS.md"),
    /outside target root|not a directory|symlink/
  );
});

test("inventory reports depth and file count limit findings", async () => {
  const depthRoot = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await mkdir(path.join(depthRoot, "nested"));
  const depthInventory = await createInventory(depthRoot, {
    maxDepth: 0,
    maxFileBytes: 1024,
    maxFiles: 10,
    maxTotalBytes: 1024
  });
  assert.equal(depthInventory.findings.find((finding) => finding.id === "PFS-INVENTORY-DEPTH")?.decision, "INCONCLUSIVE");

  const countRoot = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await writeFile(path.join(countRoot, "a.txt"), "a");
  await writeFile(path.join(countRoot, "b.txt"), "b");
  const countInventory = await createInventory(countRoot, {
    maxDepth: 10,
    maxFileBytes: 1024,
    maxFiles: 1,
    maxTotalBytes: 1024
  });
  assert.equal(countInventory.findings.find((finding) => finding.id === "PFS-FILE-COUNT")?.decision, "INCONCLUSIVE");
});

test("inventory reports oversized file and total source findings", async () => {
  const fileRoot = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await writeFile(path.join(fileRoot, "large.txt"), "12345");
  const fileInventory = await createInventory(fileRoot, {
    maxDepth: 10,
    maxFileBytes: 4,
    maxFiles: 10,
    maxTotalBytes: 100
  });
  assert.equal(fileInventory.findings.find((finding) => finding.id === "PFS-LARGE-FILE")?.decision, "INCONCLUSIVE");

  const totalRoot = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await writeFile(path.join(totalRoot, "a.txt"), "12345");
  await writeFile(path.join(totalRoot, "b.txt"), "67890");
  const totalInventory = await createInventory(totalRoot, {
    maxDepth: 10,
    maxFileBytes: 100,
    maxFiles: 10,
    maxTotalBytes: 8
  });
  assert.equal(totalInventory.findings.find((finding) => finding.id === "PFS-LARGE-SOURCE")?.decision, "INCONCLUSIVE");
});

test("inventory rejects normalized path collisions when the filesystem can represent them", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  await writeFile(path.join(root, "Readme.md"), "a");
  await writeFile(path.join(root, "README.md"), "b");
  if ((await readdir(root)).length < 2) {
    t.skip("case-insensitive filesystem collapsed the collision fixture");
    return;
  }

  await assert.rejects(createInventory(root), /normalized path collision/);
});

test("inventory reports POSIX special files as inconclusive when mkfifo is available", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-source-"));
  const fifo = path.join(root, "pipe");
  const result = spawnSync("mkfifo", [fifo]);
  if (result.status !== 0) {
    t.skip("mkfifo unavailable");
    return;
  }

  const inventory = await createInventory(root);

  assert.equal(inventory.findings.find((finding) => finding.id === "PFS-SPECIAL-FILE")?.decision, "INCONCLUSIVE");
});

async function fsLink(existingPath: string, newPath: string): Promise<void> {
  const { link } = await import("node:fs/promises");
  await link(existingPath, newPath);
}
