import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { validateDestinationForWrite, validateRelativePath } from "../src/util/path.ts";
import { createInventory } from "../src/inventory.ts";

test("relative path validation rejects traversal and platform escapes", () => {
  assert.throws(() => validateRelativePath("../AGENTS.md"), /unsafe segment|escapes/);
  assert.throws(() => validateRelativePath("/tmp/AGENTS.md"), /escapes/);
  assert.throws(() => validateRelativePath("C:/Users/name/file"), /escapes/);
  assert.equal(validateRelativePath("nested/AGENTS.md"), "nested/AGENTS.md");
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
