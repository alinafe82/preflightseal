import test from "node:test";
import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { acquireLocalSource, resolveCachedLocalSourceRoot } from "../src/acquire/local.ts";
import { createInventory } from "../src/inventory.ts";
import type { SourceIdentity } from "../src/types.ts";

test("local freeze preserves safe relative symlink metadata without following it", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await mkdir(path.join(source, "docs"));
  await writeFile(path.join(source, "docs", "reviewed.txt"), "reviewed\n");
  await symlink("docs/reviewed.txt", path.join(source, "link.txt"));

  const frozen = await acquireLocalSource(source);
  const inventory = await createInventory(frozen.root);
  const linkEntry = inventory.entries.find((entry) => entry.path === "link.txt");

  assert.equal(linkEntry?.type, "symlink");
  assert.equal(linkEntry?.symlinkTarget, "docs/reviewed.txt");
});

test("local freeze rejects symlink targets outside source root", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  await writeFile(path.join(outside, "secret.txt"), "secret\n");
  await symlink(path.relative(source, path.join(outside, "secret.txt")), path.join(source, "escape.txt"));

  await assert.rejects(
    acquireLocalSource(source),
    /symlink target escapes source root/
  );
});

test("local freeze rejects absolute symlink targets", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  const outside = await mkdtemp(path.join(os.tmpdir(), "pfs-outside-"));
  const absoluteTarget = path.join(outside, "secret.txt");
  await writeFile(absoluteTarget, "secret\n");
  await symlink(absoluteTarget, path.join(source, "absolute.txt"));

  await assert.rejects(
    acquireLocalSource(source),
    /unsafe absolute/
  );
});

test("local freeze rejects hard-linked source files", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  await link(path.join(source, "AGENTS.md"), path.join(source, "copy.md"));

  await assert.rejects(
    acquireLocalSource(source),
    /multiple hard links/
  );
});

test("local freeze rejects file type changes during snapshot", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), `# reviewed type change ${Date.now()}\n`);

  await assert.rejects(
    acquireLocalSource(source, {
      async onAfterInitialInventory() {
        await rm(path.join(source, "AGENTS.md"));
        await mkdir(path.join(source, "AGENTS.md"));
      }
    }),
    /changed type/
  );
});

test("local freeze rejects file size changes during snapshot", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), `# reviewed size change ${Date.now()}\n`);

  await assert.rejects(
    acquireLocalSource(source, {
      async onAfterInitialInventory() {
        await writeFile(path.join(source, "AGENTS.md"), "# reviewed with extra bytes\n");
      }
    }),
    /changed size|changed during freeze/
  );
});

test("local freeze rejects a source file that cannot be safely opened after inventory", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  const filePath = path.join(source, "AGENTS.md");
  await writeFile(filePath, `# unreadable ${Date.now()}\n`);

  try {
    await assert.rejects(
      acquireLocalSource(source, {
        async onAfterInitialInventory() {
          await chmod(filePath, 0o000);
        }
      }),
      /cannot be safely opened/
    );
  } finally {
    await chmod(filePath, 0o600).catch(() => undefined);
  }
});

test("local freeze rejects symlink target changes during snapshot", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "a.txt"), "a\n");
  await writeFile(path.join(source, "b.txt"), "b\n");
  await symlink("a.txt", path.join(source, "link.txt"));

  await assert.rejects(
    acquireLocalSource(source, {
      async onAfterInitialInventory() {
        await rm(path.join(source, "link.txt"));
        await symlink("b.txt", path.join(source, "link.txt"));
      }
    }),
    /symlink changed/
  );
});

test("local freeze rejects symlink targets with backslashes", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await symlink("dir\\file.txt", path.join(source, "link.txt"));

  await assert.rejects(
    acquireLocalSource(source),
    /backslashes/
  );
});

test("local freeze rejects staging mutation before snapshot verification", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), `# staging mutation ${Date.now()}\n`);

  await assert.rejects(
    acquireLocalSource(source, {
      async onBeforeSnapshotInventory(stagingSourceRoot) {
        await writeFile(path.join(stagingSourceRoot, "AGENTS.md"), "# changed in staging\n");
      }
    }),
    /local snapshot digest mismatch/
  );
});

test("local freeze fails closed when another process creates an invalid cache object before promotion", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), `# promotion race ${Date.now()}\n`);

  await assert.rejects(
    acquireLocalSource(source, {
      async onBeforePromote(_stagingDir, cacheObjectDir) {
        await mkdir(cacheObjectDir, { recursive: true });
        await writeFile(path.join(cacheObjectDir, "busy"), "occupied\n");
      }
    }),
    /cached local source tree is missing/
  );
});

test("local freeze fails closed when a competing cache object has an unsafe source locator", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), `# unsafe cache source ${Date.now()}\n`);

  await assert.rejects(
    acquireLocalSource(source, {
      async onBeforePromote(_stagingDir, cacheObjectDir) {
        await mkdir(cacheObjectDir, { recursive: true });
        await symlink("source", path.join(cacheObjectDir, "source"));
      }
    }),
    /ELOOP|too many/i
  );
});

test("local frozen source resolver rejects wrong identity and locator metadata", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), "# reviewed\n");
  const frozen = await acquireLocalSource(source);

  await assert.rejects(
    resolveCachedLocalSourceRoot({ ...frozen.metadata, kind: "github" } as SourceIdentity),
    /source identity is not local/
  );
  await assert.rejects(
    resolveCachedLocalSourceRoot({ ...frozen.metadata, cacheKey: `sha256/${"0".repeat(64)}` }),
    /cache key does not match/
  );
  await assert.rejects(
    resolveCachedLocalSourceRoot({ ...frozen.metadata, immutableLocator: `preflightseal-cache:sha256/${"0".repeat(64)}` }),
    /immutable locator does not match/
  );
});

test("local frozen source resolver rejects corrupted cache objects", async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-local-"));
  await writeFile(path.join(source, "AGENTS.md"), "# original unique cache corruption test\n");
  const frozen = await acquireLocalSource(source);
  await writeFile(path.join(frozen.root, "AGENTS.md"), "# corrupted\n");

  await assert.rejects(
    resolveCachedLocalSourceRoot(frozen.metadata),
    /cached local source digest mismatch/
  );
});
