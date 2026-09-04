import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { snykAgentScanProvider } from "../src/analyzers/external.ts";
import { createInventory } from "../src/inventory.ts";
import { sanitizeEvidence } from "../src/util/text.ts";

test("external scanner requires an explicit trusted executable", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  process.env.SNYK_TOKEN = "test-token";
  delete process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 1_000 });

    assert.equal(result.status, "UNAVAILABLE");
    assert.match(result.error ?? "", /trusted scanner executable/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner is not applicable without skill files", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  await writeFile(path.join(source, "AGENTS.md"), "# demo\n");
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = "/bin/false";
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 1_000 });

    assert.equal(result.status, "NOT_APPLICABLE");
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner rejects relative executable paths", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = "scanner";
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 1_000 });

    assert.equal(result.status, "UNAVAILABLE");
    assert.match(result.error ?? "", /absolute executable path/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner requires provider token when skill files are present", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = "/bin/false";
  delete process.env.SNYK_TOKEN;

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 1_000 });

    assert.equal(result.status, "UNAVAILABLE");
    assert.match(result.error ?? "", /SNYK_TOKEN/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner spawn errors are unavailable evidence", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = path.join(source, "missing-scanner");
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 1_000 });

    assert.equal(result.status, "UNAVAILABLE");
    assert.match(result.error ?? "", /ENOENT/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner exposes a stable provider version", async () => {
  assert.equal(await snykAgentScanProvider().version(), "0.5.17");
});

test("external scanner runs with an isolated HOME and minimal environment", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "scanner.sh");
  const capturedHome = path.join(harness, "home.txt");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, `#!/bin/sh\nprintf '%s' "$HOME" > ${shellQuote(capturedHome)}\nprintf '{"findings":[]}'\n`);
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });
    const home = await readFile(capturedHome, "utf8");

    assert.equal(result.status, "PASS");
    assert.notEqual(home, env.home ?? "");
    assert.match(home, /preflightseal-analyzer-/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner timeout is explicit evidence and never pass", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "slow-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, "#!/bin/sh\nsleep 2\nprintf '{\"findings\":[]}'\n");
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 100 });

    assert.equal(result.status, "TIMEOUT");
    assert.match(result.error ?? "", /Timed out/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner malformed JSON is explicit error evidence", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "bad-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, "#!/bin/sh\nprintf 'not json SNYK_TOKEN=abc123456789secret'\n");
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });

    assert.equal(result.status, "ERROR");
    assert.match(result.error ?? "", /Scanner emitted malformed JSON/);
    assert.doesNotMatch(result.error ?? "", /abc123456789secret/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner nonzero exit without findings is explicit error evidence", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "failing-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, "#!/bin/sh\nprintf '{\"findings\":[]}'\nprintf 'scanner failed' >&2\nexit 2\n");
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });

    assert.equal(result.status, "ERROR");
    assert.match(result.error ?? "", /Scanner exited 2/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner kills excessive stdout and stderr output", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "noisy-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, "#!/bin/sh\nhead -c 6291456 /dev/zero\nhead -c 2097152 /dev/zero >&2\n");
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });

    assert.equal(result.status, "ERROR");
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner kills excessive stderr output", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "stderr-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, "#!/bin/sh\nhead -c 2097152 /dev/zero >&2\nprintf '{\"findings\":[]}'\n");
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });

    assert.notEqual(result.status, "PASS");
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner normalizes absolute source paths in findings", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "finding-scanner.sh");
  const skillPath = path.join(source, "skills", "demo", "SKILL.md");
  await mkdir(path.dirname(skillPath), { recursive: true });
  await writeFile(skillPath, "# demo\n");
  await writeFile(scanner, `#!/bin/sh\nprintf '%s' '${JSON.stringify({
    findings: [{
      ruleId: "demo",
      title: "Demo finding",
      severity: "high",
      path: skillPath,
      description: "review this"
    }]
  })}'\n`);
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });

    assert.equal(result.status, "FINDINGS");
    assert.equal(result.findings[0].path, "skills/demo/SKILL.md");
    assert.match(result.findings[0].fingerprint, /^pfs1:sha256:/);
  } finally {
    restoreScannerEnv(env);
  }
});

test("external scanner preserves outside paths and falls back to scanned skill path", async () => {
  const env = preserveScannerEnv();
  const source = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-source-"));
  const harness = await mkdtemp(path.join(os.tmpdir(), "pfs-ext-harness-"));
  const scanner = path.join(harness, "finding-scanner.sh");
  await mkdir(path.join(source, "skills", "demo"), { recursive: true });
  await writeFile(path.join(source, "skills", "demo", "SKILL.md"), "# demo\n");
  await writeFile(scanner, `#!/bin/sh\nprintf '%s' '${JSON.stringify({
    findings: [
      { ruleId: "outside", title: "Outside", severity: "low", path: "/outside/file.txt", description: "outside path" },
      { ruleId: "fallback", title: "Fallback", message: "fallback path" }
    ]
  })}'\n`);
  await chmod(scanner, 0o700);
  process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = scanner;
  process.env.SNYK_TOKEN = "test-token";

  try {
    const inventory = await createInventory(source);
    const result = await snykAgentScanProvider().scan({ sourceRoot: source, inventory, timeoutMs: 5_000 });
    const byId = new Map(result.findings.map((finding) => [finding.id, finding.path]));

    assert.equal(byId.get("SNYK-AGENT-SCAN-OUTSIDE"), "file.txt");
    assert.equal(byId.get("SNYK-AGENT-SCAN-FALLBACK"), "skills/demo/SKILL.md");
  } finally {
    restoreScannerEnv(env);
  }
});

test("evidence sanitization redacts token-shaped values", () => {
  const openAiLikeToken = `sk-${"testsecretvalue1234567890"}`;
  assert.equal(sanitizeEvidence("SNYK_TOKEN=abc123456789secret"), "[REDACTED]");
  assert.equal(sanitizeEvidence(`failed with ${openAiLikeToken}`), "failed with [REDACTED]");
});

function preserveScannerEnv(): { executable?: string; token?: string; home?: string } {
  return {
    executable: process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN,
    token: process.env.SNYK_TOKEN,
    home: process.env.HOME
  };
}

function restoreScannerEnv(env: { executable?: string; token?: string }): void {
  if (env.executable === undefined) {
    delete process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN;
  } else {
    process.env.PREFLIGHTSEAL_SNYK_AGENT_SCAN = env.executable;
  }
  if (env.token === undefined) {
    delete process.env.SNYK_TOKEN;
  } else {
    process.env.SNYK_TOKEN = env.token;
  }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}
