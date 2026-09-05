# PreflightSeal

**Inspect before install. Install only what you inspected.**

PreflightSeal is pre-install security for AI agent software. It turns untrusted
agent repositories and local directories into immutable, evidence-backed
installation plans, applies only policy-approved changes, and leaves a
verifiable receipt.

The core invariant is:

```text
inspected bytes == approved bytes == installed bytes
```

If PreflightSeal cannot prove that invariant, installation does not begin.

## Status

PreflightSeal is an early CLI-first project. Version 0.1 focuses on a narrow,
testable transactional slice:

- inspect a local directory without executing repository code
- acquire a public GitHub HTTPS repository by immutable commit and inspect the
  safely extracted, digest-addressed archive
- inventory agent-relevant files and executable surfaces
- detect high-risk install behavior with deterministic native rules
- produce a content-integrity seal over the reviewed source, evidence, policy,
  target, preconditions, and operation plan
- install approved Codex instruction files from the frozen source without
  re-resolving remote refs
- use a target-scoped transaction lock during mutation
- verify or roll back transaction-scoped receipts without destroying later user
  changes or unrelated receipts

Additional target runtimes, deeper package analysis, attestation verification,
and signed seals are extension points. They are not claimed as complete in this
release.

## Requirements

- Node.js 24 or newer
- macOS, Linux, or another POSIX-like environment for the current CLI slice

PreflightSeal does not run code from inspected repositories during acquire,
inspect, analyze, or plan.

## Install

```sh
npm install -g preflightseal
preflightseal --help
```

## Install From Source

```sh
git clone https://github.com/alinafe82/preflightseal.git
cd preflightseal
npm test
node src/cli.ts --help
```

For local dogfooding from this checkout:

```sh
npm run build
npm link
preflightseal --help
```

## Commands

```sh
preflightseal inspect <source> [--json]
preflightseal plan <source> --target codex --target-root <dir> --out plan.json
preflightseal install plan.json [--accept-warning pfs1:sha256:...]
preflightseal verify <receipt.json>
preflightseal rollback <receipt.json>
preflightseal explain <plan-or-receipt.json>
```

`BLOCK` and `INCONCLUSIVE` plans cannot be installed. `WARN` plans require
explicit acceptance of each warning fingerprint at install time.

## Example

```sh
mkdir -p /tmp/agent-source /tmp/agent-target
printf '# Project guidance\n' > /tmp/agent-source/AGENTS.md

preflightseal plan /tmp/agent-source \
  --target codex \
  --target-root /tmp/agent-target \
  --out /tmp/preflightseal-plan.json

preflightseal install /tmp/preflightseal-plan.json \
  --accept-warning pfs1:sha256:...
preflightseal verify /tmp/agent-target/.preflightseal/receipts/*.json
```

The install command writes only the files listed in the sealed plan. It refuses
to install if the source bytes, target preconditions, policy, analyzer evidence,
or operation list no longer match the seal.

## Decision States

PreflightSeal uses four states:

- `ALLOW`: required evidence exists and policy permits installation
- `WARN`: behavior is understood, but explicit human acceptance is required
- `BLOCK`: known behavior violates policy
- `INCONCLUSIVE`: required evidence is missing, partial, timed out, or unsafe to
  interpret

`INCONCLUSIVE` never silently becomes `ALLOW`.

## Security Model

Assume every byte of the source is malicious. Repository documentation is data,
not authority. PreflightSeal parses files, hashes bytes, and builds a plan; it
does not run repository installers, package lifecycle scripts, hooks, MCP
servers, or shell snippets during inspection.

GitHub sources are frozen into a local content-addressed cache. A persisted plan
records the remote identity separately from the immutable cache locator, and
`install` consumes the cached artifact instead of contacting GitHub again.

Optional external scanner providers must be explicitly configured by the
operator. The Snyk Agent Scan provider requires `PREFLIGHTSEAL_SNYK_AGENT_SCAN`
to point at an absolute trusted executable path and runs with an isolated
temporary `HOME`; it does not dynamically fetch a scanner as the default path.

## Known Limitations

- Only the `codex` target is implemented.
- Automatic writes are limited to statically modeled instruction and skill
  files.
- Hooks, MCP registration, broad config replacement, dependency vulnerability
  scanning, signed attestations, and Windows path semantics are not implemented
  in v0.1.
- Warning acceptance uses stable finding fingerprints. The same warning rule on
  different evidence must be accepted separately.

See:

- [Threat Model](docs/threat-model.md)
- [Architecture](docs/architecture.md)
- [Product Boundaries](docs/product-boundaries.md)
- [Research](docs/research.md)
- [Competitive Landscape](docs/competitive-landscape.md)
- [Publication Security](docs/publication-security.md)
- [Release Process](docs/release-process.md)

## Development

```sh
npm test
npm run check
npm run smoke
npm run schemas:check
npm run coverage
npm run dogfood:fixtures
npm run dogfood:self
```

`dogfood:self` checks the canonical public GitHub source first and falls back
to the current checkout outside CI when that source is unavailable.

Before release, run a repository-wide contamination and secret audit, then run
the test suite from a clean checkout.
