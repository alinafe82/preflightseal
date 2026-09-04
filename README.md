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
  safely extracted archive
- inventory agent-relevant files and executable surfaces
- detect high-risk install behavior with deterministic native rules
- produce a content-integrity seal over the reviewed source, evidence, policy,
  target, preconditions, and operation plan
- install approved Codex instruction files transactionally
- verify or roll back the receipt without destroying later user changes

Additional target runtimes, deeper package analysis, attestation verification,
and signed seals are extension points. They are not claimed as complete in this
release.

## Requirements

- Node.js 24 or newer
- macOS, Linux, or another POSIX-like environment for the current CLI slice

PreflightSeal does not run code from inspected repositories during acquire,
inspect, analyze, or plan.

## Install From Source

```sh
git clone https://github.com/preflightseal/preflightseal.git
cd preflightseal
npm test
node src/cli.ts --help
```

For local dogfooding from this checkout:

```sh
npm link
preflightseal --help
```

## Commands

```sh
preflightseal inspect <source> [--json]
preflightseal plan <source> --target codex --target-root <dir> --out plan.json
preflightseal install plan.json [--accept-warning PFS-CODEX-INSTRUCTIONS]
preflightseal verify <receipt.json>
preflightseal rollback <receipt.json>
preflightseal explain <plan-or-receipt.json>
```

`BLOCK` and `INCONCLUSIVE` plans cannot be installed. `WARN` plans require
explicit acceptance of each warning id at install time.

## Example

```sh
mkdir -p /tmp/agent-source /tmp/agent-target
printf '# Project guidance\n' > /tmp/agent-source/AGENTS.md

preflightseal plan /tmp/agent-source \
  --target codex \
  --target-root /tmp/agent-target \
  --out /tmp/preflightseal-plan.json

preflightseal install /tmp/preflightseal-plan.json
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

See:

- [Threat Model](docs/threat-model.md)
- [Architecture](docs/architecture.md)
- [Product Boundaries](docs/product-boundaries.md)
- [Research](docs/research.md)
- [Competitive Landscape](docs/competitive-landscape.md)

## Development

```sh
npm test
npm run check
npm run smoke
```

Before release, run a repository-wide contamination and secret audit, then run
the test suite from a clean checkout.
