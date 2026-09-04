# Architecture

PreflightSeal is a CLI-first Node.js application. The trusted computing base is
kept small: core inspection, hashing, policy, planning, and transactional file
operations use Node standard-library modules.

## Runtime Flow

```text
source input
  -> acquisition/freeze
  -> deterministic inventory
  -> analyzer evidence
  -> policy evaluation
  -> operation planning
  -> content-integrity seal
  -> install from reviewed bytes
  -> receipt
  -> verify or rollback
```

## Core Modules

- `acquire/github`: canonicalizes public GitHub HTTPS repository URLs, resolves
  mutable refs to commit SHAs, downloads the exact tarball, hashes it while
  streaming, validates archive redirect hosts, and stores it as an immutable
  content-addressed cache object.
- `acquire/tar`: validates GitHub tar entries before extraction and rejects
  traversal, links, unsupported entry types, oversized content, excessive
  nesting, and normalized path collisions.
- `inventory`: walks source trees without following symlinks, hashes files,
  classifies agent-relevant artifacts, and produces a deterministic digest.
- `native analyzer`: parses known manifests and text files for install-boundary
  risk signals.
- `policy`: converts analyzer evidence into `ALLOW`, `WARN`, `BLOCK`, or
  `INCONCLUSIVE`.
- `plan`: binds immutable source identity, inventory digest, analyzer evidence,
  policy, target, preconditions, and operations into a seal.
- `transaction`: applies only sealed operations, writes receipts, verifies
  installed bytes, holds a target-scoped lock during mutation, and rolls back
  only transaction-owned changes when current bytes still match the installed
  receipt.
- `target/codex`: maps approved source artifacts to Codex target paths.

## Seal

The v0.1 seal is a content-integrity digest, not a digital signature.

```text
seal = sha256(canonical JSON({
  schema_version,
  immutable_source_identity,
  target,
  inventory_digest,
  analyzer_evidence_digest,
  policy_digest,
  operations,
  preconditions
}))
```

If source bytes, target state, analyzer evidence, policy, operations, or
preconditions change, the seal no longer authorizes installation.
Volatile acquisition timestamps are not seal inputs.

## Source Identity

GitHub source identity separates presentation metadata from the local frozen
artifact:

```text
canonical remote identity: https://github.com/<owner>/<repo>
resolved revision: commit SHA
archive digest: sha256
content digest: inventory digest of the extracted source
cache key: sha256/<archive-digest>
immutable locator: preflightseal-cache:sha256/<archive-digest>
```

Install resolves GitHub plans through the immutable cache locator and verifies
the cached archive and extracted content before applying operations. It does not
contact GitHub or resolve branches during apply.

## Transaction State

Target state is scoped by receipt and transaction:

```text
.preflightseal/
  receipts/<receipt-id>.json
  transactions/<transaction-id>/journal.json
  backups/<transaction-id>/
  rollbacks/<receipt-id>.json
  locks/<target-lock>.lock/
```

Rollback removes only files and backups owned by the receipt being rolled back
and preserves unrelated receipts, backups, rollback evidence, and installed
files.

## Target Runtime

The first target is Codex. The v0.1 operation planner only installs
instruction files that are explicitly represented in the sealed operation list.
Executable surfaces such as hooks and MCP registrations are inventoried and
treated as policy-controlled risk evidence; they are not started during
inspection.

## External Evidence Providers

External scanners are evidence providers, not policy authorities. Providers run
with `shell: false`, argument-array invocation, timeout and output limits, a
minimal environment, and an isolated temporary `HOME`. The v0.1 Snyk Agent Scan
provider requires the operator to configure an absolute trusted executable path;
it does not fetch a scanner dynamically by default.

## Extension Points

- additional source acquisition adapters
- scanner providers with machine-readable output
- additional target runtimes
- signed seals
- richer dependency graph analyzers

Extension points cannot bypass the core invariant.
