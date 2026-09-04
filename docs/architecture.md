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
  streaming, and stores it content-addressably.
- `acquire/tar`: validates GitHub tar entries before extraction and rejects
  traversal, links, unsupported entry types, oversized content, excessive
  nesting, and normalized path collisions.
- `inventory`: walks source trees without following symlinks, hashes files,
  classifies agent-relevant artifacts, and produces a deterministic digest.
- `native analyzer`: parses known manifests and text files for install-boundary
  risk signals.
- `policy`: converts analyzer evidence into `ALLOW`, `WARN`, `BLOCK`, or
  `INCONCLUSIVE`.
- `plan`: binds source identity, inventory digest, analyzer evidence, policy,
  target, preconditions, and operations into a seal.
- `transaction`: applies only sealed operations, writes receipts, verifies
  installed bytes, and rolls back only when current bytes still match the
  installed receipt.
- `target/codex`: maps approved source artifacts to Codex target paths.

## Seal

The v0.1 seal is a content-integrity digest, not a digital signature.

```text
seal = sha256(canonical JSON({
  schema_version,
  source,
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

## Target Runtime

The first target is Codex. The v0.1 operation planner only installs
instruction files that are explicitly represented in the sealed operation list.
Executable surfaces such as hooks and MCP registrations are inventoried and
treated as policy-controlled risk evidence; they are not started during
inspection.

## Extension Points

- additional source acquisition adapters
- scanner providers with machine-readable output
- additional target runtimes
- signed seals
- richer dependency graph analyzers

Extension points cannot bypass the core invariant.
