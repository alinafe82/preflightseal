# Research

This document captures the security capabilities that shaped the v0.1 design.
Each dependency or external evidence source is treated as input to policy, not
as direct authority to install.

## Node.js 24

- Capability: current Node.js LTS runtime with built-in TypeScript type
  stripping for erasable TypeScript syntax.
- Trust boundary: local runtime and standard library.
- Execution behavior: runs PreflightSeal code, never repository-controlled
  inspected code during inspect or plan.
- Failure modes: unsupported syntax, older runtime, platform differences.
- Security implications: smaller dependency tree reduces bootstrap risk.
- Reason for inclusion: CLI portability and built-in test runner.
- Fallback: add a compile step later if older Node support is required.

Reference: https://nodejs.org/en/about/previous-releases

## npm Lifecycle Scripts And Lockfiles

- Capability: npm manifests and lockfiles describe package installation behavior
  and integrity metadata.
- Trust boundary: package manifests are attacker-controlled source data.
- Execution behavior: lifecycle fields such as `preinstall`, `install`,
  `postinstall`, and `prepare` can execute during package installation.
- Failure modes: lockfile missing, lockfile out of sync, mutable dependency
  ranges, lifecycle scripts hidden in dependencies.
- Security implications: PreflightSeal must parse and report lifecycle behavior
  without invoking npm install.
- Reason for inclusion: agent packages commonly use npm distribution.
- Fallback: classify incomplete dependency evidence as `INCONCLUSIVE` when a
  policy requires dependency evidence.

References:

- https://docs.npmjs.com/cli/v11/using-npm/scripts
- https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json
- https://docs.npmjs.com/generating-provenance-statements

## OSV

- Capability: vulnerability database and scanner ecosystem for package
  dependency evidence.
- Trust boundary: external vulnerability data and scanner output.
- Execution behavior: OSV tooling analyzes manifests and lockfiles; it must not
  run repository code.
- Failure modes: unavailable service, incomplete ecosystem coverage, malformed
  output, timeout.
- Security implications: failure is evidence, not a clean result.
- Reason for inclusion: dependency vulnerability evidence is useful but not
  sufficient for install-boundary authorization.
- Fallback: native manifest inspection plus `INCONCLUSIVE` when OSV evidence is
  required and unavailable.

Reference: https://google.github.io/osv-scanner/

## Sigstore, SLSA, And GitHub Artifact Attestations

- Capability: provenance and artifact integrity evidence.
- Trust boundary: identity provider, transparency log, attestation issuer, and
  verifier tooling.
- Execution behavior: verification should consume artifact metadata and
  attestations without executing inspected source.
- Failure modes: unsigned artifacts, ambiguous identity, offline verifier,
  unsupported predicate, missing subject digest.
- Security implications: attestations can strengthen source confidence but do
  not replace operation planning.
- Reason for inclusion: future signed-seal and provenance verification support.
- Fallback: content digest and policy-controlled `INCONCLUSIVE` if provenance is
  mandatory.

References:

- https://docs.sigstore.dev/
- https://slsa.dev/spec/v1.0/
- https://docs.github.com/en/actions/security-guides/using-artifact-attestations

## GitHub Sources

- Capability: resolve public HTTPS repositories to immutable commit identity and
  retrieve exact archive bytes.
- Trust boundary: GitHub API and archive service.
- Execution behavior: no clone hooks, submodules, filters, or repository code
  execution.
- Failure modes: mutable refs, redirects, rate limits, archive format changes,
  extraction hazards.
- Security implications: install must use the reviewed artifact digest, not the
  requested branch name.
- Reason for inclusion: public GitHub repositories are a primary source type.
- Fallback: `INCONCLUSIVE` until the exact archive can be frozen and safely
  extracted.

Reference: https://docs.github.com/en/rest/repos/contents

## MCP Configuration

- Capability: MCP configuration can register local commands or remote servers
  that expand agent authority.
- Trust boundary: inspected MCP definitions are attacker-controlled.
- Execution behavior: PreflightSeal must not start MCP servers during inspect or
  plan.
- Failure modes: command indirection, environment expansion, credentials in
  config, mutable package runners.
- Security implications: registration is an authority-expanding change and must
  be represented as policy-controlled evidence.
- Reason for inclusion: MCP is a common agent extension surface.
- Fallback: native static detection and `WARN` or `BLOCK` until non-executing
  analyzer evidence is available.

Reference: https://modelcontextprotocol.io/specification/

## Codex Target

- Capability: project instruction files and configuration influence the agent
  runtime.
- Trust boundary: target runtime configuration directory and project files.
- Execution behavior: installing instructions changes future agent behavior even
  when no code is executed immediately.
- Failure modes: config replacement, nested instruction precedence,
  unreviewed hooks or MCP entries, target state changing between plan and apply.
- Security implications: target preconditions must be sealed and revalidated.
- Reason for inclusion: first supported target runtime.
- Fallback: only install explicitly planned instruction files; treat executable
  target changes as policy-controlled risk.

Reference: https://learn.chatgpt.com/docs/config-file/config-reference

## Safe Archive Extraction

- Capability: unpack source archives without path traversal, symlink escape,
  hard-link escape, archive bombs, or normalized path collisions.
- Trust boundary: archive entries are attacker-controlled.
- Execution behavior: extraction parses bytes and writes only to an isolated
  staging directory after validation.
- Failure modes: absolute paths, `..`, duplicate normalized names,
  case-folding collisions, Unicode normalization collisions, oversized entries,
  excessive nesting, symlinks, hard links.
- Security implications: unsafe extraction must be `INCONCLUSIVE` or `BLOCK`,
  never a partial success that can install.
- Reason for inclusion: required for GitHub archive support.
- Fallback: do not install from archives until safe extraction completes.

Reference: https://security.snyk.io/research/zip-slip-vulnerability
