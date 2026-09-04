# Security Policy

## Reporting

Please report security issues privately to the maintainers before public
disclosure. Include:

- affected version or commit
- source type used during inspection
- command invoked
- expected decision state
- observed decision state
- whether installation began

Do not include secrets, private keys, access tokens, or customer data in reports.

The official repository is `https://github.com/alinafe82/preflightseal`. The
official npm package name is `preflightseal` when published by the maintainer.
Please report confusing package names, impersonation attempts, or compromised
release artifacts as security issues.

## Security Invariants

PreflightSeal treats source input as malicious. The current invariants are:

- inspection never executes repository-controlled code
- mutable sources must resolve to immutable evidence before installation
- GitHub plans install from the frozen cache object and do not re-resolve remote
  refs during apply
- installation reads only approved bytes and verifies source hashes again
- `BLOCK` and `INCONCLUSIVE` plans cannot install
- `WARN` findings require explicit scoped acceptance
- install and rollback hold a target-scoped transaction lock before mutation
- rollback refuses to overwrite later user changes and preserves unrelated
  receipts, backups, and installed files
- destination validation rejects traversal, symlink escapes, and existing
  multi-link target files

## Scanner Failures

Scanner failures are evidence. `ERROR`, `TIMEOUT`, `UNAVAILABLE`, `PARTIAL`,
and malformed output are represented explicitly and are never converted to
"zero findings."

Optional external scanners must be configured with an explicit trusted
executable path. Scanner processes run without a shell, with a temporary
isolated `HOME`, a minimal environment, timeout enforcement, and bounded output
capture. Credentials are passed only when the provider requires them and are
redacted from scanner error evidence.

## Release Integrity

Maintainer releases should be built from protected `main`, pass CI, and publish
to npm through GitHub Actions trusted publishing with provenance. Long-lived npm
publish tokens should not be used for routine releases.
