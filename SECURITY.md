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

## Security Invariants

PreflightSeal treats source input as malicious. The current invariants are:

- inspection never executes repository-controlled code
- mutable sources must resolve to immutable evidence before installation
- installation reads only approved bytes and verifies each source hash again
- `BLOCK` and `INCONCLUSIVE` plans cannot install
- `WARN` findings require explicit scoped acceptance
- rollback refuses to overwrite later user changes
- destination validation rejects traversal, symlink escapes, and existing
  multi-link target files

## Scanner Failures

Scanner failures are evidence. `ERROR`, `TIMEOUT`, `UNAVAILABLE`, `PARTIAL`,
and malformed output are represented explicitly and are never converted to
"zero findings."
