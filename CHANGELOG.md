# Changelog

## 0.1.0

- Initial CLI vertical slice for local directory inspection, sealed Codex
  instruction-file plans, transactional install, verification, and rollback.
- Hardened GitHub plans to install from frozen content-addressed cache objects
  instead of remote repository URLs.
- Scoped rollback state by receipt and transaction so unrelated receipts and
  backups survive rollback.
- Added target locking, scanner execution isolation, source-policy detection,
  decompression limits, and stable CLI error-code output.
- Added stable warning fingerprints, schema fixtures, package/secret/
  contamination checks, and deterministic dogfood coverage.
- Made local self-dogfood fall back to the current checkout outside CI when the
  canonical public GitHub source is unavailable.
