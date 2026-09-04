# ADR 0003: Use Four Decision States

## Status

Accepted

## Context

Security preflight results need to distinguish known violations from missing
evidence. A three-state allow/warn/block model can accidentally treat scanner
timeouts or unsupported semantics as a clean result.

## Decision

PreflightSeal uses `ALLOW`, `WARN`, `BLOCK`, and `INCONCLUSIVE`.

## Consequences

- `BLOCK` prevents installation
- `INCONCLUSIVE` prevents installation by default
- `WARN` requires explicit scoped acceptance
- scanner failure states remain visible evidence
