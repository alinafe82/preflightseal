# ADR 0002: Target Node.js 24 And Erasable TypeScript

## Status

Accepted

## Context

The CLI should have a small trusted computing base. A compile toolchain or
runtime transpiler increases bootstrap surface for the first release.

## Decision

PreflightSeal v0.1 targets Node.js 24 or newer and uses TypeScript syntax that
Node can strip directly. Tests run with the built-in `node:test` runner.

## Consequences

- no runtime dependencies are required for the first slice
- package installation avoids lifecycle scripts
- older Node versions are not supported in v0.1
- a compile step can be added later if broader Node support becomes important
