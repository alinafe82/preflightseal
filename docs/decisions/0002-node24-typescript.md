# ADR 0002: Target Node.js 24 And Erasable TypeScript

## Status

Accepted

## Context

The CLI should have a small trusted computing base. Local development can use
Node.js 24 erasable TypeScript directly, but installed npm packages cannot rely
on Node's TypeScript stripping for files under `node_modules`.

## Decision

PreflightSeal v0.1 targets Node.js 24 or newer and uses TypeScript syntax that
Node can strip directly in the source checkout. npm packages publish compiled
JavaScript in `dist/` so the installed `preflightseal` bin runs without a
runtime transpiler. Tests run with the built-in `node:test` runner.

## Consequences

- no runtime dependencies are required for the first slice
- package installation avoids lifecycle scripts
- older Node versions are not supported in v0.1
- the build step is emit-only and rewrites relative TypeScript imports to
  JavaScript imports for npm distribution
