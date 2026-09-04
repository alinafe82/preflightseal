# ADR 0001: Bind Inspection, Approval, And Installation With A Seal

## Status

Accepted

## Context

AI-agent software can change future behavior of privileged development
environments. A review that inspects one set of bytes but installs another does
not create a trustworthy boundary.

## Decision

PreflightSeal will compute a content-integrity seal over source identity,
source digest, analyzer evidence digest, policy digest, target runtime,
preconditions, and operation plan. Installation requires a valid seal and
rechecks source bytes and target preconditions before writing.

## Consequences

- mutable source names cannot authorize installation by themselves
- target drift invalidates a plan
- changing policy or analyzer evidence invalidates a plan
- v0.1 seals are digests, not digital signatures
