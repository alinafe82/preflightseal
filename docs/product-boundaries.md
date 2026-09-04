# Product Boundaries

PreflightSeal is a transactional security preflight for AI agent software.

It answers one question:

```text
Can these exact reviewed bytes safely cross the installation boundary, and what
will happen if they do?
```

## In Scope For 0.1

- CLI-first workflow
- local directory source inspection
- GitHub HTTPS source acquisition through immutable commit tarballs
- Codex as the first target runtime
- deterministic inventory of agent-relevant files
- native static rules for install-boundary risk
- content-integrity seals
- policy evaluation with `ALLOW`, `WARN`, `BLOCK`, and `INCONCLUSIVE`
- transactional file writes for approved instruction files
- receipts, verification, and rollback

## Out Of Scope For 0.1

- web dashboard
- SaaS backend
- private repository authentication
- arbitrary upstream installer execution
- runtime firewalling
- endpoint protection
- package-manager replacement
- automatic MCP authentication
- automatic hook trust
- digital signatures or certificate authority behavior

## Product Non-Claims

PreflightSeal is not an antivirus, generic vulnerability scanner, opaque AI
risk score, package manager, or MCP runtime firewall. Scanner providers supply
evidence; policy makes decisions.
