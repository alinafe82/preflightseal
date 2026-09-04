# Threat Model

## Assumption

Every byte of inspected source is malicious.

The attacker controls filenames, directory structure, symlinks, package
manifests, lockfiles, scripts, hooks, MCP definitions, agent instructions,
documentation, encoded files, URLs, terminal control characters, and dependency
declarations.

## Protected Assets

- source code and local files reachable by the operator
- Git credentials and SSH configuration
- cloud credentials and environment variables
- package registry credentials
- browsers, local databases, terminals, and deployment tools
- agent runtime configuration

## Primary Attack Paths

- mutable reference swap between inspection and installation
- archive traversal or path collision
- symlink or hard-link destination escape
- package lifecycle script execution
- hook registration
- MCP server registration
- shell startup mutation
- PATH mutation
- destructive cleanup commands
- config replacement that expands agent authority
- scanner failure hidden as "no findings"

## Security Invariants

1. Inspection never executes repository-controlled code.
2. Mutable source references must freeze to immutable identity.
3. Installation must not resolve the source a second time.
4. Scanner failure is evidence.
5. Policy controls installation.
6. Repository policy is untrusted input.
7. Destination validation is canonical and symlink-aware.
8. Rollback cannot destroy later user changes.

## Decision States

- `ALLOW`: evidence completed and policy permits installation
- `WARN`: behavior is understood but requires scoped human acceptance
- `BLOCK`: known behavior violates policy
- `INCONCLUSIVE`: required evidence is missing or unsafe to interpret

`INCONCLUSIVE` never becomes `ALLOW` by default.
