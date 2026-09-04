# Competitive Landscape

PreflightSeal is deliberately narrower than a general security platform.

## Package Vulnerability Scanners

Examples: OSV-Scanner, npm audit.

They answer whether dependencies have known vulnerability records. They do not
fully answer what an AI-agent repository will install into a privileged agent
runtime, which hooks or MCP servers it will configure, or whether reviewed bytes
match installed bytes.

## Provenance And Attestation Tools

Examples: Sigstore, SLSA provenance, GitHub artifact attestations, npm
provenance.

They answer who produced an artifact and whether metadata binds to a digest.
They do not derive an installation transaction or enforce local policy.

## Agent Configuration Scanners

Agent configuration scanners can provide valuable evidence about risky tools,
instructions, and MCP surfaces. PreflightSeal treats these scanners as evidence
providers. They cannot authorize installation directly, and any scanner that
fails, times out, emits malformed output, or requires unsafe execution results
in explicit failure evidence.

## PreflightSeal's Differentiator

PreflightSeal focuses on the installation boundary:

- freeze source identity
- hash reviewed bytes
- derive installation operations without running source code
- bind evidence, policy, target state, and operations into a seal
- install only sealed operations
- leave a receipt that can be verified or safely rolled back
