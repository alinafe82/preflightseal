export const SCHEMA_VERSION = {
  SOURCE: "preflightseal.source.v1",
  FINDING: "preflightseal.finding.v1",
  ANALYZER_RESULT: "preflightseal.analyzer-result.v1",
  POLICY_EVALUATION: "preflightseal.policy-evaluation.v1",
  INSTALL_OPERATION: "preflightseal.install-operation.v1",
  PLAN: "preflightseal.plan.v1",
  RECEIPT: "preflightseal.receipt.v1",
  VERIFICATION_RESULT: "preflightseal.verification-result.v1",
  ROLLBACK_RESULT: "preflightseal.rollback-result.v1",
  TRANSACTION: "preflightseal.transaction.v1",
  CACHE_LOCAL: "preflightseal.cache.local.v1",
  CACHE_GITHUB: "preflightseal.cache.github.v1"
} as const;

export const SCHEMA_ID = {
  SOURCE: "https://preflightseal.dev/schemas/source-identity.v1.schema.json",
  FINDING: "https://preflightseal.dev/schemas/finding.v1.schema.json",
  ANALYZER_RESULT: "https://preflightseal.dev/schemas/analyzer-result.v1.schema.json",
  POLICY_EVALUATION: "https://preflightseal.dev/schemas/policy-evaluation.v1.schema.json",
  INSTALL_OPERATION: "https://preflightseal.dev/schemas/install-operation.v1.schema.json",
  PLAN: "https://preflightseal.dev/schemas/preflight-plan.v1.schema.json",
  RECEIPT: "https://preflightseal.dev/schemas/install-receipt.v1.schema.json",
  VERIFICATION_RESULT: "https://preflightseal.dev/schemas/verification-result.v1.schema.json",
  ROLLBACK_RESULT: "https://preflightseal.dev/schemas/rollback-result.v1.schema.json"
} as const;

export function assertSupportedSchemaVersion(actual: unknown, expected: string, label: string): void {
  if (actual !== expected) {
    throw new Error(`unsupported ${label} schema: expected ${expected}, got ${String(actual)}`);
  }
}
