import { SCHEMA_VERSION } from "./schema.ts";

export type DecisionState = "ALLOW" | "WARN" | "BLOCK" | "INCONCLUSIVE";

export type AnalyzerStatus =
  | "PASS"
  | "FINDINGS"
  | "ERROR"
  | "TIMEOUT"
  | "UNAVAILABLE"
  | "NOT_RUN"
  | "NOT_APPLICABLE"
  | "PARTIAL";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type InventoryEntryType = "directory" | "file" | "symlink";

export interface Finding {
  schemaVersion: typeof SCHEMA_VERSION.FINDING;
  id: string;
  fingerprint: string;
  title: string;
  category: string;
  decision: DecisionState;
  severity: Severity;
  path?: string;
  evidence: string;
  providerId?: string;
  operationIdentity?: string;
  recommendation: string;
}

export interface InventoryEntry {
  path: string;
  type: InventoryEntryType;
  mode: number;
  size: number;
  sha256?: string;
  symlinkTarget?: string;
  executable?: boolean;
  artifactKinds: string[];
}

export interface Inventory {
  root: string;
  entries: InventoryEntry[];
  digest: string;
  findings: Finding[];
}

export interface SourceIdentity {
  schemaVersion: typeof SCHEMA_VERSION.SOURCE;
  kind: "local" | "github";
  originalInput: string;
  canonical: string;
  canonicalIdentity: string;
  requestedRef?: string;
  resolvedRevision: string;
  archiveSha256?: string;
  contentDigest: string;
  cacheKey?: string;
  immutableLocator?: string;
  retrievedAt: string;
  metadata?: Record<string, unknown>;
}

export interface AnalyzerResult {
  schemaVersion: typeof SCHEMA_VERSION.ANALYZER_RESULT;
  providerId: string;
  status: AnalyzerStatus;
  startedAt: string;
  finishedAt: string;
  version?: string;
  reportDigest: string;
  findings: Finding[];
  error?: string;
}

export interface Policy {
  id: string;
  version: string;
  requiredAnalyzers: string[];
  warnRequiresAcceptance: boolean;
  blockedFindingIds: string[];
}

export interface PolicyEvaluation {
  schemaVersion: typeof SCHEMA_VERSION.POLICY_EVALUATION;
  decision: DecisionState;
  reasons: string[];
  warningIds: string[];
  warningFingerprints: string[];
  blockingIds: string[];
  blockingFingerprints: string[];
  inconclusiveProviderIds: string[];
}

export interface TargetStatePrecondition {
  targetPath: string;
  expected: FileState;
}

export type FileState =
  | { kind: "absent" }
  | { kind: "file"; sha256: string; size: number; mode: number };

export interface InstallOperation {
  schemaVersion: typeof SCHEMA_VERSION.INSTALL_OPERATION;
  op: "write_file";
  sourcePath: string;
  targetPath: string;
  sha256: string;
  size: number;
  mode: number;
}

export interface PlanTarget {
  runtime: "codex";
  root: string;
}

export interface PreflightPlan {
  schemaVersion: typeof SCHEMA_VERSION.PLAN;
  createdAt: string;
  source: SourceIdentity;
  target: PlanTarget;
  inventoryDigest: string;
  analyzerEvidenceDigest: string;
  analyzerResults: AnalyzerResult[];
  policy: Policy;
  policyDigest: string;
  evaluation: PolicyEvaluation;
  warningFingerprints: string[];
  operations: InstallOperation[];
  preconditions: TargetStatePrecondition[];
  seal: string;
}

export interface ReceiptOperation {
  op: "write_file";
  targetPath: string;
  before: FileState;
  after: FileState;
  backupPath?: string;
}

export interface InstallReceipt {
  schemaVersion: typeof SCHEMA_VERSION.RECEIPT;
  receiptId: string;
  transactionId: string;
  planSeal: string;
  installedAt: string;
  target: PlanTarget;
  acceptedWarningFingerprints: string[];
  operations: ReceiptOperation[];
  receiptDigest: string;
}

export interface VerificationResult {
  schemaVersion: typeof SCHEMA_VERSION.VERIFICATION_RESULT;
  receiptId: string;
  transactionId: string;
  planSeal: string;
  verifiedAt: string;
  ok: boolean;
  conflicts: string[];
  verificationDigest: string;
}

export interface RollbackResult {
  schemaVersion: typeof SCHEMA_VERSION.ROLLBACK_RESULT;
  receiptId: string;
  transactionId: string;
  planSeal: string;
  rolledBackAt: string;
  ok: boolean;
  conflicts: string[];
  operations: string[];
  rollbackDigest: string;
}
