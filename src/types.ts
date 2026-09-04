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
  id: string;
  title: string;
  decision: DecisionState;
  severity: Severity;
  path?: string;
  evidence: string;
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
  kind: "local" | "github";
  originalInput: string;
  canonical: string;
  resolvedRevision: string;
  contentDigest: string;
  retrievedAt: string;
  metadata?: Record<string, unknown>;
}

export interface AnalyzerResult {
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
  decision: DecisionState;
  reasons: string[];
  warningIds: string[];
  blockingIds: string[];
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
  schemaVersion: "preflightseal.plan.v1";
  createdAt: string;
  source: SourceIdentity;
  target: PlanTarget;
  inventoryDigest: string;
  analyzerEvidenceDigest: string;
  analyzerResults: AnalyzerResult[];
  policy: Policy;
  policyDigest: string;
  evaluation: PolicyEvaluation;
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
  schemaVersion: "preflightseal.receipt.v1";
  planSeal: string;
  installedAt: string;
  target: PlanTarget;
  acceptedWarnings: string[];
  operations: ReceiptOperation[];
  receiptDigest: string;
}
