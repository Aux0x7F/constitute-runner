import type {
  AccessEpochRecord,
  AccessGroupRecord,
  ActionAuthorityExerciseRecord,
  ActionAuthorityGrantRecord,
  AuthorityMultiIdentityProofRecord,
  AuthorityRootOperationRecord,
  RunnerOperationRecord,
  SecurityProcessorSeedRecord,
  SurfaceAppContract,
  SurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export type SecurityObservedEvent = {
  eventRef?: string;
  eventId?: string;
  evidenceRef?: string;
  eventClass?: string;
  severity?: string;
  observedAt?: number;
  safeFacts?: Record<string, unknown>;
};

export type SecurityProcessorRunReport = {
  kind: "security.processor.run.report";
  reportId: string;
  seedId: string;
  processorRef: string;
  processorRoleRef: string;
  fabricRef: string;
  runnerOperationId: string;
  state: "clear" | "alerted" | "blocked" | "degraded";
  alertPosture: Record<string, unknown>;
  evidenceHoldPosture: Record<string, unknown>;
  accessPosture: Record<string, unknown>;
  materializationPosture: Record<string, unknown>;
  semanticBoundaries: Record<string, unknown>;
  safeFacts: Record<string, unknown>;
  evidenceRefs: string[];
  blockedReasons: string[];
  observedAt: number;
  expiresAt?: number;
};

export function buildSecurityProcessorRun(input: {
  seed: SecurityProcessorSeedRecord;
  runnerOperation: RunnerOperationRecord;
  observedEvents?: SecurityObservedEvent[];
  now?: number;
}): SecurityProcessorRunReport;

export function assertSecurityProcessorRunReport(record: unknown): SecurityProcessorRunReport;
export function securityBootstrapFixture(now?: number): {
  seed: SecurityProcessorSeedRecord;
  runnerOperation: RunnerOperationRecord;
  observedEvents: SecurityObservedEvent[];
};

export type AppRunnerFulfillmentReport = {
  kind: "app.runner.fulfillment.report";
  reportId: string;
  runnerId: string;
  runnerRef: string;
  hostRef: string;
  runnerOperationId: string;
  operation: string;
  state: "requested" | "accepted" | "running" | "succeeded" | "released" | "rolledBack" | "blocked" | "failed" | "rejected" | "cancelled";
  requesterRef: string;
  subjectRef: string;
  contractRef: string;
  appContractRef: string;
  appId: string;
  version: string;
  manifestRef: string;
  grantRefs: string[];
  capabilityRefs: string[];
  inputRefs: string[];
  outputRefs: string[];
  evidenceRefs: string[];
  proofRefs: string[];
  releaseRefs: string[];
  resourceBudget: Record<string, unknown>;
  resourcePosture: Record<string, unknown> | null;
  secretBoundary: Record<string, unknown>;
  releasePosture: Record<string, unknown> | null;
  rollbackPosture: Record<string, unknown> | null;
  releaseRef: string;
  rollbackRef: string;
  operationPosture: Record<string, unknown>;
  fulfillmentPosture: Record<string, unknown>;
  safeFacts: Record<string, unknown>;
  blockedReasons: string[];
  observedAt: number;
  expiresAt?: number;
};

export function buildAppRunnerFulfillment(input: {
  appContract: SurfaceAppContract;
  manifest: SurfaceAppManifest;
  runnerOperation: RunnerOperationRecord;
  now?: number;
  reportId?: string;
}): AppRunnerFulfillmentReport;

export function assertAppRunnerFulfillmentReport(record: unknown): AppRunnerFulfillmentReport;
export function appRunnerFulfillmentFixture(now?: number): {
  appContract: SurfaceAppContract;
  manifest: SurfaceAppManifest;
  runnerOperation: RunnerOperationRecord;
};

export function buildMultiIdentityGrantProof(input: {
  rootOperation?: AuthorityRootOperationRecord;
  actionGrants?: ActionAuthorityGrantRecord[];
  actionExercises?: ActionAuthorityExerciseRecord[];
  accessGroup?: AccessGroupRecord;
  accessEpoch?: AccessEpochRecord;
  proof: AuthorityMultiIdentityProofRecord;
}): AuthorityMultiIdentityProofRecord;

export function multiIdentityGrantFixture(now?: number): {
  rootOperation: AuthorityRootOperationRecord;
  actionGrants: ActionAuthorityGrantRecord[];
  actionExercises: ActionAuthorityExerciseRecord[];
  accessGroup: AccessGroupRecord;
  accessEpoch: AccessEpochRecord;
  proof: AuthorityMultiIdentityProofRecord;
};
