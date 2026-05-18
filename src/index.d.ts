import type {
  AccessEpochRecord,
  AccessGroupRecord,
  ActionAuthorityExerciseRecord,
  ActionAuthorityGrantRecord,
  AppRunnerFulfillmentLifecycle,
  AppRunnerFulfillmentReport,
  AuthorityMultiIdentityProofRecord,
  AuthorityRootOperationRecord,
  RunnerHostFulfillmentPosture,
  RunnerOperationRecord,
  SecurityProcessorSeedRecord,
  SurfaceAppContract,
  SurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export type { AppRunnerFulfillmentLifecycle, AppRunnerFulfillmentReport, RunnerHostFulfillmentPosture } from "../../constitute-protocol/src/index.js";

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

export function securityAppContractFixture(now?: number): {
  appContract: SurfaceAppContract;
  manifest: SurfaceAppManifest;
  seed: SecurityProcessorSeedRecord;
  runnerOperation: RunnerOperationRecord;
};

export function buildAppRunnerFulfillment(input: {
  appContract: SurfaceAppContract;
  manifest: SurfaceAppManifest;
  runnerOperation: RunnerOperationRecord;
  hostFulfillmentPosture?: RunnerHostFulfillmentPosture;
  now?: number;
  reportId?: string;
}): AppRunnerFulfillmentReport;

export function assertAppRunnerFulfillmentReport(record: unknown): AppRunnerFulfillmentReport;
export function buildRunnerHostFulfillmentPosture(input: {
  runnerOperation: RunnerOperationRecord;
  serviceRefs?: string[];
  contractRefs?: string[];
  evidenceRefs?: string[];
  witnessRefs?: string[];
  blockedReasons?: string[];
  now?: number;
  postureId?: string;
}): RunnerHostFulfillmentPosture;
export function assertRunnerHostPosture(record: unknown): RunnerHostFulfillmentPosture;
export function buildAppRunnerFulfillmentLifecycle(input: {
  appContract?: SurfaceAppContract;
  manifest?: SurfaceAppManifest;
  runnerOperation?: RunnerOperationRecord;
  report?: AppRunnerFulfillmentReport;
  now?: number;
  reportId?: string;
  lifecycleId?: string;
  witnessRefs?: string[];
  releaseWitnessRefs?: string[];
  releasedAt?: number;
  rolledBackAt?: number;
  rejectedAt?: number;
  expiredAt?: number;
}): AppRunnerFulfillmentLifecycle;
export function assertAppRunnerFulfillmentLifecycle(record: unknown): AppRunnerFulfillmentLifecycle;
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
