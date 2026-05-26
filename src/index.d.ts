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
  SurfaceAppContract,
  SurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export type { AppRunnerFulfillmentLifecycle, AppRunnerFulfillmentReport, RunnerHostFulfillmentPosture } from "../../constitute-protocol/src/index.js";

export type RunnerModuleResolutionPosture = {
  kind: "runner.module.resolution.posture";
  state: "ready" | "degraded" | "blocked";
  requestedModuleRef: string;
  resolverRef: string;
  moduleRef: string;
  repoRef: string;
  role: string;
  sourceSnapshotRef: string;
  contentIndexRef: string;
  artifactRef: string;
  materializedPathRef: string;
  executableRef: string;
  executableHashRef: string;
  storageMaterializationPostureRef: string;
  storageExecutableInstantiationPostureRef: string;
  storageRefs: string[];
  availabilityRefs: string[];
  conflictRefs: string[];
  blockedReasons: string[];
  safeFacts: Record<string, unknown>;
  observedAt: number;
};

export function resolveRunnerModuleFromResolver(input: {
  moduleResolverPosture?: Record<string, unknown>;
  moduleRef?: string;
  processorModuleRef?: string;
  nativeModuleRef?: string;
  blockedReasons?: string[];
  now?: number;
  observedAt?: number;
}): RunnerModuleResolutionPosture;

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

export function buildRunnerBuildOperationFixture(now?: number): {
  runnerOperation: RunnerOperationRecord;
  hostPosture: RunnerHostFulfillmentPosture;
};

export function buildRunnerOperationForBuild(input: {
  buildContract: {
    buildContractRef: string;
    sourceSnapshotRef: string;
    recipeRef: string;
  };
  buildRun: {
    buildContractRef: string;
    sourceSnapshotRef: string;
    recipeRef: string;
    runnerRef: string;
    runnerOperationRef: string;
    state: string;
    grantRefs?: string[];
    artifactRefs?: string[];
    proofRefs?: string[];
    releaseCandidateRefs?: string[];
    evidenceRefs?: string[];
    blockedReasons?: string[];
    requestedAt?: number;
    startedAt?: number;
    completedAt?: number;
    expiresAt?: number;
  };
  runnerMemberRef: string;
  moduleRef?: string;
  processorModuleRef?: string;
  moduleResolverPosture?: Record<string, unknown>;
  moduleResolutionPosture?: RunnerModuleResolutionPosture;
  hostRef?: string;
  requesterRef?: string;
  resourceBudget?: Record<string, unknown>;
  resourcePosture?: Record<string, unknown>;
  secretBoundary?: Record<string, unknown>;
  releasePosture?: Record<string, unknown>;
  rollbackPosture?: Record<string, unknown>;
  rollbackRef?: string;
  now?: number;
  observedAt?: number;
}): RunnerOperationRecord;

export function buildRunnerOperationForModuleLoad(input: {
  moduleRef?: string;
  processorModuleRef?: string;
  nativeModuleRef?: string;
  moduleResolverPosture?: Record<string, unknown>;
  moduleResolutionPosture?: RunnerModuleResolutionPosture;
  lifecycleManifestSeed?: Record<string, unknown>;
  lifecycleManifestPosture?: Record<string, unknown>;
  lifecycleManifestRef?: string;
  promotionIntentPosture?: Record<string, unknown>;
  promotionIntentRef?: string;
  fulfillmentSessionId?: string;
  contractRef?: string;
  subjectRef?: string;
  runnerId?: string;
  runnerRef?: string;
  runnerMemberRef?: string;
  hostRef?: string;
  requesterRef?: string;
  grantRefs?: string[];
  capabilityRefs?: string[];
  evidenceRefs?: string[];
  proofRefs?: string[];
  releaseRefs?: string[];
  blockedReasons?: string[];
  resourceBudget?: Record<string, unknown>;
  secretBoundary?: Record<string, unknown>;
  releasePosture?: Record<string, unknown> | null;
  rollbackPosture?: Record<string, unknown> | null;
  rollbackRef?: string;
  operationId?: string;
  operationState?: string;
  targetOperationState?: string;
  now?: number;
  requestedAt?: number;
  observedAt?: number;
  expiresAt?: number;
}): RunnerOperationRecord;

export function buildRunnerFulfillmentSession(input: {
  runnerOperation: RunnerOperationRecord;
  hostPosture?: RunnerHostFulfillmentPosture;
  sessionId?: string;
  parentIntentRef?: string;
  runtimeRef?: string;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  now?: number;
  observedAt?: number;
}): Record<string, unknown>;

export function projectFulfillmentSessionReadModel(input: {
  fulfillmentSession: Record<string, unknown>;
  runnerOperation?: RunnerOperationRecord;
  hostPosture?: RunnerHostFulfillmentPosture;
  adapterDebtPosture?: Record<string, unknown>;
  storageAvailabilityRefs?: string[];
  storageRefs?: string[];
  executableRefs?: string[];
  projectionRef?: string;
  now?: number;
  observedAt?: number;
}): Record<string, unknown>;

export function fulfillRunnerOperationDispatch(input: {
  runnerOperation: RunnerOperationRecord;
  serviceRefs?: string[];
  witnessRefs?: string[];
  contractRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  adapterDebtPosture?: Record<string, unknown>;
  storageAvailabilityRefs?: string[];
  storageRefs?: string[];
  executableRefs?: string[];
  now?: number;
  observedAt?: number;
}): {
  kind: string;
  state: string;
  dispatchRef: string;
  runnerOperation: RunnerOperationRecord;
  hostPosture: RunnerHostFulfillmentPosture;
  fulfillmentSession: Record<string, unknown>;
  fulfillmentSessionProjection: Record<string, unknown>;
  runtimeReportMessage: {
    type: string;
    hostFulfillmentPosture: RunnerHostFulfillmentPosture;
    fulfillmentSession: Record<string, unknown>;
    fulfillmentSessionProjection: Record<string, unknown>;
  };
  blockedReasons: string[];
  observedAt: number;
};

export function fulfillAcceptedRuntimeRunnerDispatches(input: {
  runtimeSnapshot?: { runnerOperations?: Record<string, unknown> | unknown[] };
  snapshot?: { runnerOperations?: Record<string, unknown> | unknown[] };
  runnerOperations?: Record<string, unknown> | unknown[];
  dispatches?: unknown[];
  serviceRefs?: string[];
  witnessRefs?: string[];
  contractRefs?: string[];
  evidenceRefs?: string[];
  adapterRef?: string;
  runtimeRef?: string;
  sourceRuntimeRef?: string;
  now?: number;
  observedAt?: number;
  putRuntimeReport?: (
    hostFulfillmentPosture: RunnerHostFulfillmentPosture,
    runtimeReportMessage: { type: string; hostFulfillmentPosture: RunnerHostFulfillmentPosture },
    dispatch: unknown,
  ) => unknown | Promise<unknown>;
  putRunnerHostFulfillmentPosture?: (
    hostFulfillmentPosture: RunnerHostFulfillmentPosture,
    runtimeReportMessage: { type: string; hostFulfillmentPosture: RunnerHostFulfillmentPosture },
    dispatch: unknown,
  ) => unknown | Promise<unknown>;
}): Promise<{
  kind: string;
  state: string;
  adapterRef: string;
  sourceRuntimeRef: string;
  fulfilledCount: number;
  skippedCount: number;
  fulfilled: Array<{
    dispatchId: string;
    operationId: string;
    state: string;
    runnerOperation: RunnerOperationRecord;
    hostPosture: RunnerHostFulfillmentPosture;
    fulfillmentSession: Record<string, unknown>;
    runtimeReportMessage: {
      type: string;
      hostFulfillmentPosture: RunnerHostFulfillmentPosture;
      fulfillmentSession: Record<string, unknown>;
    };
    reportResult: unknown;
    blockedReasons: string[];
  }>;
  skipped: Array<Record<string, unknown>>;
  blockedReasons: string[];
  observedAt: number;
}>;

export function createRuntimeRunnerFulfillmentAdapter(options?: {
  adapterRef?: string;
  serviceRefs?: string[];
  witnessRefs?: string[];
  contractRefs?: string[];
  evidenceRefs?: string[];
  now?: number;
  observedAt?: number;
}): (context: {
  dispatch?: { runnerOperation?: RunnerOperationRecord } & Record<string, unknown>;
  runnerOperation?: RunnerOperationRecord;
  snapshot?: unknown;
  bridgeRef?: string;
  runtimeRef?: string;
  adapterRef?: string;
}) => Promise<{
  kind: string;
  state: string;
  dispatchRef: string;
  runnerOperation: RunnerOperationRecord;
  hostPosture: RunnerHostFulfillmentPosture;
  runtimeReportMessage: {
    type: string;
    hostFulfillmentPosture: RunnerHostFulfillmentPosture;
  };
  blockedReasons: string[];
  observedAt: number;
}>;

export function installRuntimeRunnerFulfillmentAdapter(target?: Record<string, unknown>, options?: {
  adapterRef?: string;
  serviceRefs?: string[];
  witnessRefs?: string[];
  contractRefs?: string[];
  evidenceRefs?: string[];
  now?: number;
  observedAt?: number;
}): {
  kind: string;
  adapterRef: string;
  role: string;
  fulfillDispatch: ReturnType<typeof createRuntimeRunnerFulfillmentAdapter>;
  safeFacts: Record<string, unknown>;
};

export function buildRunnerModuleLoadOperationFixture(now?: number): {
  moduleResolverPosture: Record<string, unknown>;
  runnerOperation: RunnerOperationRecord;
  hostPosture: RunnerHostFulfillmentPosture;
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
