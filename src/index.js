import {
  AGREEMENT,
  BUILD,
  RUNNER,
  SURFACE_APP,
  SWARM,
  assertAccessEpoch,
  assertAccessGroup,
  assertActionAuthorityExercise,
  assertActionAuthorityGrant,
  assertAppRunnerFulfillmentLifecycle as assertProtocolAppRunnerFulfillmentLifecycle,
  assertAppRunnerFulfillmentReport as assertProtocolAppRunnerFulfillmentReport,
  assertAuthorityMultiIdentityProof,
  assertAuthorityRootOperation,
  assertFulfillmentSession,
  assertRunnerOperation,
  assertRunnerHostFulfillmentPosture,
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export const APP_RUNNER_FULFILLMENT_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_REPORT;
export const APP_RUNNER_FULFILLMENT_LIFECYCLE_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_LIFECYCLE;
export const RUNNER_MODULE_RESOLUTION_POSTURE_KIND = "runner.module.resolution.posture";

const TERMINAL_BLOCKED_STATES = new Set([
  RUNNER.OPERATION_STATE.BLOCKED,
  RUNNER.OPERATION_STATE.FAILED,
  RUNNER.OPERATION_STATE.REJECTED,
  RUNNER.OPERATION_STATE.CANCELLED,
]);
const UNSAFE_KEY_PATTERN = /^(raw|payload|body|ciphertext|plaintext|secret|token|password|privateKey|seedPhrase|sdp|candidate|mediaBytes|bytes)$/i;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function stringSet(values) {
  return new Set(asArray(values).map((value) => String(value || "").trim()).filter(Boolean));
}

function intersects(left, right) {
  for (const value of left) {
    if (right.has(value)) return true;
  }
  return false;
}

function unique(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

function isObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function rejectUnsafeSafeFacts(value, context, path = []) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectUnsafeSafeFacts(entry, context, [...path, String(index)]));
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (UNSAFE_KEY_PATTERN.test(key)) {
      throw new Error(`${context} safe facts contain unsafe key ${[...path, key].join(".")}`);
    }
    rejectUnsafeSafeFacts(nested, context, [...path, key]);
  }
}

function appContractRefUniverse(appContract, manifest) {
  return stringSet([
    appContract?.contractId,
    appContract?.appRef,
    appContract?.appId && appContract?.version ? `${appContract.appId}@${appContract.version}` : "",
    manifest?.manifestId,
    manifest?.currentAppContractRef,
    manifest?.appId && manifest?.currentVersion ? `${manifest.appId}@${manifest.currentVersion}` : "",
  ]);
}

function manifestSourceRefs(manifest) {
  const sourceMode = String(manifest?.defaultSourceMode || SURFACE_APP.FULFILLMENT_MODE.BUNDLED).trim();
  const version = asArray(manifest?.versions).find((entry) => entry?.version === manifest?.currentVersion) || {};
  const bundled = asArray(version.bundledSourceRefs).length ? version.bundledSourceRefs : manifest?.bundledSourceRefs;
  const remote = asArray(version.remoteSourceRefs).length ? version.remoteSourceRefs : manifest?.remoteSourceRefs;
  if (sourceMode === SURFACE_APP.FULFILLMENT_MODE.BUNDLED) return unique(asArray(bundled));
  return unique(asArray(remote));
}

function repoRefForModuleRef(moduleRef) {
  const value = String(moduleRef || "").trim();
  if (!value) return "";
  if (value.startsWith("repo:")) return value;
  if (value.startsWith("module:native-dev:")) return `repo:${value.replace(/^module:native-dev:/, "")}`;
  const withoutModulePrefix = value.replace(/^module:/, "");
  const versionIndex = withoutModulePrefix.lastIndexOf("@");
  const withoutVersion = versionIndex > 0 ? withoutModulePrefix.slice(0, versionIndex) : withoutModulePrefix;
  const repoName = withoutVersion.split("/")[0] || "";
  return repoName ? `repo:${repoName}` : "";
}

function nativeModuleRefForModuleRef(moduleRef) {
  const repoRef = repoRefForModuleRef(moduleRef);
  const repoName = repoRef.replace(/^repo:/, "");
  return repoName ? `module:native-dev:${repoName}` : "";
}

function findModuleResolution(moduleResolverPosture, moduleRef) {
  const requestedModuleRef = String(moduleRef || "").trim();
  const moduleCandidates = unique([
    requestedModuleRef,
    nativeModuleRefForModuleRef(requestedModuleRef),
  ]);
  const repoCandidates = unique([
    repoRefForModuleRef(requestedModuleRef),
  ]);
  return asArray(moduleResolverPosture?.moduleResolutions)
    .filter(isObject)
    .find((resolution) => (
      moduleCandidates.includes(String(resolution.moduleRef || "").trim())
      || repoCandidates.includes(String(resolution.repoRef || "").trim())
    )) || null;
}

export function resolveRunnerModuleFromResolver(input = {}) {
  const observedAt = Number(input.now || input.observedAt || 0) || nowSeconds();
  const moduleResolverPosture = isObject(input.moduleResolverPosture)
    ? input.moduleResolverPosture
    : null;
  const requestedModuleRef = String(input.moduleRef || input.processorModuleRef || input.nativeModuleRef || "").trim();
  const resolution = moduleResolverPosture && requestedModuleRef
    ? findModuleResolution(moduleResolverPosture, requestedModuleRef)
    : null;
  const conflictRefs = unique(asArray(resolution?.conflictRefs));
  const blockedReasons = unique([
    ...(!requestedModuleRef ? ["missingModuleRef"] : []),
    ...(!moduleResolverPosture ? ["missingModuleResolver"] : []),
    ...(moduleResolverPosture && requestedModuleRef && !resolution ? ["missingModuleResolution"] : []),
    ...(resolution && String(resolution.state || "") !== "materialized" ? [`moduleResolution:${String(resolution.state || "unknown")}`] : []),
    ...(resolution && !String(resolution.sourceSnapshotRef || moduleResolverPosture?.sourceSnapshotRef || "").trim() ? ["missingSourceSnapshotRef"] : []),
    ...(resolution && !String(resolution.artifactRef || "").trim() ? ["missingArtifactRef"] : []),
    ...asArray(resolution?.blockedReasons),
    ...asArray(input.blockedReasons),
  ]);
  const state = blockedReasons.length
    ? "blocked"
    : (conflictRefs.length || ["trackingConflicts", "degraded"].includes(String(moduleResolverPosture?.state || ""))
      ? "degraded"
      : "ready");
  const posture = {
    kind: RUNNER_MODULE_RESOLUTION_POSTURE_KIND,
    state,
    requestedModuleRef,
    resolverRef: String(moduleResolverPosture?.resolverRef || ""),
    moduleRef: String(resolution?.moduleRef || ""),
    repoRef: String(resolution?.repoRef || ""),
    role: String(resolution?.role || ""),
    sourceSnapshotRef: String(resolution?.sourceSnapshotRef || moduleResolverPosture?.sourceSnapshotRef || ""),
    contentIndexRef: String(resolution?.contentIndexRef || moduleResolverPosture?.contentIndexRef || ""),
    artifactRef: String(resolution?.artifactRef || ""),
    materializedPathRef: String(resolution?.materializedPathRef || ""),
    executableRef: String(resolution?.executableRef || ""),
    executableHashRef: String(resolution?.executableHashRef || ""),
    storageMaterializationPostureRef: String(resolution?.storageMaterializationPostureRef || ""),
    storageExecutableInstantiationPostureRef: String(resolution?.storageExecutableInstantiationPostureRef || ""),
    storageRefs: unique(asArray(resolution?.storageRefs)),
    availabilityRefs: unique(asArray(resolution?.availabilityRefs)),
    conflictRefs,
    blockedReasons,
    safeFacts: {
      requestedModuleRef,
      moduleRef: String(resolution?.moduleRef || ""),
      resolverRef: String(moduleResolverPosture?.resolverRef || ""),
      artifactReady: Boolean(resolution?.artifactRef),
      executableReady: Boolean(resolution?.executableRef && resolution?.executableHashRef),
      storageRefCount: asArray(resolution?.storageRefs).length,
      availabilityRefCount: asArray(resolution?.availabilityRefs).length,
      conflictCount: conflictRefs.length,
    },
    observedAt,
  };
  rejectUnsafeSafeFacts(posture.safeFacts, "runner module resolution posture");
  return posture;
}

export function buildRunnerOperationForModuleLoad(input = {}) {
  const now = Number(input.now || input.requestedAt || 0) || nowSeconds();
  const requestedModuleRef = String(input.moduleRef || input.processorModuleRef || input.nativeModuleRef || "").trim();
  const lifecycleManifest = isObject(input.lifecycleManifestSeed)
    ? input.lifecycleManifestSeed
    : (isObject(input.lifecycleManifestPosture) ? input.lifecycleManifestPosture : null);
  const promotionIntentPosture = isObject(input.promotionIntentPosture)
    ? input.promotionIntentPosture
    : null;
  const lifecycleManifestRef = String(
    input.lifecycleManifestRef
    || lifecycleManifest?.manifestRef
    || lifecycleManifest?.lifecycleManifestRef
    || "",
  ).trim();
  const promotionIntentRef = String(
    input.promotionIntentRef
    || promotionIntentPosture?.intentionRef
    || "",
  ).trim();
  const lifecycleRefs = unique([
    lifecycleManifestRef,
    promotionIntentRef,
    lifecycleManifest?.targetRef,
    promotionIntentPosture?.canonicalHashRef,
    ...asArray(lifecycleManifest?.candidateRefs),
    ...asArray(lifecycleManifest?.sourceSnapshotRefs),
    ...asArray(lifecycleManifest?.contentIndexRefs),
    ...asArray(lifecycleManifest?.buildRefs),
    ...asArray(lifecycleManifest?.artifactRefs),
    ...asArray(lifecycleManifest?.storageRefs),
    ...asArray(lifecycleManifest?.proofRefs),
    ...asArray(lifecycleManifest?.logRefs),
    ...asArray(lifecycleManifest?.metricRefs),
    ...asArray(lifecycleManifest?.releaseCandidateRefs),
    ...asArray(lifecycleManifest?.rollbackRefs),
    ...asArray(lifecycleManifest?.cleanupRefs),
    ...asArray(lifecycleManifest?.proofGateRefs),
    ...asArray(lifecycleManifest?.governanceRefs),
    ...asArray(lifecycleManifest?.conflictRefs),
    ...asArray(lifecycleManifest?.evidenceRefs),
    ...asArray(promotionIntentPosture?.proofGateRefs),
    ...asArray(promotionIntentPosture?.reducerRefs),
    ...asArray(promotionIntentPosture?.evidenceRefs),
  ]);
  const lifecycleBlockedReasons = unique([
    ...(lifecycleManifest && lifecycleManifest.state === "blocked"
      ? (asArray(lifecycleManifest.blockedReasons).length ? lifecycleManifest.blockedReasons : ["lifecycleManifest:blocked"])
      : []),
    ...(promotionIntentPosture && promotionIntentPosture.state === "blocked"
      ? (asArray(promotionIntentPosture.blockedReasons).length ? promotionIntentPosture.blockedReasons : ["promotionIntent:blocked"])
      : []),
  ]);
  const moduleResolutionPosture = isObject(input.moduleResolutionPosture)
    ? input.moduleResolutionPosture
    : resolveRunnerModuleFromResolver({
      moduleResolverPosture: input.moduleResolverPosture,
      moduleRef: requestedModuleRef,
      now,
    });
  const moduleResolutionBlockedReasons = asArray(moduleResolutionPosture?.blockedReasons)
    .map((reason) => `moduleResolver:${reason}`);
  const storageRefs = unique(asArray(moduleResolutionPosture?.storageRefs));
  const availabilityRefs = unique(asArray(moduleResolutionPosture?.availabilityRefs));
  const conflictRefs = unique(asArray(moduleResolutionPosture?.conflictRefs));
  const executableRef = String(moduleResolutionPosture?.executableRef || "").trim();
  const executableHashRef = String(moduleResolutionPosture?.executableHashRef || "").trim();
  const moduleLoadBlockedReasons = unique([
    ...lifecycleBlockedReasons,
    ...moduleResolutionBlockedReasons,
    ...(!String(moduleResolutionPosture?.artifactRef || "").trim() ? ["moduleLoad:missingArtifactRef"] : []),
    ...(!String(moduleResolutionPosture?.materializedPathRef || "").trim() ? ["moduleLoad:missingMaterializedPathRef"] : []),
    ...(!executableRef ? ["moduleLoad:missingExecutableRef"] : []),
    ...(!executableHashRef ? ["moduleLoad:missingExecutableHashRef"] : []),
    ...(storageRefs.length ? [] : ["moduleLoad:missingStorageRef"]),
    ...asArray(input.blockedReasons),
  ]);
  const requestedOperationState = String(input.operationState || input.targetOperationState || "").trim();
  const allowedPreparedStates = new Set([
    RUNNER.OPERATION_STATE.REQUESTED,
    RUNNER.OPERATION_STATE.ACCEPTED,
    RUNNER.OPERATION_STATE.RUNNING,
    RUNNER.OPERATION_STATE.SUCCEEDED,
  ]);
  const operationState = moduleLoadBlockedReasons.length
    ? RUNNER.OPERATION_STATE.BLOCKED
    : (allowedPreparedStates.has(requestedOperationState)
      ? requestedOperationState
      : RUNNER.OPERATION_STATE.SUCCEEDED);
  const succeeded = operationState === RUNNER.OPERATION_STATE.SUCCEEDED;
  const accepted = [
    RUNNER.OPERATION_STATE.ACCEPTED,
    RUNNER.OPERATION_STATE.RUNNING,
    RUNNER.OPERATION_STATE.SUCCEEDED,
  ].includes(operationState);
  const running = [
    RUNNER.OPERATION_STATE.RUNNING,
    RUNNER.OPERATION_STATE.SUCCEEDED,
  ].includes(operationState);
  const subjectRef = String(moduleResolutionPosture?.moduleRef || requestedModuleRef || input.subjectRef || "").trim();
  const contractRef = String(input.contractRef || lifecycleManifestRef || subjectRef || "module:native-dev:unknown").trim();
  const operationId = String(
    input.operationId || `runner-operation:module-load:${(subjectRef || contractRef).replace(/[^A-Za-z0-9_.:-]/g, "-")}:${now}`,
  ).trim();
  const fulfillmentSessionId = String(
    input.fulfillmentSessionId
    || (lifecycleManifestRef ? `fulfillment-session:module-load:${lifecycleManifestRef.replace(/[^A-Za-z0-9_.:-]/g, "-")}:${now}` : ""),
  ).trim();
  const runnerOperation = {
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId,
    runnerId: String(input.runnerId || "runner:local-host:module-load").trim(),
    runnerRef: String(input.runnerMemberRef || input.runnerRef || "").trim(),
    hostRef: String(input.hostRef || "host:runner-lab").trim(),
    requesterRef: String(input.requesterRef || "identity:aux").trim(),
    subjectRef,
    contractRef,
    operation: RUNNER.OPERATION.EXECUTE,
    state: operationState,
    grantRefs: unique(asArray(input.grantRefs).length ? input.grantRefs : ["authority:grant:runner-module-load"]),
    capabilityRefs: unique(["capability:runner.module.load", ...asArray(input.capabilityRefs)]),
    inputRefs: unique([
      ...lifecycleRefs,
      requestedModuleRef,
      moduleResolutionPosture?.resolverRef,
      moduleResolutionPosture?.moduleRef,
      moduleResolutionPosture?.sourceSnapshotRef,
      moduleResolutionPosture?.contentIndexRef,
      moduleResolutionPosture?.artifactRef,
      moduleResolutionPosture?.materializedPathRef,
      executableRef,
      executableHashRef,
      moduleResolutionPosture?.storageMaterializationPostureRef,
      moduleResolutionPosture?.storageExecutableInstantiationPostureRef,
      ...storageRefs,
      ...availabilityRefs,
      ...conflictRefs,
    ]),
    outputRefs: succeeded
      ? unique([
        `module-load:${subjectRef}`,
        moduleResolutionPosture?.artifactRef,
        moduleResolutionPosture?.materializedPathRef,
        executableRef,
      ])
      : (moduleLoadBlockedReasons.length ? [] : unique([
        `module-load:${subjectRef}`,
        moduleResolutionPosture?.artifactRef,
        moduleResolutionPosture?.materializedPathRef,
        executableRef,
      ])),
    evidenceRefs: unique([
      ...(succeeded ? ["runner:evidence:module-load"] : []),
      ...(succeeded && executableRef ? ["runner:evidence:executable-bytes"] : []),
      ...(moduleResolutionPosture && !moduleResolutionBlockedReasons.length ? ["runner:evidence:module-resolution"] : []),
      ...(lifecycleManifestRef ? ["runner:evidence:lifecycle-manifest-selected"] : []),
      ...asArray(input.evidenceRefs),
    ]),
    proofRefs: unique([
      ...asArray(input.proofRefs),
      ...asArray(lifecycleManifest?.proofRefs),
    ]),
    releaseRefs: unique([
      ...asArray(input.releaseRefs),
      ...asArray(lifecycleManifest?.releaseCandidateRefs),
    ]),
    resourceBudget: input.resourceBudget || {
      profileRef: "resource-profile:module-load-lite",
      maxMemoryMiB: 256,
      maxCpuPct: 20,
    },
    secretBoundary: input.secretBoundary || { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: input.releasePosture || (lifecycleManifestRef ? {
      state: lifecycleManifest?.state === "blocked" ? SURFACE_APP.RELEASE_POSTURE.BLOCKED : SURFACE_APP.RELEASE_POSTURE.BUILD_READY,
      buildRef: asArray(lifecycleManifest?.buildRefs)[0] || contractRef,
      releaseRef: asArray(lifecycleManifest?.releaseCandidateRefs)[0] || lifecycleManifestRef,
      rollbackRef: asArray(lifecycleManifest?.rollbackRefs)[0] || `rollback:${contractRef.replaceAll(":", "-")}`,
      ...(lifecycleBlockedReasons.length ? { blockedReasons: lifecycleBlockedReasons } : {}),
    } : null),
    rollbackPosture: input.rollbackPosture || (lifecycleManifestRef ? {
      state: lifecycleManifest?.state === "blocked" ? SURFACE_APP.RELEASE_POSTURE.BLOCKED : SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      rollbackRef: asArray(lifecycleManifest?.rollbackRefs)[0] || `rollback:${contractRef.replaceAll(":", "-")}`,
      ...(lifecycleBlockedReasons.length ? { blockedReasons: lifecycleBlockedReasons } : {}),
    } : null),
    rollbackRef: input.rollbackRef || asArray(lifecycleManifest?.rollbackRefs)[0] || `rollback:${contractRef.replaceAll(":", "-")}`,
    blockedReasons: moduleLoadBlockedReasons,
    safeFacts: {
      executionKind: "nativeModuleLoad",
      lifecycleManifestRef,
      promotionIntentRef,
      fulfillmentSessionId,
      lifecycleManifestState: String(lifecycleManifest?.state || ""),
      lifecycleManifestAcceptedAsMain: Boolean(lifecycleManifest?.safeFacts?.acceptedAsMain),
      lifecycleProofGateCount: asArray(lifecycleManifest?.proofGateRefs).length,
      lifecycleReleaseCandidateCount: asArray(lifecycleManifest?.releaseCandidateRefs).length,
      moduleResolutionState: String(moduleResolutionPosture?.state || ""),
      moduleResolverRef: String(moduleResolutionPosture?.resolverRef || ""),
      moduleRef: String(moduleResolutionPosture?.moduleRef || ""),
      moduleArtifactReady: Boolean(moduleResolutionPosture?.artifactRef),
      moduleMaterializedPathReady: Boolean(moduleResolutionPosture?.materializedPathRef),
      moduleExecutableReady: Boolean(executableRef && executableHashRef),
      moduleExecutableRef: executableRef,
      moduleExecutableHashRef: executableHashRef,
      moduleStorageRefCount: storageRefs.length,
      moduleAvailabilityRefCount: availabilityRefs.length,
      moduleConflictCount: conflictRefs.length,
    },
    requestedAt: now,
    acceptedAt: accepted ? now + 1 : undefined,
    startedAt: running ? now + 2 : undefined,
    completedAt: succeeded ? now + 3 : undefined,
    observedAt: Number(input.observedAt || (succeeded ? now + 3 : accepted ? now + 1 : now)),
    expiresAt: Number(input.expiresAt || now + 3600),
  };
  if (fulfillmentSessionId) runnerOperation.fulfillmentSessionId = fulfillmentSessionId;
  rejectUnsafeSafeFacts(runnerOperation.safeFacts, "runner module load operation");
  return assertRunnerOperation(runnerOperation);
}

export function buildRunnerFulfillmentSession(input = {}) {
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const hostPosture = input.hostPosture
    ? assertRunnerHostFulfillmentPosture(input.hostPosture)
    : buildRunnerHostFulfillmentPosture({
      ...input,
      runnerOperation,
    });
  const observedAt = Number(input.now || hostPosture.observedAt || runnerOperation.observedAt || 0) || nowSeconds();
  const safeFacts = isObject(runnerOperation.safeFacts) ? runnerOperation.safeFacts : {};
  const sessionId = String(
    input.sessionId
    || runnerOperation.fulfillmentSessionId
    || safeFacts.fulfillmentSessionId
    || `fulfillment-session:${runnerOperation.operationId}`,
  ).trim();
  const parentIntentRef = String(
    input.parentIntentRef
    || safeFacts.promotionIntentRef
    || runnerOperation.contractRef,
  ).trim();
  const storageInputRefs = unique([
    ...asArray(runnerOperation.inputRefs).filter((ref) => (
      ref.startsWith("storage:")
      || ref.startsWith("storage-module-")
      || ref.startsWith("materialized:path:")
      || ref.startsWith("executable:module:")
      || ref.startsWith("sha256:")
    )),
  ]);
  const processorCapabilityRefs = unique(
    asArray(runnerOperation.capabilityRefs)
      .map((ref) => String(ref || "").replace(/^capability:/, "")),
  );
  const blockedReasons = unique([
    ...asArray(input.blockedReasons),
    ...asArray(hostPosture.blockedReasons),
    ...asArray(runnerOperation.blockedReasons),
  ]);
  const state = blockedReasons.length
    ? SWARM.FULFILLMENT_SESSION_STATE.BLOCKED
    : (hostPosture.state === RUNNER.HOST_FULFILLMENT_STATE.SUCCEEDED
      ? SWARM.FULFILLMENT_SESSION_STATE.RUNNING
      : SWARM.FULFILLMENT_SESSION_STATE.ACTIONABLE);
  return assertFulfillmentSession({
    kind: SWARM.RECORD_KIND.FULFILLMENT_SESSION,
    sessionId,
    parentIntentRef,
    subjectRef: runnerOperation.subjectRef,
    contractRef: runnerOperation.contractRef,
    state,
    nodePostures: [
      {
        nodeRef: String(input.runtimeRef || "runtime:runner-dispatch"),
        role: SWARM.FULFILLMENT_SESSION_NODE_ROLE.RUNTIME,
        state: SWARM.FULFILLMENT_SESSION_STATE.ACTIONABLE,
        participantRef: runnerOperation.requesterRef,
        memberRef: runnerOperation.requesterRef,
        contractRef: runnerOperation.contractRef,
        capabilityRefs: ["runtime.runner.dispatch"],
        inputRefs: unique([parentIntentRef, runnerOperation.contractRef]),
        outputRefs: [`runtime-runner-dispatch:${runnerOperation.operationId}`],
        evidenceRefs: ["runtime:evidence:runner-dispatch"],
        blockedReasons: [],
        safeFacts: {
          dispatchPrepared: true,
        },
      },
      {
        nodeRef: runnerOperation.runnerId,
        role: SWARM.FULFILLMENT_SESSION_NODE_ROLE.PROCESSOR,
        state,
        participantRef: runnerOperation.runnerRef,
        memberRef: runnerOperation.runnerRef,
        contractRef: runnerOperation.contractRef,
        capabilityRefs: processorCapabilityRefs,
        inputRefs: runnerOperation.inputRefs,
        outputRefs: runnerOperation.outputRefs,
        evidenceRefs: runnerOperation.evidenceRefs,
        blockedReasons,
        safeFacts: {
          operationId: runnerOperation.operationId,
          hostRef: runnerOperation.hostRef,
        },
      },
      ...(storageInputRefs.length ? [{
        nodeRef: "storage:materialization",
        role: SWARM.FULFILLMENT_SESSION_NODE_ROLE.STORAGE,
        state: blockedReasons.length ? SWARM.FULFILLMENT_SESSION_STATE.BLOCKED : SWARM.FULFILLMENT_SESSION_STATE.RUNNING,
        contractRef: runnerOperation.contractRef,
        capabilityRefs: ["storage.module.materialize"],
        inputRefs: storageInputRefs,
        outputRefs: storageInputRefs,
        evidenceRefs: ["storage:evidence:module-materialized"],
        blockedReasons,
        safeFacts: {
          materializationRefCount: storageInputRefs.length,
        },
      }] : []),
    ],
    dependencyRefs: unique(runnerOperation.inputRefs),
    routerBindingRefs: [],
    carrierEdgeRefs: [],
    mediaPathRefs: [],
    lifecyclePlanRefs: unique([
      runnerOperation.contractRef,
      safeFacts.lifecycleManifestRef,
    ]),
    availabilityRefs: asArray(runnerOperation.inputRefs).filter((ref) => ref.startsWith("storage-availability:")),
    evidenceRefs: unique([
      ...asArray(hostPosture.evidenceRefs),
      ...asArray(input.evidenceRefs),
      "evidence:fulfillment-session:runner-module-load",
    ]),
    releaseRefs: runnerOperation.releaseRefs,
    blockedReasons,
    safeFacts: {
      lifecycleManifestRef: String(safeFacts.lifecycleManifestRef || ""),
      promotionIntentRef: String(safeFacts.promotionIntentRef || ""),
      moduleRef: String(safeFacts.moduleRef || runnerOperation.subjectRef || ""),
      hostRef: runnerOperation.hostRef,
    },
    issuedAt: Number(runnerOperation.requestedAt || observedAt),
    observedAt,
    expiresAt: Number(runnerOperation.expiresAt || observedAt + 3600),
  });
}

export function projectFulfillmentSessionReadModel(input = {}) {
  const fulfillmentSession = assertFulfillmentSession(input.fulfillmentSession);
  const runnerOperation = input.runnerOperation
    ? assertRunnerOperation(input.runnerOperation)
    : null;
  const hostPosture = input.hostPosture
    ? assertRunnerHostFulfillmentPosture(input.hostPosture)
    : null;
  const observedAt = Number(input.now || input.observedAt || fulfillmentSession.observedAt || 0) || nowSeconds();
  const sessionSafeFacts = isObject(fulfillmentSession.safeFacts) ? fulfillmentSession.safeFacts : {};
  const adapterDebtPosture = isObject(input.adapterDebtPosture) ? input.adapterDebtPosture : null;
  const storageAvailabilityRefs = unique([
    ...asArray(fulfillmentSession.availabilityRefs),
    ...asArray(input.storageAvailabilityRefs),
    ...asArray(runnerOperation?.inputRefs).filter((ref) => ref.startsWith("storage-availability:")),
  ]);
  const storageRefs = unique([
    ...asArray(input.storageRefs),
    ...asArray(runnerOperation?.inputRefs).filter((ref) => ref.startsWith("storage:")),
  ]);
  const executableRefs = unique([
    ...asArray(input.executableRefs),
    ...asArray(runnerOperation?.inputRefs).filter((ref) => ref.startsWith("executable:module:")),
  ]);
  const blockedReasons = unique([
    ...asArray(fulfillmentSession.blockedReasons),
    ...asArray(hostPosture?.blockedReasons),
    ...asArray(runnerOperation?.blockedReasons),
  ]);
  const adapterDebtState = String(adapterDebtPosture?.state || "").trim();
  const state = blockedReasons.length
    ? "blocked"
    : (adapterDebtState && adapterDebtState !== "clear" && adapterDebtState !== "ready")
      ? "degraded"
      : "ready";
  const lifecycleManifestRef = String(
    sessionSafeFacts.lifecycleManifestRef
    || fulfillmentSession.contractRef
    || "",
  ).trim();
  const parentIntentRef = String(fulfillmentSession.parentIntentRef || sessionSafeFacts.promotionIntentRef || "").trim();
  const runnerRef = String(runnerOperation?.runnerRef || hostPosture?.runnerRef || "").trim();
  const hostRef = String(runnerOperation?.hostRef || hostPosture?.hostRef || sessionSafeFacts.hostRef || "").trim();
  const projection = {
    kind: SWARM.RECORD_KIND.RUNTIME_FULFILLMENT_SESSION_PROJECTION,
    projectionRef: String(input.projectionRef || `runtime:fulfillment-session:projection:${fulfillmentSession.sessionId}`),
    state,
    sessionId: fulfillmentSession.sessionId,
    lifecycleManifestRef,
    parentIntentRef,
    subjectRef: fulfillmentSession.subjectRef,
    contractRef: fulfillmentSession.contractRef,
    hostRef,
    runnerRef,
    storageAvailabilityRefs,
    storageRefs,
    executableRefs,
    adapterDebtState,
    adapterDebtRef: String(adapterDebtPosture?.postureRef || adapterDebtPosture?.kind || ""),
    queryKeys: {
      bySession: fulfillmentSession.sessionId,
      byManifest: lifecycleManifestRef,
      byParentIntent: parentIntentRef,
      bySubject: fulfillmentSession.subjectRef,
      byHost: hostRef,
      byRunner: runnerRef,
      byStorageAvailability: storageAvailabilityRefs,
    },
    currentPosture: {
      sessionState: fulfillmentSession.state,
      runnerOperationState: runnerOperation?.state || "",
      hostFulfillmentState: hostPosture?.state || "",
      nodeCount: asArray(fulfillmentSession.nodePostures).length,
    },
    evidenceRefs: unique([
      ...asArray(fulfillmentSession.evidenceRefs),
      ...asArray(hostPosture?.evidenceRefs),
      ...asArray(runnerOperation?.evidenceRefs),
      "evidence:runtime:fulfillment-session-projection",
    ]),
    blockedReasons,
    safeFacts: {
      lateConsumerQueryable: true,
      sourceTruthOwnedByRuntime: false,
      adapterDebtTracked: Boolean(adapterDebtState),
    },
    observedAt,
  };
  rejectUnsafeSafeFacts(projection.safeFacts, "runtime fulfillment session projection");
  return projection;
}

export function fulfillRunnerOperationDispatch(input = {}) {
  const source = assertRunnerOperation(input.runnerOperation);
  const now = Number(input.now || input.observedAt || 0) || nowSeconds();
  const inputRefs = unique(asArray(source.inputRefs));
  const blockedReasons = unique([
    ...asArray(input.blockedReasons),
    ...asArray(source.blockedReasons),
    ...(!source.operationId ? ["dispatch:missingOperationId"] : []),
    ...(source.operation !== RUNNER.OPERATION.EXECUTE ? [`dispatch:unsupportedOperation:${source.operation || "unknown"}`] : []),
    ...(source.expiresAt !== undefined && Number(source.expiresAt || 0) <= now ? ["dispatch:expired"] : []),
    ...(inputRefs.some((ref) => ref.startsWith("artifact:")) ? [] : ["dispatch:missingArtifactRef"]),
    ...(inputRefs.some((ref) => ref.startsWith("materialized:path:")) ? [] : ["dispatch:missingMaterializedPathRef"]),
    ...(inputRefs.some((ref) => ref.startsWith("executable:module:")) ? [] : ["dispatch:missingExecutableRef"]),
    ...(inputRefs.some((ref) => ref.startsWith("storage:")) ? [] : ["dispatch:missingStorageRef"]),
  ]);
  const state = blockedReasons.length
    ? RUNNER.OPERATION_STATE.BLOCKED
    : RUNNER.OPERATION_STATE.SUCCEEDED;
  const runnerOperation = assertRunnerOperation({
    ...source,
    state,
    blockedReasons,
    evidenceRefs: unique([
      ...asArray(source.evidenceRefs),
      ...(state === RUNNER.OPERATION_STATE.SUCCEEDED ? ["runner:evidence:dispatch-fulfilled"] : []),
    ]),
    acceptedAt: source.acceptedAt || now,
    startedAt: state === RUNNER.OPERATION_STATE.SUCCEEDED ? now + 1 : source.startedAt,
    completedAt: state === RUNNER.OPERATION_STATE.SUCCEEDED ? now + 2 : source.completedAt,
    observedAt: state === RUNNER.OPERATION_STATE.SUCCEEDED ? now + 2 : now,
    safeFacts: {
      ...(isObject(source.safeFacts) ? source.safeFacts : {}),
      dispatchFulfilledByRunner: state === RUNNER.OPERATION_STATE.SUCCEEDED,
    },
  });
  const hostPosture = buildRunnerHostFulfillmentPosture({
    ...input,
    runnerOperation,
    now: runnerOperation.observedAt,
  });
  const fulfillmentSession = buildRunnerFulfillmentSession({
    ...input,
    runnerOperation,
    hostPosture,
    now: runnerOperation.observedAt,
  });
  const fulfillmentSessionProjection = projectFulfillmentSessionReadModel({
    ...input,
    runnerOperation,
    hostPosture,
    fulfillmentSession,
    now: runnerOperation.observedAt,
  });
  return {
    kind: "runner.dispatch.fulfillment",
    state: hostPosture.state,
    dispatchRef: `runtime-runner-dispatch:${runnerOperation.operationId}`,
    runnerOperation,
    hostPosture,
    fulfillmentSession,
    fulfillmentSessionProjection,
    runtimeReportMessage: {
      type: "runtime.runner.host.fulfillment.put",
      hostFulfillmentPosture: hostPosture,
      fulfillmentSession,
      fulfillmentSessionProjection,
    },
    blockedReasons: hostPosture.blockedReasons || [],
    observedAt: runnerOperation.observedAt,
  };
}

function runtimeRunnerDispatchEntries(input = {}) {
  const containers = [
    input.dispatches,
    input.runnerOperations,
    input.runtimeSnapshot?.runnerOperations,
    input.snapshot?.runnerOperations,
  ];
  const entries = [];
  for (const container of containers) {
    if (!container) continue;
    if (Array.isArray(container)) {
      entries.push(...container.filter(isObject));
    } else if (isObject(container)) {
      entries.push(...Object.values(container).filter(isObject));
    }
  }
  return entries;
}

function runtimeDispatchState(dispatch) {
  return String(
    dispatch?.state
    || dispatch?.hostFulfillmentPosture?.state
    || dispatch?.runnerOperation?.state
    || "",
  ).trim();
}

function isAcceptedRuntimeDispatch(dispatch) {
  const state = runtimeDispatchState(dispatch);
  if (state === RUNNER.HOST_FULFILLMENT_STATE.ACCEPTED) return true;
  return [
    RUNNER.OPERATION_STATE.REQUESTED,
    RUNNER.OPERATION_STATE.ACCEPTED,
    RUNNER.OPERATION_STATE.RUNNING,
  ].includes(String(dispatch?.runnerOperation?.state || state || "").trim());
}

export async function fulfillAcceptedRuntimeRunnerDispatches(input = {}) {
  const now = Number(input.now || input.observedAt || 0) || nowSeconds();
  const putRuntimeReport = typeof input.putRuntimeReport === "function"
    ? input.putRuntimeReport
    : (typeof input.putRunnerHostFulfillmentPosture === "function"
      ? (hostFulfillmentPosture, runtimeReportMessage, dispatch) => input.putRunnerHostFulfillmentPosture(hostFulfillmentPosture, runtimeReportMessage, dispatch)
      : null);
  const fulfilled = [];
  const skipped = [];
  const blockedReasons = [];
  const dispatches = runtimeRunnerDispatchEntries(input);

  for (const dispatch of dispatches) {
    const dispatchId = String(dispatch.dispatchId || dispatch.operationId || dispatch.runnerOperation?.operationId || "").trim();
    if (!isAcceptedRuntimeDispatch(dispatch)) {
      skipped.push({
        dispatchId,
        operationId: String(dispatch.operationId || dispatch.runnerOperation?.operationId || "").trim(),
        state: runtimeDispatchState(dispatch) || "unknown",
        reason: "notAccepted",
      });
      continue;
    }
    if (!isObject(dispatch.runnerOperation)) {
      const reason = `dispatch:${dispatchId || "unknown"}:missingRunnerOperation`;
      skipped.push({ dispatchId, state: runtimeDispatchState(dispatch) || "accepted", reason });
      blockedReasons.push(reason);
      continue;
    }

    const fulfillment = fulfillRunnerOperationDispatch({
      runnerOperation: dispatch.runnerOperation,
      serviceRefs: input.serviceRefs,
      contractRefs: input.contractRefs,
      witnessRefs: input.witnessRefs,
      evidenceRefs: input.evidenceRefs,
      now,
    });
    let reportResult = null;
    if (putRuntimeReport) {
      reportResult = await putRuntimeReport(
        fulfillment.runtimeReportMessage.hostFulfillmentPosture,
        fulfillment.runtimeReportMessage,
        dispatch,
      );
    }
    fulfilled.push({
      dispatchId: dispatchId || fulfillment.dispatchRef,
      operationId: fulfillment.runnerOperation.operationId,
      state: fulfillment.state,
      runnerOperation: fulfillment.runnerOperation,
      hostPosture: fulfillment.hostPosture,
      fulfillmentSession: fulfillment.fulfillmentSession,
      runtimeReportMessage: fulfillment.runtimeReportMessage,
      reportResult,
      blockedReasons: fulfillment.blockedReasons || [],
    });
    blockedReasons.push(...asArray(fulfillment.blockedReasons));
  }

  const state = blockedReasons.length
    ? "blocked"
    : (fulfilled.length ? "succeeded" : "idle");
  return {
    kind: "runner.runtime-dispatch.bridge",
    state,
    adapterRef: String(input.adapterRef || "adapter:runner.runtime-dispatch").trim(),
    sourceRuntimeRef: String(input.runtimeRef || input.sourceRuntimeRef || "").trim(),
    fulfilledCount: fulfilled.length,
    skippedCount: skipped.length,
    fulfilled,
    skipped,
    blockedReasons: unique(blockedReasons),
    observedAt: now,
  };
}

export function createRuntimeRunnerFulfillmentAdapter(options = {}) {
  const adapterRef = String(options.adapterRef || "adapter:runner.execution-fulfillment:local").trim();
  const serviceRefs = asArray(options.serviceRefs);
  const contractRefs = asArray(options.contractRefs);
  const witnessRefs = asArray(options.witnessRefs);
  const evidenceRefs = asArray(options.evidenceRefs);
  return async function fulfillDispatch(context = {}) {
    const runnerOperation = context.runnerOperation || context.dispatch?.runnerOperation;
    return fulfillRunnerOperationDispatch({
      runnerOperation,
      serviceRefs,
      contractRefs,
      witnessRefs,
      evidenceRefs: unique([
        ...evidenceRefs,
        adapterRef ? `evidence:${adapterRef}` : "",
      ]),
      now: Number(options.now || options.observedAt || 0) || nowSeconds(),
    });
  };
}

export function installRuntimeRunnerFulfillmentAdapter(target = globalThis, options = {}) {
  if (!target || typeof target !== "object") {
    throw new Error("runtime runner adapter target is required");
  }
  const adapterRef = String(options.adapterRef || "adapter:runner.execution-fulfillment:local").trim();
  const fulfillDispatch = createRuntimeRunnerFulfillmentAdapter({ ...options, adapterRef });
  const existing = target.constituteRuntimeRunnerBridge && typeof target.constituteRuntimeRunnerBridge === "object"
    ? target.constituteRuntimeRunnerBridge
    : {};
  const registration = {
    ...existing,
    kind: "runtime.runner.host-adapter.registration",
    adapterRef,
    role: "executionFulfillment",
    fulfillDispatch,
    safeFacts: {
      ...(existing.safeFacts && typeof existing.safeFacts === "object" ? existing.safeFacts : {}),
      hostAdapterRegistered: true,
      serviceHostIdentitySeparated: true,
    },
  };
  target.constituteRuntimeRunnerBridge = registration;
  return registration;
}

function normalizedAppOperationState(runnerOperation, blockedReasons) {
  if (blockedReasons.length) return "blocked";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.REJECTED) return "rejected";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.FAILED) return "failed";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.CANCELLED) return "cancelled";
  if (runnerOperation.operation === RUNNER.OPERATION.RELEASE || runnerOperation.state === RUNNER.OPERATION_STATE.RELEASED) return "released";
  if (runnerOperation.operation === RUNNER.OPERATION.ROLLBACK && runnerOperation.state === RUNNER.OPERATION_STATE.SUCCEEDED) return "rolledBack";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.SUCCEEDED) return "succeeded";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.RUNNING) return "running";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.ACCEPTED) return "accepted";
  if (runnerOperation.state === RUNNER.OPERATION_STATE.REQUESTED) return "requested";
  return runnerOperation.state || "unknown";
}

function normalizedHostFulfillmentState(runnerOperation, blockedReasons) {
  if (blockedReasons.length) return RUNNER.HOST_FULFILLMENT_STATE.BLOCKED;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.REJECTED) return RUNNER.HOST_FULFILLMENT_STATE.REJECTED;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.CANCELLED) return RUNNER.HOST_FULFILLMENT_STATE.CANCELLED;
  if (runnerOperation.operation === RUNNER.OPERATION.RELEASE || runnerOperation.state === RUNNER.OPERATION_STATE.RELEASED) return RUNNER.HOST_FULFILLMENT_STATE.RELEASED;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.SUCCEEDED) return RUNNER.HOST_FULFILLMENT_STATE.SUCCEEDED;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.RUNNING) return RUNNER.HOST_FULFILLMENT_STATE.RUNNING;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.ACCEPTED || runnerOperation.state === RUNNER.OPERATION_STATE.REQUESTED) return RUNNER.HOST_FULFILLMENT_STATE.ACCEPTED;
  if (runnerOperation.state === RUNNER.OPERATION_STATE.FAILED || runnerOperation.state === RUNNER.OPERATION_STATE.BLOCKED) return RUNNER.HOST_FULFILLMENT_STATE.BLOCKED;
  return RUNNER.HOST_FULFILLMENT_STATE.DEGRADED;
}

export function buildRunnerHostFulfillmentPosture(input = {}) {
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const observedAt = Number(input.now || runnerOperation.observedAt || 0) || nowSeconds();
  const operationExpiresAt = Number(runnerOperation.expiresAt || 0) || 0;
  const blockedReasons = unique([
    ...asArray(input.blockedReasons),
    ...(TERMINAL_BLOCKED_STATES.has(runnerOperation.state) ? [`runnerOperation:${runnerOperation.state}`] : []),
    ...(runnerOperation.expiresAt !== undefined && Number(runnerOperation.expiresAt || 0) <= observedAt ? ["runnerOperationExpired"] : []),
    ...(!runnerOperation.hostRef ? ["missingHostRef"] : []),
  ]);
  const state = normalizedHostFulfillmentState(runnerOperation, blockedReasons);
  const posture = {
    kind: SWARM.RECORD_KIND.RUNNER_HOST_FULFILLMENT_POSTURE,
    postureId: String(input.postureId || `runner-host:${runnerOperation.runnerId}:${runnerOperation.operationId}`),
    runnerId: runnerOperation.runnerId,
    runnerRef: runnerOperation.runnerRef,
    hostRef: runnerOperation.hostRef,
    operationId: runnerOperation.operationId,
    operation: runnerOperation.operation,
    state,
    requesterRef: runnerOperation.requesterRef,
    subjectRef: runnerOperation.subjectRef,
    contractRef: runnerOperation.contractRef,
    serviceRefs: unique(asArray(input.serviceRefs)),
    contractRefs: unique([runnerOperation.contractRef, ...asArray(input.contractRefs)]),
    grantRefs: unique(runnerOperation.grantRefs),
    capabilityRefs: unique(runnerOperation.capabilityRefs),
    inputRefs: unique(runnerOperation.inputRefs),
    outputRefs: unique(runnerOperation.outputRefs),
    evidenceRefs: unique([
      ...asArray(runnerOperation.evidenceRefs),
      ...(state === RUNNER.HOST_FULFILLMENT_STATE.ACCEPTED ? ["evidence:runner-host:accepted"] : []),
      ...(state === RUNNER.HOST_FULFILLMENT_STATE.SUCCEEDED ? ["evidence:runner-host:completed"] : []),
      ...asArray(input.evidenceRefs),
    ]),
    proofRefs: unique(runnerOperation.proofRefs),
    releaseRefs: unique(runnerOperation.releaseRefs),
    witnessRefs: unique(asArray(input.witnessRefs)),
    resourceBudget: runnerOperation.resourceBudget,
    resourcePosture: runnerOperation.resourcePosture || null,
    secretBoundary: runnerOperation.secretBoundary || { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: runnerOperation.releasePosture || null,
    rollbackPosture: runnerOperation.rollbackPosture || null,
    safeFacts: {
      hostRef: runnerOperation.hostRef,
      contractRef: runnerOperation.contractRef,
      serviceHostIdentitySeparated: runnerOperation.hostRef !== runnerOperation.contractRef,
      operation: runnerOperation.operation,
    },
    blockedReasons,
    observedAt,
    ...(operationExpiresAt > observedAt ? { expiresAt: operationExpiresAt } : {}),
  };
  if (runnerOperation.releaseRef) posture.releaseRef = runnerOperation.releaseRef;
  if (runnerOperation.rollbackRef) posture.rollbackRef = runnerOperation.rollbackRef;
  return assertRunnerHostFulfillmentPosture(posture);
}

export function assertRunnerHostPosture(record) {
  return assertRunnerHostFulfillmentPosture(record);
}

export function buildAppRunnerFulfillment(input = {}) {
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const appContract = input.appContract ? assertSurfaceAppContract(input.appContract) : null;
  const manifest = input.manifest ? assertSurfaceAppManifest(input.manifest) : null;
  const hostFulfillmentPosture = input.hostFulfillmentPosture
    ? assertRunnerHostFulfillmentPosture(input.hostFulfillmentPosture)
    : buildRunnerHostFulfillmentPosture(input);
  const observedAt = Number(input.now || runnerOperation.observedAt || 0) || nowSeconds();
  const operationExpiresAt = Number(runnerOperation.expiresAt || 0) || 0;
  const refs = appContractRefUniverse(appContract, manifest);
  const sourceMode = String(manifest?.defaultSourceMode || SURFACE_APP.FULFILLMENT_MODE.BUNDLED).trim();
  const sourceRefs = manifest ? manifestSourceRefs(manifest) : [];
  const blockedReasons = [];
  if (!appContract) blockedReasons.push("missingAppContract");
  if (!manifest) blockedReasons.push("missingAppManifest");
  if (TERMINAL_BLOCKED_STATES.has(runnerOperation.state)) blockedReasons.push(`runnerOperation:${runnerOperation.state}`);
  if (runnerOperation.expiresAt !== undefined && Number(runnerOperation.expiresAt || 0) <= observedAt) blockedReasons.push("runnerOperationExpired");
  if (refs.size && !refs.has(runnerOperation.contractRef)) blockedReasons.push("contractRefMismatch");
  if (!intersects(stringSet(runnerOperation.inputRefs), refs)) blockedReasons.push("inputRefMismatch");
  if (!runnerOperation.resourceBudget || typeof runnerOperation.resourceBudget !== "object") blockedReasons.push("missingResourceBudget");
  if (runnerOperation.secretBoundary?.state === SURFACE_APP.SECRET_BOUNDARY.BLOCKED) blockedReasons.push("secretBoundaryBlocked");
  if (runnerOperation.releasePosture?.state === SURFACE_APP.RELEASE_POSTURE.BLOCKED) blockedReasons.push("releasePostureBlocked");
  if (runnerOperation.rollbackPosture?.state === SURFACE_APP.RELEASE_POSTURE.BLOCKED) blockedReasons.push("rollbackPostureBlocked");
  if (["blocked", "rejected", "cancelled"].includes(hostFulfillmentPosture.state)) {
    blockedReasons.push(...asArray(hostFulfillmentPosture.blockedReasons).map((reason) => `host:${reason}`));
  }
  const state = normalizedAppOperationState(runnerOperation, unique(blockedReasons));
  const report = {
    kind: APP_RUNNER_FULFILLMENT_KIND,
    reportId: String(input.reportId || `app-runner:${runnerOperation.runnerId}:${runnerOperation.operationId}`),
    runnerId: runnerOperation.runnerId,
    runnerRef: runnerOperation.runnerRef,
    hostRef: runnerOperation.hostRef,
    runnerOperationId: runnerOperation.operationId,
    operation: runnerOperation.operation,
    state,
    requesterRef: runnerOperation.requesterRef,
    subjectRef: runnerOperation.subjectRef,
    contractRef: runnerOperation.contractRef,
    appContractRef: String(appContract?.appRef || appContract?.contractId || ""),
    appId: String(appContract?.appId || manifest?.appId || ""),
    version: String(appContract?.version || manifest?.currentVersion || ""),
    manifestRef: String(manifest?.manifestId || ""),
    sourceMode,
    sourceRefs,
    grantRefs: unique(runnerOperation.grantRefs),
    capabilityRefs: unique(runnerOperation.capabilityRefs),
    inputRefs: unique(runnerOperation.inputRefs),
    outputRefs: unique(runnerOperation.outputRefs),
    evidenceRefs: unique(runnerOperation.evidenceRefs),
    proofRefs: unique(runnerOperation.proofRefs),
    releaseRefs: unique(runnerOperation.releaseRefs),
    resourceBudget: runnerOperation.resourceBudget,
    resourcePosture: runnerOperation.resourcePosture || null,
    secretBoundary: runnerOperation.secretBoundary || { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: runnerOperation.releasePosture || null,
    rollbackPosture: runnerOperation.rollbackPosture || null,
    hostFulfillmentPosture,
    releaseRef: runnerOperation.releaseRef || "",
    rollbackRef: runnerOperation.rollbackRef || "",
    operationPosture: {
      state,
      accepted: Boolean(runnerOperation.acceptedAt || runnerOperation.startedAt || runnerOperation.completedAt),
      rejected: ["blocked", "failed", "rejected", "cancelled"].includes(state),
      requestedAt: runnerOperation.requestedAt,
      acceptedAt: runnerOperation.acceptedAt,
      startedAt: runnerOperation.startedAt,
      completedAt: runnerOperation.completedAt,
      observedAt,
    },
    fulfillmentPosture: {
      state,
      outputRefs: unique(runnerOperation.outputRefs),
      releaseRefs: unique(runnerOperation.releaseRefs),
      proofRefs: unique(runnerOperation.proofRefs),
      evidenceRefs: unique(runnerOperation.evidenceRefs),
      expiresAt: runnerOperation.expiresAt,
    },
    safeFacts: {
      appId: String(appContract?.appId || manifest?.appId || ""),
      version: String(appContract?.version || manifest?.currentVersion || ""),
      sourceMode,
      sourceRefCount: sourceRefs.length,
      moduleRoleCount: asArray(appContract?.requiredModuleRoles).length,
      outputRefCount: asArray(runnerOperation.outputRefs).length,
      releaseRefCount: asArray(runnerOperation.releaseRefs).length,
      proofRefCount: asArray(runnerOperation.proofRefs).length,
    },
    blockedReasons: unique(blockedReasons),
    observedAt,
    ...(operationExpiresAt > observedAt ? { expiresAt: operationExpiresAt } : {}),
  };
  return assertAppRunnerFulfillmentReport(report);
}

export function assertAppRunnerFulfillmentReport(record) {
  return assertProtocolAppRunnerFulfillmentReport(record);
}

export function buildAppRunnerFulfillmentLifecycle(input = {}) {
  const report = input.report
    ? assertAppRunnerFulfillmentReport(input.report)
    : buildAppRunnerFulfillment(input);
  const lifecycle = {
    ...report,
    kind: APP_RUNNER_FULFILLMENT_LIFECYCLE_KIND,
    lifecycleId: String(input.lifecycleId || `app-runner-lifecycle:${report.reportId}`),
    witnessRefs: unique([
      ...asArray(report.witnessRefs),
      ...asArray(input.witnessRefs),
    ]),
    releaseWitnessRefs: unique([
      ...asArray(report.releaseWitnessRefs),
      ...asArray(input.releaseWitnessRefs),
    ]),
    requestedAt: report.operationPosture?.requestedAt,
    acceptedAt: report.operationPosture?.acceptedAt,
    startedAt: report.operationPosture?.startedAt,
    completedAt: report.operationPosture?.completedAt,
    releasedAt: input.releasedAt || (report.state === RUNNER.FULFILLMENT_STATE.RELEASED ? report.observedAt : undefined),
    rolledBackAt: input.rolledBackAt || (report.state === RUNNER.FULFILLMENT_STATE.ROLLED_BACK ? report.observedAt : undefined),
    rejectedAt: input.rejectedAt || (["blocked", "failed", "rejected", "cancelled"].includes(report.state) ? report.observedAt : undefined),
    expiredAt: input.expiredAt,
  };
  return assertProtocolAppRunnerFulfillmentLifecycle(lifecycle);
}

export function assertAppRunnerFulfillmentLifecycle(record) {
  return assertProtocolAppRunnerFulfillmentLifecycle(record);
}

export function appRunnerFulfillmentFixture(now = nowSeconds()) {
  const appContract = assertSurfaceAppContract({
    contractId: "surface-app:runner-proof",
    schemaVersion: SURFACE_APP.SCHEMA_VERSION,
    appId: "constitute-runner-proof",
    appRef: "app:runner-proof",
    version: "0.1.0",
    displayName: "Runner Proof",
    requiredPrimitives: ["runtime.attach", "runner.operation"],
    requiredModuleRoles: [
      SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
      SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    ],
    modules: [
      {
        moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.attach"],
        issuedAt: now,
      },
      {
        moduleRef: "constitute-runner-proof/product-view@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.posture.render"],
        issuedAt: now,
      },
    ],
    updatePosture: { state: SURFACE_APP.UPDATE_POSTURE.STATIC },
    serviceManagerPosture: {
      managerId: "manager:runner-proof",
      subjectRef: "app:runner-proof",
      managerRef: "manager:runner-proof",
      state: SURFACE_APP.SERVICE_MANAGER_POSTURE.MANUAL,
      serviceRefs: ["app:runner-proof"],
      capabilityRefs: ["service.manage"],
      evidenceRefs: ["build:runner-proof"],
      issuedAt: now,
      expiresAt: now + 3600,
    },
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:runner-proof",
      releaseRef: "release:runner-proof",
      rollbackRef: "rollback:runner-proof",
    },
    issuedAt: now,
  });
  const manifest = assertSurfaceAppManifest({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST,
    manifestId: "manifest:runner-proof",
    appId: appContract.appId,
    state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
    currentAppContractRef: appContract.appRef,
    currentVersion: appContract.version,
    defaultSourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    requiredModuleRoles: appContract.requiredModuleRoles,
    bundledSourceRefs: ["bundle:runner-proof@0.1.0"],
    versions: [
      {
        appContractRef: appContract.appRef,
        version: appContract.version,
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        requiredModuleRoles: appContract.requiredModuleRoles,
        bundledSourceRefs: ["bundle:runner-proof@0.1.0"],
        grantRefs: ["grant:app:runner-proof:run"],
        runnerRequirementRefs: ["runner:req:runner-proof"],
        serviceManagerRequirementRefs: ["service-manager:req:runner-proof"],
        compatibilityRefs: ["protocol:surface-app:v1"],
        compatibilityWindow: {
          minVersion: "0.1.0",
          maxVersion: "0.1.x",
          protocolRef: "protocol:surface-app:v1",
        },
        bootstrapContractRef: "bootstrap-contract:runner-proof",
        releaseContractRef: "release:runner-proof",
        evidenceRefs: ["build:runner-proof"],
        issuedAt: now,
      },
    ],
    appContractRefs: [appContract.appRef],
    grantRefs: ["grant:app:runner-proof:run"],
    runnerRequirementRefs: ["runner:req:runner-proof"],
    serviceManagerRequirementRefs: ["service-manager:req:runner-proof"],
    compatibilityRefs: ["protocol:surface-app:v1"],
    bootstrapContractRefs: ["bootstrap-contract:runner-proof"],
    releaseContractRefs: ["release:runner-proof"],
    authorityRefs: ["authority:runner-proof"],
    evidenceRefs: ["build:runner-proof"],
    issuedAt: now,
  });
  const runnerOperation = assertRunnerOperation({
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: "runner-operation:app-proof:execute:1",
    runnerId: "runner:local-host:app-proof",
    runnerRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:runner-lab",
    requesterRef: "identity:aux",
    subjectRef: appContract.appRef,
    contractRef: appContract.appRef,
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.OPERATION_STATE.SUCCEEDED,
    grantRefs: ["grant:app:runner-proof:run"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: [manifest.manifestId, appContract.appRef],
    outputRefs: ["artifact:runner-proof:dist", "proof:runner-proof:surface"],
    evidenceRefs: ["evidence:runner:accepted", "evidence:runner:completed"],
    proofRefs: ["proof:runner-proof:surface"],
    releaseRefs: ["release:runner-proof"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 256,
      maxCpuPct: 25,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:app-proof",
      profileId: "resource-profile:operator-dev",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 96, cpuPct: 4 },
      budgets: { memoryMiB: 256, cpuPct: 25 },
      sampledAt: now + 3,
    },
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: appContract.releasePosture,
    releaseRef: "release:runner-proof",
    rollbackRef: "rollback:runner-proof",
    safeFacts: {
      appId: appContract.appId,
      mode: "operatorDev",
    },
    requestedAt: now,
    acceptedAt: now + 1,
    startedAt: now + 2,
    completedAt: now + 10,
    observedAt: now + 12,
    expiresAt: now + 3600,
  });
  return { appContract, manifest, runnerOperation };
}

export function buildRunnerBuildOperationFixture(now = nowSeconds()) {
  const buildContract = {
    buildContractRef: "build:contract:build-runner-proof",
    sourceSnapshotRef: "source:snapshot:head",
    recipeRef: "build:recipe:browser-module",
  };
  const buildRun = {
    runRef: "build:run:build-runner-proof",
    buildContractRef: buildContract.buildContractRef,
    sourceSnapshotRef: buildContract.sourceSnapshotRef,
    recipeRef: buildContract.recipeRef,
    runnerRef: "runner:local-host:build",
    runnerOperationRef: "runner-operation:build-build-runner-proof:execute:1",
    state: "succeeded",
    grantRefs: ["authority:grant:runner-build"],
    artifactRefs: ["build:artifact:module"],
    proofRefs: ["build:proof:build-runner-proof"],
    releaseCandidateRefs: ["release:candidate:build-runner-proof"],
    evidenceRefs: ["runner:evidence:build-accepted", "runner:evidence:build-completed"],
    blockedReasons: [],
    requestedAt: now,
    startedAt: now + 2,
    completedAt: now + 9,
    expiresAt: now + 3600,
  };
  const runnerOperation = buildRunnerOperationForBuild({
    buildContract,
    buildRun,
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:runner-lab",
    requesterRef: "identity:aux",
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:build-build-runner-proof",
      profileId: "resource-profile:build-lite",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 144, cpuPct: 8 },
      budgets: { memoryMiB: 512, cpuPct: 35 },
      sampledAt: now + 3,
    },
  });
  return {
    runnerOperation,
    hostPosture: buildRunnerHostFulfillmentPosture({
      runnerOperation,
      serviceRefs: ["build:contract:build-runner-proof"],
      witnessRefs: ["witness:build:runner-host"],
    }),
  };
}

export function buildRunnerModuleLoadOperationFixture(now = nowSeconds()) {
  const moduleResolverPosture = {
    kind: "operator.native-module.resolver",
    state: "ready",
    resolverRef: "module-resolver:native-dev:build-proof",
    sourceSnapshotRef: "source:snapshot:native-dev:build-proof",
    contentIndexRef: "content-index:native-dev:build-proof",
    moduleResolutions: [
      {
        moduleRef: "module:native-dev:constitute-build",
        repoRef: "repo:constitute-build",
        role: "build-fulfillment",
        state: "materialized",
        sourceSnapshotRef: "source:snapshot:native-dev:constitute-build:build-proof",
        contentIndexRef: "content-index:native-dev:constitute-build:build-proof",
        artifactRef: "artifact:native-dev:constitute-build:build-proof",
        materializedPathRef: "materialized:path:workspace-dev:constitute-build",
        storageMaterializationPostureRef: "storage-module-materialization-posture:constitute-build-proof",
        storageExecutableInstantiationPostureRef:
          "storage-module-executable-instantiation-posture:constitute-build-proof",
        executableRef: "executable:module:module_native-dev_constitute-build:build-proof",
        executableHashRef: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        objectRefs: [
          "storage:object:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        availabilityRefs: ["storage-availability:constitute-build-proof"],
        storagePostureRefs: [
          "storage-module-materialization-posture:constitute-build-proof",
          "storage-module-executable-instantiation-posture:constitute-build-proof",
        ],
        storageRefs: [
          "storage:object:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        conflictRefs: [],
      },
    ],
    transitionConflicts: [],
    blockedReasons: [],
  };
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture,
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:runner-lab",
    requesterRef: "identity:aux",
    grantRefs: ["authority:grant:runner-module-load"],
    now,
  });
  return {
    moduleResolverPosture,
    runnerOperation,
    hostPosture: buildRunnerHostFulfillmentPosture({
      runnerOperation,
      serviceRefs: ["module:native-dev:constitute-build"],
      witnessRefs: ["witness:module-load:runner-host"],
      now: runnerOperation.observedAt,
    }),
  };
}

export function buildRunnerOperationForBuild(input = {}) {
  const buildContract = input.buildContract || {};
  const buildRun = input.buildRun || input.run || {};
  const now = Number(input.now || buildRun.requestedAt || 0) || nowSeconds();
  const contractRef = String(buildRun.buildContractRef || buildContract.buildContractRef || "").trim();
  const sourceSnapshotRef = String(buildRun.sourceSnapshotRef || buildContract.sourceSnapshotRef || "").trim();
  const recipeRef = String(buildRun.recipeRef || buildContract.recipeRef || "").trim();
  const requestedModuleRef = String(input.processorModuleRef || input.moduleRef || "").trim();
  const moduleResolutionPosture = isObject(input.moduleResolutionPosture)
    ? input.moduleResolutionPosture
    : (isObject(input.moduleResolverPosture) || requestedModuleRef
      ? resolveRunnerModuleFromResolver({
        moduleResolverPosture: input.moduleResolverPosture,
        moduleRef: requestedModuleRef || input.moduleRef,
        now,
      })
      : null);
  const moduleResolutionBlockedReasons = asArray(moduleResolutionPosture?.blockedReasons)
    .map((reason) => `moduleResolver:${reason}`);
  const blockedReasons = unique([
    ...asArray(buildRun.blockedReasons),
    ...moduleResolutionBlockedReasons,
  ]);
  const succeeded = buildRun.state === "succeeded" && blockedReasons.length === 0;
  const state = succeeded
    ? RUNNER.OPERATION_STATE.SUCCEEDED
    : buildRun.state === "failed"
      ? RUNNER.OPERATION_STATE.FAILED
      : RUNNER.OPERATION_STATE.BLOCKED;
  const artifactRefs = succeeded ? unique(asArray(buildRun.artifactRefs)) : [];
  const proofRefs = succeeded ? unique(asArray(buildRun.proofRefs)) : [];
  const releaseRefs = succeeded ? unique(asArray(buildRun.releaseCandidateRefs)) : [];
  const moduleInputRefs = moduleResolutionPosture && !moduleResolutionBlockedReasons.length
    ? unique([
      moduleResolutionPosture.moduleRef,
      moduleResolutionPosture.sourceSnapshotRef,
      moduleResolutionPosture.contentIndexRef,
      moduleResolutionPosture.artifactRef,
      ...asArray(moduleResolutionPosture.storageRefs),
    ])
    : [];
  const releasePosture = input.releasePosture || {
    state: succeeded ? SURFACE_APP.RELEASE_POSTURE.BUILD_READY : SURFACE_APP.RELEASE_POSTURE.BLOCKED,
    buildRef: contractRef,
    ...(releaseRefs[0] ? { releaseRef: releaseRefs[0] } : {}),
    rollbackRef: input.rollbackRef || `rollback:${contractRef.replaceAll(":", "-")}`,
    ...(succeeded ? {} : { blockedReasons }),
  };
  const rollbackPosture = input.rollbackPosture || {
    state: succeeded ? SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY : SURFACE_APP.RELEASE_POSTURE.BLOCKED,
    rollbackRef: input.rollbackRef || `rollback:${contractRef.replaceAll(":", "-")}`,
    ...(succeeded ? {} : { blockedReasons }),
  };
  const runnerOperation = {
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: String(buildRun.runnerOperationRef || input.operationId || `runner-operation:${contractRef}:execute`).trim(),
    runnerId: String(buildRun.runnerRef || input.runnerId || "runner:local-host:build").trim(),
    runnerRef: String(input.runnerMemberRef || input.runnerRef || "").trim(),
    hostRef: String(input.hostRef || "host:runner-lab").trim(),
    requesterRef: String(input.requesterRef || "identity:aux").trim(),
    subjectRef: contractRef,
    contractRef,
    operation: RUNNER.OPERATION.EXECUTE,
    state,
    grantRefs: unique(asArray(buildRun.grantRefs).length ? buildRun.grantRefs : input.grantRefs),
    capabilityRefs: [BUILD.CAPABILITY.RUN_EXECUTE],
    inputRefs: unique([sourceSnapshotRef, recipeRef, ...moduleInputRefs]),
    outputRefs: unique([...artifactRefs, ...proofRefs, ...releaseRefs]),
    evidenceRefs: unique([
      ...asArray(buildRun.evidenceRefs),
      ...(succeeded ? ["runner:evidence:build-completed"] : []),
      ...(moduleResolutionPosture && !moduleResolutionBlockedReasons.length ? ["runner:evidence:module-resolution"] : []),
    ]),
    proofRefs,
    releaseRefs,
    resourceBudget: input.resourceBudget || {
      profileRef: "resource-profile:build-lite",
      maxMemoryMiB: 512,
      maxCpuPct: 35,
    },
    secretBoundary: input.secretBoundary || { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture,
    rollbackPosture,
    rollbackRef: input.rollbackRef || `rollback:${contractRef.replaceAll(":", "-")}`,
    blockedReasons,
    safeFacts: {
      processorContract: "build",
      sourceSnapshotRef,
      recipeRef,
      artifactCount: artifactRefs.length,
      releaseCandidateCount: releaseRefs.length,
      ...(moduleResolutionPosture ? {
        moduleResolutionState: moduleResolutionPosture.state,
        moduleResolverRef: moduleResolutionPosture.resolverRef,
        moduleRef: moduleResolutionPosture.moduleRef,
        moduleArtifactReady: Boolean(moduleResolutionPosture.artifactRef),
        moduleStorageRefCount: asArray(moduleResolutionPosture.storageRefs).length,
        moduleConflictCount: asArray(moduleResolutionPosture.conflictRefs).length,
      } : {}),
    },
    requestedAt: Number(buildRun.requestedAt || now),
    acceptedAt: succeeded ? Number(buildRun.requestedAt || now) + 1 : undefined,
    startedAt: succeeded ? Number(buildRun.startedAt || now + 2) : undefined,
    completedAt: succeeded ? Number(buildRun.completedAt || now + 9) : undefined,
    observedAt: Number(input.observedAt || buildRun.completedAt || now + 1),
    expiresAt: Number(buildRun.expiresAt || now + 3600),
  };
  if (input.resourcePosture) runnerOperation.resourcePosture = input.resourcePosture;
  if (releaseRefs[0]) runnerOperation.releaseRef = releaseRefs[0];
  if (!succeeded && runnerOperation.blockedReasons.length === 0) {
    runnerOperation.blockedReasons = [`buildRun:${buildRun.state || "blocked"}`];
  }
  return assertRunnerOperation(runnerOperation);
}

export function buildMultiIdentityGrantProof(input = {}) {
  const rootOperation = input.rootOperation ? assertAuthorityRootOperation(input.rootOperation) : null;
  const actionGrants = asArray(input.actionGrants).map(assertActionAuthorityGrant);
  const actionExercises = asArray(input.actionExercises).map(assertActionAuthorityExercise);
  const accessGroup = input.accessGroup ? assertAccessGroup(input.accessGroup) : null;
  const accessEpoch = input.accessEpoch ? assertAccessEpoch(input.accessEpoch) : null;
  const proof = assertAuthorityMultiIdentityProof(input.proof);
  const blockedReasons = new Set(asArray(proof.blockedReasons));

  if (!rootOperation) blockedReasons.add("missingRootOperation");
  if (rootOperation && rootOperation.state !== AGREEMENT.ACTION_GRANT_STATE.APPLIED) blockedReasons.add(`rootOperation:${rootOperation.state}`);
  if (!actionGrants.some((grant) => grant.elevated === true && asArray(grant.rootRefs).length > 0)) blockedReasons.add("missingAdminGrant");
  if (!actionGrants.some((grant) => grant.grantId.includes("full-access"))) blockedReasons.add("missingFullAccessGrant");
  if (!accessGroup) blockedReasons.add("missingAccessGroup");
  if (!accessEpoch) blockedReasons.add("missingAccessEpoch");
  if (accessGroup && accessEpoch && accessGroup.currentEpochId !== accessEpoch.epochId) blockedReasons.add("accessEpochMismatch");
  if (accessGroup && !asArray(accessGroup.memberRefs).includes(proof.granteeMemberRef)) blockedReasons.add("granteeMissingFromAccessGroup");
  if (accessEpoch && !asArray(accessEpoch.memberRefs).includes(proof.granteeMemberRef)) blockedReasons.add("granteeMissingFromAccessEpoch");
  const grantIds = new Set(actionGrants.map((grant) => grant.grantId));
  for (const grantRef of proof.actionGrantRefs || []) {
    if (!grantIds.has(grantRef)) blockedReasons.add(`missingGrant:${grantRef}`);
  }
  const exerciseGrantIds = new Set(actionExercises.map((exercise) => exercise.grantId));
  if (!actionExercises.length) blockedReasons.add("missingActionExercise");
  for (const grant of actionGrants) {
    if (!exerciseGrantIds.has(grant.grantId) && grant.action !== "identity.fullAccess") {
      blockedReasons.add(`missingExercise:${grant.grantId}`);
    }
  }

  if (blockedReasons.size === 0) return proof;
  return assertAuthorityMultiIdentityProof({
    ...proof,
    state: AGREEMENT.AUTHORITY_PROOF_STATE.DEGRADED,
    blockedReasons: [...blockedReasons].sort(),
  });
}

export function multiIdentityGrantFixture(now = nowSeconds()) {
  const ownerIdentityRef = "identity:aux";
  const granteeIdentityRef = "identity:agent-dev";
  const granteeMemberRef = "member:agent-dev:cli";
  const rootRef = "root:aux:primary";
  const deviceRef = "device:aux:browser";
  const rootOperation = assertAuthorityRootOperation({
    kind: SWARM.RECORD_KIND.AUTHORITY_ROOT_OPERATION,
    operationId: "root-op:aux:grant-agent-full-access",
    operation: AGREEMENT.ROOT_OPERATION.REFRESH_ROOT,
    identityRef: ownerIdentityRef,
    actorRef: rootRef,
    targetRef: deviceRef,
    adminGrantRefs: ["grant:aux:root-admin"],
    deviceRefs: [deviceRef],
    notificationRefs: ["notification:agent-full-access"],
    evidenceRefs: ["sig:root-op:aux:grant-agent-full-access"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    safeFacts: { purpose: "agentFullAccessProof" },
    issuedAt: now,
    expiresAt: now + 3600,
  });
  const actionGrants = [
    assertActionAuthorityGrant({
      kind: SWARM.RECORD_KIND.AUTHORITY_ACTION_GRANT,
      grantId: "grant:identity:agent-full-access",
      issuerRef: ownerIdentityRef,
      subjectRef: granteeMemberRef,
      audienceRefs: [granteeIdentityRef],
      authorityDomain: SWARM.AUTHORITY_DOMAIN.IDENTITY,
      resourceRef: "identity:aux:contracts",
      action: "identity.fullAccess",
      state: AGREEMENT.ACTION_GRANT_STATE.ACCEPTED,
      scope: {
        inheritance: "full",
        contracts: ["contract-a", "contract-b", "contract-c", "contract-d", "event-analysis"],
      },
      capabilityRefs: ["identity.grant.fullaccess"],
      elevated: true,
      rootRefs: [rootRef],
      delegation: { allowed: true, maxDepth: 1, inheritedFrom: ["grant:aux:root-admin"] },
      evidenceRefs: ["sig:grant:identity:agent-full-access"],
      issuedAt: now + 1,
      expiresAt: now + 3600,
    }),
    assertActionAuthorityGrant({
      kind: SWARM.RECORD_KIND.AUTHORITY_ACTION_GRANT,
      grantId: "grant:sample:agent-writer",
      issuerRef: ownerIdentityRef,
      subjectRef: granteeMemberRef,
      audienceRefs: ["service:sample"],
      authorityDomain: SWARM.AUTHORITY_DOMAIN.SERVICE,
      resourceRef: "contract:sample.default",
      action: "sample.event.write",
      state: AGREEMENT.ACTION_GRANT_STATE.ACCEPTED,
      scope: { contractRef: "contract:sample.default", reduce: true },
      capabilityRefs: ["sample.events.observe"],
      parentGrantRefs: ["grant:identity:agent-full-access"],
      evidenceRefs: ["sig:grant:sample:agent-writer"],
      issuedAt: now + 2,
      expiresAt: now + 3600,
    }),
  ];
  const actionExercises = [
    assertActionAuthorityExercise({
      kind: SWARM.RECORD_KIND.AUTHORITY_ACTION_EXERCISE,
      exerciseId: "exercise:sample:agent-writer:1",
      grantId: "grant:sample:agent-writer",
      actorRef: granteeMemberRef,
      subjectRef: "event:sample:agent-test",
      resourceRef: "contract:sample.default",
      action: "sample.event.write",
      state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
      evidenceRefs: ["event:sample:agent-test"],
      resultRefs: ["projection:sample.events"],
      safeFacts: { exerciseClass: "writeReduce" },
      issuedAt: now + 3,
      observedAt: now + 4,
    }),
  ];
  const accessGroup = assertAccessGroup({
    kind: SWARM.RECORD_KIND.ACCESS_GROUP,
    groupId: "access-group:identity:aux:event-analysis",
    ownerRef: ownerIdentityRef,
    subjectRef: "event-fabric:sample.default",
    contentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL, AGREEMENT.CONTENT_CLASS.SAFE_INDEX],
    memberRefs: ["member:sample:processor", granteeMemberRef],
    adminRefs: [rootRef],
    currentEpochId: "access-epoch:identity:aux:event-analysis:3",
    partitionRefs: ["partition:event-fabric:sample-analysis"],
    policyRefs: ["policy:identity:agent-full-access"],
    safeFacts: { purpose: "eventAnalysisReplay" },
    issuedAt: now + 5,
  });
  const accessEpoch = assertAccessEpoch({
    kind: SWARM.RECORD_KIND.ACCESS_EPOCH,
    epochId: accessGroup.currentEpochId,
    groupId: accessGroup.groupId,
    sequence: 3,
    changeKind: AGREEMENT.ACCESS_EPOCH_CHANGE.ADD_MEMBER,
    previousEpochId: "access-epoch:identity:aux:event-analysis:2",
    memberRefs: accessGroup.memberRefs,
    addedMemberRefs: [granteeMemberRef],
    partitionRefs: accessGroup.partitionRefs,
    keyRef: "key-ref:identity:aux:event-analysis:3",
    proofRefs: ["proof:caac-open:agent-dev"],
    safeFacts: { change: "agentAccess" },
    issuedAt: now + 6,
    expiresAt: now + 3600,
  });
  const proof = assertAuthorityMultiIdentityProof({
    kind: SWARM.RECORD_KIND.AUTHORITY_MULTI_IDENTITY_PROOF,
    proofId: "authority-proof:aux-to-agent:full-access",
    ownerIdentityRef,
    granteeIdentityRef,
    granteeMemberRef,
    subjectRefs: [
      "contract:alpha.default",
      "contract:beta.default",
      "contract:gamma.default",
      "contract:delta.default",
      "contract:event-analysis.default",
    ],
    actionGrantRefs: actionGrants.map((grant) => grant.grantId),
    accessGroupRefs: [accessGroup.groupId],
    accessEpochRefs: [accessEpoch.epochId],
    privateEnvelopeRefs: ["private-envelope:sample-event:sample"],
    revocationRefs: ["revocation:grant:identity:agent-full-access"],
    checks: [
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.SYNC,
        plane: AGREEMENT.PLANE.DELIVERY_WITNESS,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:alpha.default",
        grantRefs: ["grant:identity:agent-full-access"],
        evidenceRefs: ["witness:sample:agent-sync"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.READ,
        plane: AGREEMENT.PLANE.ACCESS_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "event-fabric:sample.default",
        accessGroupRefs: [accessGroup.groupId],
        accessEpochRefs: [accessEpoch.epochId],
        evidenceRefs: ["proof:caac-open:agent-dev"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.WRITE_REDUCE,
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:sample.default",
        grantRefs: ["grant:sample:agent-writer"],
        exerciseRefs: ["exercise:sample:agent-writer:1"],
        evidenceRefs: ["event:sample:agent-test"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.REVOKE_EXPIRE,
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "grant:identity:agent-full-access",
        grantRefs: ["grant:identity:agent-full-access"],
        evidenceRefs: ["revocation:grant:identity:agent-full-access"],
        expiresAt: now + 3600,
      },
    ],
    state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
    evidenceRefs: ["proof:multi-identity:agent-dev"],
    safeFacts: {
      proofClass: "multiIdentityFullAccess",
      grantee: "agent-dev",
      syncWithoutRead: true,
      readWithoutWrite: true,
    },
    issuedAt: now + 7,
    expiresAt: now + 3600,
  });
  return {
    rootOperation,
    actionGrants,
    actionExercises,
    accessGroup,
    accessEpoch,
    proof,
  };
}
