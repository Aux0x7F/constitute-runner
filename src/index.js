import {
  AGREEMENT,
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
  assertRunnerOperation,
  assertRunnerHostFulfillmentPosture,
  assertCybersecProcessorSeed,
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export const CYBERSEC_RUN_KIND = "cybersec.processor.run.report";
export const APP_RUNNER_FULFILLMENT_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_REPORT;
export const APP_RUNNER_FULFILLMENT_LIFECYCLE_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_LIFECYCLE;

const ALERT_SEVERITIES = new Set(["critical", "error", "warn"]);
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

function normalizeObservedEvent(event, index) {
  const normalized = {
    eventRef: String(event?.eventRef || event?.evidenceRef || event?.eventId || `event:${index}`).trim(),
    eventClass: String(event?.eventClass || "").trim(),
    severity: String(event?.severity || "info").trim().toLowerCase(),
    observedAt: Number(event?.observedAt || 0) || 0,
    safeFacts: event?.safeFacts && typeof event.safeFacts === "object" && !Array.isArray(event.safeFacts)
      ? event.safeFacts
      : {},
  };
  rejectUnsafeSafeFacts(normalized.safeFacts, "observed event");
  return normalized;
}

function summarizeSeverity(events) {
  return events.reduce((counts, event) => {
    counts[event.severity] = (counts[event.severity] || 0) + 1;
    return counts;
  }, {});
}

function inputUniverse(seed) {
  return stringSet([
    seed.fabricRef,
    ...asArray(seed.inputAccessClassRefs),
    ...asArray(seed.inputEventClasses),
    ...asArray(seed.inputContentClasses),
    ...asArray(seed.evidenceProfileRefs),
    ...asArray(seed.detailRefs),
  ]);
}

function outputUniverse(seed) {
  return stringSet([
    ...asArray(seed.alertOutputRefs),
    ...asArray(seed.evidenceHoldRefs),
    ...asArray(seed.retentionHoldRefs),
    ...asArray(seed.storageRefs),
  ]);
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
    runnerId: "runner:lab-gateway:app-proof",
    runnerRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:lab-gateway",
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

export function cybersecAppContractFixture(now = nowSeconds()) {
  const cybersec = cybersecBootstrapFixture(now);
  const seed = cybersec.seed;
  const appContract = assertSurfaceAppContract({
    contractId: "surface-app:constitute-cybersec@0.1.0",
    schemaVersion: SURFACE_APP.SCHEMA_VERSION,
    appId: "constitute-cybersec",
    appRef: "app:constitute-cybersec",
    version: "0.1.0",
    displayName: "Constitute Cybersecurity",
    requiredPrimitives: [
      "runtime.attach",
      "event.fabric.processor.contract",
      "cybersec.processor.seed",
      "surface.app.authority.access.posture",
    ],
    rootRefs: ["root:aux:primary"],
    deviceRefs: ["device:aux:browser"],
    grantRefs: ["grant:app:constitute-cybersec:run"],
    authorityRefs: ["authority:cybersec.bootstrap"],
    accessGroupRefs: seed.accessGroupRefs,
    requiredContentClasses: seed.inputContentClasses,
    requiredModuleRoles: [
      SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
      SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
      SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    ],
    modules: [
      {
        moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.attach", "runtime.posture.observe"],
        outputs: ["runtime.intent", "adapter.evidence"],
        issuedAt: now,
      },
      {
        moduleRef: "constitute-cybersec/event-projection-model@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["event.fabric.processor.contract", "materialization.budget"],
        inputs: seed.inputAccessClassRefs,
        outputs: ["cybersec.alerts.readModel", "cybersec.evidenceHold.readModel"],
        issuedAt: now,
      },
      {
        moduleRef: "constitute-cybersec/product-view@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.posture.render"],
        inputs: ["cybersec.alerts.readModel", "cybersec.evidenceHold.readModel"],
        outputs: ["cybersec.intent"],
        issuedAt: now,
      },
    ],
    projectionSubscriptions: [
      {
        projectionId: "cybersec.event-fabric",
        channelId: seed.fabricRef,
        processorRoleRef: seed.processorRoleRef,
        inputAccessClassRefs: seed.inputAccessClassRefs,
        inputEventClasses: seed.inputEventClasses,
        inputContentClasses: seed.inputContentClasses,
        accessGroupRefs: seed.accessGroupRefs,
      },
    ],
    permissionRequirements: [
      {
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        grantRefs: ["grant:app:constitute-cybersec:run"],
        actions: ["cybersec.processor.run"],
      },
      {
        plane: AGREEMENT.PLANE.ACCESS_AUTHORITY,
        accessGroupRefs: seed.accessGroupRefs,
        contentClasses: seed.inputContentClasses,
      },
    ],
    capabilityRequirements: [
      {
        capabilityRef: "event.fabric.observe",
        processorRoleRef: seed.processorRoleRef,
        inputAccessClassRefs: seed.inputAccessClassRefs,
      },
      {
        capabilityRef: "cybersec.processor.run",
        seedRef: seed.seedId,
      },
    ],
    materializationBudgets: [
      {
        kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
        budgetId: "cybersec.encrypted-detail.refs",
        sourceAuthority: seed.fabricRef,
        consumerRef: "constitute-cybersec",
        payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.RETAINED_RAW,
        copyRole: SWARM.MATERIALIZATION_COPY_ROLE.REFERENCE_ONLY,
        transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.REFERENCE_ONLY,
        privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.ENCRYPTED_DETAIL,
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        limits: { maxItems: 500, maxBytes: 0 },
        snapshotPolicy: { mode: "referenceOnly", cadence: "onDemand" },
        deltaPolicy: { mode: "eventTimeOrdered" },
        coalescing: { key: "detailRef" },
        cardinality: { maxEventClasses: 16, maxDetailRefs: 500 },
        schema: { state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT, version: "cybersec.detailRefs.v1" },
        referenceRefs: seed.detailRefs,
        issuedAt: now,
      },
      {
        kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
        budgetId: "cybersec.alerts.ui",
        sourceAuthority: seed.fabricRef,
        consumerRef: "constitute-cybersec",
        payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.PROJECTION,
        copyRole: SWARM.MATERIALIZATION_COPY_ROLE.PROJECTION,
        transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE,
        privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.UI_PROJECTION,
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        limits: { maxItems: 100, maxBytes: 128000 },
        snapshotPolicy: { mode: "latest", maxAgeSeconds: 60 },
        deltaPolicy: { mode: "coalesced", key: "alertRef" },
        coalescing: { key: "alertRef" },
        cardinality: { maxAlertRefs: 100, maxSeverityLabels: 8 },
        schema: { state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT, version: "cybersec.alerts.v1" },
        issuedAt: now,
      },
    ],
    serviceManagerPosture: {
      managerId: "manager:constitute-cybersec",
      subjectRef: "app:constitute-cybersec",
      managerRef: "runner:lab-gateway:cybersec-bootstrap",
      state: SURFACE_APP.SERVICE_MANAGER_POSTURE.MANUAL,
      serviceRefs: ["app:constitute-cybersec"],
      capabilityRefs: ["cybersec.processor.run", "event.fabric.observe"],
      grantRefs: ["grant:app:constitute-cybersec:run"],
      authorityRefs: ["authority:cybersec.bootstrap"],
      evidenceRefs: ["build:cybersec:bootstrap"],
      issuedAt: now,
      expiresAt: now + 3600,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
      accessGroupRefs: seed.accessGroupRefs,
      authorityRefs: ["authority:cybersec.bootstrap"],
      detailRefs: seed.detailRefs,
      requiredContentClasses: seed.inputContentClasses,
      evidenceRefs: ["cybersec:access-boundary:bootstrap"],
    },
    updatePosture: { state: SURFACE_APP.UPDATE_POSTURE.STATIC, checkedAt: now },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:cybersec:bootstrap",
      releaseRef: "release:cybersec:bootstrap",
      rollbackRef: "rollback:cybersec:bootstrap",
    },
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const manifest = assertSurfaceAppManifest({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST,
    manifestId: "manifest:constitute-cybersec",
    appId: appContract.appId,
    state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
    currentAppContractRef: appContract.appRef,
    currentVersion: appContract.version,
    defaultSourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    requiredModuleRoles: appContract.requiredModuleRoles,
    bundledSourceRefs: ["bundle:constitute-cybersec@0.1.0"],
    versions: [
      {
        appContractRef: appContract.appRef,
        version: appContract.version,
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        requiredModuleRoles: appContract.requiredModuleRoles,
        bundledSourceRefs: ["bundle:constitute-cybersec@0.1.0"],
        grantRefs: appContract.grantRefs,
        runnerRequirementRefs: ["runner:req:cybersec-bootstrap"],
        serviceManagerRequirementRefs: ["service-manager:req:cybersec-bootstrap"],
        compatibilityRefs: ["protocol:surface-app:v1", "protocol:cybersec-seed:v1"],
        compatibilityWindow: {
          minVersion: "0.1.0",
          maxVersion: "0.1.x",
          protocolRef: "protocol:surface-app:v1",
        },
        bootstrapContractRef: "bootstrap-contract:cybersec-bootstrap",
        releaseContractRef: "release:cybersec:bootstrap",
        authorityRefs: appContract.authorityRefs,
        evidenceRefs: ["build:cybersec:bootstrap", seed.seedId],
        issuedAt: now,
        expiresAt: now + 90 * 24 * 60 * 60,
      },
    ],
    appContractRefs: [appContract.appRef],
    grantRefs: appContract.grantRefs,
    runnerRequirementRefs: ["runner:req:cybersec-bootstrap"],
    serviceManagerRequirementRefs: ["service-manager:req:cybersec-bootstrap"],
    compatibilityRefs: ["protocol:surface-app:v1", "protocol:cybersec-seed:v1"],
    bootstrapContractRefs: ["bootstrap-contract:cybersec-bootstrap"],
    releaseContractRefs: ["release:cybersec:bootstrap"],
    authorityRefs: appContract.authorityRefs,
    evidenceRefs: ["build:cybersec:bootstrap", seed.seedId],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const runnerOperation = assertRunnerOperation({
    ...cybersec.runnerOperation,
    operationId: "runner-operation:cybersec-app:execute:1",
    subjectRef: appContract.appRef,
    contractRef: appContract.appRef,
    grantRefs: appContract.grantRefs,
    inputRefs: [manifest.manifestId, appContract.appRef, seed.seedId],
    outputRefs: ["artifact:cybersec:bootstrap", ...seed.alertOutputRefs, ...seed.evidenceHoldRefs],
    proofRefs: ["proof:cybersec:surface-app"],
    releaseRefs: ["release:cybersec:bootstrap"],
    releaseRef: "release:cybersec:bootstrap",
    rollbackRef: "rollback:cybersec:bootstrap",
    safeFacts: {
      appId: appContract.appId,
      mode: "operatorDev",
      processorRole: seed.processorRoleRef,
    },
  });
  return { appContract, manifest, seed, runnerOperation };
}

export function buildCybersecProcessorRun(input = {}) {
  const seed = assertCybersecProcessorSeed(input.seed);
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const observedAt = Number(input.now || 0) || nowSeconds();
  const observedEvents = asArray(input.observedEvents).map(normalizeObservedEvent);
  const blockedReasons = [];

  if (seed.state !== "ready") blockedReasons.push(`seed:${seed.state}`);
  if (seed.expiresAt !== undefined && Number(seed.expiresAt || 0) <= observedAt) blockedReasons.push("seedExpired");
  if (seed.processorRoleRef !== "role:cybersec.processor") blockedReasons.push("processorRoleMismatch");
  if (TERMINAL_BLOCKED_STATES.has(runnerOperation.state)) blockedReasons.push(`runnerOperation:${runnerOperation.state}`);
  if (runnerOperation.expiresAt !== undefined && Number(runnerOperation.expiresAt || 0) <= observedAt) blockedReasons.push("runnerOperationExpired");
  if (!intersects(stringSet(runnerOperation.inputRefs), inputUniverse(seed))) blockedReasons.push("inputRefMismatch");
  if (!intersects(stringSet(runnerOperation.outputRefs), outputUniverse(seed))) blockedReasons.push("outputRefMismatch");
  if (asArray(seed.accessGroupRefs).length === 0) blockedReasons.push("missingAccessGroup");
  if (asArray(seed.detailRefs).length === 0) blockedReasons.push("missingDetailRef");
  if (asArray(seed.storageRefs).length === 0) blockedReasons.push("missingStorageRef");

  const alertEvents = observedEvents.filter((event) => (
    ALERT_SEVERITIES.has(event.severity)
    || event.eventClass.toLowerCase().includes("cybersec")
  ));
  const heldEventRefs = unique(observedEvents.map((event) => event.eventRef));
  const severityCounts = summarizeSeverity(observedEvents);
  const state = blockedReasons.length
    ? "blocked"
    : alertEvents.length
      ? "alerted"
      : "clear";
  const evidenceRefs = unique([
    ...asArray(seed.evidenceRefs),
    ...asArray(runnerOperation.evidenceRefs),
    ...heldEventRefs,
  ]);
  const safeFacts = {
    threatAnalysisRole: seed.threatAnalysisRole,
    eventCount: observedEvents.length,
    alertCount: alertEvents.length,
    heldEvidenceCount: heldEventRefs.length,
    inputEventClassCount: asArray(seed.inputEventClasses).length,
    inputContentClassCount: asArray(seed.inputContentClasses).length,
    accessGroupCount: asArray(seed.accessGroupRefs).length,
    storageRefCount: asArray(seed.storageRefs).length,
    detailRefCount: asArray(seed.detailRefs).length,
    loggingBoundary: seed.semanticBoundaries?.logging || "",
    storageBoundary: seed.semanticBoundaries?.storage || "",
    eventDomainBoundary: seed.semanticBoundaries?.eventDomain || "",
  };
  rejectUnsafeSafeFacts(safeFacts, "cybersec processor run");
  return assertCybersecProcessorRunReport({
    kind: CYBERSEC_RUN_KIND,
    reportId: `cybersec-run:${seed.seedId}:${runnerOperation.operationId}`,
    seedId: seed.seedId,
    processorRef: seed.processorRef,
    processorRoleRef: seed.processorRoleRef,
    fabricRef: seed.fabricRef,
    runnerOperationId: runnerOperation.operationId,
    state,
    alertPosture: {
      state: blockedReasons.length ? "blocked" : alertEvents.length ? "open" : "clear",
      alertOutputRefs: unique(seed.alertOutputRefs || []),
      alertEventRefs: unique(alertEvents.map((event) => event.eventRef)),
      severityCounts,
    },
    evidenceHoldPosture: {
      state: blockedReasons.length ? "blocked" : heldEventRefs.length ? "holding" : "armed",
      evidenceHoldRefs: unique(seed.evidenceHoldRefs || []),
      retentionHoldRefs: unique(seed.retentionHoldRefs || []),
      heldEventRefs,
    },
    accessPosture: {
      state: blockedReasons.length ? "blocked" : "authorized",
      accessGroupRefs: unique(seed.accessGroupRefs || []),
      inputAccessClassRefs: unique(seed.inputAccessClassRefs || []),
      inputContentClasses: unique(seed.inputContentClasses || []),
      detailRefs: unique(seed.detailRefs || []),
      custodyState: seed.encryptedDetailCustody?.state || "unspecified",
    },
    materializationPosture: {
      state: blockedReasons.length ? "blocked" : "withinBudget",
      materializationBudgetRefs: unique(seed.materializationBudgetRefs || []),
      processorContractRefs: unique(seed.processorContractRefs || []),
      storageRefs: unique(seed.storageRefs || []),
    },
    semanticBoundaries: seed.semanticBoundaries,
    safeFacts,
    evidenceRefs,
    blockedReasons,
    observedAt,
    expiresAt: seed.expiresAt,
  });
}

export function assertCybersecProcessorRunReport(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("cybersec processor run report must be an object");
  if (record.kind !== CYBERSEC_RUN_KIND) throw new Error("invalid cybersec processor run report kind");
  for (const field of ["reportId", "seedId", "processorRef", "processorRoleRef", "fabricRef", "runnerOperationId", "state"]) {
    if (!String(record[field] || "").trim()) throw new Error(`cybersec processor run report missing ${field}`);
  }
  if (!["clear", "alerted", "blocked", "degraded"].includes(record.state)) throw new Error("invalid cybersec processor run report state");
  for (const field of ["alertPosture", "evidenceHoldPosture", "accessPosture", "materializationPosture", "semanticBoundaries", "safeFacts"]) {
    if (!record[field] || typeof record[field] !== "object" || Array.isArray(record[field])) {
      throw new Error(`cybersec processor run report ${field} must be an object`);
    }
  }
  for (const field of ["evidenceRefs", "blockedReasons"]) {
    if (!Array.isArray(record[field])) throw new Error(`cybersec processor run report ${field} must be an array`);
  }
  if (record.state === "blocked" && record.blockedReasons.length === 0) {
    throw new Error("blocked cybersec processor run requires blockedReasons");
  }
  rejectUnsafeSafeFacts(record.safeFacts, "cybersec processor run report");
  if (!Number(record.observedAt || 0)) throw new Error("cybersec processor run report missing observedAt");
  return record;
}

export function cybersecBootstrapFixture(now = nowSeconds()) {
  const seed = assertCybersecProcessorSeed({
    kind: SWARM.RECORD_KIND.CYBERSEC_PROCESSOR_SEED,
    seedId: "cybersec-seed:logging.default",
    fabricRef: "event-fabric:logging.default",
    processorRef: "constitute-cybersec",
    processorRoleRef: "role:cybersec.processor",
    state: "ready",
    threatAnalysisRole: "eventFabricThreatAnalysis",
    inputAccessClassRefs: ["event-class:logging.cybersec.encrypted-detail"],
    inputEventClasses: ["runtime.diagnostic", "media.path"],
    inputContentClasses: ["encryptedDetail", "safeIndex"],
    accessGroupRefs: ["access-group:logging.cybersec.default"],
    processorContractRefs: ["processor-contract:logging.cybersec"],
    evidenceProfileRefs: ["logging.cybersec.default"],
    materializationBudgetRefs: ["logging.cybersec.default.90d"],
    storageRefs: ["storage:logging.cybersec.archive"],
    detailRefs: ["encrypted-detail:logging.default"],
    alertOutputRefs: ["cybersec:alerts:logging.default"],
    evidenceHoldRefs: ["cybersec:evidence-hold:logging.default"],
    retentionHoldRefs: ["retention:cybersec-hold:logging.default"],
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: ["access-group:logging.cybersec.default"],
      detailRefs: ["encrypted-detail:logging.default"],
    },
    semanticBoundaries: {
      logging: "mayConsumeMaterializations",
      storage: "ciphertextFulfillmentOnly",
      eventDomain: "doesNotOwn",
    },
    safeFacts: {
      purpose: "cybersecThreatAnalysis",
      detailCustody: "encryptedDetailRef",
      alerting: "seeded",
    },
    evidenceRefs: ["logging.cybersec.default"],
    blockedReasons: [],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const runnerOperation = assertRunnerOperation({
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: "runner-operation:cybersec-bootstrap:execute:1",
    runnerId: "runner:lab-gateway:cybersec-bootstrap",
    runnerRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:lab-gateway",
    requesterRef: "identity:aux",
    subjectRef: "cybersec-processor:dev",
    contractRef: "cybersec-processor:seed@0.1.0",
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.OPERATION_STATE.SUCCEEDED,
    grantRefs: ["authority-grant:runner:cybersec-bootstrap"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: [seed.fabricRef, ...seed.inputAccessClassRefs],
    outputRefs: [...seed.alertOutputRefs, ...seed.evidenceHoldRefs],
    evidenceRefs: ["evidence:runner:started", "evidence:runner:completed"],
    proofRefs: ["proof:runner:cybersec-bootstrap"],
    releaseRefs: ["release:runner:cybersec-bootstrap"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 512,
      maxCpuPct: 40,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:cybersec-bootstrap",
      profileId: "resource-profile:operator-dev",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 128, cpuPct: 8 },
      budgets: { memoryMiB: 512, cpuPct: 40 },
      sampledAt: now + 3,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED,
    },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:runner:cybersec-bootstrap",
      releaseRef: "release:runner:cybersec-bootstrap",
      rollbackRef: "rollback:runner:cybersec-bootstrap",
    },
    releaseRef: "release:runner:cybersec-bootstrap",
    rollbackRef: "rollback:runner:cybersec-bootstrap",
    safeFacts: {
      role: "cybersecProcessor",
      mode: "operatorDev",
    },
    requestedAt: now,
    acceptedAt: now + 1,
    startedAt: now + 2,
    completedAt: now + 12,
    observedAt: now + 15,
    expiresAt: now + 3600,
  });
  return {
    seed,
    runnerOperation,
    observedEvents: [
      {
        eventRef: "event:runtime:media-path:1",
        eventClass: "media.path",
        severity: "warn",
        observedAt: now + 14,
        safeFacts: {
          posture: "mediaPathBlocked",
          contentClass: "encryptedDetail",
        },
      },
    ],
  };
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
        contracts: ["gateway", "logging", "nvr", "storage", "cybersec"],
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
      grantId: "grant:logging:agent-writer",
      issuerRef: ownerIdentityRef,
      subjectRef: granteeMemberRef,
      audienceRefs: ["service:logging"],
      authorityDomain: SWARM.AUTHORITY_DOMAIN.SERVICE,
      resourceRef: "contract:logging.default",
      action: "logging.event.write",
      state: AGREEMENT.ACTION_GRANT_STATE.ACCEPTED,
      scope: { contractRef: "contract:logging.default", reduce: true },
      capabilityRefs: ["logging.events.observe"],
      parentGrantRefs: ["grant:identity:agent-full-access"],
      evidenceRefs: ["sig:grant:logging:agent-writer"],
      issuedAt: now + 2,
      expiresAt: now + 3600,
    }),
  ];
  const actionExercises = [
    assertActionAuthorityExercise({
      kind: SWARM.RECORD_KIND.AUTHORITY_ACTION_EXERCISE,
      exerciseId: "exercise:logging:agent-writer:1",
      grantId: "grant:logging:agent-writer",
      actorRef: granteeMemberRef,
      subjectRef: "event:logging:agent-test",
      resourceRef: "contract:logging.default",
      action: "logging.event.write",
      state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
      evidenceRefs: ["event:logging:agent-test"],
      resultRefs: ["projection:logging.events"],
      safeFacts: { exerciseClass: "writeReduce" },
      issuedAt: now + 3,
      observedAt: now + 4,
    }),
  ];
  const accessGroup = assertAccessGroup({
    kind: SWARM.RECORD_KIND.ACCESS_GROUP,
    groupId: "access-group:identity:aux:cybersec-events",
    ownerRef: ownerIdentityRef,
    subjectRef: "event-fabric:logging.default",
    contentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL, AGREEMENT.CONTENT_CLASS.SAFE_INDEX],
    memberRefs: ["member:logging:processor", granteeMemberRef],
    adminRefs: [rootRef],
    currentEpochId: "access-epoch:identity:aux:cybersec-events:3",
    partitionRefs: ["partition:event-fabric:logging-cybersec"],
    policyRefs: ["policy:identity:agent-full-access"],
    safeFacts: { purpose: "cybersecReplay" },
    issuedAt: now + 5,
  });
  const accessEpoch = assertAccessEpoch({
    kind: SWARM.RECORD_KIND.ACCESS_EPOCH,
    epochId: accessGroup.currentEpochId,
    groupId: accessGroup.groupId,
    sequence: 3,
    changeKind: AGREEMENT.ACCESS_EPOCH_CHANGE.ADD_MEMBER,
    previousEpochId: "access-epoch:identity:aux:cybersec-events:2",
    memberRefs: accessGroup.memberRefs,
    addedMemberRefs: [granteeMemberRef],
    partitionRefs: accessGroup.partitionRefs,
    keyRef: "key-ref:identity:aux:cybersec-events:3",
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
      "contract:gateway.default",
      "contract:logging.default",
      "contract:nvr.streams",
      "contract:storage.default",
      "contract:cybersec.default",
    ],
    actionGrantRefs: actionGrants.map((grant) => grant.grantId),
    accessGroupRefs: [accessGroup.groupId],
    accessEpochRefs: [accessEpoch.epochId],
    privateEnvelopeRefs: ["private-envelope:logging-event:sample"],
    revocationRefs: ["revocation:grant:identity:agent-full-access"],
    checks: [
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.SYNC,
        plane: AGREEMENT.PLANE.DELIVERY_WITNESS,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:gateway.default",
        grantRefs: ["grant:identity:agent-full-access"],
        evidenceRefs: ["witness:gateway:agent-sync"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.READ,
        plane: AGREEMENT.PLANE.ACCESS_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "event-fabric:logging.default",
        accessGroupRefs: [accessGroup.groupId],
        accessEpochRefs: [accessEpoch.epochId],
        evidenceRefs: ["proof:caac-open:agent-dev"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.WRITE_REDUCE,
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:logging.default",
        grantRefs: ["grant:logging:agent-writer"],
        exerciseRefs: ["exercise:logging:agent-writer:1"],
        evidenceRefs: ["event:logging:agent-test"],
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
