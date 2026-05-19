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
  assertSurfaceAppContract,
  assertSurfaceAppManifest,
} from "../../constitute-protocol/src/index.js";

export const APP_RUNNER_FULFILLMENT_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_REPORT;
export const APP_RUNNER_FULFILLMENT_LIFECYCLE_KIND = SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_LIFECYCLE;

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
