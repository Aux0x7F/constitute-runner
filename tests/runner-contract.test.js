import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  appRunnerFulfillmentFixture,
  assertAppRunnerFulfillmentLifecycle,
  assertAppRunnerFulfillmentReport,
  assertRunnerHostPosture,
  buildMultiIdentityGrantProof,
  buildAppRunnerFulfillment,
  buildAppRunnerFulfillmentLifecycle,
  buildRunnerBuildOperationFixture,
  buildRunnerHostFulfillmentPosture,
  buildRunnerModuleLoadOperationFixture,
  buildRunnerOperationForBuild,
  buildRunnerOperationForModuleLoad,
  installRuntimeRunnerFulfillmentAdapter,
  fulfillAcceptedRuntimeRunnerDispatches,
  fulfillRunnerOperationDispatch,
  multiIdentityGrantFixture,
  resolveRunnerModuleFromResolver,
} from "../src/index.js";

const MODULE_STORAGE_OBJECT_REF =
  "storage:object:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MODULE_EXECUTABLE_HASH_REF =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function makeNativeModuleResolver(overrides = {}) {
  const resolution = {
    moduleRef: "module:native-dev:constitute-build",
    repoRef: "repo:constitute-build",
    role: "build-fulfillment",
    state: "materialized",
    sourceSnapshotRef: "source:snapshot:native-dev:constitute-build:abc123",
    contentIndexRef: "content-index:native-dev:constitute-build:abc123",
    artifactRef: "artifact:native-dev:constitute-build:abc123",
    materializedPathRef: "materialized:path:workspace-dev:constitute-build",
    storageMaterializationPostureRef: "storage-module-materialization-posture:constitute-build:abc123",
    storageExecutableInstantiationPostureRef:
      "storage-module-executable-instantiation-posture:constitute-build:abc123",
    executableRef: "executable:module:module_native-dev_constitute-build:abc123",
    executableHashRef: MODULE_EXECUTABLE_HASH_REF,
    objectRefs: [MODULE_STORAGE_OBJECT_REF],
    availabilityRefs: ["storage-availability:constitute-build:abc123"],
    storagePostureRefs: [
      "storage-module-materialization-posture:constitute-build:abc123",
      "storage-module-executable-instantiation-posture:constitute-build:abc123",
    ],
    storageRefs: [MODULE_STORAGE_OBJECT_REF],
    conflictRefs: [],
    ...(overrides.resolution || {}),
  };
  return {
    kind: "operator.native-module.resolver",
    state: "ready",
    resolverRef: "module-resolver:native-dev:abc123",
    sourceSnapshotRef: "source:snapshot:native-dev:abc123",
    contentIndexRef: "content-index:native-dev:abc123",
    moduleResolutions: [resolution],
    transitionConflicts: [],
    blockedReasons: [],
    ...overrides,
  };
}

test("multi-identity grant proof preserves authority plane separation", () => {
  const proof = buildMultiIdentityGrantProof(multiIdentityGrantFixture());
  assert.equal(proof.state, "proved");
  assert.equal(proof.checks.some((check) => check.check === "sync" && check.plane === "deliveryWitness"), true);
  assert.equal(proof.checks.some((check) => check.check === "read" && check.plane === "accessAuthority"), true);
  assert.equal(proof.checks.some((check) => check.check === "writeReduce" && check.plane === "actionAuthority"), true);
  assert.equal(proof.checks.some((check) => check.check === "revokeExpire" && check.plane === "actionAuthority"), true);
  assert.equal(proof.safeFacts.syncWithoutRead, true);
  assert.equal(proof.safeFacts.readWithoutWrite, true);
});

test("multi-identity grant proof degrades when access epoch omits grantee", () => {
  const fixture = multiIdentityGrantFixture();
  const proof = buildMultiIdentityGrantProof({
    ...fixture,
    accessEpoch: {
      ...fixture.accessEpoch,
      memberRefs: ["member:sample:processor"],
    },
  });
  assert.equal(proof.state, "degraded");
  assert.equal(proof.blockedReasons.includes("granteeMissingFromAccessEpoch"), true);
});

test("runner cli executes the multi-identity grant fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "multi-identity-grant"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const proof = JSON.parse(stdout);
  assert.equal(proof.state, "proved");
  assert.equal(proof.safeFacts.proofClass, "multiIdentityFullAccess");
});

test("app runner fulfillment reports executed app contract posture", () => {
  const fixture = appRunnerFulfillmentFixture();
  const hostPosture = buildRunnerHostFulfillmentPosture({
    ...fixture,
    serviceRefs: ["app:runner-proof"],
    witnessRefs: ["witness:operator:host-proof"],
  });
  assert.equal(hostPosture.kind, "runner.host.fulfillment.posture");
  assert.equal(hostPosture.state, "succeeded");
  assert.equal(hostPosture.safeFacts.serviceHostIdentitySeparated, true);
  assertRunnerHostPosture(hostPosture);

  const report = buildAppRunnerFulfillment({
    ...fixture,
    hostFulfillmentPosture: hostPosture,
  });
  assert.equal(report.kind, "app.runner.fulfillment.report");
  assert.equal(report.state, "succeeded");
  assert.equal(report.appId, "constitute-runner-proof");
  assert.equal(report.version, "0.1.0");
  assert.equal(report.sourceMode, "bundled");
  assert.deepEqual(report.sourceRefs, ["bundle:runner-proof@0.1.0"]);
  assert.equal(report.operationPosture.accepted, true);
  assert.equal(report.hostFulfillmentPosture.hostRef, "host:runner-lab");
  assert.equal(report.fulfillmentPosture.outputRefs.includes("artifact:runner-proof:dist"), true);
  assert.equal(report.fulfillmentPosture.releaseRefs.includes("release:runner-proof"), true);
  assert.deepEqual(report.blockedReasons, []);
  assertAppRunnerFulfillmentReport(report);

  const lifecycle = buildAppRunnerFulfillmentLifecycle({
    report,
    witnessRefs: ["witness:operator:runner-proof"],
  });
  assert.equal(lifecycle.kind, "app.runner.fulfillment.lifecycle");
  assert.equal(lifecycle.state, "succeeded");
  assert.equal(lifecycle.reportId, report.reportId);
  assert.deepEqual(lifecycle.witnessRefs, ["witness:operator:runner-proof"]);
  assertAppRunnerFulfillmentLifecycle(lifecycle);
});

test("app runner fulfillment blocks app contract and manifest mismatches", () => {
  const fixture = appRunnerFulfillmentFixture();
  const report = buildAppRunnerFulfillment({
    ...fixture,
    runnerOperation: {
      ...fixture.runnerOperation,
      contractRef: "app:wrong",
      inputRefs: ["manifest:wrong"],
    },
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("contractRefMismatch"), true);
  assert.equal(report.blockedReasons.includes("inputRefMismatch"), true);
});

test("app runner fulfillment blocks expired operation posture", () => {
  const fixture = appRunnerFulfillmentFixture(1_700_000_000);
  const report = buildAppRunnerFulfillment({
    ...fixture,
    now: 1_700_004_000,
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("runnerOperationExpired"), true);
  assert.equal(report.blockedReasons.includes("host:runnerOperationExpired"), true);
});

test("app runner fulfillment rejects unsafe safe-fact leakage", () => {
  const report = buildAppRunnerFulfillment(appRunnerFulfillmentFixture());
  assert.throws(() => assertAppRunnerFulfillmentReport({
    ...report,
    safeFacts: {
      ...report.safeFacts,
      token: "must-not-copy",
    },
  }), /unsafe (safe fact )?key:? token/);
});

test("runner cli executes the app fulfillment fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "app-fulfillment"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const report = JSON.parse(stdout);
  assert.equal(report.state, "succeeded");
  assert.equal(report.safeFacts.appId, "constitute-runner-proof");
});

test("runner cli executes the app lifecycle fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "app-lifecycle"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const lifecycle = JSON.parse(stdout);
  assert.equal(lifecycle.kind, "app.runner.fulfillment.lifecycle");
  assert.equal(lifecycle.state, "succeeded");
  assert.equal(lifecycle.safeFacts.appId, "constitute-runner-proof");
});

test("runner exposes build operation evidence without owning build semantics", () => {
  const fixture = buildRunnerBuildOperationFixture();
  assert.equal(fixture.runnerOperation.contractRef, "build:contract:build-runner-proof");
  assert.equal(fixture.runnerOperation.outputRefs.includes("release:candidate:build-runner-proof"), true);
  assert.equal(fixture.hostPosture.state, "succeeded");
  assert.equal(fixture.hostPosture.contractRef, "build:contract:build-runner-proof");
  assert.equal(fixture.hostPosture.safeFacts.serviceHostIdentitySeparated, true);
  assertRunnerHostPosture(fixture.hostPosture);
});

test("runner derives build operation from build contract and run records", () => {
  const runnerOperation = buildRunnerOperationForBuild({
    buildContract: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
    },
    buildRun: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
      runnerRef: "runner:local-host:build",
      runnerOperationRef: "runner-operation:build-build-runner-proof:execute:1",
      state: "succeeded",
      grantRefs: ["authority:grant:runner-build"],
      artifactRefs: ["build:artifact:module"],
      proofRefs: ["build:proof:build-runner-proof"],
      releaseCandidateRefs: ["release:candidate:build-runner-proof"],
      evidenceRefs: ["runner:evidence:build-completed"],
      requestedAt: 1_779_266_000,
      startedAt: 1_779_266_002,
      completedAt: 1_779_266_009,
      expiresAt: 1_779_269_600,
    },
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
  });
  assert.equal(runnerOperation.kind, "runner.operation");
  assert.equal(runnerOperation.contractRef, "build:contract:build-runner-proof");
  assert.equal(runnerOperation.safeFacts.processorContract, "build");
  assert.deepEqual(runnerOperation.inputRefs, ["source:snapshot:head", "build:recipe:browser-module"]);
  assert.equal(runnerOperation.outputRefs.includes("release:candidate:build-runner-proof"), true);
});

test("runner prepares build processor module refs from native resolver posture", () => {
  const moduleResolverPosture = makeNativeModuleResolver();
  const moduleResolution = resolveRunnerModuleFromResolver({
    moduleResolverPosture,
    moduleRef: "module:native-dev:constitute-build",
    now: 1_779_266_000,
  });
  assert.equal(moduleResolution.kind, "runner.module.resolution.posture");
  assert.equal(moduleResolution.state, "ready");
  assert.equal(moduleResolution.artifactRef, "artifact:native-dev:constitute-build:abc123");

  const runnerOperation = buildRunnerOperationForBuild({
    buildContract: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
    },
    buildRun: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
      runnerRef: "runner:local-host:build",
      runnerOperationRef: "runner-operation:build-build-runner-proof:execute:1",
      state: "succeeded",
      grantRefs: ["authority:grant:runner-build"],
      artifactRefs: ["build:artifact:module"],
      proofRefs: ["build:proof:build-runner-proof"],
      releaseCandidateRefs: ["release:candidate:build-runner-proof"],
      evidenceRefs: ["runner:evidence:build-completed"],
      requestedAt: 1_779_266_000,
      startedAt: 1_779_266_002,
      completedAt: 1_779_266_009,
      expiresAt: 1_779_269_600,
    },
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    processorModuleRef: "module:native-dev:constitute-build",
    moduleResolverPosture,
  });

  assert.equal(runnerOperation.state, "succeeded");
  assert(runnerOperation.inputRefs.includes("module:native-dev:constitute-build"));
  assert(runnerOperation.inputRefs.includes("artifact:native-dev:constitute-build:abc123"));
  assert(runnerOperation.inputRefs.includes(MODULE_STORAGE_OBJECT_REF));
  assert(runnerOperation.evidenceRefs.includes("runner:evidence:module-resolution"));
  assert.equal(runnerOperation.safeFacts.moduleResolutionState, "ready");
  assert.equal(runnerOperation.safeFacts.moduleArtifactReady, true);
});

test("runner blocks native processor preparation when resolver cannot satisfy the module", () => {
  const runnerOperation = buildRunnerOperationForBuild({
    buildContract: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
    },
    buildRun: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
      runnerRef: "runner:local-host:build",
      runnerOperationRef: "runner-operation:build-build-runner-proof:execute:1",
      state: "succeeded",
      grantRefs: ["authority:grant:runner-build"],
      artifactRefs: ["build:artifact:module"],
      proofRefs: ["build:proof:build-runner-proof"],
      releaseCandidateRefs: ["release:candidate:build-runner-proof"],
      evidenceRefs: ["runner:evidence:build-completed"],
      requestedAt: 1_779_266_000,
      startedAt: 1_779_266_002,
      completedAt: 1_779_266_009,
      expiresAt: 1_779_269_600,
    },
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    processorModuleRef: "module:native-dev:constitute-missing",
    moduleResolverPosture: makeNativeModuleResolver(),
  });

  assert.equal(runnerOperation.state, "blocked");
  assert(runnerOperation.blockedReasons.includes("moduleResolver:missingModuleResolution"));
  assert.equal(runnerOperation.outputRefs.includes("build:artifact:module"), false);
});

test("runner loads accepted native module refs through resolver storage posture", () => {
  const moduleResolverPosture = makeNativeModuleResolver();
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture,
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    grantRefs: ["authority:grant:runner-module-load"],
    now: 1_779_266_020,
  });

  assert.equal(runnerOperation.kind, "runner.operation");
  assert.equal(runnerOperation.state, "succeeded");
  assert.equal(runnerOperation.safeFacts.executionKind, "nativeModuleLoad");
  assert.equal(runnerOperation.safeFacts.moduleResolutionState, "ready");
  assert(runnerOperation.inputRefs.includes("module-resolver:native-dev:abc123"));
  assert(runnerOperation.inputRefs.includes("artifact:native-dev:constitute-build:abc123"));
  assert(runnerOperation.inputRefs.includes("materialized:path:workspace-dev:constitute-build"));
  assert(runnerOperation.inputRefs.includes(MODULE_STORAGE_OBJECT_REF));
  assert(runnerOperation.inputRefs.includes("executable:module:module_native-dev_constitute-build:abc123"));
  assert.equal(runnerOperation.safeFacts.moduleExecutableReady, true);
  assert(runnerOperation.outputRefs.includes("module-load:module:native-dev:constitute-build"));
  assert(runnerOperation.outputRefs.includes("executable:module:module_native-dev_constitute-build:abc123"));
  assert(runnerOperation.evidenceRefs.includes("runner:evidence:module-load"));
  assert(runnerOperation.evidenceRefs.includes("runner:evidence:executable-bytes"));
});

test("runner binds module load to lifecycle manifest selection and fulfillment session", () => {
  const lifecycleManifestSeed = {
    kind: "lifecycle.manifest.seed",
    manifestRef: "lifecycle:manifest:native-dev:constitute-build:abc123",
    state: "degraded",
    promotionState: "candidateReady",
    targetRef: "lifecycle-target:native-dev:constitute-build:main",
    candidateRefs: ["candidate:native-dev:constitute-build:abc123"],
    sourceSnapshotRefs: ["source:snapshot:native-dev:constitute-build:abc123"],
    contentIndexRefs: ["content-index:native-dev:constitute-build:abc123"],
    buildRefs: ["build:contract:native-dev:constitute-build:abc123"],
    artifactRefs: ["build:artifact:native-dev:constitute-build:abc123"],
    storageRefs: [MODULE_STORAGE_OBJECT_REF],
    proofRefs: ["build:proof:native-dev:constitute-build:abc123"],
    releaseCandidateRefs: ["release:candidate:native-dev:constitute-build:abc123"],
    rollbackRefs: ["rollback:lifecycle:native-dev:constitute-build:abc123"],
    cleanupRefs: ["cleanup:lifecycle:native-dev:constitute-build:abc123"],
    proofGateRefs: ["proof-gate:native-build:projection-fulfilled"],
    governanceRefs: ["governance:promotion:native-dev:operator-seed"],
    conflictRefs: ["transition-conflict:constitute-build:repo:dirty"],
    evidenceRefs: ["build:proof:native-dev:constitute-build:abc123"],
    blockedReasons: [],
    safeFacts: {
      acceptedAsMain: false,
      promotionModel: "candidate-ready-not-pr",
    },
    observedAt: 1_779_266_020,
    expiresAt: 1_779_266_320,
  };
  const promotionIntentPosture = {
    kind: "contract.intention.posture",
    intentionRef: "promotion:intent:native-dev:constitute-build:abc123",
    state: "degraded",
    canonicalHashRef: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    proofGateRefs: lifecycleManifestSeed.proofGateRefs,
    reducerRefs: ["reducer:lifecycle-promotion:native-dev"],
    evidenceRefs: lifecycleManifestSeed.evidenceRefs,
  };
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver({ state: "degraded" }),
    lifecycleManifestSeed,
    promotionIntentPosture,
    operationState: "accepted",
    runnerId: "runner:operator:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:operator-lab",
    now: 1_779_266_060,
  });

  assert.equal(runnerOperation.contractRef, lifecycleManifestSeed.manifestRef);
  assert.equal(runnerOperation.safeFacts.lifecycleManifestRef, lifecycleManifestSeed.manifestRef);
  assert.equal(runnerOperation.safeFacts.promotionIntentRef, promotionIntentPosture.intentionRef);
  assert.equal(runnerOperation.safeFacts.lifecycleManifestAcceptedAsMain, false);
  assert.equal(runnerOperation.safeFacts.lifecycleProofGateCount, 1);
  assert(runnerOperation.inputRefs.includes(lifecycleManifestSeed.manifestRef));
  assert(runnerOperation.inputRefs.includes(promotionIntentPosture.intentionRef));
  assert(runnerOperation.inputRefs.includes("proof-gate:native-build:projection-fulfilled"));
  assert(runnerOperation.inputRefs.includes("cleanup:lifecycle:native-dev:constitute-build:abc123"));
  assert(runnerOperation.releaseRefs.includes("release:candidate:native-dev:constitute-build:abc123"));
  assert(runnerOperation.proofRefs.includes("build:proof:native-dev:constitute-build:abc123"));
  assert(runnerOperation.evidenceRefs.includes("runner:evidence:lifecycle-manifest-selected"));

  const fulfilled = fulfillRunnerOperationDispatch({
    runnerOperation,
    serviceRefs: ["module:native-dev:constitute-build"],
    contractRefs: [lifecycleManifestSeed.manifestRef],
    witnessRefs: ["witness:module-load:runner-host"],
    now: 1_779_266_080,
  });

  assert.equal(fulfilled.fulfillmentSession.kind, "fulfillment.session");
  assert.equal(fulfilled.fulfillmentSession.contractRef, lifecycleManifestSeed.manifestRef);
  assert.equal(fulfilled.fulfillmentSession.parentIntentRef, promotionIntentPosture.intentionRef);
  assert.equal(fulfilled.fulfillmentSession.subjectRef, "module:native-dev:constitute-build");
  assert.equal(fulfilled.fulfillmentSession.state, "running");
  assert(fulfilled.fulfillmentSession.lifecyclePlanRefs.includes(lifecycleManifestSeed.manifestRef));
  assert(fulfilled.runtimeReportMessage.fulfillmentSession.sessionId, "runtime report carries the session");
  assert.equal(fulfilled.fulfillmentSessionProjection.kind, "runtime.fulfillment-session.projection");
  assert.equal(fulfilled.fulfillmentSessionProjection.lifecycleManifestRef, lifecycleManifestSeed.manifestRef);
  assert.equal(fulfilled.fulfillmentSessionProjection.parentIntentRef, promotionIntentPosture.intentionRef);
  assert.equal(fulfilled.fulfillmentSessionProjection.queryKeys.byManifest, lifecycleManifestSeed.manifestRef);
  assert.equal(fulfilled.fulfillmentSessionProjection.queryKeys.byParentIntent, promotionIntentPosture.intentionRef);
  assert.equal(fulfilled.fulfillmentSessionProjection.safeFacts.lateConsumerQueryable, true);
  assert.deepEqual(fulfilled.fulfillmentSessionProjection.blockedReasons, []);
  assert.equal(
    fulfilled.runtimeReportMessage.fulfillmentSessionProjection.projectionRef,
    fulfilled.fulfillmentSessionProjection.projectionRef,
  );
});

test("runner can prepare accepted runtime dispatch before terminal fulfillment", () => {
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    now: 1_779_266_060,
  });

  assert.equal(runnerOperation.state, "accepted");
  assert.equal(runnerOperation.acceptedAt, 1_779_266_061);
  assert.equal(runnerOperation.completedAt, undefined);
  assert(runnerOperation.outputRefs.includes("module-load:module:native-dev:constitute-build"));
});

test("runner fulfills accepted runtime dispatch into terminal host posture", () => {
  const accepted = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerId: "runner:operator:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:operator-lab",
    now: 1_779_266_060,
  });
  const fulfilled = fulfillRunnerOperationDispatch({
    runnerOperation: accepted,
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:module-load:runner-host"],
    now: 1_779_266_080,
  });

  assert.equal(fulfilled.kind, "runner.dispatch.fulfillment");
  assert.equal(fulfilled.runnerOperation.state, "succeeded");
  assert.equal(fulfilled.hostPosture.state, "succeeded");
  assert.equal(fulfilled.runtimeReportMessage.type, "runtime.runner.host.fulfillment.put");
  assert.equal(fulfilled.hostPosture.operationId, accepted.operationId);
  assert(fulfilled.runnerOperation.evidenceRefs.includes("runner:evidence:dispatch-fulfilled"));
});

test("runner bridge fulfills accepted runtime dispatch and reports to runtime client", async () => {
  const accepted = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerId: "runner:operator:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:operator-lab",
    now: 1_779_266_060,
  });
  const reports = [];

  const bridge = await fulfillAcceptedRuntimeRunnerDispatches({
    runtimeSnapshot: {
      runnerOperations: {
        [accepted.operationId]: {
          kind: "runtime.runner.operation.dispatch",
          dispatchId: `runtime-runner-dispatch:${accepted.operationId}`,
          state: "accepted",
          runnerOperation: accepted,
        },
        "runner-operation:already-terminal": {
          kind: "runtime.runner.operation.dispatch",
          dispatchId: "runtime-runner-dispatch:already-terminal",
          state: "succeeded",
        },
      },
    },
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:module-load:runner-host"],
    putRuntimeReport: async (hostFulfillmentPosture, runtimeReportMessage, dispatch) => {
      reports.push({ hostFulfillmentPosture, runtimeReportMessage, dispatch });
      return { ok: true, state: hostFulfillmentPosture.state };
    },
    now: 1_779_266_080,
  });

  assert.equal(bridge.kind, "runner.runtime-dispatch.bridge");
  assert.equal(bridge.state, "succeeded");
  assert.equal(bridge.fulfilledCount, 1);
  assert.equal(bridge.skippedCount, 1);
  assert.equal(bridge.fulfilled[0].operationId, accepted.operationId);
  assert.equal(bridge.fulfilled[0].hostPosture.state, "succeeded");
  assert.equal(bridge.fulfilled[0].runtimeReportMessage.type, "runtime.runner.host.fulfillment.put");
  assert.deepEqual(bridge.fulfilled[0].reportResult, { ok: true, state: "succeeded" });
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostFulfillmentPosture.operationId, accepted.operationId);
});

test("runner installs a runtime bridge host adapter registration", async () => {
  const accepted = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerId: "runner:host-fabric:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:windows-desktop",
    now: 1_779_266_090,
  });
  const host = {};
  const registration = installRuntimeRunnerFulfillmentAdapter(host, {
    adapterRef: "adapter:runner.execution-fulfillment:local-test",
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:runner-adapter:local-test"],
    now: 1_779_266_100,
  });

  assert.equal(registration.kind, "runtime.runner.host-adapter.registration");
  assert.equal(registration.role, "executionFulfillment");
  assert.equal(registration.safeFacts.hostAdapterRegistered, true);
  assert.equal(host.constituteRuntimeRunnerBridge.adapterRef, "adapter:runner.execution-fulfillment:local-test");

  const fulfillment = await host.constituteRuntimeRunnerBridge.fulfillDispatch({
    dispatch: {
      kind: "runtime.runner.operation.dispatch",
      dispatchId: `runtime-runner-dispatch:${accepted.operationId}`,
      state: "accepted",
      runnerOperation: accepted,
    },
    runnerOperation: accepted,
  });

  assert.equal(fulfillment.runtimeReportMessage.type, "runtime.runner.host.fulfillment.put");
  assert.equal(fulfillment.hostPosture.state, "succeeded");
  assert(fulfillment.hostPosture.evidenceRefs.includes("evidence:adapter:runner.execution-fulfillment:local-test"));
  assert(fulfillment.hostPosture.witnessRefs.includes("witness:runner-adapter:local-test"));
});

test("runner carries native module conflicts without turning them into Git blockers", () => {
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver({
      state: "degraded",
      resolution: {
        conflictRefs: ["transition-conflict:constitute-build:cargo-git:constitute-protocol"],
      },
    }),
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    now: 1_779_266_030,
  });

  assert.equal(runnerOperation.state, "succeeded");
  assert.equal(runnerOperation.safeFacts.moduleResolutionState, "degraded");
  assert.equal(runnerOperation.safeFacts.moduleConflictCount, 1);
  assert(
    runnerOperation.inputRefs.includes("transition-conflict:constitute-build:cargo-git:constitute-protocol"),
  );
});

test("runner blocks native module load when materialization posture is incomplete", () => {
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver({
      resolution: {
        materializedPathRef: "",
        executableRef: "",
        executableHashRef: "",
        storageRefs: [],
      },
    }),
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    now: 1_779_266_040,
  });

  assert.equal(runnerOperation.state, "blocked");
  assert(runnerOperation.blockedReasons.includes("moduleLoad:missingMaterializedPathRef"));
  assert(runnerOperation.blockedReasons.includes("moduleLoad:missingExecutableRef"));
  assert(runnerOperation.blockedReasons.includes("moduleLoad:missingExecutableHashRef"));
  assert(runnerOperation.blockedReasons.includes("moduleLoad:missingStorageRef"));
  assert.deepEqual(runnerOperation.outputRefs, []);
});

test("runner cli executes the build operation fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "build-operation"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const fixture = JSON.parse(stdout);
  assert.equal(fixture.runnerOperation.state, "succeeded");
  assert.equal(fixture.hostPosture.state, "succeeded");
  assert.equal(fixture.runnerOperation.safeFacts.processorContract, "build");
});

test("runner module-load fixture returns terminal host fulfillment posture", () => {
  const fixture = buildRunnerModuleLoadOperationFixture(1_779_266_050);

  assert.equal(fixture.runnerOperation.state, "succeeded");
  assert.equal(fixture.runnerOperation.safeFacts.executionKind, "nativeModuleLoad");
  assert.equal(fixture.hostPosture.state, "succeeded");
  assert.equal(fixture.hostPosture.operationId, fixture.runnerOperation.operationId);
  assert.equal(fixture.hostPosture.safeFacts.serviceHostIdentitySeparated, true);
  assert(fixture.hostPosture.outputRefs.includes("module-load:module:native-dev:constitute-build"));
  assertRunnerHostPosture(fixture.hostPosture);
});

test("runner cli executes the module-load fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "module-load"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const fixture = JSON.parse(stdout);
  assert.equal(fixture.runnerOperation.state, "succeeded");
  assert.equal(fixture.runnerOperation.safeFacts.executionKind, "nativeModuleLoad");
  assert.equal(fixture.hostPosture.state, "succeeded");
  assert.equal(fixture.hostPosture.subjectRef, "module:native-dev:constitute-build");
});

test("runner cli derives build operation from input records", () => {
  const input = {
    buildContract: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
    },
    buildRun: {
      buildContractRef: "build:contract:build-runner-proof",
      sourceSnapshotRef: "source:snapshot:head",
      recipeRef: "build:recipe:browser-module",
      runnerRef: "runner:local-host:build",
      runnerOperationRef: "runner-operation:build-build-runner-proof:execute:1",
      state: "blocked",
      grantRefs: ["authority:grant:runner-build"],
      blockedReasons: ["runner.resource.unavailable"],
      requestedAt: 1_779_266_000,
      expiresAt: 1_779_269_600,
    },
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
  };
  const file = new URL("../target/runner-build-input.json", import.meta.url);
  const filePath = fileURLToPath(file);
  fs.mkdirSync(fileURLToPath(new URL("../target/", import.meta.url)), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(input), "utf8");
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--input", filePath], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const runnerOperation = JSON.parse(stdout);
  assert.equal(runnerOperation.state, "blocked");
  assert.deepEqual(runnerOperation.blockedReasons, ["runner.resource.unavailable"]);
});

test("runner cli derives module-load host posture from input refs", () => {
  const input = {
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    emitHostPosture: true,
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:module-load:runner-host"],
    now: 1_779_266_060,
  };
  const file = new URL("../target/runner-module-load-input.json", import.meta.url);
  const filePath = fileURLToPath(file);
  fs.mkdirSync(fileURLToPath(new URL("../target/", import.meta.url)), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(input), "utf8");
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--input", filePath], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const report = JSON.parse(stdout);
  assert.equal(report.runnerOperation.state, "succeeded");
  assert.equal(report.hostPosture.state, "succeeded");
  assert.equal(report.hostPosture.safeFacts.operation, "execute");
  assert(report.hostPosture.witnessRefs.includes("witness:module-load:runner-host"));
});

test("runner cli fulfills accepted dispatch input", () => {
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerId: "runner:operator:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:operator-lab",
    now: 1_779_266_090,
  });
  const input = {
    fulfillDispatch: true,
    runnerOperation,
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:module-load:runner-host"],
    now: 1_779_266_100,
  };
  const file = new URL("../target/runner-dispatch-input.json", import.meta.url);
  const filePath = fileURLToPath(file);
  fs.mkdirSync(fileURLToPath(new URL("../target/", import.meta.url)), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(input), "utf8");
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--input", filePath], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const report = JSON.parse(stdout);
  assert.equal(report.kind, "runner.dispatch.fulfillment");
  assert.equal(report.runnerOperation.state, "succeeded");
  assert.equal(report.hostPosture.state, "succeeded");
  assert.equal(report.runtimeReportMessage.type, "runtime.runner.host.fulfillment.put");
});

test("runner cli bridges accepted runtime dispatch snapshot", () => {
  const runnerOperation = buildRunnerOperationForModuleLoad({
    moduleRef: "module:native-dev:constitute-build",
    moduleResolverPosture: makeNativeModuleResolver(),
    operationState: "accepted",
    runnerId: "runner:operator:module-load",
    runnerMemberRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:operator-lab",
    now: 1_779_266_120,
  });
  const input = {
    runtimeRunnerBridge: true,
    runtimeSnapshot: {
      runnerOperations: {
        [runnerOperation.operationId]: {
          kind: "runtime.runner.operation.dispatch",
          dispatchId: `runtime-runner-dispatch:${runnerOperation.operationId}`,
          state: "accepted",
          runnerOperation,
        },
      },
    },
    serviceRefs: ["module:native-dev:constitute-build"],
    witnessRefs: ["witness:module-load:runner-host"],
    now: 1_779_266_130,
  };
  const file = new URL("../target/runner-bridge-input.json", import.meta.url);
  const filePath = fileURLToPath(file);
  fs.mkdirSync(fileURLToPath(new URL("../target/", import.meta.url)), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(input), "utf8");
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--input", filePath], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const bridge = JSON.parse(stdout);
  assert.equal(bridge.kind, "runner.runtime-dispatch.bridge");
  assert.equal(bridge.state, "succeeded");
  assert.equal(bridge.fulfilledCount, 1);
  assert.equal(bridge.fulfilled[0].runtimeReportMessage.type, "runtime.runner.host.fulfillment.put");
});
