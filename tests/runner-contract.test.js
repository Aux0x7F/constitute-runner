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
  buildRunnerOperationForBuild,
  multiIdentityGrantFixture,
} from "../src/index.js";

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
