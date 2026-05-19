import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import {
  appRunnerFulfillmentFixture,
  assertAppRunnerFulfillmentLifecycle,
  assertAppRunnerFulfillmentReport,
  assertRunnerHostPosture,
  buildMultiIdentityGrantProof,
  buildAppRunnerFulfillment,
  buildAppRunnerFulfillmentLifecycle,
  buildRunnerHostFulfillmentPosture,
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
