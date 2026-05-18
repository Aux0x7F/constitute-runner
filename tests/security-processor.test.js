import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import {
  appRunnerFulfillmentFixture,
  assertAppRunnerFulfillmentReport,
  buildMultiIdentityGrantProof,
  assertSecurityProcessorRunReport,
  buildAppRunnerFulfillment,
  buildSecurityProcessorRun,
  multiIdentityGrantFixture,
  securityAppContractFixture,
  securityBootstrapFixture,
} from "../src/index.js";

test("security bootstrap runner emits alert and evidence-hold posture", () => {
  const report = buildSecurityProcessorRun(securityBootstrapFixture());
  assert.equal(report.kind, "security.processor.run.report");
  assert.equal(report.state, "alerted");
  assert.equal(report.processorRef, "constitute-security");
  assert.equal(report.alertPosture.state, "open");
  assert.equal(report.evidenceHoldPosture.state, "holding");
  assert.deepEqual(report.blockedReasons, []);
  assert.equal(report.safeFacts.storageBoundary, "ciphertextFulfillmentOnly");
  assert.equal(report.safeFacts.eventDomainBoundary, "doesNotOwn");
  assertSecurityProcessorRunReport(report);
});

test("security bootstrap blocks when runner inputs do not match seed access", () => {
  const fixture = securityBootstrapFixture();
  const report = buildSecurityProcessorRun({
    ...fixture,
    runnerOperation: {
      ...fixture.runnerOperation,
      inputRefs: ["event-fabric:unrelated"],
    },
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("inputRefMismatch"), true);
  assert.equal(report.accessPosture.state, "blocked");
});

test("security bootstrap rejects unsafe safe-fact leakage", () => {
  const fixture = securityBootstrapFixture();
  assert.throws(() => buildSecurityProcessorRun({
    ...fixture,
    observedEvents: [{
      eventRef: "event:unsafe",
      eventClass: "runtime.diagnostic",
      severity: "error",
      safeFacts: {
        payload: "must-not-copy",
      },
    }],
  }), /unsafe key payload/);
});

test("security bootstrap blocks expired seed posture", () => {
  const fixture = securityBootstrapFixture(1_700_000_000);
  const report = buildSecurityProcessorRun({
    ...fixture,
    now: 1_800_000_000,
  });
  assert.equal(report.state, "blocked");
  assert.equal(report.blockedReasons.includes("seedExpired"), true);
  assert.equal(report.blockedReasons.includes("runnerOperationExpired"), true);
});

test("security runner cli executes the bootstrap fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "security-bootstrap"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const report = JSON.parse(stdout);
  assert.equal(report.state, "alerted");
  assert.equal(report.safeFacts.alertCount, 1);
});

test("security app fixture declares event fabric, access, and materialization requirements", () => {
  const now = 1_700_000_000;
  const fixture = securityAppContractFixture(now);
  assert.equal(fixture.appContract.appId, "constitute-security");
  assert.equal(fixture.appContract.grantRefs.includes("grant:app:constitute-security:run"), true);
  assert.deepEqual(fixture.appContract.accessGroupRefs, ["access-group:logging.security.default"]);
  assert.deepEqual(fixture.appContract.requiredContentClasses, ["encryptedDetail", "safeIndex"]);
  assert.equal(fixture.appContract.projectionSubscriptions[0].processorRoleRef, "role:security.processor");
  assert.equal(fixture.appContract.materializationBudgets.some((budget) => budget.budgetId === "security.encrypted-detail.refs"), true);
  assert.equal(fixture.appContract.materializationBudgets.some((budget) => budget.budgetId === "security.alerts.ui"), true);

  const report = buildAppRunnerFulfillment(fixture);
  assert.equal(report.state, "succeeded");
  assert.equal(report.appId, "constitute-security");
  assert.equal(report.sourceMode, "bundled");
  assert.equal(report.safeFacts.sourceRefCount, 1);
  assert.equal(report.inputRefs.includes(fixture.seed.seedId), true);
  assertAppRunnerFulfillmentReport(report);
});

test("security runner cli emits the security app contract fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "security-app-contract"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const fixture = JSON.parse(stdout);
  assert.equal(fixture.appContract.appId, "constitute-security");
  assert.equal(fixture.manifest.currentAppContractRef, "app:constitute-security");
  assert.equal(fixture.seed.processorRoleRef, "role:security.processor");
});

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
      memberRefs: ["member:logging:processor"],
    },
  });
  assert.equal(proof.state, "degraded");
  assert.equal(proof.blockedReasons.includes("granteeMissingFromAccessEpoch"), true);
});

test("security runner cli executes the multi-identity grant fixture", () => {
  const stdout = execFileSync(process.execPath, ["./src/cli.mjs", "--fixture", "multi-identity-grant"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  const proof = JSON.parse(stdout);
  assert.equal(proof.state, "proved");
  assert.equal(proof.safeFacts.proofClass, "multiIdentityFullAccess");
});

test("app runner fulfillment reports executed app contract posture", () => {
  const report = buildAppRunnerFulfillment(appRunnerFulfillmentFixture());
  assert.equal(report.kind, "app.runner.fulfillment.report");
  assert.equal(report.state, "succeeded");
  assert.equal(report.appId, "constitute-runner-proof");
  assert.equal(report.version, "0.1.0");
  assert.equal(report.sourceMode, "bundled");
  assert.deepEqual(report.sourceRefs, ["bundle:runner-proof@0.1.0"]);
  assert.equal(report.operationPosture.accepted, true);
  assert.equal(report.fulfillmentPosture.outputRefs.includes("artifact:runner-proof:dist"), true);
  assert.equal(report.fulfillmentPosture.releaseRefs.includes("release:runner-proof"), true);
  assert.deepEqual(report.blockedReasons, []);
  assertAppRunnerFulfillmentReport(report);
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
