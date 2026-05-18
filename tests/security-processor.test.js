import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import {
  buildMultiIdentityGrantProof,
  assertSecurityProcessorRunReport,
  buildSecurityProcessorRun,
  multiIdentityGrantFixture,
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
