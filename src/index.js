import {
  RUNNER,
  SURFACE_APP,
  SWARM,
  assertRunnerOperation,
  assertSecurityProcessorSeed,
} from "../../constitute-protocol/src/index.js";

export const SECURITY_RUN_KIND = "security.processor.run.report";

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

export function buildSecurityProcessorRun(input = {}) {
  const seed = assertSecurityProcessorSeed(input.seed);
  const runnerOperation = assertRunnerOperation(input.runnerOperation);
  const observedAt = Number(input.now || 0) || nowSeconds();
  const observedEvents = asArray(input.observedEvents).map(normalizeObservedEvent);
  const blockedReasons = [];

  if (seed.state !== "ready") blockedReasons.push(`seed:${seed.state}`);
  if (seed.expiresAt !== undefined && Number(seed.expiresAt || 0) <= observedAt) blockedReasons.push("seedExpired");
  if (seed.processorRoleRef !== "role:security.processor") blockedReasons.push("processorRoleMismatch");
  if (TERMINAL_BLOCKED_STATES.has(runnerOperation.state)) blockedReasons.push(`runnerOperation:${runnerOperation.state}`);
  if (runnerOperation.expiresAt !== undefined && Number(runnerOperation.expiresAt || 0) <= observedAt) blockedReasons.push("runnerOperationExpired");
  if (!intersects(stringSet(runnerOperation.inputRefs), inputUniverse(seed))) blockedReasons.push("inputRefMismatch");
  if (!intersects(stringSet(runnerOperation.outputRefs), outputUniverse(seed))) blockedReasons.push("outputRefMismatch");
  if (asArray(seed.accessGroupRefs).length === 0) blockedReasons.push("missingAccessGroup");
  if (asArray(seed.detailRefs).length === 0) blockedReasons.push("missingDetailRef");
  if (asArray(seed.storageRefs).length === 0) blockedReasons.push("missingStorageRef");

  const alertEvents = observedEvents.filter((event) => (
    ALERT_SEVERITIES.has(event.severity)
    || event.eventClass.toLowerCase().includes("security")
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
  rejectUnsafeSafeFacts(safeFacts, "security processor run");
  return assertSecurityProcessorRunReport({
    kind: SECURITY_RUN_KIND,
    reportId: `security-run:${seed.seedId}:${runnerOperation.operationId}`,
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

export function assertSecurityProcessorRunReport(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("security processor run report must be an object");
  if (record.kind !== SECURITY_RUN_KIND) throw new Error("invalid security processor run report kind");
  for (const field of ["reportId", "seedId", "processorRef", "processorRoleRef", "fabricRef", "runnerOperationId", "state"]) {
    if (!String(record[field] || "").trim()) throw new Error(`security processor run report missing ${field}`);
  }
  if (!["clear", "alerted", "blocked", "degraded"].includes(record.state)) throw new Error("invalid security processor run report state");
  for (const field of ["alertPosture", "evidenceHoldPosture", "accessPosture", "materializationPosture", "semanticBoundaries", "safeFacts"]) {
    if (!record[field] || typeof record[field] !== "object" || Array.isArray(record[field])) {
      throw new Error(`security processor run report ${field} must be an object`);
    }
  }
  for (const field of ["evidenceRefs", "blockedReasons"]) {
    if (!Array.isArray(record[field])) throw new Error(`security processor run report ${field} must be an array`);
  }
  if (record.state === "blocked" && record.blockedReasons.length === 0) {
    throw new Error("blocked security processor run requires blockedReasons");
  }
  rejectUnsafeSafeFacts(record.safeFacts, "security processor run report");
  if (!Number(record.observedAt || 0)) throw new Error("security processor run report missing observedAt");
  return record;
}

export function securityBootstrapFixture(now = nowSeconds()) {
  const seed = assertSecurityProcessorSeed({
    kind: SWARM.RECORD_KIND.SECURITY_PROCESSOR_SEED,
    seedId: "security-seed:logging.default",
    fabricRef: "event-fabric:logging.default",
    processorRef: "constitute-security",
    processorRoleRef: "role:security.processor",
    state: "ready",
    threatAnalysisRole: "eventFabricThreatAnalysis",
    inputAccessClassRefs: ["event-class:logging.security.encrypted-detail"],
    inputEventClasses: ["runtime.diagnostic", "media.path"],
    inputContentClasses: ["encryptedDetail", "safeIndex"],
    accessGroupRefs: ["access-group:logging.security.default"],
    processorContractRefs: ["processor-contract:logging.security"],
    evidenceProfileRefs: ["logging.security.default"],
    materializationBudgetRefs: ["logging.security.default.90d"],
    storageRefs: ["storage:logging.security.archive"],
    detailRefs: ["encrypted-detail:logging.default"],
    alertOutputRefs: ["security:alerts:logging.default"],
    evidenceHoldRefs: ["security:evidence-hold:logging.default"],
    retentionHoldRefs: ["retention:security-hold:logging.default"],
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: ["access-group:logging.security.default"],
      detailRefs: ["encrypted-detail:logging.default"],
    },
    semanticBoundaries: {
      logging: "mayConsumeMaterializations",
      storage: "ciphertextFulfillmentOnly",
      eventDomain: "doesNotOwn",
    },
    safeFacts: {
      purpose: "securityThreatAnalysis",
      detailCustody: "encryptedDetailRef",
      alerting: "seeded",
    },
    evidenceRefs: ["logging.security.default"],
    blockedReasons: [],
    issuedAt: now,
    expiresAt: now + 90 * 24 * 60 * 60,
  });
  const runnerOperation = assertRunnerOperation({
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: "runner-operation:security-bootstrap:execute:1",
    runnerId: "runner:lab-gateway:security-bootstrap",
    runnerRef: "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1",
    hostRef: "host:lab-gateway",
    requesterRef: "identity:aux",
    subjectRef: "security-processor:dev",
    contractRef: "security-processor:seed@0.1.0",
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.OPERATION_STATE.SUCCEEDED,
    grantRefs: ["authority-grant:runner:security-bootstrap"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: [seed.fabricRef, ...seed.inputAccessClassRefs],
    outputRefs: [...seed.alertOutputRefs, ...seed.evidenceHoldRefs],
    evidenceRefs: ["evidence:runner:started", "evidence:runner:completed"],
    proofRefs: ["proof:runner:security-bootstrap"],
    releaseRefs: ["release:runner:security-bootstrap"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 512,
      maxCpuPct: 40,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:security-bootstrap",
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
      buildRef: "build:runner:security-bootstrap",
      releaseRef: "release:runner:security-bootstrap",
      rollbackRef: "rollback:runner:security-bootstrap",
    },
    releaseRef: "release:runner:security-bootstrap",
    rollbackRef: "rollback:runner:security-bootstrap",
    safeFacts: {
      role: "securityProcessor",
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
