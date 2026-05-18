import type {
  RunnerOperationRecord,
  SecurityProcessorSeedRecord,
} from "../../constitute-protocol/src/index.js";

export type SecurityObservedEvent = {
  eventRef?: string;
  eventId?: string;
  evidenceRef?: string;
  eventClass?: string;
  severity?: string;
  observedAt?: number;
  safeFacts?: Record<string, unknown>;
};

export type SecurityProcessorRunReport = {
  kind: "security.processor.run.report";
  reportId: string;
  seedId: string;
  processorRef: string;
  processorRoleRef: string;
  fabricRef: string;
  runnerOperationId: string;
  state: "clear" | "alerted" | "blocked" | "degraded";
  alertPosture: Record<string, unknown>;
  evidenceHoldPosture: Record<string, unknown>;
  accessPosture: Record<string, unknown>;
  materializationPosture: Record<string, unknown>;
  semanticBoundaries: Record<string, unknown>;
  safeFacts: Record<string, unknown>;
  evidenceRefs: string[];
  blockedReasons: string[];
  observedAt: number;
  expiresAt?: number;
};

export function buildSecurityProcessorRun(input: {
  seed: SecurityProcessorSeedRecord;
  runnerOperation: RunnerOperationRecord;
  observedEvents?: SecurityObservedEvent[];
  now?: number;
}): SecurityProcessorRunReport;

export function assertSecurityProcessorRunReport(record: unknown): SecurityProcessorRunReport;
export function securityBootstrapFixture(now?: number): {
  seed: SecurityProcessorSeedRecord;
  runnerOperation: RunnerOperationRecord;
  observedEvents: SecurityObservedEvent[];
};
