import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import type { ResolvedGatewayAbuseAuditLedgerConfig } from "./abuse-config.js";

export type GatewayAbuseAuditKind =
  | "request"
  | "anomaly"
  | "quota"
  | "correlation"
  | "incident"
  | "containment";

export type GatewayAbuseAuditRecord = {
  id: number;
  ts: number;
  kind: GatewayAbuseAuditKind;
  method: string;
  actor: string;
  device: string;
  ip: string;
  session: string;
  channel: string;
  account: string;
  tool?: string;
  allowed?: boolean;
  action?: string;
  checkId?: string;
  severity?: "warn" | "critical";
  score?: number;
  fingerprint?: string;
  clusterId?: string;
  incidentId?: string;
  reasonCodes?: string[];
  payload?: unknown;
};

type AuditPersisted = {
  version: 1;
  nextId: number;
  updatedAtMs: number;
  records: GatewayAbuseAuditRecord[];
};

const DEFAULT_AUDIT_CONFIG: ResolvedGatewayAbuseAuditLedgerConfig = {
  mode: "off",
  retentionDays: 14,
  maxRecords: 100_000,
  redactPayloads: true,
};

const PERSIST_DEBOUNCE_MS = 500;

let loaded = false;
let nextId = 1;
let persistTimer: NodeJS.Timeout | undefined;
let persistInFlight = false;
let persistQueued = false;
const auditRecords: GatewayAbuseAuditRecord[] = [];

function resolveStorePath(): string {
  return path.join(resolveStateDir(process.env), "gateway-abuse-audit-ledger.json");
}

function parseTupleKey(key: string): {
  method: string;
  actor: string;
  device: string;
  ip: string;
  session: string;
  channel: string;
  account: string;
} {
  const result = {
    method: "unknown-method",
    actor: "unknown-actor",
    device: "unknown-device",
    ip: "unknown-ip",
    session: "none",
    channel: "none",
    account: "none",
  };
  for (const part of key.split("|")) {
    const [rawName, ...valueParts] = part.split("=");
    const value = valueParts.join("=").trim();
    if (!value) {
      continue;
    }
    if (rawName in result) {
      result[rawName as keyof typeof result] = value;
    }
  }
  return result;
}

function ensureLoaded(): void {
  if (loaded) {
    return;
  }
  loaded = true;
  const storePath = resolveStorePath();
  try {
    if (!fsSync.existsSync(storePath)) {
      return;
    }
    const raw = fsSync.readFileSync(storePath, "utf-8");
    const parsed = JSON.parse(raw) as Partial<AuditPersisted>;
    if (parsed.version !== 1 || !Array.isArray(parsed.records)) {
      return;
    }
    nextId = typeof parsed.nextId === "number" && parsed.nextId > 0 ? Math.floor(parsed.nextId) : 1;
    for (const record of parsed.records) {
      if (
        !record ||
        typeof record !== "object" ||
        typeof record.id !== "number" ||
        typeof record.ts !== "number" ||
        typeof record.kind !== "string"
      ) {
        continue;
      }
      auditRecords.push(record);
    }
  } catch {
    // Ignore unreadable persisted state and continue with empty in-memory state.
  }
}

function serializeState(nowMs: number): AuditPersisted {
  return {
    version: 1,
    nextId,
    updatedAtMs: nowMs,
    records: [...auditRecords],
  };
}

function schedulePersist(nowMs: number): void {
  if (persistInFlight) {
    persistQueued = true;
    return;
  }
  if (persistTimer) {
    clearTimeout(persistTimer);
  }
  persistTimer = setTimeout(() => {
    persistTimer = undefined;
    void persistState(nowMs);
  }, PERSIST_DEBOUNCE_MS);
}

async function persistState(nowMs: number): Promise<void> {
  persistInFlight = true;
  try {
    const storePath = resolveStorePath();
    await fs.mkdir(path.dirname(storePath), { recursive: true });
    const payload = serializeState(nowMs);
    await fs.writeFile(storePath, JSON.stringify(payload), "utf-8");
  } catch {
    // Best-effort persistence only.
  } finally {
    persistInFlight = false;
    if (persistQueued) {
      persistQueued = false;
      schedulePersist(Date.now());
    }
  }
}

function pruneRecords(nowMs: number, config: ResolvedGatewayAbuseAuditLedgerConfig): void {
  const maxAgeMs = Math.max(1, config.retentionDays) * 24 * 60 * 60 * 1000;
  const minTs = nowMs - maxAgeMs;
  let start = 0;
  while (start < auditRecords.length && auditRecords[start] && auditRecords[start].ts < minTs) {
    start += 1;
  }
  if (start > 0) {
    auditRecords.splice(0, start);
  }
  if (auditRecords.length > config.maxRecords) {
    const overflow = auditRecords.length - config.maxRecords;
    auditRecords.splice(0, overflow);
  }
}

export function recordGatewayAbuseAuditEvent(params: {
  kind: GatewayAbuseAuditKind;
  key: string;
  method?: string;
  tool?: string;
  allowed?: boolean;
  action?: string;
  checkId?: string;
  severity?: "warn" | "critical";
  score?: number;
  fingerprint?: string;
  clusterId?: string;
  incidentId?: string;
  reasonCodes?: string[];
  payload?: unknown;
  auditConfig?: ResolvedGatewayAbuseAuditLedgerConfig;
  nowMs?: number;
}): GatewayAbuseAuditRecord | undefined {
  const nowMs = params.nowMs ?? Date.now();
  const auditConfig = params.auditConfig ?? DEFAULT_AUDIT_CONFIG;
  ensureLoaded();

  if (auditConfig.mode === "off") {
    return undefined;
  }

  const tuple = parseTupleKey(params.key);
  const record: GatewayAbuseAuditRecord = {
    id: nextId++,
    ts: nowMs,
    kind: params.kind,
    method: params.method ?? tuple.method,
    actor: tuple.actor,
    device: tuple.device,
    ip: tuple.ip,
    session: tuple.session,
    channel: tuple.channel,
    account: tuple.account,
    tool: params.tool,
    allowed: params.allowed,
    action: params.action,
    checkId: params.checkId,
    severity: params.severity,
    score: params.score,
    fingerprint: params.fingerprint,
    clusterId: params.clusterId,
    incidentId: params.incidentId,
    reasonCodes: params.reasonCodes,
    payload: auditConfig.redactPayloads ? undefined : params.payload,
  };

  auditRecords.push(record);
  pruneRecords(nowMs, auditConfig);
  schedulePersist(nowMs);
  return record;
}

export function queryGatewayAbuseAuditLedger(params?: {
  limit?: number;
  kind?: GatewayAbuseAuditKind;
  actor?: string;
  channel?: string;
  tool?: string;
  incidentId?: string;
}): GatewayAbuseAuditRecord[] {
  ensureLoaded();
  const limit = params?.limit ? Math.max(1, Math.min(5_000, Math.floor(params.limit))) : 100;
  const filtered = auditRecords.filter((record) => {
    if (params?.kind && record.kind !== params.kind) {
      return false;
    }
    if (params?.actor && record.actor !== params.actor) {
      return false;
    }
    if (params?.channel && record.channel !== params.channel) {
      return false;
    }
    if (params?.tool && record.tool !== params.tool) {
      return false;
    }
    if (params?.incidentId && record.incidentId !== params.incidentId) {
      return false;
    }
    return true;
  });
  return filtered.slice(-limit).toReversed();
}

export function getGatewayAbuseAuditLedgerSnapshot(): AuditPersisted {
  ensureLoaded();
  return serializeState(Date.now());
}

export const __testing = {
  resetGatewayAbuseAuditLedgerState() {
    loaded = false;
    nextId = 1;
    auditRecords.splice(0, auditRecords.length);
    if (persistTimer) {
      clearTimeout(persistTimer);
      persistTimer = undefined;
    }
    persistInFlight = false;
    persistQueued = false;
  },
};
