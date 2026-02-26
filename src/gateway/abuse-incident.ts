import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import type { GatewayAbuseMode } from "../config/config.js";
import { resolveStateDir } from "../config/paths.js";
import type { ResolvedGatewayAbuseIncidentConfig } from "./abuse-config.js";
import { buildGatewayAbuseTupleScopeKey, parseGatewayAbuseTupleKey } from "./abuse-tuple-key.js";

export type GatewayAbuseIncidentState = "open" | "investigating" | "contained" | "resolved";
export type GatewayAbuseIncidentSeverity = "warn" | "critical";
export type GatewayAbuseIncidentAction = "acknowledge" | "escalate" | "release" | "resolve";

type IncidentTimelineEntry = {
  ts: number;
  type:
    | "opened"
    | "signal"
    | "contained"
    | "containment_expired"
    | "acknowledged"
    | "released"
    | "escalated"
    | "resolved";
  note?: string;
  actor?: string;
  source?: string;
  checkId?: string;
  severity?: GatewayAbuseIncidentSeverity;
};

type GatewayAbuseIncidentRecord = {
  id: string;
  state: GatewayAbuseIncidentState;
  severity: GatewayAbuseIncidentSeverity;
  scopeKey: string;
  tupleScopeKey: string;
  clusterId?: string;
  createdAtMs: number;
  updatedAtMs: number;
  checkIds: string[];
  timeline: IncidentTimelineEntry[];
  containment?: {
    expiresAtMs: number;
  };
};

type IncidentPersisted = {
  version: 1;
  nextId: number;
  updatedAtMs: number;
  incidents: GatewayAbuseIncidentRecord[];
};

type ContainmentState = {
  incidentId: string;
  expiresAtMs: number;
};

const DEFAULT_INCIDENT_CONFIG: ResolvedGatewayAbuseIncidentConfig = {
  mode: "off",
  autoContainment: {
    enabled: false,
    minSeverity: "critical",
    ttlMs: 600_000,
  },
  retentionDays: 14,
};

const MAX_INCIDENTS = 5_000;
const PERSIST_DEBOUNCE_MS = 500;

const incidentsById = new Map<string, GatewayAbuseIncidentRecord>();
const activeIncidentByScope = new Map<string, string>();
const containmentByTupleScope = new Map<string, ContainmentState>();

let loaded = false;
let nextId = 1;
let persistTimer: NodeJS.Timeout | undefined;
let persistInFlight = false;
let persistQueued = false;

function resolveStorePath(): string {
  return path.join(resolveStateDir(process.env), "gateway-abuse-incidents.json");
}

function parseTupleScope(key: string): string {
  const tuple = parseGatewayAbuseTupleKey(key);
  return buildGatewayAbuseTupleScopeKey(tuple);
}

function resolveIncidentScopeKey(params: { tupleScopeKey: string; clusterId?: string }): string {
  if (params.clusterId) {
    return `cluster=${params.clusterId}`;
  }
  return `tuple=${params.tupleScopeKey}`;
}

function severityRank(severity: GatewayAbuseIncidentSeverity): number {
  return severity === "critical" ? 2 : 1;
}

function shouldAutoContain(params: {
  mode: GatewayAbuseMode;
  config: ResolvedGatewayAbuseIncidentConfig;
  severity: GatewayAbuseIncidentSeverity;
}): boolean {
  if (params.mode !== "enforce") {
    return false;
  }
  if (!params.config.autoContainment.enabled) {
    return false;
  }
  if (params.config.autoContainment.minSeverity === "warn") {
    return true;
  }
  return params.severity === "critical";
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
    const parsed = JSON.parse(raw) as Partial<IncidentPersisted>;
    if (parsed.version !== 1 || !Array.isArray(parsed.incidents)) {
      return;
    }
    nextId = typeof parsed.nextId === "number" && parsed.nextId > 0 ? Math.floor(parsed.nextId) : 1;
    for (const incident of parsed.incidents) {
      if (
        !incident ||
        typeof incident !== "object" ||
        typeof incident.id !== "string" ||
        typeof incident.scopeKey !== "string" ||
        typeof incident.tupleScopeKey !== "string" ||
        !Array.isArray(incident.timeline)
      ) {
        continue;
      }
      incidentsById.set(incident.id, {
        id: incident.id,
        state:
          incident.state === "open" ||
          incident.state === "investigating" ||
          incident.state === "contained" ||
          incident.state === "resolved"
            ? incident.state
            : "open",
        severity: incident.severity === "critical" ? "critical" : "warn",
        scopeKey: incident.scopeKey,
        tupleScopeKey: incident.tupleScopeKey,
        clusterId: incident.clusterId,
        createdAtMs: typeof incident.createdAtMs === "number" ? incident.createdAtMs : 0,
        updatedAtMs: typeof incident.updatedAtMs === "number" ? incident.updatedAtMs : 0,
        checkIds: Array.isArray(incident.checkIds)
          ? incident.checkIds.filter((value): value is string => typeof value === "string")
          : [],
        timeline: incident.timeline,
        containment:
          incident.containment && typeof incident.containment.expiresAtMs === "number"
            ? {
                expiresAtMs: incident.containment.expiresAtMs,
              }
            : undefined,
      });
      if (incident.state !== "resolved") {
        activeIncidentByScope.set(incident.scopeKey, incident.id);
      }
      if (
        incident.state === "contained" &&
        incident.containment &&
        typeof incident.containment.expiresAtMs === "number"
      ) {
        containmentByTupleScope.set(incident.tupleScopeKey, {
          incidentId: incident.id,
          expiresAtMs: incident.containment.expiresAtMs,
        });
      }
    }
  } catch {
    // Ignore unreadable persisted state and continue with empty in-memory state.
  }
}

function serializeState(nowMs: number): IncidentPersisted {
  const incidents = [...incidentsById.values()]
    .toSorted((a, b) => a.updatedAtMs - b.updatedAtMs)
    .slice(-MAX_INCIDENTS);
  return {
    version: 1,
    nextId,
    updatedAtMs: nowMs,
    incidents,
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

function pruneExpiredContainment(nowMs: number): boolean {
  let changed = false;
  for (const [tupleScopeKey, containment] of containmentByTupleScope) {
    if (containment.expiresAtMs > nowMs) {
      continue;
    }
    containmentByTupleScope.delete(tupleScopeKey);
    changed = true;
    const incident = incidentsById.get(containment.incidentId);
    if (!incident) {
      continue;
    }
    if (incident.state === "contained") {
      incident.state = "investigating";
      incident.containment = undefined;
      incident.updatedAtMs = nowMs;
      incident.timeline.push({
        ts: nowMs,
        type: "containment_expired",
      });
      changed = true;
    }
  }
  return changed;
}

function pruneRetainedIncidents(nowMs: number, retentionDays: number): boolean {
  const retentionMs = Math.max(1, retentionDays) * 24 * 60 * 60 * 1000;
  const cutoffMs = nowMs - retentionMs;
  let changed = false;
  for (const [incidentId, incident] of incidentsById) {
    if (incident.updatedAtMs >= cutoffMs) {
      continue;
    }
    // Keep unresolved incidents for operator continuity and active containment safety.
    if (incident.state !== "resolved") {
      continue;
    }
    incidentsById.delete(incidentId);
    activeIncidentByScope.delete(incident.scopeKey);
    containmentByTupleScope.delete(incident.tupleScopeKey);
    changed = true;
  }
  return changed;
}

function upsertCheckId(incident: GatewayAbuseIncidentRecord, checkId: string): void {
  if (!incident.checkIds.includes(checkId)) {
    incident.checkIds.push(checkId);
  }
}

function buildIncidentId(): string {
  const id = `inc_${String(nextId).padStart(6, "0")}`;
  nextId += 1;
  return id;
}

export type GatewayAbuseIncidentDecision = {
  mode: GatewayAbuseMode;
  incidentId: string;
  created: boolean;
  state: GatewayAbuseIncidentState;
  severity: GatewayAbuseIncidentSeverity;
  checkId: string;
  autoContained: boolean;
  containmentExpiresAtMs?: number;
};

export type GatewayAbuseContainmentDecision = {
  active: boolean;
  incidentId?: string;
  retryAfterMs: number;
  scopeKey: string;
};

export function recordGatewayAbuseIncidentSignal(params: {
  key: string;
  source: "anomaly" | "quota" | "correlation";
  severity: GatewayAbuseIncidentSeverity;
  checkId: string;
  reasonCodes?: string[];
  clusterId?: string;
  incidentConfig?: ResolvedGatewayAbuseIncidentConfig;
  nowMs?: number;
}): GatewayAbuseIncidentDecision | undefined {
  const nowMs = params.nowMs ?? Date.now();
  const incidentConfig = params.incidentConfig ?? DEFAULT_INCIDENT_CONFIG;
  ensureLoaded();
  pruneExpiredContainment(nowMs);
  pruneRetainedIncidents(nowMs, incidentConfig.retentionDays);

  if (incidentConfig.mode === "off") {
    return undefined;
  }

  const tupleScopeKey = parseTupleScope(params.key);
  const scopeKey = resolveIncidentScopeKey({
    tupleScopeKey,
    clusterId: params.clusterId,
  });
  const existingId = activeIncidentByScope.get(scopeKey);
  const existing = existingId ? incidentsById.get(existingId) : undefined;
  const created = !existing;
  const incident =
    existing ??
    (() => {
      const opened: GatewayAbuseIncidentRecord = {
        id: buildIncidentId(),
        state: "open",
        severity: params.severity,
        scopeKey,
        tupleScopeKey,
        clusterId: params.clusterId,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        checkIds: [params.checkId],
        timeline: [
          {
            ts: nowMs,
            type: "opened",
            source: params.source,
            checkId: params.checkId,
            severity: params.severity,
          },
        ],
      };
      incidentsById.set(opened.id, opened);
      activeIncidentByScope.set(scopeKey, opened.id);
      return opened;
    })();

  if (severityRank(params.severity) > severityRank(incident.severity)) {
    incident.severity = params.severity;
  }
  upsertCheckId(incident, params.checkId);
  incident.updatedAtMs = nowMs;
  incident.timeline.push({
    ts: nowMs,
    type: "signal",
    source: params.source,
    checkId: params.checkId,
    severity: params.severity,
    note: params.reasonCodes?.join(",") || undefined,
  });

  let autoContained = false;
  let containmentExpiresAtMs: number | undefined;
  if (
    shouldAutoContain({
      mode: incidentConfig.mode,
      config: incidentConfig,
      severity: params.severity,
    })
  ) {
    autoContained = true;
    containmentExpiresAtMs = nowMs + incidentConfig.autoContainment.ttlMs;
    incident.state = "contained";
    incident.containment = {
      expiresAtMs: containmentExpiresAtMs,
    };
    containmentByTupleScope.set(tupleScopeKey, {
      incidentId: incident.id,
      expiresAtMs: containmentExpiresAtMs,
    });
    incident.timeline.push({
      ts: nowMs,
      type: "contained",
      checkId: params.checkId,
      severity: params.severity,
    });
  } else if (incident.state === "open") {
    incident.state = "investigating";
  }

  schedulePersist(nowMs);
  return {
    mode: incidentConfig.mode,
    incidentId: incident.id,
    created,
    state: incident.state,
    severity: incident.severity,
    checkId: params.checkId,
    autoContained,
    containmentExpiresAtMs,
  };
}

export function getActiveGatewayAbuseContainment(params: {
  key: string;
  nowMs?: number;
  incidentConfig?: ResolvedGatewayAbuseIncidentConfig;
}): GatewayAbuseContainmentDecision {
  const nowMs = params.nowMs ?? Date.now();
  const incidentConfig = params.incidentConfig ?? DEFAULT_INCIDENT_CONFIG;
  ensureLoaded();
  const retentionPruned = pruneRetainedIncidents(nowMs, incidentConfig.retentionDays);
  const containmentPruned = pruneExpiredContainment(nowMs);
  let changed = retentionPruned || containmentPruned;

  const scopeKey = parseTupleScope(params.key);
  const containment = containmentByTupleScope.get(scopeKey);
  if (!containment) {
    if (changed) {
      schedulePersist(nowMs);
    }
    return {
      active: false,
      retryAfterMs: 0,
      scopeKey,
    };
  }
  const retryAfterMs = Math.max(0, containment.expiresAtMs - nowMs);
  if (retryAfterMs <= 0) {
    containmentByTupleScope.delete(scopeKey);
    changed = true;
    if (changed) {
      schedulePersist(nowMs);
    }
    return {
      active: false,
      retryAfterMs: 0,
      scopeKey,
    };
  }
  if (changed) {
    schedulePersist(nowMs);
  }
  return {
    active: true,
    incidentId: containment.incidentId,
    retryAfterMs,
    scopeKey,
  };
}

export function transitionGatewayAbuseIncident(params: {
  incidentId: string;
  action: GatewayAbuseIncidentAction;
  actor?: string;
  note?: string;
  nowMs?: number;
  incidentConfig?: ResolvedGatewayAbuseIncidentConfig;
}): GatewayAbuseIncidentRecord | undefined {
  const nowMs = params.nowMs ?? Date.now();
  const incidentConfig = params.incidentConfig ?? DEFAULT_INCIDENT_CONFIG;
  ensureLoaded();
  const retentionPruned = pruneRetainedIncidents(nowMs, incidentConfig.retentionDays);
  const containmentPruned = pruneExpiredContainment(nowMs);
  if (retentionPruned || containmentPruned) {
    schedulePersist(nowMs);
  }

  const incident = incidentsById.get(params.incidentId);
  if (!incident) {
    return undefined;
  }

  incident.updatedAtMs = nowMs;
  if (params.action === "acknowledge") {
    if (incident.state === "open") {
      incident.state = "investigating";
    }
    incident.timeline.push({
      ts: nowMs,
      type: "acknowledged",
      actor: params.actor,
      note: params.note,
    });
  } else if (params.action === "escalate") {
    incident.severity = "critical";
    incident.timeline.push({
      ts: nowMs,
      type: "escalated",
      actor: params.actor,
      note: params.note,
      severity: "critical",
    });
  } else if (params.action === "release") {
    incident.state = "investigating";
    incident.containment = undefined;
    containmentByTupleScope.delete(incident.tupleScopeKey);
    incident.timeline.push({
      ts: nowMs,
      type: "released",
      actor: params.actor,
      note: params.note,
    });
  } else if (params.action === "resolve") {
    incident.state = "resolved";
    incident.containment = undefined;
    containmentByTupleScope.delete(incident.tupleScopeKey);
    activeIncidentByScope.delete(incident.scopeKey);
    incident.timeline.push({
      ts: nowMs,
      type: "resolved",
      actor: params.actor,
      note: params.note,
    });
  }

  schedulePersist(nowMs);
  return incident;
}

export function getGatewayAbuseIncidentSnapshot(params?: {
  nowMs?: number;
  incidentConfig?: ResolvedGatewayAbuseIncidentConfig;
}): IncidentPersisted {
  const nowMs = params?.nowMs ?? Date.now();
  const incidentConfig = params?.incidentConfig ?? DEFAULT_INCIDENT_CONFIG;
  ensureLoaded();
  const retentionPruned = pruneRetainedIncidents(nowMs, incidentConfig.retentionDays);
  const containmentPruned = pruneExpiredContainment(nowMs);
  if (retentionPruned || containmentPruned) {
    schedulePersist(nowMs);
  }
  return serializeState(nowMs);
}

export const __testing = {
  resetGatewayAbuseIncidentState() {
    incidentsById.clear();
    activeIncidentByScope.clear();
    containmentByTupleScope.clear();
    loaded = false;
    nextId = 1;
    if (persistTimer) {
      clearTimeout(persistTimer);
      persistTimer = undefined;
    }
    persistInFlight = false;
    persistQueued = false;
  },
};
