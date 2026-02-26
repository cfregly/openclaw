import { createHash } from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import type { GatewayAbuseMode } from "../config/config.js";
import { resolveStateDir } from "../config/paths.js";
import type { ResolvedGatewayAbuseCorrelationConfig } from "./abuse-config.js";
import { parseGatewayAbuseTupleKey } from "./abuse-tuple-key.js";

type CorrelationSource = "request" | "quota" | "anomaly";
type CorrelationSeverity = "none" | "warning" | "critical";

type CorrelationTuple = {
  method: string;
  actor: string;
  device: string;
  ip: string;
  session: string;
  channel: string;
  account: string;
};

type CorrelationSignal = {
  ts: number;
  source: CorrelationSource;
  score: number;
  reasonCodes: string[];
  tuple: CorrelationTuple;
  weight: number;
};

type CorrelationCluster = {
  clusterId: string;
  fingerprint: string;
  updatedAtMs: number;
  signals: CorrelationSignal[];
};

type CorrelationPersisted = {
  version: 1;
  updatedAtMs: number;
  clusters: CorrelationCluster[];
};

export type GatewayAbuseCorrelationDecision = {
  observed: boolean;
  mode: GatewayAbuseMode;
  severity: CorrelationSeverity;
  clusterId: string;
  clusterScore: number;
  threshold?: number;
  checkId: string;
  fingerprint: string;
  fanout: {
    actors: number;
    devices: number;
    ips: number;
    accounts: number;
  };
  reasonCodes: string[];
};

const DEFAULT_CORRELATION_CONFIG: ResolvedGatewayAbuseCorrelationConfig = {
  mode: "off",
  windowMs: 900_000,
  decayHalfLifeMs: 300_000,
  warningScore: 50,
  criticalScore: 80,
};

const MAX_CLUSTERS = 2_000;
const MAX_SIGNALS_PER_CLUSTER = 512;
const PERSIST_DEBOUNCE_MS = 500;

const clustersByFingerprint = new Map<string, CorrelationCluster>();
let loaded = false;
let persistTimer: NodeJS.Timeout | undefined;
let persistInFlight = false;
let persistQueued = false;

function resolveStorePath(): string {
  return path.join(resolveStateDir(process.env), "gateway-abuse-correlation.json");
}

function normalizeText(text: string): string {
  return text.replace(/\s+/g, " ").trim().toLowerCase();
}

function toFingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
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
    const parsed = JSON.parse(raw) as Partial<CorrelationPersisted>;
    if (parsed.version !== 1 || !Array.isArray(parsed.clusters)) {
      return;
    }
    for (const cluster of parsed.clusters) {
      if (
        !cluster ||
        typeof cluster !== "object" ||
        typeof cluster.fingerprint !== "string" ||
        typeof cluster.clusterId !== "string" ||
        !Array.isArray(cluster.signals)
      ) {
        continue;
      }
      const normalizedSignals = cluster.signals.filter((signal) => {
        return (
          signal &&
          typeof signal === "object" &&
          typeof signal.ts === "number" &&
          typeof signal.source === "string" &&
          typeof signal.score === "number" &&
          typeof signal.weight === "number" &&
          Array.isArray(signal.reasonCodes) &&
          signal.tuple &&
          typeof signal.tuple === "object"
        );
      });
      clustersByFingerprint.set(cluster.fingerprint, {
        clusterId: cluster.clusterId,
        fingerprint: cluster.fingerprint,
        updatedAtMs: typeof cluster.updatedAtMs === "number" ? cluster.updatedAtMs : 0,
        signals: normalizedSignals.slice(-MAX_SIGNALS_PER_CLUSTER),
      });
    }
  } catch {
    // Ignore unreadable correlation state and continue with empty in-memory state.
  }
}

function serializeState(nowMs: number): CorrelationPersisted {
  const clusters = [...clustersByFingerprint.values()].slice(-MAX_CLUSTERS);
  return {
    version: 1,
    updatedAtMs: nowMs,
    clusters,
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

function resolveSignalWeight(params: { source: CorrelationSource; score: number }): number {
  const sourceBonus = params.source === "anomaly" ? 20 : params.source === "quota" ? 12 : 5;
  const scoreWeight = Math.max(0, Math.min(60, Math.floor(params.score / 2)));
  return sourceBonus + scoreWeight;
}

function pruneCluster(cluster: CorrelationCluster, nowMs: number, windowMs: number): void {
  cluster.signals = cluster.signals.filter((signal) => nowMs - signal.ts <= windowMs);
  if (cluster.signals.length > MAX_SIGNALS_PER_CLUSTER) {
    cluster.signals = cluster.signals.slice(-MAX_SIGNALS_PER_CLUSTER);
  }
  cluster.updatedAtMs = nowMs;
}

function pruneGlobal(nowMs: number, windowMs: number): void {
  for (const [fingerprint, cluster] of clustersByFingerprint) {
    pruneCluster(cluster, nowMs, windowMs);
    if (cluster.signals.length === 0) {
      clustersByFingerprint.delete(fingerprint);
    }
  }
  if (clustersByFingerprint.size <= MAX_CLUSTERS) {
    return;
  }
  const overflow = clustersByFingerprint.size - MAX_CLUSTERS;
  const oldest = [...clustersByFingerprint.entries()]
    .toSorted(([, a], [, b]) => a.updatedAtMs - b.updatedAtMs)
    .slice(0, overflow);
  for (const [fingerprint] of oldest) {
    clustersByFingerprint.delete(fingerprint);
  }
}

function computeClusterScore(params: {
  cluster: CorrelationCluster;
  nowMs: number;
  decayHalfLifeMs: number;
}): { clusterScore: number; fanout: GatewayAbuseCorrelationDecision["fanout"] } {
  let decayedSignalScore = 0;
  const actors = new Set<string>();
  const devices = new Set<string>();
  const ips = new Set<string>();
  const accounts = new Set<string>();

  for (const signal of params.cluster.signals) {
    const ageMs = Math.max(0, params.nowMs - signal.ts);
    const decay = Math.pow(0.5, ageMs / params.decayHalfLifeMs);
    decayedSignalScore += signal.weight * decay;
    actors.add(signal.tuple.actor);
    devices.add(signal.tuple.device);
    ips.add(signal.tuple.ip);
    if (signal.tuple.account !== "none") {
      accounts.add(signal.tuple.account);
    }
  }

  const fanoutActors = Math.max(0, actors.size - 1) * 12;
  const fanoutDevices = Math.max(0, devices.size - 1) * 6;
  const fanoutIps = Math.max(0, ips.size - 1) * 10;
  const fanoutAccounts = Math.max(0, accounts.size - 1) * 8;

  const clusterScore = Math.round(
    decayedSignalScore + fanoutActors + fanoutDevices + fanoutIps + fanoutAccounts,
  );
  return {
    clusterScore,
    fanout: {
      actors: actors.size,
      devices: devices.size,
      ips: ips.size,
      accounts: accounts.size,
    },
  };
}

function resolveSeverity(params: {
  clusterScore: number;
  config: ResolvedGatewayAbuseCorrelationConfig;
}): { severity: CorrelationSeverity; threshold?: number; checkId: string } {
  if (params.clusterScore >= params.config.criticalScore) {
    return {
      severity: "critical",
      threshold: params.config.criticalScore,
      checkId: "gateway.abuse.correlation.critical",
    };
  }
  if (params.clusterScore >= params.config.warningScore) {
    return {
      severity: "warning",
      threshold: params.config.warningScore,
      checkId: "gateway.abuse.correlation.warning",
    };
  }
  return {
    severity: "none",
    threshold: undefined,
    checkId: "gateway.abuse.correlation.none",
  };
}

export function resolveGatewayAbuseCorrelationFingerprint(params: {
  method: string;
  text?: string;
  toolName?: string;
}): string {
  const normalizedText = typeof params.text === "string" ? normalizeText(params.text) : "";
  const normalizedTool = typeof params.toolName === "string" ? normalizeText(params.toolName) : "";
  const seed = [params.method, normalizedTool, normalizedText].filter(Boolean).join("|");
  return toFingerprint(seed || params.method);
}

export function recordGatewayAbuseCorrelationSignal(params: {
  key: string;
  source: CorrelationSource;
  score: number;
  reasonCodes?: string[];
  fingerprint: string;
  correlationConfig?: ResolvedGatewayAbuseCorrelationConfig;
  nowMs?: number;
}): GatewayAbuseCorrelationDecision {
  const nowMs = params.nowMs ?? Date.now();
  const correlationConfig = params.correlationConfig ?? DEFAULT_CORRELATION_CONFIG;
  ensureLoaded();

  if (correlationConfig.mode === "off") {
    return {
      observed: false,
      mode: correlationConfig.mode,
      severity: "none",
      clusterId: `corr_${params.fingerprint}`,
      clusterScore: 0,
      threshold: undefined,
      checkId: "gateway.abuse.correlation.none",
      fingerprint: params.fingerprint,
      fanout: { actors: 0, devices: 0, ips: 0, accounts: 0 },
      reasonCodes: params.reasonCodes ?? [],
    };
  }

  pruneGlobal(nowMs, correlationConfig.windowMs);
  const cluster =
    clustersByFingerprint.get(params.fingerprint) ??
    (() => {
      const created: CorrelationCluster = {
        clusterId: `corr_${params.fingerprint}`,
        fingerprint: params.fingerprint,
        updatedAtMs: nowMs,
        signals: [],
      };
      clustersByFingerprint.set(params.fingerprint, created);
      return created;
    })();

  cluster.signals.push({
    ts: nowMs,
    source: params.source,
    score: params.score,
    reasonCodes: params.reasonCodes ?? [],
    tuple: parseGatewayAbuseTupleKey(params.key),
    weight: resolveSignalWeight({
      source: params.source,
      score: params.score,
    }),
  });
  pruneCluster(cluster, nowMs, correlationConfig.windowMs);

  const { clusterScore, fanout } = computeClusterScore({
    cluster,
    nowMs,
    decayHalfLifeMs: correlationConfig.decayHalfLifeMs,
  });
  const severity = resolveSeverity({ clusterScore, config: correlationConfig });
  schedulePersist(nowMs);

  return {
    observed: severity.severity !== "none",
    mode: correlationConfig.mode,
    severity: severity.severity,
    clusterId: cluster.clusterId,
    clusterScore,
    threshold: severity.threshold,
    checkId: severity.checkId,
    fingerprint: cluster.fingerprint,
    fanout,
    reasonCodes: params.reasonCodes ?? [],
  };
}

export function getGatewayAbuseCorrelationSnapshot(): CorrelationPersisted {
  ensureLoaded();
  return serializeState(Date.now());
}

export const __testing = {
  resetGatewayAbuseCorrelationState() {
    clustersByFingerprint.clear();
    loaded = false;
    if (persistTimer) {
      clearTimeout(persistTimer);
      persistTimer = undefined;
    }
    persistInFlight = false;
    persistQueued = false;
  },
};
