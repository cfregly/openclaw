import { createHash } from "node:crypto";
import type { GatewayAbuseMode } from "../config/config.js";
import type { ResolvedGatewayAbuseAnomalyConfig } from "./abuse-config.js";

const TARGET_RPC_METHODS = new Set(["chat.send", "send", "node.invoke"]);
const FINGERPRINT_RETENTION_MS = 15 * 60 * 1000;
const STATE_STALE_MS = 60 * 60 * 1000;
const MAX_STATE_KEYS = 5_000;
const PRUNE_INTERVAL_MS = 30_000;

type AnomalyDetector = {
  reason: string;
  score: number;
  pattern: RegExp;
};

const DETECTORS: AnomalyDetector[] = [
  {
    reason: "prompt_exfiltration_terms",
    score: 30,
    pattern:
      /\b(system prompt|hidden instructions|developer instructions|internal prompt|reveal prompt)\b/i,
  },
  {
    reason: "secret_exfiltration_terms",
    score: 30,
    pattern: /\b(api keys?|tokens?|secrets?|credentials?|passwords?|private keys?|ssh keys?)\b/i,
  },
  {
    reason: "policy_bypass_terms",
    score: 20,
    pattern: /\b(ignore previous|bypass|jailbreak|disable safety|override policy)\b/i,
  },
  {
    reason: "capability_enumeration_terms",
    score: 20,
    pattern: /\b(list tools|available tools|function schema|plugin list|enumerate tools)\b/i,
  },
  {
    reason: "bulk_extraction_terms",
    score: 20,
    pattern: /\b(exfiltrat|dump|export all|entire history|all conversations|bulk extract)\b/i,
  },
];

type FingerprintState = {
  count: number;
  lastSeenMs: number;
};

type ActorAnomalyState = {
  lastSeenMs: number;
  lastFingerprint?: string;
  blockedUntilMs: number;
  fingerprints: Map<string, FingerprintState>;
};

const stateByKey = new Map<string, ActorAnomalyState>();
let lastPruneMs = 0;

type AnomalyAction = "allow" | "warn" | "throttle" | "block";

export type GatewayAbuseAnomalyInput = {
  text?: string;
  toolName?: string;
};

export type GatewayAbuseAnomalyDecision = {
  allowed: boolean;
  observed: boolean;
  enforced: boolean;
  mode: GatewayAbuseMode;
  action: AnomalyAction;
  retryAfterMs: number;
  score: number;
  threshold?: number;
  key: string;
  fingerprint?: string;
  reasonCodes: string[];
  checkId: string;
};

const DEFAULT_ANOMALY_CONFIG: ResolvedGatewayAbuseAnomalyConfig = {
  mode: "off",
  warningThreshold: 30,
  throttleThreshold: 60,
  blockThreshold: 90,
  blockDurationMs: 300_000,
};

function normalizeText(input: string): string {
  return input.replace(/\s+/g, " ").trim().toLowerCase();
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).toSorted(([a], [b]) =>
    a.localeCompare(b),
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

function stableStringifyFallback(value: unknown): string {
  try {
    return stableStringify(value);
  } catch {
    if (value === null || value === undefined) {
      return `${value}`;
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
      return `${value}`;
    }
    return Object.prototype.toString.call(value);
  }
}

function fingerprintFromInput(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

function resolveCheckId(action: AnomalyAction): string {
  if (action === "warn") {
    return "gateway.abuse.anomaly.warning";
  }
  if (action === "throttle") {
    return "gateway.abuse.anomaly.throttle";
  }
  if (action === "block") {
    return "gateway.abuse.anomaly.block";
  }
  return "gateway.abuse.anomaly.allow";
}

function resolveState(key: string, nowMs: number): ActorAnomalyState {
  pruneState(nowMs);
  const current = stateByKey.get(key);
  if (current) {
    return current;
  }
  const created: ActorAnomalyState = {
    lastSeenMs: nowMs,
    lastFingerprint: undefined,
    blockedUntilMs: 0,
    fingerprints: new Map<string, FingerprintState>(),
  };
  stateByKey.set(key, created);
  return created;
}

function pruneState(nowMs: number): void {
  const shouldPrune = nowMs - lastPruneMs >= PRUNE_INTERVAL_MS || stateByKey.size > MAX_STATE_KEYS;
  if (!shouldPrune) {
    return;
  }
  lastPruneMs = nowMs;

  for (const [key, value] of stateByKey) {
    if (nowMs - value.lastSeenMs > STATE_STALE_MS) {
      stateByKey.delete(key);
      continue;
    }
    for (const [fingerprint, entry] of value.fingerprints) {
      if (nowMs - entry.lastSeenMs > FINGERPRINT_RETENTION_MS) {
        value.fingerprints.delete(fingerprint);
      }
    }
  }

  if (stateByKey.size <= MAX_STATE_KEYS) {
    return;
  }

  const overflow = stateByKey.size - MAX_STATE_KEYS;
  const oldest = [...stateByKey.entries()]
    .toSorted(([, a], [, b]) => a.lastSeenMs - b.lastSeenMs)
    .slice(0, overflow);
  for (const [key] of oldest) {
    stateByKey.delete(key);
  }
}

function resolveThrottleRetryAfterMs(blockDurationMs: number): number {
  return Math.max(5_000, Math.min(60_000, Math.floor(blockDurationMs / 6)));
}

function scoreAnomaly(params: {
  normalizedText: string;
  toolName?: string;
  state: ActorAnomalyState;
  nowMs: number;
}): {
  score: number;
  fingerprint: string;
  reasonCodes: string[];
} {
  const reasonCodes: string[] = [];
  let score = 0;

  for (const detector of DETECTORS) {
    if (detector.pattern.test(params.normalizedText)) {
      score += detector.score;
      reasonCodes.push(detector.reason);
    }
  }

  if (params.normalizedText.length > 1200 && reasonCodes.length > 0) {
    score += 10;
    reasonCodes.push("long_extraction_payload");
  }

  if (typeof params.toolName === "string" && params.toolName.trim().length > 0) {
    const normalizedTool = params.toolName.trim().toLowerCase();
    if (
      /(exec|shell|process|filesystem|network|env|credential|token|secret)/.test(normalizedTool)
    ) {
      score += 10;
      reasonCodes.push("high_risk_tool_command");
    }
  }

  const fingerprint = fingerprintFromInput(params.normalizedText);
  const existingFingerprint = params.state.fingerprints.get(fingerprint);
  const nextCount = (existingFingerprint?.count ?? 0) + 1;
  params.state.fingerprints.set(fingerprint, { count: nextCount, lastSeenMs: params.nowMs });
  if (nextCount > 1) {
    score += Math.min(40, 20 * (nextCount - 1));
    reasonCodes.push("template_reuse");
  }

  if (
    params.state.lastFingerprint &&
    params.state.lastFingerprint === fingerprint &&
    params.nowMs - params.state.lastSeenMs <= 5_000
  ) {
    score += 15;
    reasonCodes.push("rapid_repeat");
  }

  params.state.lastFingerprint = fingerprint;
  params.state.lastSeenMs = params.nowMs;
  return { score, fingerprint, reasonCodes };
}

function resolveAction(
  score: number,
  config: ResolvedGatewayAbuseAnomalyConfig,
): { action: AnomalyAction; threshold?: number } {
  if (score >= config.blockThreshold) {
    return { action: "block", threshold: config.blockThreshold };
  }
  if (score >= config.throttleThreshold) {
    return { action: "throttle", threshold: config.throttleThreshold };
  }
  if (score >= config.warningThreshold) {
    return { action: "warn", threshold: config.warningThreshold };
  }
  return { action: "allow", threshold: undefined };
}

function denyFromAction(action: AnomalyAction, mode: GatewayAbuseMode): boolean {
  if (mode !== "enforce") {
    return false;
  }
  return action === "throttle" || action === "block";
}

function buildNodeInvokeText(command: string, params: unknown): string {
  const serializedParams = stableStringifyFallback(params);
  return `command=${command}\nparams=${serializedParams}`.slice(0, 4000);
}

export function isGatewayAbuseAnomalyRpcMethod(method: string): boolean {
  return TARGET_RPC_METHODS.has(method);
}

export function resolveGatewayAbuseAnomalyRpcInput(params: {
  method: string;
  requestParams?: Record<string, unknown>;
}): GatewayAbuseAnomalyInput | undefined {
  const requestParams = params.requestParams ?? {};
  if (params.method === "chat.send") {
    const text = typeof requestParams.message === "string" ? requestParams.message : undefined;
    return text ? { text } : undefined;
  }
  if (params.method === "send") {
    const text = typeof requestParams.message === "string" ? requestParams.message : undefined;
    return text ? { text } : undefined;
  }
  if (params.method === "node.invoke") {
    const command = typeof requestParams.command === "string" ? requestParams.command.trim() : "";
    if (!command) {
      return undefined;
    }
    return {
      text: buildNodeInvokeText(command, requestParams.params),
      toolName: command,
    };
  }
  return undefined;
}

export function consumeGatewayAbuseAnomaly(params: {
  key: string;
  input: GatewayAbuseAnomalyInput;
  anomalyConfig?: ResolvedGatewayAbuseAnomalyConfig;
  nowMs?: number;
}): GatewayAbuseAnomalyDecision {
  const nowMs = params.nowMs ?? Date.now();
  const anomalyConfig = params.anomalyConfig ?? DEFAULT_ANOMALY_CONFIG;
  const mode = anomalyConfig.mode;
  const text = typeof params.input.text === "string" ? params.input.text : "";
  const normalizedText = normalizeText(text);
  const hasSignalInput = normalizedText.length > 0 || Boolean(params.input.toolName);

  if (mode === "off" || !hasSignalInput) {
    return {
      allowed: true,
      observed: false,
      enforced: false,
      mode,
      action: "allow",
      retryAfterMs: 0,
      score: 0,
      threshold: undefined,
      key: params.key,
      fingerprint: undefined,
      reasonCodes: [],
      checkId: resolveCheckId("allow"),
    };
  }

  const state = resolveState(params.key, nowMs);
  if (state.blockedUntilMs > nowMs && mode === "enforce") {
    const retryAfterMs = Math.max(0, state.blockedUntilMs - nowMs);
    return {
      allowed: false,
      observed: true,
      enforced: true,
      mode,
      action: "block",
      retryAfterMs,
      score: anomalyConfig.blockThreshold,
      threshold: anomalyConfig.blockThreshold,
      key: params.key,
      fingerprint: state.lastFingerprint,
      reasonCodes: ["temporary_block_active"],
      checkId: resolveCheckId("block"),
    };
  }

  const scored = scoreAnomaly({
    normalizedText,
    toolName: params.input.toolName,
    state,
    nowMs,
  });
  const action = resolveAction(scored.score, anomalyConfig);
  const deny = denyFromAction(action.action, mode);

  if (deny && action.action === "block") {
    state.blockedUntilMs = nowMs + anomalyConfig.blockDurationMs;
  }

  const retryAfterMs =
    action.action === "block"
      ? anomalyConfig.blockDurationMs
      : action.action === "throttle"
        ? resolveThrottleRetryAfterMs(anomalyConfig.blockDurationMs)
        : 0;

  return {
    allowed: !deny,
    observed: action.action !== "allow",
    enforced: deny,
    mode,
    action: action.action,
    retryAfterMs,
    score: scored.score,
    threshold: action.threshold,
    key: params.key,
    fingerprint: scored.fingerprint,
    reasonCodes: scored.reasonCodes,
    checkId: resolveCheckId(action.action),
  };
}

export const __testing = {
  resetGatewayAbuseAnomalyState() {
    stateByKey.clear();
    lastPruneMs = 0;
  },
};
