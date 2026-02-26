import type { IncomingMessage } from "node:http";
import type { GatewayAbuseMode } from "../config/config.js";
import type { ResolvedGatewayAbuseQuotaConfig } from "./abuse-config.js";
import { resolveClientIp } from "./net.js";
import type { GatewayClient } from "./server-methods/types.js";

const TARGET_RPC_METHODS = new Set(["chat.send", "send", "node.invoke"]);

type WindowBucket = {
  count: number;
  windowStartMs: number;
};

type QuotaBucket = {
  burst: WindowBucket;
  sustained: WindowBucket;
};

const quotaBuckets = new Map<string, QuotaBucket>();

export type GatewayAbuseQuotaDecision = {
  allowed: boolean;
  observed: boolean;
  enforced: boolean;
  retryAfterMs: number;
  mode: GatewayAbuseMode;
  key: string;
  scope: "burst" | "sustained" | "multiple" | "none";
  limit?: number;
  windowMs?: number;
};

const DEFAULT_QUOTA_CONFIG: ResolvedGatewayAbuseQuotaConfig = {
  mode: "off",
  burstLimit: 20,
  burstWindowMs: 10_000,
  sustainedLimit: 120,
  sustainedWindowMs: 60_000,
};

function normalizePart(value: unknown, fallback: string): string {
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : fallback;
}

function ensureWindow(bucket: WindowBucket, windowMs: number, nowMs: number): void {
  if (nowMs - bucket.windowStartMs >= windowMs) {
    bucket.windowStartMs = nowMs;
    bucket.count = 0;
  }
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function isGatewayAbuseQuotaRpcMethod(method: string): boolean {
  return TARGET_RPC_METHODS.has(method);
}

export function resolveGatewayAbuseQuotaRpcKey(params: {
  method: string;
  client: GatewayClient | null;
  requestParams?: Record<string, unknown>;
}): string {
  const requestParams = params.requestParams ?? {};
  const actorId = normalizePart(params.client?.connect?.client?.id, "unknown-actor");
  const deviceId = normalizePart(params.client?.connect?.device?.id, "unknown-device");
  const clientIp = normalizePart(params.client?.clientIp, "unknown-ip");
  const sessionKey = normalizePart(requestParams.sessionKey, "none");
  const channel = normalizePart(requestParams.channel, "none");
  const accountId = normalizePart(requestParams.accountId, "none");
  return [
    `method=${normalizePart(params.method, "unknown-method")}`,
    `actor=${actorId}`,
    `device=${deviceId}`,
    `ip=${clientIp}`,
    `session=${sessionKey}`,
    `channel=${channel}`,
    `account=${accountId}`,
  ].join("|");
}

export function resolveGatewayAbuseQuotaHttpKey(params: {
  method: string;
  req: IncomingMessage;
  trustedProxies?: string[];
  allowRealIpFallback?: boolean;
  actorId?: string;
  deviceId?: string;
  channel?: string;
  accountId?: string;
  sessionKey?: string;
}): string {
  const clientIp =
    resolveClientIp({
      remoteAddr: params.req.socket?.remoteAddress ?? "",
      forwardedFor: headerValue(params.req.headers?.["x-forwarded-for"]),
      realIp: headerValue(params.req.headers?.["x-real-ip"]),
      trustedProxies: params.trustedProxies,
      allowRealIpFallback: params.allowRealIpFallback,
    }) ?? "unknown-ip";

  return [
    `method=${normalizePart(params.method, "unknown-method")}`,
    `actor=${normalizePart(params.actorId, "unknown-actor")}`,
    `device=${normalizePart(params.deviceId, "none")}`,
    `ip=${normalizePart(clientIp, "unknown-ip")}`,
    `session=${normalizePart(params.sessionKey, "none")}`,
    `channel=${normalizePart(params.channel, "none")}`,
    `account=${normalizePart(params.accountId, "none")}`,
  ].join("|");
}

export function consumeGatewayAbuseQuota(params: {
  key: string;
  quotaConfig?: ResolvedGatewayAbuseQuotaConfig;
  nowMs?: number;
}): GatewayAbuseQuotaDecision {
  const nowMs = params.nowMs ?? Date.now();
  const quotaConfig = params.quotaConfig ?? DEFAULT_QUOTA_CONFIG;
  const mode = quotaConfig.mode;

  if (mode === "off") {
    return {
      allowed: true,
      observed: false,
      enforced: false,
      retryAfterMs: 0,
      mode,
      key: params.key,
      scope: "none",
    };
  }

  const existing =
    quotaBuckets.get(params.key) ??
    (() => {
      const created: QuotaBucket = {
        burst: { count: 0, windowStartMs: nowMs },
        sustained: { count: 0, windowStartMs: nowMs },
      };
      quotaBuckets.set(params.key, created);
      return created;
    })();

  ensureWindow(existing.burst, quotaConfig.burstWindowMs, nowMs);
  ensureWindow(existing.sustained, quotaConfig.sustainedWindowMs, nowMs);

  const burstExceeded = existing.burst.count >= quotaConfig.burstLimit;
  const sustainedExceeded = existing.sustained.count >= quotaConfig.sustainedLimit;

  if (burstExceeded || sustainedExceeded) {
    const burstRetryMs = burstExceeded
      ? Math.max(0, existing.burst.windowStartMs + quotaConfig.burstWindowMs - nowMs)
      : 0;
    const sustainedRetryMs = sustainedExceeded
      ? Math.max(0, existing.sustained.windowStartMs + quotaConfig.sustainedWindowMs - nowMs)
      : 0;
    const scope =
      burstExceeded && sustainedExceeded ? "multiple" : burstExceeded ? "burst" : "sustained";
    const retryAfterMs = Math.max(burstRetryMs, sustainedRetryMs);

    const limit =
      scope === "sustained"
        ? quotaConfig.sustainedLimit
        : scope === "burst"
          ? quotaConfig.burstLimit
          : undefined;
    const windowMs =
      scope === "sustained"
        ? quotaConfig.sustainedWindowMs
        : scope === "burst"
          ? quotaConfig.burstWindowMs
          : undefined;

    return {
      allowed: mode !== "enforce",
      observed: true,
      enforced: mode === "enforce",
      retryAfterMs,
      mode,
      key: params.key,
      scope,
      limit,
      windowMs,
    };
  }

  existing.burst.count += 1;
  existing.sustained.count += 1;

  return {
    allowed: true,
    observed: false,
    enforced: false,
    retryAfterMs: 0,
    mode,
    key: params.key,
    scope: "none",
  };
}

export const __testing = {
  resetGatewayAbuseQuotaState() {
    quotaBuckets.clear();
  },
};
