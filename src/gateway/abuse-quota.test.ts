import { afterEach, describe, expect, it } from "vitest";
import {
  __testing,
  consumeGatewayAbuseQuota,
  isGatewayAbuseQuotaRpcMethod,
  resolveGatewayAbuseQuotaHttpKey,
  resolveGatewayAbuseQuotaRpcKey,
} from "./abuse-quota.js";

afterEach(() => {
  __testing.resetGatewayAbuseQuotaState();
});

describe("gateway abuse quota", () => {
  it("targets only abuse-sensitive RPC methods", () => {
    expect(isGatewayAbuseQuotaRpcMethod("chat.send")).toBe(true);
    expect(isGatewayAbuseQuotaRpcMethod("send")).toBe(true);
    expect(isGatewayAbuseQuotaRpcMethod("node.invoke")).toBe(true);
    expect(isGatewayAbuseQuotaRpcMethod("health")).toBe(false);
  });

  it("enforces burst limits when mode=enforce", () => {
    const key = resolveGatewayAbuseQuotaRpcKey({
      method: "chat.send",
      client: {
        clientIp: "127.0.0.1",
        connect: {
          minProtocol: 1,
          maxProtocol: 1,
          role: "operator",
          scopes: ["operator.admin"],
          client: {
            id: "openclaw-control-ui",
            version: "1.0.0",
            platform: "darwin",
            mode: "ui",
          },
        },
      },
      requestParams: { sessionKey: "agent:main:main" },
    });

    const quotaConfig = {
      mode: "enforce" as const,
      burstLimit: 1,
      burstWindowMs: 60_000,
      sustainedLimit: 100,
      sustainedWindowMs: 600_000,
    };

    const first = consumeGatewayAbuseQuota({ key, quotaConfig, nowMs: 1000 });
    expect(first.allowed).toBe(true);

    const second = consumeGatewayAbuseQuota({ key, quotaConfig, nowMs: 2000 });
    expect(second.allowed).toBe(false);
    expect(second.enforced).toBe(true);
    expect(second.scope).toBe("burst");
    expect(second.retryAfterMs).toBeGreaterThan(0);
  });

  it("reports would-block in observe mode without denying", () => {
    const key =
      "method=chat.send|actor=a|device=d|ip=1.2.3.4|session=none|channel=none|account=none";
    const quotaConfig = {
      mode: "observe" as const,
      burstLimit: 1,
      burstWindowMs: 60_000,
      sustainedLimit: 100,
      sustainedWindowMs: 600_000,
    };

    const first = consumeGatewayAbuseQuota({ key, quotaConfig, nowMs: 1000 });
    expect(first.allowed).toBe(true);

    const second = consumeGatewayAbuseQuota({ key, quotaConfig, nowMs: 2000 });
    expect(second.allowed).toBe(true);
    expect(second.observed).toBe(true);
    expect(second.enforced).toBe(false);
  });

  it("builds HTTP keys using trusted proxy client IP resolution", () => {
    const req = {
      socket: { remoteAddress: "127.0.0.1" },
      headers: {
        "x-forwarded-for": "203.0.113.10",
      },
    } as unknown as import("node:http").IncomingMessage;

    const key = resolveGatewayAbuseQuotaHttpKey({
      method: "chat.send",
      req,
      trustedProxies: ["127.0.0.1"],
      actorId: "user:alice",
      sessionKey: "agent:main:openai:alice",
    });

    expect(key).toContain("method=chat.send");
    expect(key).toContain("actor=user:alice");
    expect(key).toContain("ip=203.0.113.10");
  });

  it("escapes tuple delimiters in computed keys", () => {
    const req = {
      socket: { remoteAddress: "127.0.0.1" },
      headers: {
        "x-forwarded-for": "203.0.113.99",
      },
    } as unknown as import("node:http").IncomingMessage;

    const key = resolveGatewayAbuseQuotaHttpKey({
      method: "chat.send",
      req,
      trustedProxies: ["127.0.0.1"],
      actorId: "user|alice=admin%",
      sessionKey: "agent:main:user=alice|prod",
    });

    expect(key).toContain("actor=user%7Calice%3Dadmin%25");
    expect(key).toContain("session=agent:main:user%3Dalice%7Cprod");
    expect(key).not.toContain("actor=user|alice=admin%");
  });
});
