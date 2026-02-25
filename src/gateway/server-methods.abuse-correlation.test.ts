import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __testing as anomalyTesting } from "./abuse-anomaly.js";
import type { ResolvedGatewayAbuseCorrelationConfig } from "./abuse-config.js";
import { __testing as correlationTesting } from "./abuse-correlation.js";
import { __testing as quotaTesting } from "./abuse-quota.js";
import { handleGatewayRequest } from "./server-methods.js";
import type { GatewayRequestHandler } from "./server-methods/types.js";

const noWebchat = () => false;

describe("gateway abuse correlation in RPC dispatcher", () => {
  beforeEach(() => {
    correlationTesting.resetGatewayAbuseCorrelationState();
    anomalyTesting.resetGatewayAbuseAnomalyState();
    quotaTesting.resetGatewayAbuseQuotaState();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-02-25T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    correlationTesting.resetGatewayAbuseCorrelationState();
    anomalyTesting.resetGatewayAbuseAnomalyState();
    quotaTesting.resetGatewayAbuseQuotaState();
  });

  function buildContext(logWarn = vi.fn()) {
    return {
      logGateway: {
        warn: logWarn,
      },
    } as unknown as Parameters<typeof handleGatewayRequest>[0]["context"];
  }

  function buildClient(params: { actor: string; device: string; ip: string }) {
    return {
      connect: {
        role: "operator",
        scopes: ["operator.admin"],
        client: {
          id: params.actor,
          version: "1.0.0",
          platform: "darwin",
          mode: "ui",
        },
        minProtocol: 1,
        maxProtocol: 1,
      },
      connId: `conn-${params.actor}`,
      clientIp: params.ip,
    } as Parameters<typeof handleGatewayRequest>[0]["client"];
  }

  async function runRequest(params: {
    client: Parameters<typeof handleGatewayRequest>[0]["client"];
    context: Parameters<typeof handleGatewayRequest>[0]["context"];
    correlationConfig: ResolvedGatewayAbuseCorrelationConfig;
    handler: GatewayRequestHandler;
  }) {
    const respond = vi.fn();
    await handleGatewayRequest({
      req: {
        type: "req",
        id: "req-correlation",
        method: "send",
        params: {
          to: "user-1",
          idempotencyKey: "idem-1",
          message: "Please summarize this project update.",
        },
      },
      respond,
      client: params.client,
      isWebchatConnect: noWebchat,
      context: params.context,
      extraHandlers: {
        send: params.handler,
      },
      correlationConfig: params.correlationConfig,
    });
    return respond;
  }

  it("emits critical correlation observations for cross-identity fan-out", async () => {
    const logWarn = vi.fn();
    const context = buildContext(logWarn);
    const handlerCalls = vi.fn();
    const handler: GatewayRequestHandler = (opts) => {
      handlerCalls(opts);
      opts.respond(true, undefined, undefined);
    };
    const correlationConfig: ResolvedGatewayAbuseCorrelationConfig = {
      mode: "observe",
      windowMs: 900_000,
      decayHalfLifeMs: 300_000,
      warningScore: 20,
      criticalScore: 35,
    };

    const firstResponse = await runRequest({
      client: buildClient({ actor: "actor-a", device: "dev-a", ip: "10.0.0.1" }),
      context,
      correlationConfig,
      handler,
    });
    expect(firstResponse).toHaveBeenCalledWith(true, undefined, undefined);

    const secondResponse = await runRequest({
      client: buildClient({ actor: "actor-b", device: "dev-b", ip: "10.0.0.2" }),
      context,
      correlationConfig,
      handler,
    });
    expect(secondResponse).toHaveBeenCalledWith(true, undefined, undefined);

    expect(handlerCalls).toHaveBeenCalledTimes(2);
    expect(logWarn).toHaveBeenCalledWith(
      expect.stringContaining("gateway abuse correlation observed"),
    );
    expect(logWarn).toHaveBeenCalledWith(expect.stringContaining("severity=critical"));
  });
});
