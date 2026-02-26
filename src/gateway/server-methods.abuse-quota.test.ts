import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedGatewayAbuseQuotaConfig } from "./abuse-config.js";
import { __testing as quotaTesting } from "./abuse-quota.js";
import { handleGatewayRequest } from "./server-methods.js";
import type { GatewayRequestHandler } from "./server-methods/types.js";

const noWebchat = () => false;

describe("gateway abuse quota in RPC dispatcher", () => {
  beforeEach(() => {
    quotaTesting.resetGatewayAbuseQuotaState();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-02-25T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    quotaTesting.resetGatewayAbuseQuotaState();
  });

  function buildContext(logWarn = vi.fn()) {
    return {
      logGateway: {
        warn: logWarn,
      },
    } as unknown as Parameters<typeof handleGatewayRequest>[0]["context"];
  }

  function buildClient() {
    return {
      connect: {
        role: "operator",
        scopes: ["operator.admin"],
        client: {
          id: "openclaw-control-ui",
          version: "1.0.0",
          platform: "darwin",
          mode: "ui",
        },
        minProtocol: 1,
        maxProtocol: 1,
      },
      connId: "conn-1",
      clientIp: "10.0.0.5",
    } as Parameters<typeof handleGatewayRequest>[0]["client"];
  }

  async function runRequest(params: {
    method: string;
    requestParams?: Record<string, unknown>;
    context: Parameters<typeof handleGatewayRequest>[0]["context"];
    client: Parameters<typeof handleGatewayRequest>[0]["client"];
    handler: GatewayRequestHandler;
    quotaConfig: ResolvedGatewayAbuseQuotaConfig;
  }) {
    const respond = vi.fn();
    await handleGatewayRequest({
      req: {
        type: "req",
        id: crypto.randomUUID(),
        method: params.method,
        params: params.requestParams,
      },
      respond,
      client: params.client,
      isWebchatConnect: noWebchat,
      context: params.context,
      extraHandlers: {
        [params.method]: params.handler,
      },
      abuseQuotaConfig: params.quotaConfig,
    });
    return respond;
  }

  it("blocks over-limit chat.send with UNAVAILABLE + retry metadata", async () => {
    const handlerCalls = vi.fn();
    const handler: GatewayRequestHandler = (opts) => {
      handlerCalls(opts);
      opts.respond(true, undefined, undefined);
    };
    const context = buildContext();
    const client = buildClient();

    const quotaConfig: ResolvedGatewayAbuseQuotaConfig = {
      mode: "enforce",
      burstLimit: 1,
      burstWindowMs: 60_000,
      sustainedLimit: 100,
      sustainedWindowMs: 600_000,
    };

    await runRequest({
      method: "chat.send",
      requestParams: { sessionKey: "agent:main:main" },
      context,
      client,
      handler,
      quotaConfig,
    });

    const blocked = await runRequest({
      method: "chat.send",
      requestParams: { sessionKey: "agent:main:main" },
      context,
      client,
      handler,
      quotaConfig,
    });

    expect(handlerCalls).toHaveBeenCalledTimes(1);
    expect(blocked).toHaveBeenCalledWith(
      false,
      undefined,
      expect.objectContaining({
        code: "UNAVAILABLE",
        retryable: true,
      }),
    );
  });

  it("observe mode logs but does not block", async () => {
    const logWarn = vi.fn();
    const context = buildContext(logWarn);
    const client = buildClient();
    const handlerCalls = vi.fn();
    const handler: GatewayRequestHandler = (opts) => {
      handlerCalls(opts);
      opts.respond(true, undefined, undefined);
    };

    const quotaConfig: ResolvedGatewayAbuseQuotaConfig = {
      mode: "observe",
      burstLimit: 1,
      burstWindowMs: 60_000,
      sustainedLimit: 100,
      sustainedWindowMs: 600_000,
    };

    await runRequest({
      method: "send",
      requestParams: { accountId: "primary", channel: "telegram" },
      context,
      client,
      handler,
      quotaConfig,
    });
    const second = await runRequest({
      method: "send",
      requestParams: { accountId: "primary", channel: "telegram" },
      context,
      client,
      handler,
      quotaConfig,
    });

    expect(second).toHaveBeenCalledWith(true, undefined, undefined);
    expect(handlerCalls).toHaveBeenCalledTimes(2);
    expect(logWarn).toHaveBeenCalled();
  });
});
