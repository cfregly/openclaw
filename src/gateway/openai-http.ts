import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createDefaultDeps } from "../cli/deps.js";
import { agentCommand } from "../commands/agent.js";
import { emitAgentEvent, onAgentEvent, registerAgentRunContext } from "../infra/agent-events.js";
import { logWarn } from "../logger.js";
import { defaultRuntime } from "../runtime.js";
import { consumeGatewayAbuseAnomaly } from "./abuse-anomaly.js";
import { recordGatewayAbuseAuditEvent } from "./abuse-audit-ledger.js";
import type {
  ResolvedGatewayAbuseAnomalyConfig,
  ResolvedGatewayAbuseAuditLedgerConfig,
  ResolvedGatewayAbuseCorrelationConfig,
  ResolvedGatewayAbuseIncidentConfig,
  ResolvedGatewayAbuseQuotaConfig,
} from "./abuse-config.js";
import {
  recordGatewayAbuseCorrelationSignal,
  resolveGatewayAbuseCorrelationFingerprint,
} from "./abuse-correlation.js";
import {
  getActiveGatewayAbuseContainment,
  recordGatewayAbuseIncidentSignal,
} from "./abuse-incident.js";
import { consumeGatewayAbuseQuota, resolveGatewayAbuseQuotaHttpKey } from "./abuse-quota.js";
import { resolveAssistantStreamDeltaText } from "./agent-event-assistant-text.js";
import {
  buildAgentMessageFromConversationEntries,
  type ConversationEntry,
} from "./agent-prompt.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { sendJson, sendRateLimited, setSseHeaders, writeDone } from "./http-common.js";
import { handleGatewayPostJsonEndpoint } from "./http-endpoint-helpers.js";
import { resolveAgentIdForRequest, resolveSessionKey } from "./http-utils.js";

type OpenAiHttpOptions = {
  auth: ResolvedGatewayAuth;
  maxBodyBytes?: number;
  trustedProxies?: string[];
  allowRealIpFallback?: boolean;
  rateLimiter?: AuthRateLimiter;
  abuseQuotaConfig?: ResolvedGatewayAbuseQuotaConfig;
  anomalyConfig?: ResolvedGatewayAbuseAnomalyConfig;
  correlationConfig?: ResolvedGatewayAbuseCorrelationConfig;
  incidentConfig?: ResolvedGatewayAbuseIncidentConfig;
  auditLedgerConfig?: ResolvedGatewayAbuseAuditLedgerConfig;
};

type OpenAiChatMessage = {
  role?: unknown;
  content?: unknown;
  name?: unknown;
};

type OpenAiChatCompletionRequest = {
  model?: unknown;
  stream?: unknown;
  messages?: unknown;
  user?: unknown;
};

function writeSse(res: ServerResponse, data: unknown) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function buildAgentCommandInput(params: {
  prompt: { message: string; extraSystemPrompt?: string };
  sessionKey: string;
  runId: string;
}) {
  return {
    message: params.prompt.message,
    extraSystemPrompt: params.prompt.extraSystemPrompt,
    sessionKey: params.sessionKey,
    runId: params.runId,
    deliver: false as const,
    messageChannel: "webchat" as const,
    bestEffortDeliver: false as const,
  };
}

function writeAssistantRoleChunk(res: ServerResponse, params: { runId: string; model: string }) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [{ index: 0, delta: { role: "assistant" } }],
  });
}

function writeAssistantContentChunk(
  res: ServerResponse,
  params: { runId: string; model: string; content: string; finishReason: "stop" | null },
) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [
      {
        index: 0,
        delta: { content: params.content },
        finish_reason: params.finishReason,
      },
    ],
  });
}

function asMessages(val: unknown): OpenAiChatMessage[] {
  return Array.isArray(val) ? (val as OpenAiChatMessage[]) : [];
}

function extractTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (!part || typeof part !== "object") {
          return "";
        }
        const type = (part as { type?: unknown }).type;
        const text = (part as { text?: unknown }).text;
        const inputText = (part as { input_text?: unknown }).input_text;
        if (type === "text" && typeof text === "string") {
          return text;
        }
        if (type === "input_text" && typeof text === "string") {
          return text;
        }
        if (typeof inputText === "string") {
          return inputText;
        }
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

function buildAgentPrompt(messagesUnknown: unknown): {
  message: string;
  extraSystemPrompt?: string;
} {
  const messages = asMessages(messagesUnknown);

  const systemParts: string[] = [];
  const conversationEntries: ConversationEntry[] = [];

  for (const msg of messages) {
    if (!msg || typeof msg !== "object") {
      continue;
    }
    const role = typeof msg.role === "string" ? msg.role.trim() : "";
    const content = extractTextContent(msg.content).trim();
    if (!role || !content) {
      continue;
    }
    if (role === "system" || role === "developer") {
      systemParts.push(content);
      continue;
    }

    const normalizedRole = role === "function" ? "tool" : role;
    if (normalizedRole !== "user" && normalizedRole !== "assistant" && normalizedRole !== "tool") {
      continue;
    }

    const name = typeof msg.name === "string" ? msg.name.trim() : "";
    const sender =
      normalizedRole === "assistant"
        ? "Assistant"
        : normalizedRole === "user"
          ? "User"
          : name
            ? `Tool:${name}`
            : "Tool";

    conversationEntries.push({
      role: normalizedRole,
      entry: { sender, body: content },
    });
  }

  const message = buildAgentMessageFromConversationEntries(conversationEntries);

  return {
    message,
    extraSystemPrompt: systemParts.length > 0 ? systemParts.join("\n\n") : undefined,
  };
}

function resolveOpenAiSessionKey(params: {
  req: IncomingMessage;
  agentId: string;
  user?: string | undefined;
}): string {
  return resolveSessionKey({ ...params, prefix: "openai" });
}

function coerceRequest(val: unknown): OpenAiChatCompletionRequest {
  if (!val || typeof val !== "object") {
    return {};
  }
  return val as OpenAiChatCompletionRequest;
}

function resolveAgentResponseText(result: unknown): string {
  const payloads = (result as { payloads?: Array<{ text?: string }> } | null)?.payloads;
  if (!Array.isArray(payloads) || payloads.length === 0) {
    return "No response from OpenClaw.";
  }
  const content = payloads
    .map((p) => (typeof p.text === "string" ? p.text : ""))
    .filter(Boolean)
    .join("\n\n");
  return content || "No response from OpenClaw.";
}

export async function handleOpenAiHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: OpenAiHttpOptions,
): Promise<boolean> {
  const handled = await handleGatewayPostJsonEndpoint(req, res, {
    pathname: "/v1/chat/completions",
    auth: opts.auth,
    trustedProxies: opts.trustedProxies,
    allowRealIpFallback: opts.allowRealIpFallback,
    rateLimiter: opts.rateLimiter,
    maxBodyBytes: opts.maxBodyBytes ?? 1024 * 1024,
  });
  if (handled === false) {
    return false;
  }
  if (!handled) {
    return true;
  }

  const payload = coerceRequest(handled.body);
  const stream = Boolean(payload.stream);
  const model = typeof payload.model === "string" ? payload.model : "openclaw";
  const user = typeof payload.user === "string" ? payload.user : undefined;

  const agentId = resolveAgentIdForRequest({ req, model });
  const sessionKey = resolveOpenAiSessionKey({ req, agentId, user });
  const prompt = buildAgentPrompt(payload.messages);
  if (!prompt.message) {
    sendJson(res, 400, {
      error: {
        message: "Missing user message in `messages`.",
        type: "invalid_request_error",
      },
    });
    return true;
  }

  const authActorId =
    handled.authResult.user && handled.authResult.user.trim().length > 0
      ? `auth-user:${handled.authResult.user.trim().toLowerCase()}`
      : `auth:${handled.authResult.method ?? "unknown"}`;
  const abuseTupleKey = resolveGatewayAbuseQuotaHttpKey({
    method: "chat.send",
    req,
    trustedProxies: opts.trustedProxies,
    allowRealIpFallback: opts.allowRealIpFallback,
    actorId: authActorId,
  });
  const recordAudit = (params: {
    kind: "request" | "anomaly" | "quota" | "correlation" | "incident" | "containment";
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
  }) => {
    if (!opts.auditLedgerConfig) {
      return;
    }
    recordGatewayAbuseAuditEvent({
      kind: params.kind,
      key: abuseTupleKey,
      method: "chat.send",
      allowed: params.allowed,
      action: params.action,
      checkId: params.checkId,
      severity: params.severity,
      score: params.score,
      fingerprint: params.fingerprint,
      clusterId: params.clusterId,
      incidentId: params.incidentId,
      reasonCodes: params.reasonCodes,
      payload: params.payload,
      auditConfig: opts.auditLedgerConfig,
    });
  };
  if (opts.incidentConfig) {
    const containment = getActiveGatewayAbuseContainment({
      key: abuseTupleKey,
      incidentConfig: opts.incidentConfig,
    });
    if (containment.active) {
      recordAudit({
        kind: "containment",
        allowed: false,
        action: "block",
        checkId: "gateway.abuse.incident.containment",
        severity: "critical",
        incidentId: containment.incidentId,
        reasonCodes: ["active_containment"],
        payload: {
          retryAfterMs: containment.retryAfterMs,
          scope: containment.scopeKey,
        },
      });
      sendRateLimited(
        res,
        containment.retryAfterMs,
        `incident containment active for chat.send; retry after ${Math.ceil(containment.retryAfterMs / 1000)}s`,
      );
      return true;
    }
  }
  const requestCorrelationFingerprint = resolveGatewayAbuseCorrelationFingerprint({
    method: "chat.send",
    text: [prompt.extraSystemPrompt, prompt.message].filter(Boolean).join("\n\n"),
  });
  const recordIncident = (params: {
    source: "anomaly" | "quota" | "correlation";
    severity: "warn" | "critical";
    checkId: string;
    reasonCodes: string[];
    clusterId?: string;
  }) => {
    if (!opts.incidentConfig) {
      return;
    }
    const decision = recordGatewayAbuseIncidentSignal({
      key: abuseTupleKey,
      source: params.source,
      severity: params.severity,
      checkId: params.checkId,
      reasonCodes: params.reasonCodes,
      clusterId: params.clusterId,
      incidentConfig: opts.incidentConfig,
    });
    if (!decision) {
      return;
    }
    recordAudit({
      kind: "incident",
      action: decision.state,
      checkId: params.checkId,
      severity: params.severity,
      incidentId: decision.incidentId,
      reasonCodes: params.reasonCodes,
      payload: {
        source: params.source,
        autoContained: decision.autoContained,
      },
    });
    logWarn(
      `openai-compat: incident signal source=${params.source} incidentId=${decision.incidentId} state=${decision.state} autoContained=${decision.autoContained ? "yes" : "no"}`,
    );
  };
  const recordCorrelation = (params: {
    source: "request" | "quota" | "anomaly";
    score: number;
    reasonCodes: string[];
    fingerprint: string;
  }) => {
    const decision = recordGatewayAbuseCorrelationSignal({
      key: abuseTupleKey,
      source: params.source,
      score: params.score,
      reasonCodes: params.reasonCodes,
      fingerprint: params.fingerprint,
      correlationConfig: opts.correlationConfig,
    });
    if (!decision.observed) {
      return;
    }
    const thresholdLabel = decision.threshold ? String(decision.threshold) : "n/a";
    logWarn(
      `openai-compat: abuse correlation observed severity=${decision.severity} mode=${decision.mode} score=${decision.clusterScore} threshold=${thresholdLabel} checkId=${decision.checkId} clusterId=${decision.clusterId} fingerprint=${decision.fingerprint} fanoutActors=${decision.fanout.actors} fanoutIps=${decision.fanout.ips} fanoutAccounts=${decision.fanout.accounts}`,
    );
    recordIncident({
      source: "correlation",
      severity: decision.severity === "critical" ? "critical" : "warn",
      checkId: decision.checkId,
      reasonCodes: params.reasonCodes,
      clusterId: decision.clusterId,
    });
    recordAudit({
      kind: "correlation",
      allowed: true,
      action: decision.severity,
      checkId: decision.checkId,
      severity: decision.severity === "critical" ? "critical" : "warn",
      score: decision.clusterScore,
      fingerprint: decision.fingerprint,
      clusterId: decision.clusterId,
      reasonCodes: params.reasonCodes,
      payload: {
        fanout: decision.fanout,
        threshold: decision.threshold,
      },
    });
  };
  recordAudit({
    kind: "request",
    allowed: true,
    action: "allow",
    checkId: "gateway.abuse.audit.request",
    fingerprint: requestCorrelationFingerprint,
    reasonCodes: ["method_call"],
    payload: {
      method: "chat.send",
      authMethod: handled.authResult.method,
      authUser: handled.authResult.user,
    },
  });
  recordCorrelation({
    source: "request",
    score: 10,
    reasonCodes: ["method_call"],
    fingerprint: requestCorrelationFingerprint,
  });
  const anomalyDecision = consumeGatewayAbuseAnomaly({
    key: abuseTupleKey,
    input: {
      text: [prompt.extraSystemPrompt, prompt.message].filter(Boolean).join("\n\n"),
    },
    anomalyConfig: opts.anomalyConfig,
  });
  if (anomalyDecision.observed) {
    const thresholdLabel = anomalyDecision.threshold ? String(anomalyDecision.threshold) : "n/a";
    logWarn(
      `openai-compat: abuse anomaly observed mode=${anomalyDecision.mode} action=${anomalyDecision.action} score=${anomalyDecision.score} threshold=${thresholdLabel} checkId=${anomalyDecision.checkId} retryAfterMs=${anomalyDecision.retryAfterMs} fingerprint=${anomalyDecision.fingerprint ?? "none"} reasons=${anomalyDecision.reasonCodes.join(",") || "none"} key=${anomalyDecision.key}`,
    );
    if (anomalyDecision.fingerprint) {
      recordCorrelation({
        source: "anomaly",
        score: anomalyDecision.score,
        reasonCodes: anomalyDecision.reasonCodes,
        fingerprint: anomalyDecision.fingerprint,
      });
    }
    recordIncident({
      source: "anomaly",
      severity: anomalyDecision.action === "warn" ? "warn" : "critical",
      checkId: anomalyDecision.checkId,
      reasonCodes: anomalyDecision.reasonCodes,
    });
    recordAudit({
      kind: "anomaly",
      allowed: anomalyDecision.allowed,
      action: anomalyDecision.action,
      checkId: anomalyDecision.checkId,
      severity: anomalyDecision.action === "warn" ? "warn" : "critical",
      score: anomalyDecision.score,
      fingerprint: anomalyDecision.fingerprint,
      reasonCodes: anomalyDecision.reasonCodes,
      payload: {
        threshold: anomalyDecision.threshold,
        retryAfterMs: anomalyDecision.retryAfterMs,
      },
    });
  }
  if (!anomalyDecision.allowed) {
    sendRateLimited(
      res,
      anomalyDecision.retryAfterMs,
      `anomaly policy triggered for chat.send; retry after ${Math.ceil(anomalyDecision.retryAfterMs / 1000)}s`,
    );
    return true;
  }

  const quotaBudget = consumeGatewayAbuseQuota({
    key: abuseTupleKey,
    quotaConfig: opts.abuseQuotaConfig,
  });
  if (quotaBudget.observed) {
    const windowLabel = quotaBudget.windowMs
      ? `${Math.ceil(quotaBudget.windowMs / 1000)}s`
      : "mixed";
    const limitLabel = quotaBudget.limit ? String(quotaBudget.limit) : "mixed";
    logWarn(
      `openai-compat: abuse quota observed mode=${quotaBudget.mode} scope=${quotaBudget.scope} limit=${limitLabel} window=${windowLabel} retryAfterMs=${quotaBudget.retryAfterMs} key=${quotaBudget.key}`,
    );
    recordCorrelation({
      source: "quota",
      score: quotaBudget.limit ?? 25,
      reasonCodes: [`quota_${quotaBudget.scope}`],
      fingerprint: requestCorrelationFingerprint,
    });
    recordIncident({
      source: "quota",
      severity: quotaBudget.allowed ? "warn" : "critical",
      checkId: "gateway.abuse.quota.observed",
      reasonCodes: [`quota_${quotaBudget.scope}`],
    });
    recordAudit({
      kind: "quota",
      allowed: quotaBudget.allowed,
      action: quotaBudget.allowed ? "observe" : "enforce",
      checkId: "gateway.abuse.quota.observed",
      severity: quotaBudget.allowed ? "warn" : "critical",
      score: quotaBudget.limit,
      reasonCodes: [`quota_${quotaBudget.scope}`],
      payload: {
        retryAfterMs: quotaBudget.retryAfterMs,
        scope: quotaBudget.scope,
        windowMs: quotaBudget.windowMs,
      },
    });
  }
  if (!quotaBudget.allowed) {
    sendRateLimited(
      res,
      quotaBudget.retryAfterMs,
      `rate limit exceeded for chat.send; retry after ${Math.ceil(quotaBudget.retryAfterMs / 1000)}s`,
    );
    return true;
  }

  const runId = `chatcmpl_${randomUUID()}`;
  const deps = createDefaultDeps();
  const commandInput = buildAgentCommandInput({
    prompt,
    sessionKey,
    runId,
  });
  registerAgentRunContext(runId, {
    sessionKey,
    abuseAuditKey: abuseTupleKey,
    abuseAuditMethod: "chat.send",
  });

  if (!stream) {
    try {
      const result = await agentCommand(commandInput, defaultRuntime, deps);

      const content = resolveAgentResponseText(result);

      sendJson(res, 200, {
        id: runId,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [
          {
            index: 0,
            message: { role: "assistant", content },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      });
    } catch (err) {
      logWarn(`openai-compat: chat completion failed: ${String(err)}`);
      sendJson(res, 500, {
        error: { message: "internal error", type: "api_error" },
      });
    }
    return true;
  }

  setSseHeaders(res);

  let wroteRole = false;
  let sawAssistantDelta = false;
  let closed = false;

  const unsubscribe = onAgentEvent((evt) => {
    if (evt.runId !== runId) {
      return;
    }
    if (closed) {
      return;
    }

    if (evt.stream === "assistant") {
      const content = resolveAssistantStreamDeltaText(evt);
      if (!content) {
        return;
      }

      if (!wroteRole) {
        wroteRole = true;
        writeAssistantRoleChunk(res, { runId, model });
      }

      sawAssistantDelta = true;
      writeAssistantContentChunk(res, {
        runId,
        model,
        content,
        finishReason: null,
      });
      return;
    }

    if (evt.stream === "lifecycle") {
      const phase = evt.data?.phase;
      if (phase === "end" || phase === "error") {
        closed = true;
        unsubscribe();
        writeDone(res);
        res.end();
      }
    }
  });

  req.on("close", () => {
    closed = true;
    unsubscribe();
  });

  void (async () => {
    try {
      const result = await agentCommand(commandInput, defaultRuntime, deps);

      if (closed) {
        return;
      }

      if (!sawAssistantDelta) {
        if (!wroteRole) {
          wroteRole = true;
          writeAssistantRoleChunk(res, { runId, model });
        }

        const content = resolveAgentResponseText(result);

        sawAssistantDelta = true;
        writeAssistantContentChunk(res, {
          runId,
          model,
          content,
          finishReason: null,
        });
      }
    } catch (err) {
      logWarn(`openai-compat: streaming chat completion failed: ${String(err)}`);
      if (closed) {
        return;
      }
      writeAssistantContentChunk(res, {
        runId,
        model,
        content: "Error: internal error",
        finishReason: "stop",
      });
      emitAgentEvent({
        runId,
        stream: "lifecycle",
        data: { phase: "error" },
      });
    } finally {
      if (!closed) {
        closed = true;
        unsubscribe();
        writeDone(res);
        res.end();
      }
    }
  })();

  return true;
}
