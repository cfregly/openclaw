import { loadConfig } from "../config/config.js";
import {
  consumeGatewayAbuseAnomaly,
  isGatewayAbuseAnomalyRpcMethod,
  resolveGatewayAbuseAnomalyRpcInput,
} from "./abuse-anomaly.js";
import type {
  ResolvedGatewayAbuseAnomalyConfig,
  ResolvedGatewayAbuseQuotaConfig,
} from "./abuse-config.js";
import { resolveGatewayAbuseConfig } from "./abuse-config.js";
import {
  consumeGatewayAbuseQuota,
  isGatewayAbuseQuotaRpcMethod,
  resolveGatewayAbuseQuotaRpcKey,
} from "./abuse-quota.js";
import { formatControlPlaneActor, resolveControlPlaneActor } from "./control-plane-audit.js";
import { consumeControlPlaneWriteBudget } from "./control-plane-rate-limit.js";
import { ADMIN_SCOPE, authorizeOperatorScopesForMethod } from "./method-scopes.js";
import { ErrorCodes, errorShape } from "./protocol/index.js";
import { isRoleAuthorizedForMethod, parseGatewayRole } from "./role-policy.js";
import { agentHandlers } from "./server-methods/agent.js";
import { agentsHandlers } from "./server-methods/agents.js";
import { browserHandlers } from "./server-methods/browser.js";
import { channelsHandlers } from "./server-methods/channels.js";
import { chatHandlers } from "./server-methods/chat.js";
import { configHandlers } from "./server-methods/config.js";
import { connectHandlers } from "./server-methods/connect.js";
import { cronHandlers } from "./server-methods/cron.js";
import { deviceHandlers } from "./server-methods/devices.js";
import { doctorHandlers } from "./server-methods/doctor.js";
import { execApprovalsHandlers } from "./server-methods/exec-approvals.js";
import { healthHandlers } from "./server-methods/health.js";
import { logsHandlers } from "./server-methods/logs.js";
import { modelsHandlers } from "./server-methods/models.js";
import { nodeHandlers } from "./server-methods/nodes.js";
import { pushHandlers } from "./server-methods/push.js";
import { sendHandlers } from "./server-methods/send.js";
import { sessionsHandlers } from "./server-methods/sessions.js";
import { skillsHandlers } from "./server-methods/skills.js";
import { systemHandlers } from "./server-methods/system.js";
import { talkHandlers } from "./server-methods/talk.js";
import { toolsCatalogHandlers } from "./server-methods/tools-catalog.js";
import { ttsHandlers } from "./server-methods/tts.js";
import type { GatewayRequestHandlers, GatewayRequestOptions } from "./server-methods/types.js";
import { updateHandlers } from "./server-methods/update.js";
import { usageHandlers } from "./server-methods/usage.js";
import { voicewakeHandlers } from "./server-methods/voicewake.js";
import { webHandlers } from "./server-methods/web.js";
import { wizardHandlers } from "./server-methods/wizard.js";

const CONTROL_PLANE_WRITE_METHODS = new Set(["config.apply", "config.patch", "update.run"]);
function authorizeGatewayMethod(method: string, client: GatewayRequestOptions["client"]) {
  if (!client?.connect) {
    return null;
  }
  if (method === "health") {
    return null;
  }
  const roleRaw = client.connect.role ?? "operator";
  const role = parseGatewayRole(roleRaw);
  if (!role) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `unauthorized role: ${roleRaw}`);
  }
  const scopes = client.connect.scopes ?? [];
  if (!isRoleAuthorizedForMethod(role, method)) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `unauthorized role: ${role}`);
  }
  if (role === "node") {
    return null;
  }
  if (scopes.includes(ADMIN_SCOPE)) {
    return null;
  }
  const scopeAuth = authorizeOperatorScopesForMethod(method, scopes);
  if (!scopeAuth.allowed) {
    return errorShape(ErrorCodes.INVALID_REQUEST, `missing scope: ${scopeAuth.missingScope}`);
  }
  return null;
}

export const coreGatewayHandlers: GatewayRequestHandlers = {
  ...connectHandlers,
  ...logsHandlers,
  ...voicewakeHandlers,
  ...healthHandlers,
  ...channelsHandlers,
  ...chatHandlers,
  ...cronHandlers,
  ...deviceHandlers,
  ...doctorHandlers,
  ...execApprovalsHandlers,
  ...webHandlers,
  ...modelsHandlers,
  ...configHandlers,
  ...wizardHandlers,
  ...talkHandlers,
  ...toolsCatalogHandlers,
  ...ttsHandlers,
  ...skillsHandlers,
  ...sessionsHandlers,
  ...systemHandlers,
  ...updateHandlers,
  ...nodeHandlers,
  ...pushHandlers,
  ...sendHandlers,
  ...usageHandlers,
  ...agentHandlers,
  ...agentsHandlers,
  ...browserHandlers,
};

export async function handleGatewayRequest(
  opts: GatewayRequestOptions & {
    extraHandlers?: GatewayRequestHandlers;
    abuseQuotaConfig?: ResolvedGatewayAbuseQuotaConfig;
    anomalyConfig?: ResolvedGatewayAbuseAnomalyConfig;
  },
): Promise<void> {
  const { req, respond, client, isWebchatConnect, context } = opts;
  const authError = authorizeGatewayMethod(req.method, client);
  if (authError) {
    respond(false, undefined, authError);
    return;
  }
  const requestParams = (req.params ?? {}) as Record<string, unknown>;
  const resolvedAbuseConfig =
    opts.abuseQuotaConfig && opts.anomalyConfig
      ? undefined
      : resolveGatewayAbuseConfig(loadConfig());
  if (isGatewayAbuseAnomalyRpcMethod(req.method)) {
    const anomalyInput = resolveGatewayAbuseAnomalyRpcInput({
      method: req.method,
      requestParams,
    });
    if (anomalyInput) {
      const anomalyConfig = opts.anomalyConfig ?? resolvedAbuseConfig?.anomaly;
      const anomalyDecision = consumeGatewayAbuseAnomaly({
        key: resolveGatewayAbuseQuotaRpcKey({
          method: req.method,
          client,
          requestParams,
        }),
        input: anomalyInput,
        anomalyConfig,
      });
      if (anomalyDecision.observed) {
        const thresholdLabel = anomalyDecision.threshold
          ? String(anomalyDecision.threshold)
          : "n/a";
        context.logGateway.warn(
          `gateway abuse anomaly observed method=${req.method} mode=${anomalyDecision.mode} action=${anomalyDecision.action} score=${anomalyDecision.score} threshold=${thresholdLabel} checkId=${anomalyDecision.checkId} retryAfterMs=${anomalyDecision.retryAfterMs} fingerprint=${anomalyDecision.fingerprint ?? "none"} reasons=${anomalyDecision.reasonCodes.join(",") || "none"} key=${anomalyDecision.key}`,
        );
      }
      if (!anomalyDecision.allowed) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.UNAVAILABLE,
            `anomaly policy triggered for ${req.method}; retry after ${Math.ceil(anomalyDecision.retryAfterMs / 1000)}s`,
            {
              retryable: true,
              retryAfterMs: anomalyDecision.retryAfterMs,
              details: {
                checkId: anomalyDecision.checkId,
                method: req.method,
                action: anomalyDecision.action,
                score: anomalyDecision.score,
                threshold: anomalyDecision.threshold,
                fingerprint: anomalyDecision.fingerprint,
                reasons: anomalyDecision.reasonCodes,
              },
            },
          ),
        );
        return;
      }
    }
  }
  if (isGatewayAbuseQuotaRpcMethod(req.method)) {
    const quotaConfig = opts.abuseQuotaConfig ?? resolvedAbuseConfig?.quota;
    const budget = consumeGatewayAbuseQuota({
      key: resolveGatewayAbuseQuotaRpcKey({
        method: req.method,
        client,
        requestParams,
      }),
      quotaConfig,
    });
    if (budget.observed) {
      const windowLabel = budget.windowMs ? `${Math.ceil(budget.windowMs / 1000)}s` : "mixed";
      const limitLabel = budget.limit ? String(budget.limit) : "mixed";
      context.logGateway.warn(
        `gateway abuse quota observed method=${req.method} mode=${budget.mode} scope=${budget.scope} limit=${limitLabel} window=${windowLabel} retryAfterMs=${budget.retryAfterMs} key=${budget.key}`,
      );
    }
    if (!budget.allowed) {
      const limitLabel =
        budget.limit && budget.windowMs
          ? `${budget.limit} per ${Math.ceil(budget.windowMs / 1000)}s`
          : "multiple windows";
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.UNAVAILABLE,
          `rate limit exceeded for ${req.method}; retry after ${Math.ceil(budget.retryAfterMs / 1000)}s`,
          {
            retryable: true,
            retryAfterMs: budget.retryAfterMs,
            details: {
              method: req.method,
              scope: budget.scope,
              limit: limitLabel,
            },
          },
        ),
      );
      return;
    }
  }
  if (CONTROL_PLANE_WRITE_METHODS.has(req.method)) {
    const budget = consumeControlPlaneWriteBudget({ client });
    if (!budget.allowed) {
      const actor = resolveControlPlaneActor(client);
      context.logGateway.warn(
        `control-plane write rate-limited method=${req.method} ${formatControlPlaneActor(actor)} retryAfterMs=${budget.retryAfterMs} key=${budget.key}`,
      );
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.UNAVAILABLE,
          `rate limit exceeded for ${req.method}; retry after ${Math.ceil(budget.retryAfterMs / 1000)}s`,
          {
            retryable: true,
            retryAfterMs: budget.retryAfterMs,
            details: {
              method: req.method,
              limit: "3 per 60s",
            },
          },
        ),
      );
      return;
    }
  }
  const handler = opts.extraHandlers?.[req.method] ?? coreGatewayHandlers[req.method];
  if (!handler) {
    respond(
      false,
      undefined,
      errorShape(ErrorCodes.INVALID_REQUEST, `unknown method: ${req.method}`),
    );
    return;
  }
  await handler({
    req,
    params: requestParams,
    client,
    isWebchatConnect,
    respond,
    context,
  });
}
