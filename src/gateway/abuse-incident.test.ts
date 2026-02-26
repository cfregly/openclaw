import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  __testing,
  getActiveGatewayAbuseContainment,
  recordGatewayAbuseIncidentSignal,
  transitionGatewayAbuseIncident,
} from "./abuse-incident.js";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("gateway abuse incidents", () => {
  afterEach(() => {
    __testing.resetGatewayAbuseIncidentState();
    delete process.env.OPENCLAW_STATE_DIR;
  });

  it("creates incident records and applies auto-containment in enforce mode", () => {
    const key =
      "method=chat.send|actor=a|device=d1|ip=10.0.0.1|session=s1|channel=none|account=acct-a";
    const decision = recordGatewayAbuseIncidentSignal({
      key,
      source: "anomaly",
      severity: "critical",
      checkId: "gateway.abuse.anomaly.block",
      reasonCodes: ["prompt_exfiltration_terms"],
      incidentConfig: {
        mode: "enforce",
        autoContainment: {
          enabled: true,
          minSeverity: "critical",
          ttlMs: 60_000,
        },
        retentionDays: 14,
      },
      nowMs: 1_000,
    });

    expect(decision?.created).toBe(true);
    expect(decision?.autoContained).toBe(true);
    expect(decision?.state).toBe("contained");

    const containment = getActiveGatewayAbuseContainment({
      key,
      nowMs: 1_500,
    });
    expect(containment.active).toBe(true);
    expect(containment.retryAfterMs).toBeGreaterThan(0);
  });

  it("expires containment after TTL and supports operator transitions", () => {
    const key =
      "method=send|actor=a|device=d1|ip=10.0.0.1|session=s1|channel=telegram|account=acct-a";
    const created = recordGatewayAbuseIncidentSignal({
      key,
      source: "quota",
      severity: "critical",
      checkId: "gateway.abuse.quota.enforce",
      incidentConfig: {
        mode: "enforce",
        autoContainment: {
          enabled: true,
          minSeverity: "critical",
          ttlMs: 5_000,
        },
        retentionDays: 14,
      },
      nowMs: 1_000,
    });
    const incidentId = created?.incidentId;
    expect(incidentId).toBeTruthy();

    const activeNow = getActiveGatewayAbuseContainment({
      key,
      nowMs: 2_000,
    });
    expect(activeNow.active).toBe(true);

    const expired = getActiveGatewayAbuseContainment({
      key,
      nowMs: 8_000,
    });
    expect(expired.active).toBe(false);

    const acknowledged = transitionGatewayAbuseIncident({
      incidentId: incidentId!,
      action: "acknowledge",
      actor: "ops-a",
      nowMs: 9_000,
    });
    expect(acknowledged?.state).toBe("investigating");

    const resolved = transitionGatewayAbuseIncident({
      incidentId: incidentId!,
      action: "resolve",
      actor: "ops-a",
      nowMs: 10_000,
    });
    expect(resolved?.state).toBe("resolved");
  });

  it("persists incident state under OPENCLAW_STATE_DIR", async () => {
    await withTempDir("openclaw-incidents-", async (stateDir) => {
      process.env.OPENCLAW_STATE_DIR = stateDir;
      __testing.resetGatewayAbuseIncidentState();

      const decision = recordGatewayAbuseIncidentSignal({
        key: "method=chat.send|actor=a|device=d1|ip=127.0.0.1|session=s1|channel=none|account=none",
        source: "anomaly",
        severity: "warn",
        checkId: "gateway.abuse.anomaly.warning",
        incidentConfig: {
          mode: "observe",
          autoContainment: {
            enabled: false,
            minSeverity: "critical",
            ttlMs: 60_000,
          },
          retentionDays: 14,
        },
        nowMs: 1_000,
      });
      expect(decision?.incidentId).toBeTruthy();

      await sleep(800);

      const persistedPath = path.join(stateDir, "gateway-abuse-incidents.json");
      const raw = await fs.readFile(persistedPath, "utf-8");
      const parsed = JSON.parse(raw) as {
        version: number;
        incidents: Array<{ id: string }>;
      };
      expect(parsed.version).toBe(1);
      expect(parsed.incidents.length).toBeGreaterThan(0);
      expect(parsed.incidents[0]?.id).toMatch(/^inc_/);
    });
  });
});
