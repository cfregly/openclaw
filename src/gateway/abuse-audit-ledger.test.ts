import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  __testing,
  queryGatewayAbuseAuditLedger,
  recordGatewayAbuseAuditEvent,
} from "./abuse-audit-ledger.js";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("gateway abuse audit ledger", () => {
  afterEach(() => {
    __testing.resetGatewayAbuseAuditLedgerState();
    delete process.env.OPENCLAW_STATE_DIR;
  });

  it("records and queries audit rows by actor/channel/tool", () => {
    const config = {
      mode: "observe" as const,
      retentionDays: 14,
      maxRecords: 100,
      redactPayloads: true,
    };
    recordGatewayAbuseAuditEvent({
      kind: "request",
      key: "method=send|actor=actor-a|device=d1|ip=10.0.0.1|session=s1|channel=telegram|account=acct-a",
      tool: "sendText",
      auditConfig: config,
      nowMs: 1_000,
    });
    recordGatewayAbuseAuditEvent({
      kind: "anomaly",
      key: "method=chat.send|actor=actor-b|device=d2|ip=10.0.0.2|session=s2|channel=none|account=none",
      checkId: "gateway.abuse.anomaly.warning",
      auditConfig: config,
      nowMs: 2_000,
    });

    const byActor = queryGatewayAbuseAuditLedger({ actor: "actor-a" });
    expect(byActor.length).toBe(1);
    expect(byActor[0]?.channel).toBe("telegram");

    const byTool = queryGatewayAbuseAuditLedger({ tool: "sendText" });
    expect(byTool.length).toBe(1);
    expect(byTool[0]?.actor).toBe("actor-a");
  });

  it("enforces retention and maxRecords bounds", () => {
    const config = {
      mode: "observe" as const,
      retentionDays: 1,
      maxRecords: 2,
      redactPayloads: true,
    };
    recordGatewayAbuseAuditEvent({
      kind: "request",
      key: "method=send|actor=a|device=d|ip=1|session=s|channel=telegram|account=acct",
      auditConfig: config,
      nowMs: 0,
    });
    recordGatewayAbuseAuditEvent({
      kind: "request",
      key: "method=send|actor=b|device=d|ip=2|session=s|channel=telegram|account=acct",
      auditConfig: config,
      nowMs: 1_000,
    });
    recordGatewayAbuseAuditEvent({
      kind: "request",
      key: "method=send|actor=c|device=d|ip=3|session=s|channel=telegram|account=acct",
      auditConfig: config,
      nowMs: 2_000,
    });

    const rows = queryGatewayAbuseAuditLedger({ limit: 10 });
    expect(rows.length).toBe(2);
    expect(rows.map((row) => row.actor)).toEqual(["c", "b"]);
  });

  it("redacts payloads by default and persists ledger state", async () => {
    await withTempDir("openclaw-audit-ledger-", async (stateDir) => {
      process.env.OPENCLAW_STATE_DIR = stateDir;
      __testing.resetGatewayAbuseAuditLedgerState();

      recordGatewayAbuseAuditEvent({
        kind: "incident",
        key: "method=chat.send|actor=a|device=d|ip=127.0.0.1|session=s|channel=none|account=none",
        incidentId: "inc_000001",
        payload: { raw: "sensitive" },
        auditConfig: {
          mode: "observe",
          retentionDays: 14,
          maxRecords: 100,
          redactPayloads: true,
        },
        nowMs: 1_000,
      });

      await sleep(800);

      const rows = queryGatewayAbuseAuditLedger({ incidentId: "inc_000001" });
      expect(rows.length).toBe(1);
      expect(rows[0]?.payload).toBeUndefined();

      const persistedPath = path.join(stateDir, "gateway-abuse-audit-ledger.json");
      const raw = await fs.readFile(persistedPath, "utf-8");
      const parsed = JSON.parse(raw) as {
        version: number;
        records: Array<{ incidentId?: string }>;
      };
      expect(parsed.version).toBe(1);
      expect(parsed.records.length).toBe(1);
      expect(parsed.records[0]?.incidentId).toBe("inc_000001");
    });
  });
});
