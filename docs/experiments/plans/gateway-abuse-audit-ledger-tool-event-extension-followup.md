---
summary: "Follow-up scope for tool-event and extension-channel coverage after gateway abuse decision ledger"
read_when:
  - Splitting audit-ledger work into staged PRs
  - Implementing tool-event and extension fan-in security evidence
owner: "openclaw"
status: "review-ready"
last_updated: "2026-02-25"
title: "Gateway Abuse Audit Ledger Tool-Event + Extension Follow-up"
---

# Gateway Abuse Audit Ledger Tool-Event + Extension Follow-up

## Why Separate From PR-6

PR-6 is intentionally scoped to gateway abuse decision events (`request`, `anomaly`, `quota`, `correlation`, `incident`, `containment`).

This follow-up adds channel/tool instrumentation that is broader and riskier to land in the same review:

- tool-event capture from agent execution streams,
- extension/outbound fan-in coverage,
- exfiltration-oriented tool/result evidence.

## Proposed PR Title

`security(audit): add tool-event and extension fan-in coverage to abuse audit ledger`

## Scope

1. Add `tool_event` ledger rows for agent tool call lifecycle (start/finish/error) with stable run/tool correlation fields.
2. Capture extension-channel fan-in events at shared seams (plugin adapters/outbound delivery integration points), not per-channel copy/paste handlers.
3. Persist tool-result metadata in redaction-safe form (`redactPayloads=true` default) with explicit size/byte counters.
4. Add exfiltration-oriented audit reason codes for suspicious tool/result patterns (high volume, repetitive extraction templates, risky chains).
5. Expose query filters by tool, channel, run, and incident linkage.

## Acceptance Criteria

1. `tool_event` records are emitted for targeted core tool streams with deterministic IDs.
2. Extension/outbound fan-in paths emit audit rows with channel identifiers.
3. Redaction behavior is test-covered for sensitive tool payload/result fields.
4. At least 3 exfiltration-focused scenarios are test-covered (volume spike, repeated extraction sequence, risky chain).
5. Existing PR-6 behavior remains unchanged for decision-event logging and retry semantics.

## Explicit Non-goals

- Not replacing existing auth/websocket/webhook/per-sender throttles.
- Not re-implementing open PRs #25751, #19515, #15035, #26067, #26050.
- Not changing quota/anomaly/correlation/incident decision math from PRs 2-5.

## Overlap Boundaries

- Extends PR-6 evidence coverage; does not change PR-6 decision-event schema semantics.
- Complements incident timelines (PR-5) by adding tool-level evidence rows.
- Complements correlation workflows (PR-4) with richer cross-channel/tool forensic detail.

## Testing Plan

- Unit tests for tool-event row creation, redaction, and retention/pruning.
- Gateway integration tests for OpenAI/OpenResponses plus at least one extension fan-in path.
- Regression checks for existing abuse hardening suites to confirm no behavior drift.
