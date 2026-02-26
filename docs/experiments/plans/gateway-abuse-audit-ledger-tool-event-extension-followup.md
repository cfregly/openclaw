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

## PR Title

`security(audit): tool-event and extension fan-in coverage for abuse audit ledger`

## Implemented Scope

1. Added `tool_event` ledger rows for agent tool lifecycle phases (`start`/`update`/`result`) with stable run correlation fields.
2. Captured extension-channel fan-in events at the shared outbound seam (`deliverOutboundPayloadsCore`), not per-channel copy/paste handlers.
3. Persisted redaction-safe metadata (`toolCallId`, phase, result/partial-result presence + byte estimates) without storing raw tool outputs.
4. Added query filtering by `runId` for tool-event investigation paths.
5. Preserved PR-6 decision-event behavior; this PR extends evidence coverage only.

## Acceptance Criteria

1. `tool_event` records are emitted for targeted core tool streams with deterministic IDs.
2. Extension/outbound fan-in paths emit `extension_event` audit rows with channel identifiers.
3. Redaction-safe behavior is test-covered for tool payload/result evidence fields.
4. Existing PR-6 behavior remains unchanged for decision-event logging and retry semantics.

## Deferred Follow-up

1. Exfiltration-oriented heuristic reason codes (volume spike, repeated extraction sequence, risky chains) are deferred to a later iteration.

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
