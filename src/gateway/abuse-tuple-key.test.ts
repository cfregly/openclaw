import { describe, expect, it } from "vitest";
import {
  buildGatewayAbuseTupleKey,
  buildGatewayAbuseTupleScopeKey,
  parseGatewayAbuseTupleKey,
} from "./abuse-tuple-key.js";

describe("gateway abuse tuple key", () => {
  it("round-trips delimiter-bearing tuple values safely", () => {
    const tuple = {
      method: "chat.send",
      actor: "auth-user:alice|root=1%",
      device: "device=a|b",
      ip: "203.0.113.10",
      session: "agent:main:openai:user=alice|prod",
      channel: "webchat|ui",
      account: "acct=main|prod%",
    };
    const key = buildGatewayAbuseTupleKey(tuple);

    expect(key).toContain("actor=auth-user:alice%7Croot%3D1%25");
    expect(key).toContain("session=agent:main:openai:user%3Dalice%7Cprod");

    const parsed = parseGatewayAbuseTupleKey(key);
    expect(parsed).toEqual(tuple);
  });

  it("parses legacy unescaped tuple keys for backward compatibility", () => {
    const legacyKey =
      "method=chat.send|actor=user:alice|device=d1|ip=10.0.0.1|session=s1|channel=none|account=none";
    const parsed = parseGatewayAbuseTupleKey(legacyKey);
    expect(parsed).toEqual({
      method: "chat.send",
      actor: "user:alice",
      device: "d1",
      ip: "10.0.0.1",
      session: "s1",
      channel: "none",
      account: "none",
    });
  });

  it("builds scope keys without method and with delimiter escaping", () => {
    const key = buildGatewayAbuseTupleScopeKey({
      method: "send",
      actor: "auth-user:bob|admin",
      device: "dev=2",
      ip: "198.51.100.9",
      session: "s=2|x",
      channel: "telegram",
      account: "acct|ops",
    });

    expect(key).not.toContain("method=");
    expect(key).toContain("actor=auth-user:bob%7Cadmin");
    expect(key).toContain("device=dev%3D2");
    expect(key).toContain("session=s%3D2%7Cx");
  });
});
