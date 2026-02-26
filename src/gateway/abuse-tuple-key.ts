export type GatewayAbuseTuple = {
  method: string;
  actor: string;
  device: string;
  ip: string;
  session: string;
  channel: string;
  account: string;
};

export type GatewayAbuseTupleScope = Omit<GatewayAbuseTuple, "method">;

const TUPLE_KEY_PREFIX = "tuple-v1";

const DEFAULT_GATEWAY_ABUSE_TUPLE: GatewayAbuseTuple = {
  method: "unknown-method",
  actor: "unknown-actor",
  device: "unknown-device",
  ip: "unknown-ip",
  session: "none",
  channel: "none",
  account: "none",
};

const TUPLE_FIELDS: Array<keyof GatewayAbuseTuple> = [
  "method",
  "actor",
  "device",
  "ip",
  "session",
  "channel",
  "account",
];

const SCOPE_FIELDS: Array<keyof GatewayAbuseTupleScope> = [
  "actor",
  "device",
  "ip",
  "session",
  "channel",
  "account",
];

function escapeTupleValue(value: string): string {
  return value.replaceAll("%", "%25").replaceAll("|", "%7C").replaceAll("=", "%3D");
}

function unescapeTupleValue(value: string): string {
  return value.replace(/%7C/gi, "|").replace(/%3D/gi, "=").replace(/%25/gi, "%");
}

export function buildGatewayAbuseTupleKey(tuple: GatewayAbuseTuple): string {
  return `${TUPLE_KEY_PREFIX}|${TUPLE_FIELDS.map((field) => `${field}=${escapeTupleValue(tuple[field])}`).join("|")}`;
}

export function buildGatewayAbuseTupleScopeKey(tuple: GatewayAbuseTuple): string {
  return SCOPE_FIELDS.map((field) => `${field}=${escapeTupleValue(tuple[field])}`).join("|");
}

export function parseGatewayAbuseTupleKey(key: string): GatewayAbuseTuple {
  const tuple: GatewayAbuseTuple = {
    ...DEFAULT_GATEWAY_ABUSE_TUPLE,
  };
  if (!key.startsWith(`${TUPLE_KEY_PREFIX}|`)) {
    return tuple;
  }
  const rawParts = key.slice(TUPLE_KEY_PREFIX.length + 1);
  for (const part of rawParts.split("|")) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex <= 0) {
      continue;
    }
    const rawField = part.slice(0, separatorIndex);
    const rawValue = part.slice(separatorIndex + 1).trim();
    if (!rawValue) {
      continue;
    }
    if (rawField in tuple) {
      tuple[rawField as keyof GatewayAbuseTuple] = unescapeTupleValue(rawValue);
    }
  }
  return tuple;
}
