import {
  assertProductionCaDkgScheme,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
} from "@eunoma/deop-protocol";

export interface CoordinatorConfig {
  host: string;
  port: number;
  bearerToken?: string;
  roster?: DeoperatorRoster;
  caDkgV2Roster?: CaDkgV2Roster;
  frostDkgV2Roster?: FrostDkgV2Roster;
  nodeBearerTokens: Record<string, string>;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): CoordinatorConfig {
  const roster = env.DEOPERATOR_ROSTER_JSON
    ? (JSON.parse(env.DEOPERATOR_ROSTER_JSON) as DeoperatorRoster)
    : undefined;
  const caDkgV2Roster = env.CA_DKG_V2_ROSTER_JSON
    ? parseCaDkgV2Roster(JSON.parse(env.CA_DKG_V2_ROSTER_JSON))
    : undefined;
  const frostDkgV2Roster = env.FROST_DKG_V2_ROSTER_JSON
    ? parseFrostDkgV2Roster(JSON.parse(env.FROST_DKG_V2_ROSTER_JSON))
    : undefined;
  if (!roster && !caDkgV2Roster) {
    throw new Error("DEOPERATOR_ROSTER_JSON or CA_DKG_V2_ROSTER_JSON is required");
  }
  if (roster) {
    if (env.NODE_ENV === "production" || env.EUNOMA_ENV === "production") {
      assertProductionCaDkgScheme(roster);
    } else {
      validateRoster(roster);
    }
  }
  return {
    host: env.COORDINATOR_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.COORDINATOR_PORT ?? "4200", 10),
    bearerToken: env.COORDINATOR_BEARER_TOKEN,
    roster,
    caDkgV2Roster,
    frostDkgV2Roster,
    nodeBearerTokens: parseNodeBearerTokens(env.DEOPERATOR_NODE_BEARER_TOKENS_JSON),
  };
}

function parseNodeBearerTokens(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("DEOPERATOR_NODE_BEARER_TOKENS_JSON must be an object");
  }
  const out: Record<string, string> = {};
  for (const [slot, token] of Object.entries(parsed)) {
    if (!/^[0-6]$/.test(slot) || typeof token !== "string" || token.length === 0) {
      throw new Error("DEOPERATOR_NODE_BEARER_TOKENS_JSON maps slots 0-6 to tokens");
    }
    out[slot] = token;
  }
  return out;
}
