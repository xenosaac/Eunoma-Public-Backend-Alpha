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
  /**
   * Codex M5b P2 #2: state root path for coordinator-persisted artifacts. The
   * /v2/withdraw/mpcca/submit route reads the finalize transcript from this directory
   * and writes the submit transcript here as well. Sourced from `EUNOMA_STATE_ROOT`.
   */
  stateRoot?: string;
  /**
   * Codex M5b P2 #2: URL of the relayer service that the coordinator POSTs assembled
   * WithdrawV2CallArgs to. When set + `relayerBearerToken` is set, start.ts wires up
   * a default fetch-backed `relayerSubmitter`. Sourced from `RELAYER_URL`.
   */
  relayerUrl?: string;
  /**
   * Codex M5b P2 #2: bearer token for the relayer service. Sourced from
   * `RELAYER_BEARER_TOKEN`. Required when `relayerUrl` is set unless explicitly
   * opted out via `RELAYER_ALLOW_NO_AUTH=1` (dev-only).
   */
  relayerBearerToken?: string;
  /**
   * Codex M5b P2 #2: Aptos fullnode URL for waitForTx polling. Sourced from
   * `APTOS_NODE_URL`. Required for real-submit (non-simulated) chain confirmation —
   * the route fails closed with 502 chain_node_url_required_for_real_submit when
   * absent and the relayer returns simulated:false.
   */
  chainNodeUrl?: string;
  /**
   * Codex M5b P2 #2: timeout in ms for chain confirmation polling. Default 30_000.
   * Sourced from `APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS` (decimal string).
   */
  chainConfirmationTimeoutMs?: number;
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
  const chainConfirmationTimeoutMsRaw = env.APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS;
  let chainConfirmationTimeoutMs: number | undefined;
  if (chainConfirmationTimeoutMsRaw !== undefined && chainConfirmationTimeoutMsRaw !== "") {
    if (!/^[1-9][0-9]*$/.test(chainConfirmationTimeoutMsRaw)) {
      throw new Error(
        "APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS must be a positive decimal integer (ms)",
      );
    }
    chainConfirmationTimeoutMs = Number.parseInt(chainConfirmationTimeoutMsRaw, 10);
  }
  return {
    host: env.COORDINATOR_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.COORDINATOR_PORT ?? "4200", 10),
    bearerToken: env.COORDINATOR_BEARER_TOKEN,
    roster,
    caDkgV2Roster,
    frostDkgV2Roster,
    nodeBearerTokens: parseNodeBearerTokens(env.DEOPERATOR_NODE_BEARER_TOKENS_JSON),
    stateRoot: env.EUNOMA_STATE_ROOT || undefined,
    relayerUrl: env.RELAYER_URL || undefined,
    relayerBearerToken: env.RELAYER_BEARER_TOKEN || undefined,
    chainNodeUrl: env.APTOS_NODE_URL || undefined,
    ...(chainConfirmationTimeoutMs !== undefined ? { chainConfirmationTimeoutMs } : {}),
  };
}

/**
 * Codex M5b P2 #2: build the default fetch-backed relayer submitter from configFromEnv
 * values. Returns `undefined` if `relayerUrl` is not configured (the route then returns
 * 502 relayer_unreachable at submit time — fail closed). Tests inject a mock submitter
 * directly into `buildCoordinatorServer({ relayerSubmitter })` and never call this
 * factory.
 *
 * The submitter POSTs the assembled 27-field bundle to `<relayerUrl>/v2/relayer/submit/withdraw`
 * with `Authorization: Bearer <relayerBearerToken>` when configured. Non-2xx responses
 * throw an Error whose `.message` is the upstream JSON error code + message (the route
 * surfaces this as 502 relayer_returned_error).
 */
export function buildDefaultRelayerSubmitter(
  config: CoordinatorConfig,
  fetchImpl: typeof fetch = fetch,
): ((args: unknown) => Promise<{ accepted: boolean; txHash: string; simulated: boolean }>) | undefined {
  const relayerUrl = config.relayerUrl;
  if (!relayerUrl) return undefined;
  const bearer = config.relayerBearerToken;
  return async (args: unknown) => {
    const url = new URL("/v2/relayer/submit/withdraw", relayerUrl).toString();
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    const res = await fetchImpl(url, {
      method: "POST",
      headers,
      body: JSON.stringify(args),
    });
    let body: Record<string, unknown> | null = null;
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      body = null;
    }
    if (!res.ok) {
      const errCode =
        body && typeof body.error === "string" ? body.error : `http_${res.status}`;
      const errMsg =
        body && typeof body.message === "string" ? body.message : "unknown";
      throw new Error(`relayer responded ${res.status} (${errCode}): ${errMsg}`);
    }
    if (
      !body ||
      typeof body.accepted !== "boolean" ||
      typeof body.txHash !== "string" ||
      typeof body.simulated !== "boolean"
    ) {
      throw new Error(
        `relayer response missing required fields (accepted/txHash/simulated); got ${JSON.stringify(body)}`,
      );
    }
    return {
      accepted: body.accepted,
      txHash: body.txHash,
      simulated: body.simulated,
    };
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
