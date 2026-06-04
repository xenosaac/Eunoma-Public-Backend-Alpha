import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  assertProductionCaDkgScheme,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
} from "@eunoma/deop-protocol";

/**
 * CP5 RC2: a single per-asset registry row as persisted by the init_v4 artifact
 * <stateRoot>/coordinator/asset_registry.json. The `/v2/assets` endpoint serves these (mapped
 * to the frontend `AssetEntry`); `configFromEnv` reads the same artifact to derive the single
 * ACTIVE asset for the legacy `bridgeAssetType` (vault,asset) decrypt gate. Public routing
 * fields only — no secrets.
 */
export interface AssetRegistryEntry {
  metadata: string; // FA Metadata object-address (asset_addr / on-chain registry key)
  assetType?: string; // fully-qualified asset type tag (when the artifact records it)
  status: "DORMANT" | "ACTIVE" | "PAUSED";
}

/**
 * CP5 RC2: load + minimally validate the init_v4 asset registry from `stateRoot`. Returns the
 * rows, or `undefined` when stateRoot is unset / the artifact is missing / unreadable /
 * malformed (callers then fall back to env, never crash). This is the canonical replacement for
 * the singleton `BRIDGE_ASSET_TYPE` env — the registry is the source of truth for asset identity.
 */
export function assetRegistryFromStateRoot(
  stateRoot: string | undefined,
): AssetRegistryEntry[] | undefined {
  if (!stateRoot) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(stateRoot, "coordinator", "asset_registry.json"), "utf8"));
  } catch {
    return undefined;
  }
  const rows = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { assets?: unknown }).assets)
      ? (raw as { assets: unknown[] }).assets
      : undefined;
  if (!rows) return undefined;
  const out: AssetRegistryEntry[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const r = row as Record<string, unknown>;
    const status = r.status;
    const statusName =
      status === 1 || status === "ACTIVE"
        ? "ACTIVE"
        : status === 0 || status === "DORMANT"
          ? "DORMANT"
          : status === 2 || status === "PAUSED"
            ? "PAUSED"
            : undefined;
    if (typeof r.metadata !== "string" || statusName === undefined) return undefined;
    out.push({
      metadata: r.metadata,
      ...(typeof r.assetType === "string" ? { assetType: r.assetType } : {}),
      status: statusName,
    });
  }
  return out;
}

/**
 * CP5 RC2: derive the single ACTIVE asset's type tag from the registry, for the legacy
 * `bridgeAssetType` (vault,asset) decrypt gate. Returns `undefined` when the registry is absent,
 * has no ACTIVE asset, the ACTIVE asset records no `assetType`, or — defensively — when MORE than
 * one asset is ACTIVE (the launch invariant is exactly one ACTIVE asset = APT; an ambiguous gate
 * must fail closed to env rather than silently pin the wrong asset).
 */
export function deriveBridgeAssetTypeFromRegistry(
  registry: AssetRegistryEntry[] | undefined,
): string | undefined {
  if (!registry) return undefined;
  const active = registry.filter((a) => a.status === "ACTIVE");
  if (active.length !== 1) return undefined;
  return active[0].assetType;
}

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
  /**
   * M10-l (codex iter-6 P1-13): the bridge's vault address on Aptos (0x-prefixed
   * hex). Sourced from `BRIDGE_VAULT_ADDRESS`. Required by `/v2/balance/decrypt`
   * — the route rejects requests whose `vaultAddress` doesn't match this
   * configured value, preventing a caller from asking the threshold to decrypt
   * any non-bridge confidential balance that happens to share the same CA DKG.
   */
  bridgeVaultAddress?: string;
  /**
   * M10-l (codex iter-6 P1-13): the bridge's confidential-asset type tag
   * (e.g. `0x1::aptos_coin::AptosCoin`). Sourced from `BRIDGE_ASSET_TYPE`.
   * Required by `/v2/balance/decrypt` for the same chosen-balance-target reason.
   *
   * CP5 RC2 (multi-asset): the single-asset env `BRIDGE_ASSET_TYPE` is no longer the
   * source of truth — the per-asset registry (`<stateRoot>/coordinator/asset_registry.json`,
   * the init_v4 artifact) is. When `BRIDGE_ASSET_TYPE` is unset, `configFromEnv` derives
   * this from the registry's single ACTIVE asset (the launch invariant: only APT is ACTIVE,
   * stablecoins ship DORMANT — so the derived value is unambiguous). The `/v2/balance/decrypt`
   * (vault,asset) gate is preserved verbatim; it now reads the registry-derived asset rather
   * than a hand-edited env. An explicit `BRIDGE_ASSET_TYPE` still overrides (test / staged
   * cutover). See `assetRegistryFromStateRoot`.
   */
  bridgeAssetType?: string;
  /**
   * CP3 cutover: when true, the coordinator POSTs the assembled WithdrawV2CallArgs to the relayer's
   * split-v3 route `/v3/relayer/submit/withdraw` (drives 5 v3 txs, withdraw = 0 user sigs) instead
   * of the monolith `/v2` route. Env-gated via `RELAYER_USE_V3=1` for a controlled, reversible
   * cutover. The /v3 route may also return a `self_submit` signal (gas breaker open / reserve low),
   * which the submitter surfaces as a `relayer_self_submit:<reason>` error for the client fallback.
   */
  relayerUseV3?: boolean;
  /**
   * CP5 RC6(A): the ASP-root TTL window (seconds) the historical-root endpoint
   * GET /v2/asp-set/at/:rootHex honors before returning 410 Gone. Sourced from
   * `EUNOMA_ASP_ROOT_TTL_SECS` (positive decimal seconds). Unset → the server default (~6h),
   * which should track the on-chain ASP_ROOT_TTL constant so the off-chain window matches the
   * chain's E_INVALID_ASP_ROOT cutoff.
   */
  aspRootTtlSecs?: number;
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
  const stateRoot = env.EUNOMA_STATE_ROOT || undefined;
  // CP5 RC6(A): optional ASP-root TTL override (positive decimal seconds). Unset → server default.
  const aspRootTtlSecsRaw = env.EUNOMA_ASP_ROOT_TTL_SECS;
  let aspRootTtlSecs: number | undefined;
  if (aspRootTtlSecsRaw !== undefined && aspRootTtlSecsRaw !== "") {
    if (!/^[1-9][0-9]*$/.test(aspRootTtlSecsRaw)) {
      throw new Error("EUNOMA_ASP_ROOT_TTL_SECS must be a positive decimal integer (seconds)");
    }
    aspRootTtlSecs = Number.parseInt(aspRootTtlSecsRaw, 10);
  }
  // CP5 RC2: the per-asset registry (init_v4 artifact) is the source of truth for asset identity.
  // An explicit BRIDGE_ASSET_TYPE still wins (test / staged cutover); otherwise derive the single
  // ACTIVE asset from the registry so the (vault,asset) decrypt gate is registry-driven, not env.
  const bridgeAssetType =
    (env.BRIDGE_ASSET_TYPE || undefined) ??
    deriveBridgeAssetTypeFromRegistry(assetRegistryFromStateRoot(stateRoot));
  return {
    host: env.COORDINATOR_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.COORDINATOR_PORT ?? "4200", 10),
    bearerToken: env.COORDINATOR_BEARER_TOKEN,
    roster,
    caDkgV2Roster,
    frostDkgV2Roster,
    nodeBearerTokens: parseNodeBearerTokens(env.DEOPERATOR_NODE_BEARER_TOKENS_JSON),
    stateRoot,
    relayerUrl: env.RELAYER_URL || undefined,
    relayerBearerToken: env.RELAYER_BEARER_TOKEN || undefined,
    chainNodeUrl: env.APTOS_NODE_URL || undefined,
    ...(chainConfirmationTimeoutMs !== undefined ? { chainConfirmationTimeoutMs } : {}),
    bridgeVaultAddress: env.BRIDGE_VAULT_ADDRESS || undefined,
    bridgeAssetType,
    relayerUseV3: env.RELAYER_USE_V3 === "1",
    ...(aspRootTtlSecs !== undefined ? { aspRootTtlSecs } : {}),
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
  const useV3 = config.relayerUseV3 === true;
  return async (args: unknown) => {
    const path = useV3 ? "/v3/relayer/submit/withdraw" : "/v2/relayer/submit/withdraw";
    const url = new URL(path, relayerUrl).toString();
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
      const detailCode =
        body && typeof body.code === "string" ? body.code : "";
      const errMsg =
        body && typeof body.message === "string" ? body.message : "unknown";
      throw new Error(
        `relayer responded ${res.status} (${errCode}${detailCode ? `/${detailCode}` : ""}): ${errMsg}`,
      );
    }
    if (useV3) {
      // The /v3 route returns a 200 `{ action: "self_submit", reason }` when the gas breaker is
      // open / reserve is low. Surface it as a distinct error so the caller can fall back to
      // user self-submit (the FROST attestation is still unexpired).
      if (body && body.action === "self_submit") {
        const reason = typeof body.reason === "string" ? body.reason : "unknown";
        throw new Error(`relayer_self_submit: ${reason}`);
      }
      const txHashes = body?.txHashes;
      if (
        !body ||
        typeof body.accepted !== "boolean" ||
        !Array.isArray(txHashes) ||
        txHashes.length === 0 ||
        typeof body.simulated !== "boolean"
      ) {
        throw new Error(
          `relayer v3 response missing required fields (accepted/txHashes/simulated); got ${JSON.stringify(body)}`,
        );
      }
      // The last hash is step2b — the settlement tx the coordinator's downstream (resync, response)
      // tracks; the v2 monolith returned a single txHash, so this preserves the same contract.
      return {
        accepted: body.accepted,
        txHash: String(txHashes[txHashes.length - 1]),
        simulated: body.simulated,
      };
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

/**
 * CP3 deposit-delegate submitter: POSTs the assembled DepositV3DelegateArgs to the relayer's
 * `/v3/relayer/submit/deposit` (prepare_deposit_binding_v3 + deposit_step2a_v3). step2b is NEVER
 * delegated — it is the user's own CA debit. Returns the 2 relayer tx hashes. A `self_submit`
 * 200 (gas breaker open / reserve low) surfaces as a `relayer_self_submit:<reason>` error for the
 * client fallback. Returns undefined when relayerUrl is unset (deposit-delegate then unavailable).
 */
export function buildDefaultDepositRelayerSubmitter(
  config: CoordinatorConfig,
  fetchImpl: typeof fetch = fetch,
):
  | ((args: unknown) => Promise<{ accepted: boolean; txHashes: string[]; simulated: boolean }>)
  | undefined {
  const relayerUrl = config.relayerUrl;
  if (!relayerUrl) return undefined;
  const bearer = config.relayerBearerToken;
  return async (args: unknown) => {
    const url = new URL("/v3/relayer/submit/deposit", relayerUrl).toString();
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    const res = await fetchImpl(url, { method: "POST", headers, body: JSON.stringify(args) });
    let body: Record<string, unknown> | null = null;
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      body = null;
    }
    if (!res.ok) {
      const errCode = body && typeof body.error === "string" ? body.error : `http_${res.status}`;
      const errMsg = body && typeof body.message === "string" ? body.message : "unknown";
      throw new Error(`relayer responded ${res.status} (${errCode}): ${errMsg}`);
    }
    if (body && body.action === "self_submit") {
      const reason = typeof body.reason === "string" ? body.reason : "unknown";
      throw new Error(`relayer_self_submit: ${reason}`);
    }
    const txHashes = body?.txHashes;
    if (
      !body ||
      typeof body.accepted !== "boolean" ||
      !Array.isArray(txHashes) ||
      txHashes.length === 0 ||
      typeof body.simulated !== "boolean"
    ) {
      throw new Error(
        `relayer deposit response missing required fields (accepted/txHashes/simulated); got ${JSON.stringify(body)}`,
      );
    }
    return { accepted: body.accepted, txHashes: txHashes.map(String), simulated: body.simulated };
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
