// Relayer environment-driven configuration.
//
// `submitEnabled` defaults to false: the CLI submitter appends `--simulate`
// unless the env explicitly opts into broadcasting. The default-false posture
// is the documented human-approval boundary — operator review must occur
// before this is flipped on for testnet/mainnet.
//
// `bridgePackageAddress` is the package address of the deployed Move package;
// the CLI submitter splices it into the `--function-id` argument.
//
// `adminProfile` is the name of an aptos CLI profile to sign with. If unset,
// the CLI invocation omits `--profile`, which is sufficient for `--simulate`
// runs but not for real submission.
//
// `bearerToken` is REQUIRED for production. The dev-only override
// `RELAYER_ALLOW_NO_AUTH=1` is opt-in and exists for local-cluster smoke
// scripts only — production deploys must set RELAYER_BEARER_TOKEN.
export interface RelayerConfig {
  host: string;
  port: number;
  bearerToken?: string;
  /**
   * True iff the operator opted in to running with NO bearer-token auth via
   * `RELAYER_ALLOW_NO_AUTH=1`. Surfaced so `start.ts` can log a loud warning.
   */
  allowNoAuth: boolean;
  bridgePackageAddress?: string;
  adminProfile?: string;
  submitEnabled: boolean;
  // ---- CP3 (split-v3 relayer + gas economics) ----
  /**
   * Dedicated LOW-PRIVILEGE aptos CLI profile the v3 submitter signs with. MUST
   * be distinct from `adminProfile` — the v3 withdraw/deposit entries never
   * require admin (the relayer signer is unused for authority; funds move via
   * vault_signer_cap / the user's own signer). A leaked relayer key must not be
   * able to pause/rotate/admin-anything; worst case is wasted gas (recoverable).
   */
  relayerProfile?: string;
  /** Aptos REST fullnode URL for read-only views (vault_sequence, reserve balance, gas price). */
  aptosNodeUrl?: string;
  /** Communal plain-APT gas-reserve account address the relayer draws gas against. */
  reserveAccountAddress?: string;
  /** Circuit breaker: if the network gas unit price exceeds this, the relayer refuses to submit
   *  and signals self-submit instead (protects the reserve from gas spikes). */
  maxGasPriceOctas?: bigint;
  /** Reserve low-water mark: below this the relayer refuses new submissions (fails to self-submit). */
  reserveMinBalanceOctas?: bigint;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
  const bearerToken = env.RELAYER_BEARER_TOKEN;
  const allowNoAuth = env.RELAYER_ALLOW_NO_AUTH === "1";

  // Codex P2 finding: requireBearer is fail-open when expectedToken is
  // undefined. To make the submit route fail closed by default, the config
  // loader rejects a missing RELAYER_BEARER_TOKEN unless the operator has
  // explicitly opted in to no-auth via RELAYER_ALLOW_NO_AUTH=1 (dev-only).
  if (!bearerToken && !allowNoAuth) {
    throw new Error(
      "RELAYER_BEARER_TOKEN is required for production. Set RELAYER_ALLOW_NO_AUTH=1 explicitly for local-dev only.",
    );
  }

  const relayerProfile = env.RELAYER_PROFILE;
  const adminProfile = env.ADMIN_PROFILE;
  // Hard non-admin guard: the v3 relayer key must never be the admin profile. A
  // relayer-host compromise must not leak admin authority. (The v3 entries do not
  // require admin, so a dedicated low-priv profile is always sufficient.)
  if (relayerProfile && adminProfile && relayerProfile === adminProfile) {
    throw new Error(
      "RELAYER_PROFILE must NOT equal ADMIN_PROFILE — the relayer signer must be a dedicated low-privilege key.",
    );
  }
  const parseOptionalBigint = (raw: string | undefined, name: string): bigint | undefined => {
    if (raw === undefined || raw === "") return undefined;
    if (!/^[0-9]+$/.test(raw)) {
      throw new Error(`${name} must be a non-negative integer (octas), got: ${raw}`);
    }
    return BigInt(raw);
  };

  return {
    host: env.RELAYER_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.RELAYER_PORT ?? "4300", 10),
    bearerToken,
    allowNoAuth,
    bridgePackageAddress: env.BRIDGE_PACKAGE_ADDRESS,
    adminProfile,
    submitEnabled: env.RELAYER_SUBMIT_ENABLED === "1",
    relayerProfile,
    aptosNodeUrl: env.APTOS_NODE_URL,
    reserveAccountAddress: env.RESERVE_ACCOUNT_ADDRESS,
    maxGasPriceOctas: parseOptionalBigint(env.RELAYER_MAX_GAS_PRICE_OCTAS, "RELAYER_MAX_GAS_PRICE_OCTAS"),
    reserveMinBalanceOctas: parseOptionalBigint(env.RELAYER_RESERVE_MIN_BALANCE_OCTAS, "RELAYER_RESERVE_MIN_BALANCE_OCTAS"),
  };
}
