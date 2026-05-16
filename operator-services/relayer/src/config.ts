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

  return {
    host: env.RELAYER_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.RELAYER_PORT ?? "4300", 10),
    bearerToken,
    allowNoAuth,
    bridgePackageAddress: env.BRIDGE_PACKAGE_ADDRESS,
    adminProfile: env.ADMIN_PROFILE,
    submitEnabled: env.RELAYER_SUBMIT_ENABLED === "1",
  };
}
