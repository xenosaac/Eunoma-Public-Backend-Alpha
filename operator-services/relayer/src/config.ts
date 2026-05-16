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
export interface RelayerConfig {
  host: string;
  port: number;
  bearerToken?: string;
  bridgePackageAddress?: string;
  adminProfile?: string;
  submitEnabled: boolean;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
  return {
    host: env.RELAYER_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.RELAYER_PORT ?? "4300", 10),
    bearerToken: env.RELAYER_BEARER_TOKEN,
    bridgePackageAddress: env.BRIDGE_PACKAGE_ADDRESS,
    adminProfile: env.ADMIN_PROFILE,
    submitEnabled: env.RELAYER_SUBMIT_ENABLED === "1",
  };
}
