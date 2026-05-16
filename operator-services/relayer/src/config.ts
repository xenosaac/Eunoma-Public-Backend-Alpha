export interface RelayerConfig {
  host: string;
  port: number;
  bearerToken?: string;
  aptosNodeUrl: string;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
  return {
    host: env.RELAYER_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.RELAYER_PORT ?? "4300", 10),
    bearerToken: env.RELAYER_BEARER_TOKEN,
    aptosNodeUrl: env.APTOS_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com/v1",
  };
}
