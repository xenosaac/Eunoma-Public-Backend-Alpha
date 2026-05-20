import { configFromEnv } from "../config.js";
import { buildRelayerServer, createAptosCliSubmitter } from "../server.js";

let cfg;
try {
  cfg = configFromEnv();
} catch (err) {
  // RELAYER_BEARER_TOKEN missing (or other config rejection). Surface the
  // message verbatim — it tells the operator EXACTLY what env var to set.
  console.error(`relayer config error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
}

if (!cfg.bridgePackageAddress) {
  console.error(
    "BRIDGE_PACKAGE_ADDRESS env var is not set — relayer cannot encode the --function-id for `aptos move run`.",
  );
  process.exit(2);
}

const submitter = createAptosCliSubmitter(cfg.bridgePackageAddress, cfg.adminProfile, {
  submit: cfg.submitEnabled,
});

const server = buildRelayerServer({
  bearerToken: cfg.bearerToken,
  submitter,
});

await server.listen({ host: cfg.host, port: cfg.port });

if (cfg.allowNoAuth) {
  // Loud warning: the operator opted out of bearer-token auth via
  // RELAYER_ALLOW_NO_AUTH=1. Only valid for local-dev smoke scripts.
  console.warn(
    "[relayer] WARNING: RELAYER_ALLOW_NO_AUTH=1 — submit route is UNAUTHENTICATED. Local-dev only.",
  );
}

console.log(
  `relayer listening on ${cfg.host}:${cfg.port} (submitEnabled=${cfg.submitEnabled} bearerAuth=${
    cfg.bearerToken ? "on" : "off"
  } adminProfile=${cfg.adminProfile ?? "(unset)"} bridgePackage=${cfg.bridgePackageAddress})`,
);
