import { configFromEnv } from "../config.js";
import { buildRelayerServer, createAptosCliSubmitter } from "../server.js";

const cfg = configFromEnv();

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

console.log(
  `relayer listening on ${cfg.host}:${cfg.port} (submitEnabled=${cfg.submitEnabled} adminProfile=${
    cfg.adminProfile ?? "(unset)"
  } bridgePackage=${cfg.bridgePackageAddress})`,
);
