import { buildDefaultRelayerSubmitter, configFromEnv } from "../config.js";
import { buildCoordinatorServer } from "../server.js";

const cfg = configFromEnv();
// Codex M5b P2 #2: wire production submit-route options from env-driven config.
// stateRoot / chainNodeUrl / chainConfirmationTimeoutMs flow through directly; the
// relayer submitter is constructed from RELAYER_URL + RELAYER_BEARER_TOKEN. Tests
// inject `relayerSubmitter` directly via opts and never reach this factory.
const relayerSubmitter = buildDefaultRelayerSubmitter(cfg);
const { server } = buildCoordinatorServer({
  ...cfg,
  ...(relayerSubmitter ? { relayerSubmitter } : {}),
});
await server.listen({ host: cfg.host, port: cfg.port });
console.log(`coordinator listening on ${cfg.host}:${cfg.port}`);
