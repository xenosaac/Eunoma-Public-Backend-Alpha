import { configFromEnv } from "../config.js";
import { buildRelayerServer } from "../server.js";

const cfg = configFromEnv();
const server = buildRelayerServer(cfg);
await server.listen({ host: cfg.host, port: cfg.port });
console.log(`relayer listening on ${cfg.host}:${cfg.port}`);
