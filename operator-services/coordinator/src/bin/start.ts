import { configFromEnv } from "../config.js";
import { buildCoordinatorServer } from "../server.js";

const cfg = configFromEnv();
const { server } = buildCoordinatorServer(cfg);
await server.listen({ host: cfg.host, port: cfg.port });
console.log(`coordinator listening on ${cfg.host}:${cfg.port}`);
