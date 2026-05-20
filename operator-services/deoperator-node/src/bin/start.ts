import { configFromEnv } from "../config.js";
import { buildDeoperatorNodeServer } from "../server.js";

const cfg = configFromEnv();
const { server } = buildDeoperatorNodeServer(cfg);

await server.listen({ host: cfg.host, port: cfg.port });
console.log(`deoperator-node ${cfg.nodeId} listening on ${cfg.host}:${cfg.port}`);
