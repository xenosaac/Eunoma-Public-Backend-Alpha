#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnCluster } from "./_lib/spawn_cluster.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const planPath = resolve(stateRoot, "cluster/local-cluster.json");

if (!existsSync(planPath)) {
  console.error("local cluster config not found. Run `npm run local:cluster:config -- --force` first.");
  process.exit(2);
}

const plan = JSON.parse(readFileSync(planPath, "utf8"));
const handle = spawnCluster(plan, {
  onExit: (name, code, signal, hdl) => {
    if (code !== 0 && signal !== "SIGTERM" && signal !== "SIGINT") {
      console.error(`[${name}] exited with code ${code ?? signal}`);
      hdl.kill();
    }
  },
});

process.on("SIGINT", () => {
  handle.kill();
  setTimeout(() => process.exit(0), 250).unref();
});
process.on("SIGTERM", () => {
  handle.kill();
  setTimeout(() => process.exit(0), 250).unref();
});
