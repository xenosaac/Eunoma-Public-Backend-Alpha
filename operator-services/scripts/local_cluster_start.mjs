#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnCluster } from "./_lib/spawn_cluster.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_STATE_ROOT ?? process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const planPath = resolve(stateRoot, "cluster/local-cluster.json");

if (!existsSync(planPath)) {
  console.error("local cluster config not found. Run `npm run local:cluster:config -- --force` first.");
  process.exit(2);
}

const plan = remapPortablePlan(JSON.parse(readFileSync(planPath, "utf8")), stateRoot);
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

function remapPortablePlan(plan, currentStateRoot) {
  const previousStateRoot = typeof plan.stateRoot === "string" ? plan.stateRoot : undefined;
  const previousRepoRoot =
    previousStateRoot && previousStateRoot.includes("/operator-services/")
      ? previousStateRoot.slice(0, previousStateRoot.indexOf("/operator-services/"))
      : undefined;

  const replacements = [
    previousStateRoot && previousStateRoot !== currentStateRoot
      ? [previousStateRoot, currentStateRoot]
      : undefined,
    previousRepoRoot && previousRepoRoot !== repoRoot ? [previousRepoRoot, repoRoot] : undefined,
  ].filter(Boolean);

  if (replacements.length === 0) return plan;

  const remap = (value) => {
    if (typeof value === "string") {
      for (const [from, to] of replacements) {
        if (value === from) return to;
        if (value.startsWith(`${from}/`)) return `${to}${value.slice(from.length)}`;
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(remap);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, remap(child)]));
    }
    return value;
  };

  return remap(plan);
}
