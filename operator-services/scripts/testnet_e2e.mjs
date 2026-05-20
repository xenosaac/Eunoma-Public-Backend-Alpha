#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const planPath = resolve(stateRoot, "cluster/local-cluster.json");

run("npm", ["test"]);
run("npm", ["run", "privacy:scan"]);
runRustTests();

if (!hasCurrentLocalFixturePlan()) {
  run("node", ["scripts/local_cluster_config.mjs", "--force"]);
}
const plan = JSON.parse(readFileSync(planPath, "utf8"));

console.log(JSON.stringify({
  ok: true,
  command: "local:smoke",
  gates: [
    "workspace-tests",
    "privacy-scan",
    "rust-frost",
    "rust-ca-dkg-registration-sigma",
    "online-frost-dkg",
    "local-roster"
  ],
  optionalGates: {
    "local:online-frost-dkg-smoke": "HTTP cluster 4-phase DKG roundtrip; opt-in heavyweight",
    "local:frost-rotation-smoke": "Full FROST rotation propagation closed loop (DKG -> apply -> restart -> sign -> verify rotated, fail seeded); opt-in heavyweight",
    "testnet:rotate-frost-config": "Operator-driven rotation tx (simulate by default, --submit to land)"
  },
  rosterHash: plan.rosterHash,
  coordinator: `http://127.0.0.1:${plan.coordinator.port}`,
  relayer: `http://127.0.0.1:${plan.relayer.port}`,
  note: "Local verifier gates passed with ca_local fixture. The online-frost-dkg gate is exercised in-process by the Rust frost_dkg_v2_online_roundtrip test (runRustTests above); the heavyweight HTTP cluster path is opt-in via npm run local:online-frost-dkg-smoke. The full rotation propagation loop (in-memory roster + on-chain admin tx) is opt-in via npm run local:frost-rotation-smoke and npm run testnet:rotate-frost-config. This is not a testnet flow; npm run testnet:e2e remains fail-closed until MPCCA finalize emits a real CA payload."
}, null, 2));

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: serviceRoot,
    stdio: "inherit",
    env: process.env,
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function runRustTests() {
  const cargo = toolPath("cargo");
  const result = spawnSync(cargo, ["test", "--manifest-path", "crypto-worker-rust/Cargo.toml"], {
    cwd: serviceRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      RUSTC: process.env.RUSTC ?? toolPath("rustc"),
      RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
    },
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function hasCurrentLocalFixturePlan() {
  if (!existsSync(planPath)) return false;
  try {
    const plan = JSON.parse(readFileSync(planPath, "utf8"));
    return plan.roster?.caDkgScheme === "ca_local";
  } catch {
    return false;
  }
}

function toolPath(name) {
  const upper = name.toUpperCase();
  if (process.env[upper]) return process.env[upper];
  const home = process.env.HOME;
  const candidates = [
    name,
    home ? `${home}/.cargo/bin/${name}` : undefined,
    home ? `${home}/.rustup/toolchains/stable-aarch64-apple-darwin/bin/${name}` : undefined,
    home ? `${home}/.rustup/toolchains/1.86.0-aarch64-apple-darwin/bin/${name}` : undefined,
    home ? `${home}/.rustup/toolchains/1.85.0-aarch64-apple-darwin/bin/${name}` : undefined,
    home ? `${home}/.rustup/toolchains/1.83.0-aarch64-apple-darwin/bin/${name}` : undefined,
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate)) ?? name;
}
