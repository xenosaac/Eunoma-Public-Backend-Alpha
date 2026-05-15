import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(here, "..", "..");

export function spawnCluster(plan, opts = {}) {
  const log = opts.log ?? ((name, line) => console.log(`[${name}] ${line}`));
  const onExit = opts.onExit; // optional: (name, code, signal) => void
  const handle = {
    workers: [],
    nodes: [],
    coordinator: null,
    relayer: null,
    plan,
    killed: false,
    serviceRoot,
  };

  for (const worker of plan.workers) {
    handle.workers.push(start(worker.name, cargoArgs(), rustEnv(worker.env), log, onExit, handle));
  }
  for (const node of plan.nodes) {
    handle.nodes.push(
      start(node.name, ["npm", "run", "-w", "@eunoma/deoperator-node", "start"], node.env, log, onExit, handle),
    );
  }
  handle.coordinator = start(
    "coordinator",
    ["npm", "run", "-w", "@eunoma/coordinator", "start"],
    plan.coordinator.env,
    log,
    onExit,
    handle,
  );
  handle.relayer = start(
    "relayer",
    ["npm", "run", "-w", "@eunoma/relayer", "start"],
    plan.relayer.env,
    log,
    onExit,
    handle,
  );

  handle.kill = () => {
    if (handle.killed) return;
    handle.killed = true;
    const all = [...handle.workers, ...handle.nodes, handle.coordinator, handle.relayer];
    for (const child of all) {
      if (child && !child.killed) child.kill("SIGTERM");
    }
  };

  handle.restartCoordinatorAndNodes = (nextPlan) => {
    const plan2 = nextPlan ?? handle.plan;
    if (handle.coordinator && !handle.coordinator.killed) handle.coordinator.kill("SIGTERM");
    for (const node of handle.nodes) {
      if (node && !node.killed) node.kill("SIGTERM");
    }
    handle.nodes = [];
    handle.coordinator = null;
    // Restart with fresh env files. Caller is responsible for waiting on health.
    for (const node of plan2.nodes) {
      handle.nodes.push(
        start(node.name, ["npm", "run", "-w", "@eunoma/deoperator-node", "start"], node.env, log, onExit, handle),
      );
    }
    handle.coordinator = start(
      "coordinator",
      ["npm", "run", "-w", "@eunoma/coordinator", "start"],
      plan2.coordinator.env,
      log,
      onExit,
      handle,
    );
    handle.plan = plan2;
  };

  return handle;
}

function start(name, command, env, log, onExit, handle) {
  const [bin, ...args] = command;
  const child = spawn(bin, args, {
    cwd: serviceRoot,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => emit(name, chunk, log));
  child.stderr.on("data", (chunk) => emit(name, chunk, log));
  child.on("exit", (code, signal) => {
    if (onExit) {
      try {
        onExit(name, code, signal, handle);
      } catch (_err) {
        // ignore — caller's responsibility
      }
    }
  });
  return child;
}

function emit(name, chunk, log) {
  for (const line of chunk.toString().split(/\r?\n/)) {
    if (line.length > 0) log(name, line);
  }
}

function cargoArgs() {
  return [
    toolPath("cargo"),
    "run",
    "--quiet",
    "--manifest-path",
    "crypto-worker-rust/Cargo.toml",
    "--bin",
    "eunoma-crypto-worker",
  ];
}

function rustEnv(env) {
  return {
    ...env,
    RUSTC: process.env.RUSTC ?? toolPath("rustc"),
    RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
  };
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
  ].filter(Boolean);
  const found = candidates.find((candidate) => existsSync(candidate));
  return found ?? name;
}
