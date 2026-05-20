#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const args = new Set(process.argv.slice(2));
const force = args.has("--force");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);

const cargo = toolPath("cargo");
const run = spawnSync(
  cargo,
  [
    "run",
    "--quiet",
    "--manifest-path",
    "crypto-worker-rust/Cargo.toml",
    "--bin",
    "eunoma-crypto-worker",
    "--",
    "init-ca-dkg-v2-hpke-local",
    "--state-root",
    stateRoot,
    ...(force ? ["--force"] : []),
  ],
  {
    cwd: serviceRoot,
    env: {
      ...process.env,
      RUSTC: process.env.RUSTC ?? toolPath("rustc"),
      RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
    },
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  },
);

if (run.status !== 0) {
  process.stderr.write(run.stderr);
  process.exit(run.status ?? 1);
}

process.stdout.write(run.stdout);

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
