#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLocalClusterPlan, renderEnvFiles } from "@eunoma/deop-protocol";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const args = new Set(process.argv.slice(2));
const force = args.has("--force");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const clusterDir = resolve(stateRoot, "cluster");

mkdirSync(clusterDir, { recursive: true, mode: 0o700 });
chmodSync(clusterDir, 0o700);

const frost = runFrostInit();
const ca = runCaInit();
const hpke = runCaDkgV2HpkeInit();
const plan = buildLocalClusterPlan({
  stateRoot,
  vaultEk: ca.vault_ek,
  aptosNodeUrl: process.env.APTOS_NODE_URL,
  dkgEpoch: ca.dkg_epoch,
  frost: {
    groupPublicKey: frost.group_public_key,
    verifyingShares: frost.verifying_shares.map((share) => ({
      slot: share.slot,
      frostVerifyingShare: share.frost_verifying_share,
    })),
  },
  caDkgV2: {
    hpkePublicKeys: hpke.slots.map((slot) => ({
      slot: slot.slot,
      hpkePublicKey: slot.hpkePublicKey,
    })),
  },
});

writeSecretJson(resolve(clusterDir, "local-cluster.json"), plan);
writePublicJson(resolve(clusterDir, "roster.json"), {
  ...plan.roster,
  rosterHash: plan.rosterHash,
});
if (plan.caDkgV2Roster) {
  writePublicJson(resolve(clusterDir, "ca-dkg-v2-roster.json"), {
    ...plan.caDkgV2Roster,
    caDkgV2RosterHash: plan.caDkgV2RosterHash,
  });
}
renderEnvFiles(plan, clusterDir);

console.log(JSON.stringify({
  ok: true,
  stateRoot,
  clusterDir,
  rosterHash: plan.rosterHash,
  caDkgV2RosterHash: plan.caDkgV2RosterHash,
  caDkgTranscriptHash: ca.transcript_hash,
  vaultEk: ca.vault_ek,
  coordinator: `http://127.0.0.1:${plan.coordinator.port}`,
  relayer: `http://127.0.0.1:${plan.relayer.port}`,
}, null, 2));

function runFrostInit() {
  const cargo = toolPath("cargo");
  const env = {
    ...process.env,
    RUSTC: process.env.RUSTC ?? toolPath("rustc"),
    RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
  };
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
      "init-frost-local",
      "--state-root",
      stateRoot,
      ...(force ? ["--force"] : []),
    ],
    {
      cwd: serviceRoot,
      env,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (run.status !== 0) {
    process.stderr.write(run.stderr);
    process.exit(run.status ?? 1);
  }
  return JSON.parse(run.stdout);
}

function runCaDkgV2HpkeInit() {
  const cargo = toolPath("cargo");
  const env = {
    ...process.env,
    RUSTC: process.env.RUSTC ?? toolPath("rustc"),
    RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
  };
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
      env,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (run.status !== 0) {
    process.stderr.write(run.stderr);
    process.exit(run.status ?? 1);
  }
  return JSON.parse(run.stdout);
}

function runCaInit() {
  const cargo = toolPath("cargo");
  const env = {
    ...process.env,
    RUSTC: process.env.RUSTC ?? toolPath("rustc"),
    RUSTDOC: process.env.RUSTDOC ?? toolPath("rustdoc"),
  };
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
      "init-ca-local",
      "--state-root",
      stateRoot,
      "--dkg-epoch",
      process.env.DKG_EPOCH ?? "1",
      ...(force ? ["--force"] : []),
    ],
    {
      cwd: serviceRoot,
      env,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (run.status !== 0) {
    process.stderr.write(run.stderr);
    process.exit(run.status ?? 1);
  }
  return JSON.parse(run.stdout);
}

function writePublicJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o644 });
}

function writeSecretJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
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
