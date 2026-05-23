#!/usr/bin/env node
// Rotate Eunoma V2 A6 Groth16 verification keys on testnet.
//
// Default mode simulates each Aptos entry call. Real submit requires BOTH:
//   --submit
//   RELAYER_SUBMIT_ENABLED=1
//
// This script uses the Aptos CLI profile signer. It never reads or prints private keys.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { hexArg } from "./_lib/format_aptos_args.mjs";

const EXIT_USAGE = 2;
const EXIT_APTOS_SPAWN = 3;
const EXIT_TX_HASH_PARSE = 4;
const EXIT_TX_REVERTED = 5;
const EXIT_CONFIRM_TIMEOUT = 6;

const BRIDGE_DEFAULT =
  "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

let submit = false;
let profile = process.env.ADMIN_PROFILE ?? "";
let bridgePackage = process.env.BRIDGE_PACKAGE_ADDRESS ?? BRIDGE_DEFAULT;
let nodeUrl =
  process.env.APTOS_NODE_URL ??
  process.env.APTOS_TESTNET_NODE_URL ??
  "https://fullnode.testnet.aptoslabs.com";
let depositVkPath = resolve(repoRoot, "circuits/generated/deposit_binding_vk.json");
let withdrawVkPath = resolve(repoRoot, "circuits/generated/withdrawal_proof_vk.json");
let outputPath = resolve(
  serviceRoot,
  ".agent-local/eunoma-v2/coordinator/testnet_rotate_a6_vks.json",
);

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--submit") {
    submit = true;
  } else if (arg === "--profile") {
    profile = requireValue(args, ++i, "--profile");
  } else if (arg === "--bridge-address") {
    bridgePackage = requireValue(args, ++i, "--bridge-address");
  } else if (arg === "--node-url") {
    nodeUrl = requireValue(args, ++i, "--node-url");
  } else if (arg === "--deposit-vk") {
    depositVkPath = resolve(requireValue(args, ++i, "--deposit-vk"));
  } else if (arg === "--withdraw-vk") {
    withdrawVkPath = resolve(requireValue(args, ++i, "--withdraw-vk"));
  } else if (arg === "--output") {
    outputPath = resolve(requireValue(args, ++i, "--output"));
  } else if (arg === "--help" || arg === "-h") {
    usage(0);
  } else {
    console.error(`unknown argument: ${arg}`);
    usage(EXIT_USAGE);
  }
}

bridgePackage = normalizeAddress(bridgePackage);

if (submit && !profile) {
  console.error("ADMIN_PROFILE or --profile is required for --submit");
  process.exit(EXIT_USAGE);
}
if (submit && process.env.RELAYER_SUBMIT_ENABLED !== "1") {
  console.error("--submit requires RELAYER_SUBMIT_ENABLED=1");
  process.exit(EXIT_USAGE);
}

const depositVk = readVk(depositVkPath, {
  label: "deposit_binding",
  expectedPublic: 5,
  expectedIc: 6,
});
const withdrawVk = readVk(withdrawVkPath, {
  label: "withdrawal_proof",
  expectedPublic: 9,
  expectedIc: 10,
});

const operations = [
  {
    name: "rotate_deposit_binding_vk_v2_a6",
    args: vkMoveArgs(depositVk),
  },
  {
    name: "rotate_prepared_deposit_binding_vk_v2",
    args: [],
  },
  {
    name: "rotate_withdraw_proof_vk_v2_a6",
    args: vkMoveArgs(withdrawVk),
  },
  {
    name: "rotate_prepared_withdraw_proof_vk_v2",
    args: [],
  },
];

const report = {
  schema: "eunoma_testnet_rotate_a6_vks_v1",
  bridgePackage,
  profile: profile || "<default>",
  nodeUrl,
  submit,
  depositVkPath,
  withdrawVkPath,
  operations: [],
  createdAtUnixMs: Date.now(),
};

console.log(`bridge=${bridgePackage}`);
console.log(`mode=${submit ? "submit" : "simulate"}`);
console.log(`deposit IC=${depositVk.ic.length}, withdraw IC=${withdrawVk.ic.length}`);

for (const op of operations) {
  const result = await runMove(op.name, op.args);
  report.operations.push(result);
}

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(`wrote report ${outputPath}`);

if (!submit) {
  console.log("");
  console.log("simulate complete. Re-run with --submit and RELAYER_SUBMIT_ENABLED=1 to rotate on chain.");
}

function usage(code) {
  const out = code === 0 ? console.log : console.error;
  out(
    [
      "usage: testnet_rotate_a6_vks.mjs [--profile NAME] [--bridge-address HEX]",
      "                                  [--node-url URL] [--deposit-vk PATH]",
      "                                  [--withdraw-vk PATH] [--output PATH] [--submit]",
      "",
      "env:",
      "  ADMIN_PROFILE           aptos CLI profile for admin signer",
      "  BRIDGE_PACKAGE_ADDRESS  defaults to the current Eunoma testnet bridge",
      "  APTOS_NODE_URL          used for tx confirmation polling",
      "  RELAYER_SUBMIT_ENABLED  must be 1 with --submit",
    ].join("\n"),
  );
  process.exit(code);
}

function requireValue(values, index, flag) {
  const value = values[index];
  if (!value || value.startsWith("--")) {
    console.error(`${flag} requires a value`);
    usage(EXIT_USAGE);
  }
  return value;
}

function normalizeAddress(value) {
  const clean = String(value).replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length > 64) {
    throw new Error(`invalid Aptos address: ${value}`);
  }
  return `0x${clean.padStart(64, "0")}`;
}

function readVk(path, { label, expectedPublic, expectedIc }) {
  if (!existsSync(path)) {
    throw new Error(`${label} VK not found: ${path}`);
  }
  const vk = JSON.parse(readFileSync(path, "utf8"));
  if (vk.protocol !== "groth16") {
    throw new Error(`${label}: expected groth16 protocol, got ${vk.protocol}`);
  }
  if (vk.nPublic !== expectedPublic) {
    throw new Error(`${label}: expected ${expectedPublic} public inputs, got ${vk.nPublic}`);
  }
  if (!Array.isArray(vk.IC) || vk.IC.length !== expectedIc) {
    throw new Error(`${label}: expected IC length ${expectedIc}, got ${vk.IC?.length}`);
  }
  const out = {
    alpha_g1: g1Uncompr(vk.vk_alpha_1),
    beta_g2: g2Uncompr(vk.vk_beta_2),
    gamma_g2: g2Uncompr(vk.vk_gamma_2),
    delta_g2: g2Uncompr(vk.vk_delta_2),
    ic: vk.IC.map(g1Uncompr),
  };
  assertHexLen(`${label}.alpha_g1`, out.alpha_g1, 64);
  assertHexLen(`${label}.beta_g2`, out.beta_g2, 128);
  assertHexLen(`${label}.gamma_g2`, out.gamma_g2, 128);
  assertHexLen(`${label}.delta_g2`, out.delta_g2, 128);
  out.ic.forEach((ic, i) => assertHexLen(`${label}.ic_${i}`, ic, 64));
  return out;
}

function vkMoveArgs(vk) {
  return [
    vk.alpha_g1,
    vk.beta_g2,
    vk.gamma_g2,
    vk.delta_g2,
    ...vk.ic,
  ].map((v) => hexArg(v));
}

async function runMove(functionName, moveArgs) {
  const cliArgs = [
    "move",
    "run",
    "--function-id",
    `${bridgePackage}::eunoma_bridge::${functionName}`,
  ];
  for (const arg of moveArgs) cliArgs.push("--args", arg);
  if (profile) cliArgs.push("--profile", profile);
  if (!submit) cliArgs.push("--simulate");
  if (submit) cliArgs.push("--assume-yes");

  console.log(`\n> aptos ${redactArgs(cliArgs).join(" ")}`);
  const run = spawnSync("aptos", cliArgs, {
    cwd: serviceRoot,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
    env: process.env,
  });
  if (run.error) {
    console.error(`failed to spawn aptos CLI: ${run.error.message}`);
    process.exit(EXIT_APTOS_SPAWN);
  }
  process.stdout.write(run.stdout || "");
  process.stderr.write(run.stderr || "");
  if (run.status !== 0) {
    console.error(`aptos CLI exited with status ${run.status} for ${functionName}`);
    process.exit(run.status ?? 1);
  }

  const result = {
    functionName,
    status: submit ? "submitted" : "simulated",
    txHash: null,
    vmStatus: null,
    completedAtUnixMs: Date.now(),
  };
  if (!submit) return result;

  const txHash = extractTxHash(`${run.stdout || ""}\n${run.stderr || ""}`);
  if (!txHash) {
    console.error(`submit: unable to parse tx hash for ${functionName}`);
    process.exit(EXIT_TX_HASH_PARSE);
  }
  result.txHash = txHash;
  console.log(`submit: ${functionName} tx ${txHash}; polling for confirmation`);
  let confirmation;
  try {
    confirmation = await waitForTx(nodeUrl, txHash, 120_000);
  } catch (err) {
    console.error(`submit: confirmation failed for ${txHash}: ${err.message}`);
    process.exit(EXIT_CONFIRM_TIMEOUT);
  }
  result.vmStatus = confirmation.vmStatus ?? null;
  if (!confirmation.success) {
    console.error(`submit: ${functionName} tx ${txHash} reverted: ${confirmation.vmStatus ?? "unknown"}`);
    process.exit(EXIT_TX_REVERTED);
  }
  console.log(`submit: ${functionName} confirmed`);
  return result;
}

function bigToLE32hex(x) {
  let n = BigInt(x);
  if (n < 0n) throw new Error("negative coordinate");
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`coordinate exceeds 32 bytes: ${BigInt(x).toString(16)}`);
  return out.toString("hex");
}

function g1Uncompr(arr) {
  return bigToLE32hex(arr[0]) + bigToLE32hex(arr[1]);
}

function g2Uncompr(arr) {
  const [x, y] = arr;
  return bigToLE32hex(x[0]) + bigToLE32hex(x[1]) + bigToLE32hex(y[0]) + bigToLE32hex(y[1]);
}

function assertHexLen(label, hex, bytes) {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length !== bytes * 2) {
    throw new Error(`${label}: expected ${bytes} bytes hex, got ${hex.length / 2}`);
  }
}

function redactArgs(values) {
  return values.map((value) => (String(value).length > 96 ? `${String(value).slice(0, 96)}...` : value));
}

function extractTxHash(text) {
  const jsonMatch = text.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  if (jsonMatch) return jsonMatch[1];
  const plainMatch = text.match(/(?:hash|Hash)[^0-9a-fA-Fx]*?(0x[0-9a-fA-F]{64})/);
  if (plainMatch) return plainMatch[1];
  return null;
}

async function waitForTx(fullnodeUrl, txHash, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  const url = new URL(`/v1/transactions/by_hash/${txHash}`, fullnodeUrl).toString();
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const body = await res.json();
        if (body && body.type === "pending_transaction") {
          // keep polling
        } else if (body && typeof body.success === "boolean") {
          return { success: body.success, vmStatus: body.vm_status };
        }
      } else if (res.status !== 404) {
        const text = await res.text();
        throw new Error(`tx poll ${url} -> ${res.status}: ${text}`);
      }
    } catch (err) {
      if (!(err instanceof TypeError)) throw err;
    }
    await new Promise((resolvePoll) => setTimeout(resolvePoll, 1000));
  }
  throw new Error(`tx ${txHash} did not confirm within ${timeoutMs}ms`);
}
