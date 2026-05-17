#!/usr/bin/env node
// =============================================================================================
// V2 depositor-side Groth16 prover wrapper for the deposit-binding circuit.
// Mirrors operator-services/scripts/local_generate_withdraw_proof.mjs.
//
// Generates the Groth16 BN254 proof that Move's `assert_valid_deposit_binding_proof` verifies
// inside deposit_with_commitment_v2. Reads a witness JSON file (matching the circom
// `deposit_binding.circom` input shape) + uses the pre-built artifacts at `circuits/generated/`:
//   - deposit_binding_final.zkey         (proving key)
//   - deposit_binding_js/*.wasm          (witness generator)
//   - deposit_binding_vk.json            (verification key — for local self-check)
//
// Output: a JSON file `{ proofHex, publicSignals }` consumable by local_v2_deposit_submit.mjs
// via stdin or env-var passthrough.
//
// Witness JSON shape (matches circuits/inputs/valid_input.json):
//   {
//     // publics (4 — order matters):
//     "commitment":      "<decimal Fr>",
//     "amount_tag":      "<decimal Fr>",
//     "asset_id":        "<decimal Fr>",
//     "vault_addr_hash": "<decimal Fr>",
//     // privates:
//     "nullifier":     "<decimal Fr>",
//     "secret":        "<decimal Fr>",
//     "amount":        "<decimal u64>",
//     "deposit_blind": "<decimal Fr>"
//   }
//
// Args:
//   --witness-json PATH      required. Path to the witness input JSON file.
//   --output PATH            optional. Defaults to stdout (prints {proofHex, publicSignals}).
//   --circuit-root PATH      optional. Defaults to <repo>/circuits.
//
// Exit codes:
//   0    success
//   1    generic failure
//   2    usage error
//  50    circuit artifacts not built (zkey / wasm missing) — run `cd circuits && npm run all`.
//  51    witness JSON malformed.
//  52    snarkjs proof generation failed.
//  53    proof self-verification failed (proof generated but didn't verify against VK).
// =============================================================================================
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXIT_SUCCESS = 0;
const EXIT_USAGE_ERROR = 2;
const EXIT_CIRCUIT_NOT_BUILT = 50;
const EXIT_WITNESS_MALFORMED = 51;
const EXIT_PROVE_FAILED = 52;
const EXIT_SELF_VERIFY_FAILED = 53;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..");

const args = process.argv.slice(2);
let witnessJsonPath;
let outputPath;
let circuitRoot = resolve(repoRoot, "circuits");

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case "--witness-json":
      witnessJsonPath = args[++i];
      break;
    case "--output":
      outputPath = args[++i];
      break;
    case "--circuit-root":
      circuitRoot = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_generate_deposit_proof --witness-json PATH [--output PATH] [--circuit-root PATH]",
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

if (!witnessJsonPath) {
  console.error("missing required --witness-json");
  process.exit(EXIT_USAGE_ERROR);
}

const zkeyPath = resolve(circuitRoot, "generated", "deposit_binding_final.zkey");
const wasmPath = resolve(
  circuitRoot,
  "generated",
  "deposit_binding_js",
  "deposit_binding.wasm",
);
const vkPath = resolve(circuitRoot, "generated", "deposit_binding_vk.json");

for (const [name, path] of [
  ["proving key (zkey)", zkeyPath],
  ["circuit wasm", wasmPath],
  ["verification key", vkPath],
]) {
  if (!existsSync(path)) {
    console.error(
      JSON.stringify(
        {
          ok: false,
          error: "circuit_not_built",
          message:
            `${name} not found at ${path}. Run \`cd circuits && bash scripts/compile.sh && bash scripts/setup_dev.sh\` ` +
            "to build artifacts. Note: dev setup is for local testing only; real testnet requires the on-chain VK to match the zkey.",
          missing: path,
        },
        null,
        2,
      ),
    );
    process.exit(EXIT_CIRCUIT_NOT_BUILT);
  }
}

let witnessInput;
try {
  witnessInput = JSON.parse(readFileSync(witnessJsonPath, "utf8"));
} catch (err) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "witness_malformed",
        message: err instanceof Error ? err.message : "unable to parse witness JSON",
        path: witnessJsonPath,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_WITNESS_MALFORMED);
}

let snarkjs;
try {
  const snarkjsPath = resolve(circuitRoot, "node_modules", "snarkjs", "build", "main.cjs");
  snarkjs = await import(`file://${snarkjsPath}`);
} catch (err) {
  try {
    snarkjs = await import("snarkjs");
  } catch (innerErr) {
    console.error(
      JSON.stringify(
        {
          ok: false,
          error: "snarkjs_unavailable",
          message:
            "snarkjs is required to generate proofs. Install via `cd circuits && npm install`.",
          underlying:
            (err instanceof Error ? err.message : String(err)) +
            "; fallback: " +
            (innerErr instanceof Error ? innerErr.message : String(innerErr)),
        },
        null,
        2,
      ),
    );
    process.exit(EXIT_CIRCUIT_NOT_BUILT);
  }
}

let proof;
let publicSignals;
try {
  const result = await snarkjs.groth16.fullProve(witnessInput, wasmPath, zkeyPath);
  proof = result.proof;
  publicSignals = result.publicSignals;
} catch (err) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "prove_failed",
        message: err instanceof Error ? err.message : "snarkjs.groth16.fullProve threw",
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_PROVE_FAILED);
}

const vk = JSON.parse(readFileSync(vkPath, "utf8"));
const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
if (!verified) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "self_verify_failed",
        message:
          "Generated Groth16 proof failed self-verification against deposit_binding_vk.json. " +
          "The witness is inconsistent with the circuit constraints. Re-check witness inputs " +
          "(commitment, amount_tag, asset_id, vault_addr_hash, nullifier/secret/amount/deposit_blind preimages).",
        proof,
        publicSignals,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_SELF_VERIFY_FAILED);
}

// Encode the proof into the byte format the Move-side verifier expects.
// Move's assert_valid_deposit_binding_proof takes proof: vector<u8>, which is the encoded
// (pi_a[2], pi_b[2][2], pi_c[2]) tuple — 8 BN254 field elements × 32 bytes each = 256 bytes.
// BN254 G2 uses (c1, c0) order; pi_b[i] = (c0, c1) from snarkjs, so we swap.
function fr32(decString) {
  let n = BigInt(decString);
  const buf = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    buf[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return buf;
}
const proofBytes = new Uint8Array(8 * 32);
const proofParts = [
  proof.pi_a[0],
  proof.pi_a[1],
  proof.pi_b[0][1],
  proof.pi_b[0][0],
  proof.pi_b[1][1],
  proof.pi_b[1][0],
  proof.pi_c[0],
  proof.pi_c[1],
];
for (let i = 0; i < 8; i += 1) {
  proofBytes.set(fr32(proofParts[i]), i * 32);
}
const proofHex = Array.from(proofBytes)
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

const output = {
  proofHex,
  publicSignals,
  proof,
  message:
    "V2 deposit-binding Groth16 proof generated + self-verified. proofHex is consumable by " +
    "deposit_with_commitment_v2 as the `deposit_binding_proof` argument.",
};

if (outputPath) {
  writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
  console.error(`wrote ${outputPath}`);
  console.log(proofHex);
} else {
  console.log(JSON.stringify(output, null, 2));
}
process.exit(EXIT_SUCCESS);
