#!/usr/bin/env node
// =============================================================================================
// Milestone 6 sub-milestone 6-b — User-side withdraw Groth16 prover wrapper.
//
// Generates the Groth16 BN254 proof that Move's `assert_valid_withdraw_proof` verifies.
// Reads a witness JSON file (matching the circom `withdrawal_proof.circom` input shape)
// + uses the pre-built artifacts at `circuits/generated/`:
//   - withdrawal_proof_final.zkey  (proving key)
//   - withdrawal_proof_js/*.wasm   (witness generator)
//   - withdrawal_proof_vk.json     (verification key — for local self-check)
//
// Output: a JSON file `{ proofHex, publicSignals }` consumable by testnet_e2e_v2.mjs
// via env var `EUNOMA_TESTNET_WITHDRAW_PROOF` (set to proofHex).
//
// Witness JSON shape (matches circuits/inputs/withdraw_valid_input.json):
//   {
//     // publics (8):
//     "root": "<decimal>",
//     "nullifier_hash": "<decimal>",
//     "asset_id": "<decimal>",
//     "recipient_hash": "<decimal>",
//     "amount_tag": "<decimal>",
//     "ca_payload_hash": "<decimal>",
//     "request_hash": "<decimal>",
//     "vault_sequence": "<decimal>",
//     // privates:
//     "nullifier": "<decimal>",
//     "secret": "<decimal>",
//     "amount": "<decimal>",
//     "withdraw_blind": "<decimal>",
//     "chain_id": "<decimal>",
//     "merkle_path": ["<decimal>", ...],
//     "merkle_indices": ["<decimal>", ...],
//     // etc — see circuits/scripts/build_withdraw_input.js for the canonical witness builder.
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
const EXIT_GENERIC_FAILURE = 1;
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
        "usage: local_generate_withdraw_proof --witness-json PATH [--output PATH] [--circuit-root PATH]",
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

const zkeyPath = resolve(circuitRoot, "generated", "withdrawal_proof_final.zkey");
const wasmPath = resolve(
  circuitRoot,
  "generated",
  "withdrawal_proof_js",
  "withdrawal_proof.wasm",
);
const vkPath = resolve(circuitRoot, "generated", "withdrawal_proof_vk.json");

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
            `${name} not found at ${path}. Run \`cd circuits && npm run all\` to compile the circuit ` +
            "+ run the dev trusted setup + extract artifacts. Note: dev setup is for local testing only; " +
            "real testnet requires a proper trusted setup ceremony (M6-d).",
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
  // snarkjs lives in the circuits/ package (separate from operator-services/). Resolve via
  // the file:// URL so this script works without operator-services depending on snarkjs.
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
            "snarkjs is required to generate proofs. Install via `cd circuits && npm install` " +
            "to bring it in to circuits/node_modules, then re-run.",
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

// Self-verify (defense-in-depth — if the proof doesn't verify locally, the chain won't either).
const vk = JSON.parse(readFileSync(vkPath, "utf8"));
const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
if (!verified) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "self_verify_failed",
        message:
          "Generated Groth16 proof failed self-verification against withdrawal_proof_vk.json. " +
          "The witness is inconsistent with the circuit constraints. Re-check witness inputs " +
          "(commitment, Merkle path, nullifier preimage, amount_tag, request_hash).",
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
// Move's assert_valid_withdraw_proof takes proof: vector<u8>, which is the BCS-encoded
// (pi_a[2], pi_b[2][2], pi_c[2]) tuple — 8 BN254 field elements × 32 bytes each = 256 bytes.
function fr32(decString) {
  // Aptos's FormatG1Uncompr / FormatG2Uncompr / FormatFrLsb all use LITTLE-ENDIAN byte
  // order (least-significant byte first). snarkjs returns proof field elements as decimal
  // BigInts, so we encode LSB at buf[0] and MSB at buf[31].
  let n = BigInt(decString);
  const buf = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    buf[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return buf;
}
const proofBytes = new Uint8Array(8 * 32);
// G2 uncompressed byte order matches the VK extractor in circuits/scripts/extract_withdraw_vk.js:
//   x_c0 || x_c1 || y_c0 || y_c1, each as 32-byte LE.
const proofParts = [
  proof.pi_a[0],
  proof.pi_a[1],
  proof.pi_b[0][0],  // x.c0
  proof.pi_b[0][1],  // x.c1
  proof.pi_b[1][0],  // y.c0
  proof.pi_b[1][1],  // y.c1
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
    "M6-b user-side withdraw Groth16 proof generated + self-verified. The proofHex hex string " +
    "is consumable by testnet_e2e_v2.mjs via EUNOMA_TESTNET_WITHDRAW_PROOF.",
};

if (outputPath) {
  writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");
  console.error(`wrote ${outputPath}`);
  console.log(proofHex);
} else {
  console.log(JSON.stringify(output, null, 2));
}
process.exit(EXIT_SUCCESS);
