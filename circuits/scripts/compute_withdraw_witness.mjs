#!/usr/bin/env node
// =============================================================================================
// V2 withdraw circuit witness builder — A6 amount_p binding (2026-05-23).
//
// Reads the depositor's persisted withdraw witness JSON (output of
// `operator-services/scripts/local_v2_deposit_submit.mjs`) + chain state (root, vault_sequence,
// asset_id_fr) + recipient info (recipient address, derived recipient_hash, ca_payload_hash from
// post-MPCCA-finalize) + amount_p (4 × 32B Ristretto compressed Pedersen, must byte-equal deposit
// time's amount_p — depositor regenerates via SDK ConfidentialTransfer.create with deterministic
// transferAmountRandomness = HKDF(secret)) and emits a circom witness JSON matching
// `circuits/withdrawal_proof.circom` (A6: 9 publics, 51 privates).
//
// Witness shape:
//   {
//     // publics (9):
//     "root":            "<decimal Fr>",
//     "nullifier_hash":  "<decimal>",
//     "asset_id":        "<decimal>",
//     "recipient_hash":  "<decimal>",
//     "amount_tag":      "<decimal>",
//     "ca_payload_hash": "<decimal>",
//     "request_hash":    "<decimal>",
//     "vault_sequence":  "<decimal>",
//     "amount_p_digest": "<decimal>",
//     // privates (51):
//     "nullifier":       "<decimal>",
//     "secret":          "<decimal>",
//     "withdraw_blind":  "<decimal>",
//     "merkle_path":     ["<decimal>", ...20],
//     "merkle_indices":  ["<decimal>", ...20],
//     "amount_p_limbs":  ["<decimal>", ...8]
//   }
//
// Constraint identities (must equal what the circuit recomputes):
//   amount_p_digest  = Poseidon8(amount_p_limbs[0..7])
//   commitment       = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID=0)
//   nullifier_hash   = Poseidon([nullifier])
//   amount_tag       = Compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, CHAIN_ID=2,
//                               vault_sequence)
//   request_hash     = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id,
//                               vault_sequence, CHAIN_ID=2)
//   root             = Merkle inclusion of commitment at leaf in depth-20 Poseidon tree.
//
// recipient_hash derivation: Move's `derive_address_hash(recipient, "EUNOMA_RECIPIENT_V2")`
//   addr_bytes = BCS(address)                  // 32 raw bytes
//   hi  = byte_slice_padded(addr_bytes, 0, 16) // first 16 bytes, right-padded to 32 with zeros
//   lo  = byte_slice_padded(addr_bytes, 16, 32)// last 16 bytes, right-padded to 32 with zeros
//   dom = bytes_to_field_le32("EUNOMA_RECIPIENT_V2")
//   recipient_hash = Poseidon([dom, hi, lo])
//
// Args:
//   --depositor-witness PATH       required. v2_depositor_witness_v1 (must carry amountPHex now).
//   --recipient HEX                required.
//   --vault-sequence N             required.
//   --root HEX                     required.
//   --ca-payload-hash HEX          required.
//   --amount-p-hex HEX             optional. 128-byte hex (4 × 32B amount_p concat). If omitted,
//                                  read from depositor-witness `amountPHex` field (A6 deposit always
//                                  writes this). CLI override fails loud if it mismatches witness
//                                  (transfer amount_p must byte-equal deposit's by design).
//   --commitment-tree PATH         M9: multi-leaf path.
//   --testnet                      M9: asserts multi-leaf path.
//   --withdraw-blind-hex HEX       optional. auto-generates if omitted.
//   --output PATH                  optional. Write witness JSON; default = stdout.
//
// Stdout JSON header (always):
//   { ok, witnessPath, leafIndex, treeRootHex, treeTranscriptHash, mode, publics: {...},
//     withdraw_blind_hex, amount_p_digest_hex }
//
// Privacy:
//   Witness JSON carries plaintext secrets. File mode 0o600 if --output. NEVER POST.
// =============================================================================================
import { writeFileSync, readFileSync, chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const args = process.argv.slice(2);
function getArg(name, required = true) {
  const idx = args.indexOf(name);
  if (idx < 0 || idx + 1 >= args.length) {
    if (required) {
      console.error(`missing required arg: ${name}`);
      process.exit(2);
    }
    return undefined;
  }
  return args[idx + 1];
}
function hasFlag(name) {
  return args.includes(name);
}

if (hasFlag("--help") || hasFlag("-h")) {
  console.log(
    "usage: compute_withdraw_witness --depositor-witness PATH --recipient HEX \\\n" +
      "                               --vault-sequence N --root HEX --ca-payload-hash HEX \\\n" +
      "                               [--amount-p-hex HEX] [--commitment-tree PATH] [--testnet] \\\n" +
      "                               [--withdraw-blind-hex HEX] [--output PATH]",
  );
  process.exit(0);
}

const depositorWitnessPath = getArg("--depositor-witness");
const recipientArg = getArg("--recipient");
const vaultSequenceArg = getArg("--vault-sequence");
const rootArg = getArg("--root");
const caPayloadHashArg = getArg("--ca-payload-hash");
const amountPHexArg = getArg("--amount-p-hex", false);
const commitmentTreeArg = getArg("--commitment-tree", false);
const testnetFlag = hasFlag("--testnet");
const withdrawBlindArg = getArg("--withdraw-blind-hex", false);
const outputArg = getArg("--output", false);

if (testnetFlag && !commitmentTreeArg) {
  console.error(JSON.stringify({ error: "testnet_requires_commitment_tree" }));
  process.exit(2);
}

const CHAIN_ID = 2;
const POOL_ID = 0;
const TREE_DEPTH = 20;
const RECIPIENT_DOMAIN = "EUNOMA_RECIPIENT_V2";

function require32ByteHex(name, value) {
  const norm = String(value ?? "").replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(norm)) {
    console.error(`${name} must be 32-byte hex (64 chars); got "${value}" (${norm.length} chars)`);
    process.exit(2);
  }
  return norm;
}

function require128ByteHex(name, value) {
  const norm = String(value ?? "").replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{256}$/.test(norm)) {
    console.error(`${name} must be 128-byte hex (256 chars; 4 × 32B amount_p concat); got ${norm.length} chars`);
    process.exit(2);
  }
  return norm;
}

function hexToLe32(hex) {
  const norm = require32ByteHex("hex", hex);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(norm.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function aptosAddrToBcsBytes(addrHex) {
  const norm = String(addrHex ?? "").replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(norm) || norm.length === 0 || norm.length > 64) {
    console.error(`recipient must be 0x-prefixed hex up to 32 bytes; got "${addrHex}"`);
    process.exit(2);
  }
  const padded = norm.padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function u64ToLe32(decStr) {
  let n = BigInt(decStr);
  if (n < 0n || n >= 1n << 64n) {
    console.error(`u64 out of range: ${decStr}`);
    process.exit(2);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function u8ToLe32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    console.error(`u8 out of range: ${value}`);
    process.exit(2);
  }
  const out = new Uint8Array(32);
  out[0] = value;
  return out;
}

function utf8ToLe32(str) {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length > 32) {
    console.error(`utf8 too long for Fr: ${str}`);
    process.exit(2);
  }
  const out = new Uint8Array(32);
  out.set(bytes, 0);
  return out;
}

function le32ToDec(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i -= 1) {
    n = (n << 8n) | BigInt(buf[i]);
  }
  return n.toString();
}
function le32ToHex(buf) {
  return (
    "0x" +
    Array.from(buf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

// A6: split 4 × 32B amount_p into 8 × 16B LE limbs (each < 2^128, fits BN254 Fr).
function amountPHexToLimbs(hex) {
  const clean = require128ByteHex("amount-p-hex", hex);
  const limbs = [];
  for (let pointIdx = 0; pointIdx < 4; pointIdx += 1) {
    const pointStart = pointIdx * 64;
    let lo = 0n;
    for (let b = 0; b < 16; b += 1) {
      const byte = BigInt(parseInt(clean.slice(pointStart + b * 2, pointStart + b * 2 + 2), 16));
      lo |= byte << (8n * BigInt(b));
    }
    let hi = 0n;
    for (let b = 0; b < 16; b += 1) {
      const byte = BigInt(
        parseInt(clean.slice(pointStart + 32 + b * 2, pointStart + 32 + b * 2 + 2), 16),
      );
      hi |= byte << (8n * BigInt(b));
    }
    limbs.push(lo, hi);
  }
  return limbs;
}

function bigToLe32(value) {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// Parse depositor witness.
let witness;
try {
  witness = JSON.parse(readFileSync(depositorWitnessPath, "utf8"));
} catch (err) {
  console.error(`failed to read --depositor-witness ${depositorWitnessPath}: ${err?.message ?? err}`);
  process.exit(2);
}
if (witness?.schema !== "v2_depositor_witness_v1") {
  console.error(
    `unexpected schema: ${witness?.schema} (expected v2_depositor_witness_v1)`,
  );
  process.exit(2);
}
const nullifierHex = require32ByteHex("nullifierHex", witness.nullifierHex);
const secretHex = require32ByteHex("secretHex", witness.secretHex);
const assetIdHex = require32ByteHex("assetIdHex", witness.assetIdHex);

// A6: resolve amount_p_hex from CLI override OR depositor witness.
let resolvedAmountPHex;
if (amountPHexArg) {
  resolvedAmountPHex = require128ByteHex("--amount-p-hex", amountPHexArg);
  if (witness.amountPHex) {
    const witnessAmountP = require128ByteHex("witness.amountPHex", witness.amountPHex);
    if (resolvedAmountPHex !== witnessAmountP) {
      console.error(
        `--amount-p-hex (${resolvedAmountPHex.slice(0, 16)}...) mismatch with witness.amountPHex (` +
          `${witnessAmountP.slice(0, 16)}...). Transfer amount_p MUST byte-equal deposit amount_p (A6 vote conservation).`,
      );
      process.exit(2);
    }
  }
} else {
  if (!witness.amountPHex) {
    console.error(
      "depositor witness missing amountPHex (A6: required for transfer amount_p byte-binding). " +
        "Re-run local_v2_deposit_submit.mjs with A6 to regenerate, or pass --amount-p-hex explicitly.",
    );
    process.exit(2);
  }
  resolvedAmountPHex = require128ByteHex("witness.amountPHex", witness.amountPHex);
}

// Generate or parse withdraw_blind.
let withdrawBlindHex;
if (withdrawBlindArg) {
  withdrawBlindHex = require32ByteHex("--withdraw-blind-hex", withdrawBlindArg);
} else {
  const buf = randomBytes(32);
  buf[31] &= 0x3f;
  withdrawBlindHex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

if (!/^[0-9]+$/.test(vaultSequenceArg)) {
  console.error(`--vault-sequence must be decimal u64; got ${vaultSequenceArg}`);
  process.exit(2);
}

const rootHex = require32ByteHex("--root", rootArg);
const caPayloadHashHex = require32ByteHex("--ca-payload-hash", caPayloadHashArg);

// ---- Poseidon setup -----------------------------------------------------------------------
const { buildPoseidon } = await import("circomlibjs");
const poseidon = await buildPoseidon();
const F = poseidon.F;

function frFromLe(le32) {
  return F.fromRprLE(le32, 0);
}
function frToLe(el) {
  const out = new Uint8Array(32);
  F.toRprLE(out, 0, el);
  return out;
}
function hash1(a) {
  return frToLe(poseidon([frFromLe(a)]));
}
function hash2(a, b) {
  return frToLe(poseidon([frFromLe(a), frFromLe(b)]));
}
function hash3(a, b, c) {
  return frToLe(poseidon([frFromLe(a), frFromLe(b), frFromLe(c)]));
}
// Compose8 = hash_3(hash_3(in[0..2]), hash_3(in[3..5]), hash_2(in[6..7]))
// Matches circuit Compose8 template + Move eunoma_pool::poseidon_bn254 (hash_2/hash_3 only).
function compose8(le32x8) {
  const a = hash3(le32x8[0], le32x8[1], le32x8[2]);
  const b = hash3(le32x8[3], le32x8[4], le32x8[5]);
  const c = hash2(le32x8[6], le32x8[7]);
  return hash3(a, b, c);
}
function compose5(a, b, c, d, e) {
  return hash2(hash3(a, b, c), hash2(d, e));
}
function compose6(a, b, c, d, e, f) {
  return hash2(hash3(a, b, c), hash3(d, e, f));
}

// ---- derive recipient_hash ----------------------------------------------------------------
const recipientBcs = aptosAddrToBcsBytes(recipientArg);
function bytePadTo32(slice) {
  const out = new Uint8Array(32);
  out.set(slice.slice(0, 16), 0);
  return out;
}
const recipientHiLe = bytePadTo32(recipientBcs.slice(0, 16));
const recipientLoLe = bytePadTo32(recipientBcs.slice(16, 32));
const recipientDomainLe = utf8ToLe32(RECIPIENT_DOMAIN);
const recipientHashLe = hash3(recipientDomainLe, recipientHiLe, recipientLoLe);

// ---- derive nullifier_hash ----------------------------------------------------------------
const nullifierLe = hexToLe32(nullifierHex);
const secretLe = hexToLe32(secretHex);
const withdrawBlindLe = hexToLe32(withdrawBlindHex);
const assetIdLe = hexToLe32(assetIdHex);
const caPayloadHashLe = hexToLe32(caPayloadHashHex);
const rootLe = hexToLe32(rootHex);
const vaultSequenceLe = u64ToLe32(vaultSequenceArg);
const chainIdLe = u8ToLe32(CHAIN_ID);
const poolIdLe = u8ToLe32(POOL_ID);

const nullifierHashLe = hash1(nullifierLe);

// ---- A6: amount_p limbs + digest ----------------------------------------------------------
const amountPLimbsBig = amountPHexToLimbs(resolvedAmountPHex);
const amountPLimbsLe = amountPLimbsBig.map(bigToLe32);
const amountPDigestLe = compose8(amountPLimbsLe);

// ---- recompute commitment + amount_tag + request_hash (off-chain echo of circuit) ---------
// A6: amount_p_digest replaces plaintext amount in commitment + amount_tag.
const commitmentLe = compose5(nullifierLe, secretLe, assetIdLe, amountPDigestLe, poolIdLe);
const amountTagLe = compose6(
  amountPDigestLe,
  withdrawBlindLe,
  recipientHashLe,
  assetIdLe,
  chainIdLe,
  vaultSequenceLe,
);
const requestHashLe = compose6(
  amountTagLe,
  recipientHashLe,
  caPayloadHashLe,
  assetIdLe,
  vaultSequenceLe,
  chainIdLe,
);

// ---- Cross-check: depositor-stored commitment must match the recomputed one ---------------
const depositorCommitmentHex = require32ByteHex(
  "depositor witness commitmentHex",
  witness.commitmentHex,
);
const recomputedCommitmentHex = Array.from(commitmentLe)
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");
if (depositorCommitmentHex !== recomputedCommitmentHex) {
  console.error(
    `commitment mismatch — depositor witness says ${depositorCommitmentHex} but recomputed ${recomputedCommitmentHex}. ` +
      "Witness JSON or chain inputs may be stale; aborting.",
  );
  process.exit(2);
}

// ---- Compute Merkle path + indices ---------------------------------------------------------
const dirHere = dirname(fileURLToPath(import.meta.url));
const merkleHelperPath = resolve(dirHere, "poseidon_merkle.mjs");
const treeHelperPath = resolve(dirHere, "commitment_tree_v2.mjs");
const { computeMerkleRootAndPathSingleLeaf, leBytesToBig, bigToLE32, le32ToHex: le32ToHexHelp } =
  await import(`file://${merkleHelperPath}`);

const commitmentBig = leBytesToBig(commitmentLe);

let merklePathBig;
let merkleIndicesBig;
let recomputedRootBig;
let leafIndexResolved = 0;
let mode = "legacy_single_leaf";
let treeTranscriptHash = null;

if (commitmentTreeArg) {
  const { CommitmentTreeV2 } = await import(`file://${treeHelperPath}`);
  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(commitmentTreeArg, "utf8"));
  } catch (err) {
    console.error(`failed to read --commitment-tree ${commitmentTreeArg}: ${err?.message ?? err}`);
    process.exit(2);
  }
  let tree;
  try {
    tree = await CommitmentTreeV2.deserialize(snapshot);
  } catch (err) {
    console.error(`commitment_tree deserialize failed: ${err?.message ?? err}`);
    process.exit(2);
  }
  if (tree.depth !== TREE_DEPTH) {
    console.error(`tree depth mismatch: tree=${tree.depth}, circuit=${TREE_DEPTH}`);
    process.exit(2);
  }
  let pathResult;
  try {
    pathResult = await tree.pathForCommitment(commitmentBig);
  } catch (err) {
    console.error(`pathForCommitment failed: ${err?.message ?? err}`);
    process.exit(2);
  }
  merklePathBig = pathResult.path;
  merkleIndicesBig = pathResult.indices;
  leafIndexResolved = pathResult.leafIndex;
  recomputedRootBig = await tree.root();
  treeTranscriptHash = snapshot.transcriptHash;
  mode = "multi_leaf";
} else {
  const result = await computeMerkleRootAndPathSingleLeaf(commitmentBig, TREE_DEPTH);
  merklePathBig = result.merklePathBig;
  merkleIndicesBig = result.merkleIndicesBig;
  recomputedRootBig = result.rootBig;
  leafIndexResolved = 0;
}

const recomputedRootLE = bigToLE32(recomputedRootBig);
const recomputedRootHex = Array.from(recomputedRootLE)
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

const rootHexLower = rootHex.toLowerCase();
if (recomputedRootHex !== rootHexLower) {
  console.error(
    `root mismatch — --root says 0x${rootHexLower} but recomputed 0x${recomputedRootHex}. ` +
      (mode === "multi_leaf"
        ? "Check that --root matches the commitment_tree_v2 latestRootHex."
        : "Check that --root is the depth-20 single-leaf Poseidon root."),
  );
  process.exit(2);
}

// ---- Build witness JSON --------------------------------------------------------------------
const witnessJson = {
  // publics (declaration order)
  root: le32ToDec(rootLe),
  nullifier_hash: le32ToDec(nullifierHashLe),
  asset_id: le32ToDec(assetIdLe),
  recipient_hash: le32ToDec(recipientHashLe),
  amount_tag: le32ToDec(amountTagLe),
  ca_payload_hash: le32ToDec(caPayloadHashLe),
  request_hash: le32ToDec(requestHashLe),
  vault_sequence: vaultSequenceArg,
  amount_p_digest: le32ToDec(amountPDigestLe),
  // privates
  nullifier: le32ToDec(nullifierLe),
  secret: le32ToDec(secretLe),
  withdraw_blind: le32ToDec(withdrawBlindLe),
  merkle_path: merklePathBig.map((b) => b.toString()),
  merkle_indices: merkleIndicesBig.map((b) => b.toString()),
  amount_p_limbs: amountPLimbsBig.map((b) => b.toString()),
};

const summary = {
  ok: true,
  witnessPath: outputArg ?? null,
  leafIndex: leafIndexResolved,
  mode,
  treeRootHex: `0x${rootHexLower}`,
  treeTranscriptHash,
  publics: {
    root: rootHex,
    nullifier_hash: le32ToHex(nullifierHashLe),
    asset_id: assetIdHex.startsWith("0x") ? assetIdHex : `0x${assetIdHex}`,
    recipient_hash: le32ToHex(recipientHashLe),
    amount_tag: le32ToHex(amountTagLe),
    ca_payload_hash: caPayloadHashHex.startsWith("0x") ? caPayloadHashHex : `0x${caPayloadHashHex}`,
    request_hash: le32ToHex(requestHashLe),
    vault_sequence: vaultSequenceArg,
    amount_p_digest: le32ToHex(amountPDigestLe),
  },
  withdraw_blind_hex: withdrawBlindHex.startsWith("0x")
    ? withdrawBlindHex
    : `0x${withdrawBlindHex}`,
  amount_p_digest_hex: le32ToHex(amountPDigestLe),
};

if (outputArg) {
  writeFileSync(outputArg, JSON.stringify(witnessJson, null, 2) + "\n", { mode: 0o600 });
  try {
    chmodSync(outputArg, 0o600);
  } catch {
    /* best-effort; mode flag should already have set it */
  }
  console.error(`wrote witness JSON → ${outputArg} (0o600)`);
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
} else {
  process.stdout.write(JSON.stringify({ ...summary, witness: witnessJson }, null, 2) + "\n");
}
