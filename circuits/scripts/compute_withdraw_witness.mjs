#!/usr/bin/env node
// =============================================================================================
// V2 withdraw circuit witness builder.
//
// Reads the depositor's persisted withdraw witness JSON (output of
// `operator-services/scripts/local_v2_deposit_submit.mjs`) + chain state (root, vault_sequence,
// asset_id_fr) + recipient info (recipient address, derived recipient_hash, ca_payload_hash from
// post-MPCCA-finalize) and emits a circom witness JSON matching
// `circuits/withdrawal_proof.circom` (TREE_DEPTH=20, CHAIN_ID=2 hardcoded, nPublic=8).
//
// Witness shape (matches the input keys the circuit declares):
//   {
//     // publics (8, in declaration order):
//     "root":            "<decimal Fr>",
//     "nullifier_hash":  "<decimal>",
//     "asset_id":        "<decimal>",
//     "recipient_hash":  "<decimal>",
//     "amount_tag":      "<decimal>",
//     "ca_payload_hash": "<decimal>",
//     "request_hash":    "<decimal>",
//     "vault_sequence":  "<decimal>",
//     // privates:
//     "nullifier":       "<decimal>",
//     "secret":          "<decimal>",
//     "amount":          "<decimal u64>",
//     "withdraw_blind":  "<decimal>",
//     "merkle_path":     ["<decimal>", ...20],
//     "merkle_indices":  ["<decimal>", ...20]
//   }
//
// Constraint identities matched off-chain (must equal what the circuit recomputes):
//   commitment       = Compose5(nullifier, secret, asset_id, amount, POOL_ID=0)
//   nullifier_hash   = Poseidon([nullifier])
//   amount_tag       = Compose6(amount, withdraw_blind, recipient_hash, asset_id, CHAIN_ID=2,
//                               vault_sequence)
//   request_hash     = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id,
//                               vault_sequence, CHAIN_ID=2)
//   root             = Merkle inclusion of commitment at leaf 0 in depth-20 Poseidon tree
//                      with all-zero siblings (computed via poseidon_merkle.mjs).
//
// recipient_hash is computed via Move's `derive_address_hash(recipient, "EUNOMA_RECIPIENT_V2")`:
//   addr_bytes = BCS(address)                  // 32 raw bytes
//   hi  = byte_slice_padded(addr_bytes, 0, 16) // first 16 bytes, right-padded to 32 with zeros
//   lo  = byte_slice_padded(addr_bytes, 16, 32)// last 16 bytes, right-padded to 32 with zeros
//   dom = bytes_to_field_le32("EUNOMA_RECIPIENT_V2") // ASCII, right-padded to 32 with zeros
//   recipient_hash = Poseidon([dom, hi, lo])   // 3-input
//
// Args:
//   --depositor-witness PATH       required. Output of local_v2_deposit_submit.mjs (v2_depositor_witness_v1).
//   --recipient HEX                required. 32-byte Aptos address (0x-prefixed).
//   --vault-sequence N             required. u64 from BridgeVault.vault_sequence.
//   --root HEX                     required. 32-byte LE root from local_record_known_root_v2 output.
//   --ca-payload-hash HEX          required. 32-byte LE Fr-safe ca_payload_hash (via caPayloadHashFrV2).
//   --commitment-tree PATH         M9: required when --testnet. Multi-leaf commitment tree artifact.
//                                  Without it, the legacy single-leaf path (leaf 0 + zero siblings)
//                                  is used — local-fixture only.
//   --testnet                      M9: asserts multi-leaf path; --commitment-tree must be present and
//                                  the depositor's commitment must be found in the tree.
//   --withdraw-blind-hex HEX       optional. 32-byte LE Fr blinding; auto-generates if omitted.
//   --output PATH                  optional. Write witness JSON here (0o600); default = stdout.
//
// Stdout JSON header (always — even when --output writes the witness to disk):
//   { ok, witnessPath, leafIndex, treeRootHex, treeTranscriptHash, mode: "multi_leaf"|"legacy_single_leaf",
//     publics: {...}, withdraw_blind_hex }
//
// Privacy:
//   Witness JSON carries plaintext nullifier + secret + withdraw_blind + amount. Output file is
//   chmod 0o600 if --output given. This file MUST stay client-side. NEVER POST it to coordinator
//   or deoperator services. leafIndex is public-derivable (depositCount-1) and is included in the
//   stdout header so the orchestrator can write a PUBLIC withdraw_tree_context side-car artifact.
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
      "                               [--commitment-tree PATH] [--testnet] \\\n" +
      "                               [--withdraw-blind-hex HEX] [--output PATH]",
  );
  process.exit(0);
}

const depositorWitnessPath = getArg("--depositor-witness");
const recipientArg = getArg("--recipient");
const vaultSequenceArg = getArg("--vault-sequence");
const rootArg = getArg("--root");
const caPayloadHashArg = getArg("--ca-payload-hash");
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

function hexToLe32(hex) {
  const norm = require32ByteHex("hex", hex);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(norm.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function aptosAddrToBcsBytes(addrHex) {
  // Aptos address is 32 bytes. Allow short-form hex like 0xa → pad LEFT to 32 bytes.
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
const amountOctas = String(witness.amountOctas ?? "");
if (!/^[0-9]+$/.test(amountOctas)) {
  console.error(`amountOctas malformed: ${amountOctas}`);
  process.exit(2);
}

// Generate or parse withdraw_blind.
let withdrawBlindHex;
if (withdrawBlindArg) {
  withdrawBlindHex = require32ByteHex("--withdraw-blind-hex", withdrawBlindArg);
} else {
  // Generate Fr-bounded random scalar: 32 bytes LE with top 2 bits cleared (matches deposit
  // script's frRandom convention; ensures value < BN254 Fr modulus).
  const buf = randomBytes(32);
  buf[31] &= 0x3f;
  withdrawBlindHex = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Vault sequence.
if (!/^[0-9]+$/.test(vaultSequenceArg)) {
  console.error(`--vault-sequence must be decimal u64; got ${vaultSequenceArg}`);
  process.exit(2);
}

// Required public 32-byte hex.
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
const amountLe = u64ToLe32(amountOctas);
const withdrawBlindLe = hexToLe32(withdrawBlindHex);
const assetIdLe = hexToLe32(assetIdHex);
const caPayloadHashLe = hexToLe32(caPayloadHashHex);
const rootLe = hexToLe32(rootHex);
const vaultSequenceLe = u64ToLe32(vaultSequenceArg);
const chainIdLe = u8ToLe32(CHAIN_ID);
const poolIdLe = u8ToLe32(POOL_ID);

const nullifierHashLe = hash1(nullifierLe);

// ---- recompute commitment + amount_tag + request_hash (off-chain echo of circuit) ---------
const commitmentLe = compose5(nullifierLe, secretLe, assetIdLe, amountLe, poolIdLe);
const amountTagLe = compose6(
  amountLe,
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
// M9: if --commitment-tree is supplied, look up the depositor's commitment in the multi-leaf tree
// and produce its real leaf-index path. Otherwise fall back to the M8 single-leaf helper
// (rejected when --testnet is set; already gated above).
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

// Cross-check: --root must match the recomputed root.
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
  // privates
  nullifier: le32ToDec(nullifierLe),
  secret: le32ToDec(secretLe),
  amount: amountOctas,
  withdraw_blind: le32ToDec(withdrawBlindLe),
  merkle_path: merklePathBig.map((b) => b.toString()),
  merkle_indices: merkleIndicesBig.map((b) => b.toString()),
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
  },
  withdraw_blind_hex: withdrawBlindHex.startsWith("0x")
    ? withdrawBlindHex
    : `0x${withdrawBlindHex}`,
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
  // No --output → print summary + witness to stdout (caller pipes wherever).
  process.stdout.write(JSON.stringify({ ...summary, witness: witnessJson }, null, 2) + "\n");
}
