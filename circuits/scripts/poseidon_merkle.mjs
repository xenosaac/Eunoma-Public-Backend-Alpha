#!/usr/bin/env node
// =============================================================================================
// Pure Poseidon BN254 Merkle helpers — shared between record_known_root admin CLI + withdraw
// witness builder + any future indexer-side accumulator.
//
// Hash function: 2-input Poseidon BN254. Byte-identical to:
//   - aptos_std::poseidon_bn254::hash_2 (Move-side, used by Move tests)
//   - withdrawal_proof.circom MerkleInclusion's Switcher+Poseidon(2) (Groth16 side)
//   - circomlibjs's reference Poseidon BN254 (CLI side, this file)
//
// All Merkle math is on BigInt scalars in the BN254 Fr field. Byte-level I/O uses 32-byte
// little-endian (matches Aptos's FormatFrLsb and the Move bridge's de_fr_with_error).
//
// Convention: leaf is always at the LEFT child of each level (path_index = 0 throughout).
// This is the only leaf-0 / empty-otherwise-tree shape the alpha needs; partial-batch trees
// will require a different helper.
// =============================================================================================
import { buildPoseidon } from "circomlibjs";

let _poseidon;
async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

/**
 * Decode a 32-byte LE byte array into a BigInt scalar.
 */
export function leBytesToBig(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`leBytesToBig requires Uint8Array(32), got length ${bytes?.length}`);
  }
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; --i) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

/**
 * Encode a BigInt scalar as 32 bytes little-endian.
 */
export function bigToLE32(v) {
  if (typeof v !== "bigint") {
    throw new Error(`bigToLE32 requires bigint, got ${typeof v}`);
  }
  const out = new Uint8Array(32);
  let r = v;
  for (let i = 0; i < 32; ++i) {
    out[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  if (r !== 0n) {
    throw new Error("bigToLE32: value exceeds 32 bytes");
  }
  return out;
}

/**
 * Hex string ("0x..." or bare) → 32-byte LE bytes.
 */
export function hexToLE32(hex) {
  const norm = hex.replace(/^0x/, "");
  if (norm.length !== 64) throw new Error(`hexToLE32: expected 64 hex chars, got ${norm.length}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; ++i) {
    out[i] = parseInt(norm.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * 32-byte LE bytes → 0x-prefixed hex string.
 */
export function le32ToHex(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`le32ToHex requires Uint8Array(32), got length ${bytes?.length}`);
  }
  let s = "0x";
  for (let i = 0; i < 32; ++i) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

/**
 * 2-input Poseidon BN254 — `hash_2(left, right)`.
 * Returns BigInt scalar.
 */
export async function hash2(left, right) {
  const p = await getPoseidon();
  return p.F.toObject(p([left, right]));
}

/**
 * Build empty-subtree sibling array [ZERO[0], ZERO[1], ..., ZERO[depth-1]].
 * ZERO[0] = 0; ZERO[k+1] = Poseidon([ZERO[k], ZERO[k]]).
 * siblings[k] is the right-child sibling at level k (used when the cursor is at path_index=0).
 */
export async function buildEmptySiblings(depth) {
  if (!Number.isInteger(depth) || depth < 1) {
    throw new Error(`buildEmptySiblings: depth must be positive integer, got ${depth}`);
  }
  const siblings = new Array(depth);
  let z = 0n;
  siblings[0] = z;
  for (let k = 1; k < depth; k++) {
    z = await hash2(z, z);
    siblings[k] = z;
  }
  return siblings;
}

/**
 * Compute Merkle root + path for a single leaf at index 0 in an otherwise-empty tree.
 *
 * Returns {
 *   rootBig: BigInt,
 *   rootLE32: Uint8Array(32),
 *   merklePathBig: BigInt[depth],     // siblings at each level (all from ZERO chain)
 *   merkleIndicesBig: BigInt[depth],  // all zeros (leaf always left child)
 * }
 */
export async function computeMerkleRootAndPathSingleLeaf(leafBig, depth) {
  if (typeof leafBig !== "bigint") {
    throw new Error(`computeMerkleRootAndPathSingleLeaf: leafBig must be bigint`);
  }
  const merklePathBig = await buildEmptySiblings(depth);
  const merkleIndicesBig = new Array(depth).fill(0n);
  let cur = leafBig;
  for (let k = 0; k < depth; ++k) {
    cur = await hash2(cur, merklePathBig[k]);
  }
  return {
    rootBig: cur,
    rootLE32: bigToLE32(cur),
    merklePathBig,
    merkleIndicesBig,
  };
}

// CLI mode — `node poseidon_merkle.mjs --leaf-hex 0x...` prints {root, path, indices}.
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  let leafHex;
  let depthStr = "20";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--leaf-hex") leafHex = args[++i];
    else if (args[i] === "--depth") depthStr = args[++i];
    else if (args[i] === "--help" || args[i] === "-h") {
      console.log("usage: poseidon_merkle --leaf-hex HEX [--depth N=20]");
      process.exit(0);
    }
  }
  if (!leafHex) {
    console.error("--leaf-hex required");
    process.exit(2);
  }
  const depth = Number.parseInt(depthStr, 10);
  if (!Number.isInteger(depth) || depth < 1) {
    console.error("--depth must be positive integer");
    process.exit(2);
  }
  const leafLE = hexToLE32(leafHex);
  const leafBig = leBytesToBig(leafLE);
  const result = await computeMerkleRootAndPathSingleLeaf(leafBig, depth);
  console.log(
    JSON.stringify(
      {
        leafHex,
        depth,
        rootHex: le32ToHex(result.rootLE32),
        merklePathDec: result.merklePathBig.map((b) => b.toString()),
        merkleIndicesDec: result.merkleIndicesBig.map((b) => b.toString()),
      },
      null,
      2,
    ),
  );
}
