// LeanIMT (0xbow / Semaphore @zk-kit) — dynamic-depth binary Merkle tree.
//
// MUST match circuits/eunoma_templates.circom::HardenedLeanIMTInclusion exactly:
//   - node with two children = hash2(left, right) ordered by path bit
//   - rightmost odd node at a level propagates up UNCHANGED (no hash)
//   - an empty co-path sibling is encoded as 0n (the circuit treats sibling==0 as "propagate")
//   - actualDepth = number of levels until a single root remains (>=1 for >=2 leaves)
//   - leafIndex is little-endian: bit i selects left(0)/right(1) at level i
//
// hash2 is the circomlibjs-compatible Poseidon BN254 hash_2 (Move/circom byte parity),
// so JS-built roots/paths are identical to what the circuit + Move recompute.
import { hash2 } from "./poseidon_merkle.mjs";

export const LEANIMT_MAX_DEPTH = 32;

// Build a LeanIMT over `leaves` (array of bigint-coercible). Returns { root, depth, levels }.
export async function buildLeanIMT(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("buildLeanIMT: need >=1 leaf");
  }
  const levels = [leaves.map((x) => BigInt(x))];
  let cur = levels[0];
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 < cur.length) next.push(await hash2(cur[i], cur[i + 1]));
      else next.push(cur[i]); // odd node propagates up unchanged
    }
    levels.push(next);
    cur = next;
  }
  return { root: cur[0], depth: levels.length - 1, levels };
}

// Co-path for a leaf, padded to maxDepth with 0n (empty). Returns { siblings, leafIndex, actualDepth }.
export function leanIMTPath(levels, leafIndex, maxDepth = LEANIMT_MAX_DEPTH) {
  const depth = levels.length - 1;
  if (leafIndex < 0 || leafIndex >= levels[0].length) {
    throw new Error(`leanIMTPath: leaf index ${leafIndex} out of range (${levels[0].length})`);
  }
  if (depth > maxDepth) throw new Error(`leanIMTPath: depth ${depth} exceeds maxDepth ${maxDepth}`);
  const siblings = new Array(maxDepth).fill(0n);
  let idx = BigInt(leafIndex);
  for (let level = 0; level < depth; level++) {
    const nodes = levels[level];
    const isRight = (idx & 1n) === 1n;
    const sibIdx = isRight ? idx - 1n : idx + 1n;
    siblings[level] = sibIdx < BigInt(nodes.length) ? nodes[Number(sibIdx)] : 0n;
    idx = idx >> 1n;
  }
  return { siblings, leafIndex, actualDepth: depth };
}

// Convenience: build + path in one call.
export async function leanIMTInclusion(leaves, leafIndex, maxDepth = LEANIMT_MAX_DEPTH) {
  const { root, levels } = await buildLeanIMT(leaves);
  const { siblings, actualDepth } = leanIMTPath(levels, leafIndex, maxDepth);
  return { root, actualDepth, siblings, leafIndex };
}

// Recompute the root from a leaf + co-path, mirroring the circuit (propagate on 0 sibling,
// carry above actualDepth). Used by tests to assert JS↔circuit parity.
export async function leanIMTRootFromPath(leaf, siblings, leafIndex, actualDepth) {
  let node = BigInt(leaf);
  let idx = BigInt(leafIndex);
  for (let i = 0; i < siblings.length; i++) {
    const active = i < actualDepth;
    const sib = BigInt(siblings[i]);
    if (active) {
      if (sib === 0n) {
        // propagate
      } else {
        const isRight = (idx & 1n) === 1n;
        node = isRight ? await hash2(sib, node) : await hash2(node, sib);
      }
    }
    idx = idx >> 1n;
  }
  return node;
}
