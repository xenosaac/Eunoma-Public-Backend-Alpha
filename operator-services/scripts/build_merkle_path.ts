/**
 * Phase 2.Y / W.2 — Multi-leaf Merkle inclusion path builder.
 *
 * Generalizes Phase 2.X's `merklePathFor1LeafTree` to N>=1 leaves at any
 * `leafIndex` in [0, depth^2) so B.5 (and any future deposit) can produce a
 * valid withdraw witness.
 *
 * Hashing convention (per Poseidon_Research/WORK_LOG.md errata R6-4 and
 * AptosShield_Spike/operator/batch_updater.ts:214-228 `frontierInsert`):
 *   - parent = poseidon2(left, right)             (BN254 Poseidon, arity 2)
 *   - empty subtree at EVERY level = ZERO32 = 32 bytes 0x00
 *     (NOT recursive poseidon2(empty[k-1], empty[k-1]) — literal 0x00...00)
 *   - bridge `pool_batch_root_update::update_root_batch` and the spike's
 *     frontier insert both compose `poseidon2(cur, ZERO32)` against literal
 *     ZERO32 at every level when the right subtree is empty, which is what
 *     anchors this convention.
 *
 * Inclusion path semantics:
 *   For a leaf at `leafIndex` (0-based) in a depth-`depth` binary tree with
 *   `leaves.length = N` real leaves placed left-to-right at indices 0..N-1:
 *     - At level k (k = 0..depth-1):
 *         current_index_at_level_k = floor(leafIndex / 2^k)
 *         sibling_index            = current_index_at_level_k XOR 1
 *         sibling_subtree_leaf_lo  = sibling_index << k
 *         sibling_subtree_leaf_hi  = sibling_subtree_leaf_lo + 2^k - 1
 *       If sibling_subtree_leaf_lo >= N (no real leaves under it):
 *         path[k] = ZERO32
 *       Else:
 *         path[k] = hash up the sibling subtree from real leaves (with
 *                   ZERO32 fillers wherever the inner subtree is also empty)
 *     - pathIndices[k] = bit_k of leafIndex (0 = current is left child of its
 *                        parent, 1 = right child)
 *
 * Output:
 *   path:        Uint8Array[depth], each entry exactly 32 bytes
 *   pathIndices: number[depth], each entry in {0, 1}
 *
 * Self-consistency: hashing leaf together with path[0..depth-1] using
 * pathIndices to choose left/right yields the same root regardless of
 * `leafIndex` (computed via `computeMerkleRoot` below).
 */

import { hash2 } from '../shared/src/poseidon_mirror.js';

const ZERO32 = new Uint8Array(32);

/** Frontier-style empty subtree hash at level `level`.
 *   frontierEmpty(0)     = ZERO32
 *   frontierEmpty(k>=1)  = poseidon2(frontierEmpty(k-1), ZERO32)
 *
 * This is the SPIKE convention (= what `pool_batch_root_update::update_root_batch`
 * effectively folds when `cur` builds up from level-0 ZERO32 through poseidon2
 * with literal ZERO32 on the right). NOT the balanced empty-subtree-hash
 * `poseidon2(empty[k-1], empty[k-1])`.
 */
async function frontierEmpty(level: number): Promise<Uint8Array> {
  if (level === 0) return ZERO32;
  const prev = await frontierEmpty(level - 1);
  return await hash2(prev, ZERO32);
}

/** Hash a sibling subtree rooted at level `level`, covering leaves
 * [`leafLo`, `leafLo + 2^level - 1`]. Uses `leaves` for any real leaves
 * within range. Empty positions are handled per spike's frontier convention,
 * which is HYBRID:
 *
 *   - For an EMPTY leaf (level 0, leafLo >= N): return ZERO32.
 *   - For a partial subtree (some leaves real, some empty): recurse normally;
 *     empty positions inside use ZERO32 at level 0 and propagate via poseidon2.
 *   - For a FULLY empty subtree at level k (leafLo >= N):
 *       * if k <= highestActiveLevel (= msb position of N): use `frontierEmpty(k)`
 *         (= recursive poseidon2(empty[k-1], ZERO32) — matches what frontierRoot
 *         would have built up via cur from level 0 to level k as left input).
 *       * if k > highestActiveLevel: return ZERO32 (= literal — frontierRoot at
 *         these levels combines `cur` with literal ZERO32 on the right).
 *
 * This asymmetry mirrors `frontierRoot` in `AptosShield_Spike/operator/batch_updater.ts`
 * exactly. Required so the inclusion proof's fold-up matches chain root computed by
 * `pool_batch_root_update::update_root_batch`.
 *
 * Invariant: callers ensure `level >= 0` and `leafLo % (2^level) === 0`.
 */
async function hashSubtree(
  leaves: Uint8Array[],
  leafLo: number,
  level: number,
  highestActiveLevel: number,
): Promise<Uint8Array> {
  if (level === 0) {
    if (leafLo < leaves.length) {
      const leaf = leaves[leafLo];
      if (leaf.length !== 32) {
        throw new Error(
          `hashSubtree: leaf at index ${leafLo} must be 32 bytes; got ${leaf.length}`,
        );
      }
      return leaf;
    }
    return ZERO32;
  }
  const half = 1 << (level - 1);
  if (leafLo >= leaves.length) {
    // Fully empty subtree
    if (level <= highestActiveLevel) {
      return await frontierEmpty(level);
    }
    return ZERO32;
  }
  const left = await hashSubtree(leaves, leafLo, level - 1, highestActiveLevel);
  const right = await hashSubtree(leaves, leafLo + half, level - 1, highestActiveLevel);
  return hash2(left, right);
}

/** Compute msb position of `n` (highest set bit position).
 *   msbPosition(0) = -1 (no bits set; caller should special-case N=0)
 *   msbPosition(1) = 0
 *   msbPosition(2) = 1
 *   msbPosition(3) = 1
 *   msbPosition(4) = 2
 */
function msbPosition(n: number): number {
  if (n <= 0) return -1;
  let pos = -1;
  let v = n;
  while (v > 0) { pos++; v >>= 1; }
  return pos;
}

/**
 * Compute the inclusion path + path-indices vector for `leafIndex` in a
 * binary Merkle tree of depth `depth` whose first `leaves.length` leaves
 * are populated by `leaves` (left-to-right) and the rest are empty (ZERO32
 * fillers per R6-4).
 */
export async function computeMerklePath(
  leaves: Uint8Array[],
  leafIndex: number,
  depth: number = 20,
): Promise<{ path: Uint8Array[]; pathIndices: number[] }> {
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    throw new Error(`computeMerklePath: leafIndex must be a non-negative integer; got ${leafIndex}`);
  }
  if (!Number.isInteger(depth) || depth < 1 || depth > 32) {
    throw new Error(`computeMerklePath: depth must be in [1,32]; got ${depth}`);
  }
  // depth=20 → 2^20 = 1_048_576 leaves max; safe in JS number.
  const maxLeaves = Math.pow(2, depth);
  if (leafIndex >= maxLeaves) {
    throw new Error(`computeMerklePath: leafIndex ${leafIndex} exceeds 2^${depth}`);
  }
  if (leaves.length > maxLeaves) {
    throw new Error(`computeMerklePath: leaves.length ${leaves.length} exceeds 2^${depth}`);
  }
  // Note: leafIndex MAY be >= leaves.length if caller is computing a
  // "what-if" empty-leaf path; on-chain that wouldn't be a valid inclusion
  // proof since the leaf doesn't exist, but the math still produces a
  // self-consistent root for an all-ZERO32 leaf. We do NOT reject here —
  // caller is responsible for ensuring leafIndex < leaves.length when used
  // for a real withdraw.

  // highestActiveLevel = msb position of leaves.length (= where frontierRoot
  // last combines a populated nodes[k] with cur). Used by hashSubtree to decide
  // recursive frontierEmpty vs literal ZERO32 for fully-empty siblings.
  const highestActiveLevel = msbPosition(leaves.length);

  const path: Uint8Array[] = [];
  const pathIndices: number[] = [];

  for (let k = 0; k < depth; k++) {
    const currentAtLevelK = Math.floor(leafIndex / Math.pow(2, k));
    const siblingAtLevelK = currentAtLevelK ^ 1;
    const subtreeSize = 1 << k; // 2^k leaves
    const siblingLeafLo = siblingAtLevelK * subtreeSize;
    const siblingHash = await hashSubtree(leaves, siblingLeafLo, k, highestActiveLevel);
    path.push(siblingHash);
    pathIndices.push(currentAtLevelK & 1); // bit_k of leafIndex
  }

  return { path, pathIndices };
}

/**
 * Optional helper: given (leaf, path, pathIndices), fold up to root.
 * Useful for self-tests in callers that want to assert the path is valid.
 *
 *   - pathIndices[k] === 0 → current node is LEFT child  → parent = hash2(cur, path[k])
 *   - pathIndices[k] === 1 → current node is RIGHT child → parent = hash2(path[k], cur)
 */
export async function computeMerkleRoot(
  leaf: Uint8Array,
  path: Uint8Array[],
  pathIndices: number[],
): Promise<Uint8Array> {
  if (path.length !== pathIndices.length) {
    throw new Error(
      `computeMerkleRoot: path.length ${path.length} != pathIndices.length ${pathIndices.length}`,
    );
  }
  if (leaf.length !== 32) {
    throw new Error(`computeMerkleRoot: leaf must be 32 bytes; got ${leaf.length}`);
  }
  let cur = leaf;
  for (let k = 0; k < path.length; k++) {
    const sibling = path[k];
    if (sibling.length !== 32) {
      throw new Error(`computeMerkleRoot: path[${k}] must be 32 bytes; got ${sibling.length}`);
    }
    cur = pathIndices[k] === 0
      ? await hash2(cur, sibling)
      : await hash2(sibling, cur);
  }
  return cur;
}
