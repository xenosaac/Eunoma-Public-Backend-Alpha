#!/usr/bin/env node
// =============================================================================================
// M9 — Append-only Poseidon BN254 commitment tree.
//
// Replaces the M8 single-leaf-only helper for testnet paths. Hashing primitive is byte-identical
// to:
//   - aptos_std::poseidon_bn254::hash_2 (Move-side)
//   - withdrawal_proof.circom MerkleInclusion's Switcher+Poseidon(2) (Groth16 side)
//   - circomlibjs's reference Poseidon BN254 (CLI side, this file)
//
// Storage: sparse Map per level + cached zero[k] cascade. Append touches O(depth) nodes;
// `_rebuild()` is O(N * depth) — N is the leaf count, depth is 20 for V2 — and is only
// invoked lazily before `root()` / `pathForIndex()` queries.
//
// transcriptHash binds: scheme || depth || leafCount || rootLE || per-leaf{leafLE, depositCount,
// commitmentHex, sender, depositTxHash, txVersion, sequenceNumber} via length-prefixed encoding.
// Any tamper of leaves OR depositMeta invalidates transcriptHash. Verified by `deserialize()`
// which recomputes and asserts equality.
// =============================================================================================
import { keccak_256 } from "@noble/hashes/sha3";
import {
  bigToLE32,
  hash2,
  hexToLE32,
  le32ToHex,
  leBytesToBig,
} from "./poseidon_merkle.mjs";

export const TREE_DEPTH_DEFAULT = 20;
export const COMMITMENT_TREE_SCHEME = "commitment_tree_v2";

const FORBIDDEN_FIELD_NAME = /^(amount|secret|nullifier|.*blind|dk|inverse)$/i;
const FORBIDDEN_FIELD_SUFFIX = /_(amount|secret|nullifier|.*blind|dk|inverse)$/i;

function assertPublicOnlyValue(v, path) {
  if (v === null || v === undefined) return;
  if (typeof v !== "object") return;
  if (Array.isArray(v)) {
    v.forEach((item, i) => assertPublicOnlyValue(item, `${path}[${i}]`));
    return;
  }
  for (const [k, child] of Object.entries(v)) {
    if (FORBIDDEN_FIELD_NAME.test(k) || FORBIDDEN_FIELD_SUFFIX.test(k)) {
      throw new Error(`forbidden_field_in_tree_artifact:${path}.${k}`);
    }
    assertPublicOnlyValue(child, `${path}.${k}`);
  }
}

export function assertTreeArtifactPublicOnly(snapshot) {
  assertPublicOnlyValue(snapshot, "$");
}

function pushFr(enc, big) {
  enc.push(bigToLE32(big));
}

function pushU64LE(enc, n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  enc.push(b);
}

function pushU32LE(enc, n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  enc.push(b);
}

function pushLpString(enc, s) {
  const buf = new TextEncoder().encode(s ?? "");
  pushU32LE(enc, buf.length);
  enc.push(buf);
}

function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export class CommitmentTreeV2 {
  constructor(depth = TREE_DEPTH_DEFAULT) {
    if (!Number.isInteger(depth) || depth < 1 || depth > 32) {
      throw new Error(`invalid depth: ${depth}`);
    }
    this.depth = depth;
    this.leaves = [];
    this.depositMeta = [];
    this.zero = [0n];
    this._nodes = null;
    this._dirty = true;
    this.createdAtUnixMs = Date.now();
  }

  async _ensureZero() {
    for (let k = 1; k <= this.depth; k++) {
      if (this.zero[k] === undefined) {
        this.zero[k] = await hash2(this.zero[k - 1], this.zero[k - 1]);
      }
    }
  }

  // V4 OB1: ordering key is the GLOBAL on-chain `leafIndex` (0-based, monotonic across ALL assets
  // AND across both leaf classes — deposits via DepositConfirmedV4 + change notes via
  // ChangeNoteAppendedV4). The dense gap-check is now on `leafIndex` (expected === current leaf
  // count), NOT the per-asset `depositCount`. `depositCount`/`kind`/`assetType` are retained as
  // PUBLIC per-leaf metadata only (audit/observe cursors); they are NOT the tree ordering key.
  //
  // Back-compat: a legacy single-asset caller that passes only `meta.depositCount` (1-based dense)
  // and no `meta.leafIndex` is mapped to `leafIndex = depositCount - 1` so the same dense stream
  // ingests unchanged.
  append(commitmentBig, meta) {
    if (typeof commitmentBig !== "bigint") {
      throw new Error("append: commitmentBig must be bigint");
    }
    if (!meta || typeof meta !== "object") {
      throw new Error("append: meta must be an object");
    }
    // Resolve the global leaf index (ordering key). Prefer explicit leafIndex; fall back to the
    // legacy 1-based depositCount for single-asset back-compat.
    let leafIndex;
    if (meta.leafIndex !== undefined && meta.leafIndex !== null) {
      if (typeof meta.leafIndex !== "number" || !Number.isInteger(meta.leafIndex)) {
        throw new Error(`append: meta.leafIndex must be an integer, got ${meta.leafIndex}`);
      }
      leafIndex = meta.leafIndex;
    } else if (typeof meta.depositCount === "number") {
      leafIndex = meta.depositCount - 1; // legacy 1-based dense → 0-based global
    } else {
      throw new Error("append: meta.leafIndex (or legacy meta.depositCount) required");
    }
    if (leafIndex !== this.leaves.length) {
      throw new Error(
        `leaf_index_gap: expected ${this.leaves.length}, got ${leafIndex}`,
      );
    }
    if (
      typeof meta.commitmentHex !== "string" ||
      !/^0x[0-9a-fA-F]{64}$/.test(meta.commitmentHex)
    ) {
      throw new Error(`append: meta.commitmentHex must be 0x-prefixed 64-hex, got ${meta.commitmentHex}`);
    }
    const rebuiltBig = leBytesToBig(hexToLE32(meta.commitmentHex));
    if (rebuiltBig !== commitmentBig) {
      throw new Error("append: commitmentBig does not match leBytesToBig(hexToLE32(commitmentHex))");
    }
    const kind = meta.kind === "change" ? "change" : "deposit";
    this.leaves.push(commitmentBig);
    this.depositMeta.push({
      leafIndex,
      kind, // "deposit" (DepositConfirmedV4) | "change" (ChangeNoteAppendedV4)
      // depositCount is a PER-ASSET observer cursor; only meaningful for deposit leaves.
      depositCount: typeof meta.depositCount === "number" ? meta.depositCount : 0,
      assetType: typeof meta.assetType === "string" ? meta.assetType.toLowerCase() : "",
      depositTxHash: typeof meta.depositTxHash === "string" ? meta.depositTxHash : "",
      txVersion: String(meta.txVersion ?? ""),
      sequenceNumber: String(meta.sequenceNumber ?? ""),
      sender: typeof meta.sender === "string" ? meta.sender.toLowerCase() : "",
      commitmentHex: meta.commitmentHex.toLowerCase(),
    });
    this._dirty = true;
  }

  async _rebuild() {
    if (!this._dirty) return;
    await this._ensureZero();
    const nodes = [];
    for (let k = 0; k <= this.depth; k++) nodes.push(new Map());
    for (let i = 0; i < this.leaves.length; i++) {
      nodes[0].set(BigInt(i), this.leaves[i]);
    }
    let maxIdx = this.leaves.length === 0 ? -1n : BigInt(this.leaves.length - 1);
    for (let k = 0; k < this.depth; k++) {
      if (maxIdx < 0n) break;
      const cur = nodes[k];
      const nxt = nodes[k + 1];
      const nextMax = maxIdx / 2n;
      for (let j = 0n; j <= nextMax; j++) {
        const leftK = 2n * j;
        const rightK = 2n * j + 1n;
        const L = cur.has(leftK) ? cur.get(leftK) : this.zero[k];
        const R = cur.has(rightK) ? cur.get(rightK) : this.zero[k];
        nxt.set(j, await hash2(L, R));
      }
      maxIdx = nextMax;
    }
    this._nodes = nodes;
    this._dirty = false;
  }

  async root() {
    await this._ensureZero();
    if (this.leaves.length === 0) return this.zero[this.depth];
    await this._rebuild();
    return this._nodes[this.depth].get(0n) ?? this.zero[this.depth];
  }

  async pathForIndex(leafIndex) {
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`leaf_index_out_of_range: ${leafIndex} of ${this.leaves.length}`);
    }
    await this._rebuild();
    const path = [];
    const indices = [];
    let cur = BigInt(leafIndex);
    for (let k = 0; k < this.depth; k++) {
      const isRight = (cur & 1n) === 1n;
      const sibIdx = isRight ? cur - 1n : cur + 1n;
      const sib = this._nodes[k].has(sibIdx) ? this._nodes[k].get(sibIdx) : this.zero[k];
      path.push(sib);
      indices.push(isRight ? 1n : 0n);
      cur = cur >> 1n;
    }
    return { path, indices, leafIndex };
  }

  async pathForCommitment(commitmentBig) {
    if (typeof commitmentBig !== "bigint") {
      throw new Error("pathForCommitment: commitmentBig must be bigint");
    }
    const idx = this.leaves.findIndex((c) => c === commitmentBig);
    if (idx < 0) throw new Error("commitment_not_in_tree");
    return await this.pathForIndex(idx);
  }

  _computeTranscriptHash(rootBig) {
    const enc = [];
    enc.push(new TextEncoder().encode(COMMITMENT_TREE_SCHEME));
    enc.push(new Uint8Array([this.depth]));
    pushU64LE(enc, this.leaves.length);
    pushFr(enc, rootBig);
    for (let i = 0; i < this.leaves.length; i++) {
      const meta = this.depositMeta[i];
      pushFr(enc, this.leaves[i]);
      // V4 OB1: bind the global leaf_index + leaf class + asset_type so any reorder/tamper of the
      // unified (deposit + change-note, multi-asset) leaf stream invalidates the transcript hash.
      pushU64LE(enc, meta.leafIndex ?? i);
      pushLpString(enc, meta.kind ?? "deposit");
      pushLpString(enc, meta.assetType ?? "");
      pushU64LE(enc, meta.depositCount ?? 0);
      pushLpString(enc, meta.commitmentHex);
      pushLpString(enc, meta.sender);
      pushLpString(enc, meta.depositTxHash);
      pushLpString(enc, meta.txVersion);
      pushLpString(enc, meta.sequenceNumber);
    }
    const blob = concatBytes(enc);
    return "0x" + Buffer.from(keccak_256(blob)).toString("hex");
  }

  async transcriptHash() {
    const rootBig = await this.root();
    return this._computeTranscriptHash(rootBig);
  }

  async serialize() {
    const rootBig = await this.root();
    const snapshot = {
      scheme: COMMITMENT_TREE_SCHEME,
      version: 1,
      treeDepth: this.depth,
      leafCount: this.leaves.length,
      leaves: this.leaves.map((b) => le32ToHex(bigToLE32(b))),
      depositMeta: this.depositMeta.map((m) => ({ ...m })),
      latestRootHex: le32ToHex(bigToLE32(rootBig)),
      transcriptHash: this._computeTranscriptHash(rootBig),
      createdAtUnixMs: this.createdAtUnixMs,
      updatedAtUnixMs: Date.now(),
    };
    assertTreeArtifactPublicOnly(snapshot);
    return snapshot;
  }

  static async deserialize(obj) {
    if (!obj || obj.scheme !== COMMITMENT_TREE_SCHEME) {
      throw new Error(`scheme_mismatch: ${obj?.scheme}`);
    }
    if (!Number.isInteger(obj.treeDepth) || obj.treeDepth < 1) {
      throw new Error(`bad_tree_depth: ${obj.treeDepth}`);
    }
    if (!Array.isArray(obj.leaves) || !Array.isArray(obj.depositMeta)) {
      throw new Error("leaves_or_depositMeta_missing");
    }
    if (obj.leaves.length !== obj.depositMeta.length) {
      throw new Error(`length_mismatch: leaves=${obj.leaves.length} meta=${obj.depositMeta.length}`);
    }
    if (obj.leafCount !== obj.leaves.length) {
      throw new Error(`leafCount_mismatch: declared=${obj.leafCount} actual=${obj.leaves.length}`);
    }
    const t = new CommitmentTreeV2(obj.treeDepth);
    t.createdAtUnixMs = obj.createdAtUnixMs ?? Date.now();
    for (let i = 0; i < obj.leaves.length; i++) {
      const leafHex = obj.leaves[i];
      const meta = obj.depositMeta[i];
      const commitmentBig = leBytesToBig(hexToLE32(leafHex));
      t.append(commitmentBig, {
        // V4 OB1: prefer the persisted global leafIndex; fall back to dense position for legacy
        // single-asset snapshots that predate the unified-index meta.
        leafIndex: typeof meta.leafIndex === "number" ? meta.leafIndex : i,
        kind: meta.kind,
        assetType: meta.assetType,
        depositCount: meta.depositCount,
        depositTxHash: meta.depositTxHash,
        txVersion: meta.txVersion,
        sequenceNumber: meta.sequenceNumber,
        sender: meta.sender,
        commitmentHex: meta.commitmentHex ?? leafHex,
      });
    }
    const rootBig = await t.root();
    const computedTranscript = t._computeTranscriptHash(rootBig);
    if (typeof obj.transcriptHash === "string" && obj.transcriptHash !== computedTranscript) {
      throw new Error(
        `transcript_hash_mismatch: declared=${obj.transcriptHash} computed=${computedTranscript}`,
      );
    }
    const computedRootHex = le32ToHex(bigToLE32(rootBig));
    if (typeof obj.latestRootHex === "string" && obj.latestRootHex.toLowerCase() !== computedRootHex.toLowerCase()) {
      throw new Error(
        `root_mismatch: declared=${obj.latestRootHex} computed=${computedRootHex}`,
      );
    }
    return t;
  }
}

/**
 * Single-leaf root reproduction — for the M9-e final-report check that no leaf's single-leaf root
 * equals the multi-leaf root used by the withdraw.
 */
export async function singleLeafRoot(leafBig, depth = TREE_DEPTH_DEFAULT) {
  if (typeof leafBig !== "bigint") {
    throw new Error("singleLeafRoot: leafBig must be bigint");
  }
  let cur = leafBig;
  let zero = 0n;
  for (let k = 0; k < depth; k++) {
    cur = await hash2(cur, zero);
    zero = await hash2(zero, zero);
  }
  return cur;
}

export async function verifyPathAgainstRoot(leafBig, pathBig, indicesBig, rootBig) {
  if (pathBig.length !== indicesBig.length) {
    throw new Error("path/indices length mismatch");
  }
  let cur = leafBig;
  for (let k = 0; k < pathBig.length; k++) {
    const [L, R] = indicesBig[k] === 0n ? [cur, pathBig[k]] : [pathBig[k], cur];
    cur = await hash2(L, R);
  }
  return cur === rootBig;
}
