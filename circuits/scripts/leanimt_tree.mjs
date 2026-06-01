// LeanIMTTree — dynamic-depth Poseidon-BN254 tree class used for BOTH the state tree (v-next,
// migrated from the fixed-depth-20 CommitmentTreeV2) AND the ASP tree. Wraps leanimt.mjs (whose
// root/path convention is proven byte-identical to circuits/eunoma_templates.circom::
// HardenedLeanIMTInclusion — CP1's valid 2-proof was built from these paths and verified).
//
// Privacy: the serialized artifact + transcriptHash bind only PUBLIC fields (commitments, depth,
// root, per-leaf depositMeta). The forbidden-field gate rejects any secret/amount/nullifier key.
import { keccak_256 } from "@noble/hashes/sha3";
import { buildLeanIMT, leanIMTPath, LEANIMT_MAX_DEPTH } from "./leanimt.mjs";
import { bigToLE32, hexToLE32, le32ToHex, leBytesToBig } from "./poseidon_merkle.mjs";

export const LEANIMT_TREE_SCHEME = "eunoma_leanimt_tree_v1";

const FORBIDDEN_FIELD_NAME = /^(amount|secret|nullifier|.*blind|dk|inverse)$/i;
const FORBIDDEN_FIELD_SUFFIX = /_(amount|secret|nullifier|.*blind|dk|inverse)$/i;

function assertPublicOnly(v, path = "$") {
  if (v === null || v === undefined || typeof v !== "object") return;
  if (Array.isArray(v)) return v.forEach((x, i) => assertPublicOnly(x, `${path}[${i}]`));
  for (const [k, child] of Object.entries(v)) {
    if (FORBIDDEN_FIELD_NAME.test(k) || FORBIDDEN_FIELD_SUFFIX.test(k)) {
      throw new Error(`forbidden_field_in_tree_artifact:${path}.${k}`);
    }
    assertPublicOnly(child, `${path}.${k}`);
  }
}

function pushU32LE(enc, n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); enc.push(b); }
function pushU64LE(enc, n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); enc.push(b); }
function pushLp(enc, s) { const b = new TextEncoder().encode(s ?? ""); pushU32LE(enc, b.length); enc.push(b); }
function concat(parts) { let n = 0; for (const p of parts) n += p.length; const o = new Uint8Array(n); let off = 0; for (const p of parts) { o.set(p, off); off += p.length; } return o; }

export class LeanIMTTree {
  constructor() {
    this.leaves = [];       // bigint[]
    this.meta = [];         // per-leaf public metadata
    this._built = null;     // { root, depth, levels }
    this._dirty = true;
  }

  // meta: { count, commitmentHex, sender?, depositTxHash?, txVersion?, sequenceNumber? }
  append(commitmentBig, meta = {}) {
    if (typeof commitmentBig !== "bigint") throw new Error("append: commitmentBig must be bigint");
    if (meta.commitmentHex && leBytesToBig(hexToLE32(meta.commitmentHex)) !== commitmentBig) {
      throw new Error("append: commitmentHex does not match commitmentBig");
    }
    this.leaves.push(commitmentBig);
    this.meta.push({
      count: this.leaves.length,
      commitmentHex: (meta.commitmentHex ?? le32ToHex(bigToLE32(commitmentBig))).toLowerCase(),
      sender: typeof meta.sender === "string" ? meta.sender.toLowerCase() : "",
      depositTxHash: typeof meta.depositTxHash === "string" ? meta.depositTxHash : "",
      txVersion: String(meta.txVersion ?? ""),
      sequenceNumber: String(meta.sequenceNumber ?? ""),
    });
    this._dirty = true;
  }

  async _ensure() {
    if (!this._dirty && this._built) return this._built;
    this._built = this.leaves.length === 0 ? { root: 0n, depth: 0, levels: [[]] } : await buildLeanIMT(this.leaves);
    this._dirty = false;
    return this._built;
  }

  async root() { return (await this._ensure()).root; }
  async depth() { return (await this._ensure()).depth; }
  get leafCount() { return this.leaves.length; }

  indexOfCommitment(commitmentBig) { return this.leaves.findIndex((c) => c === commitmentBig); }

  async pathForCommitment(commitmentBig) {
    const idx = this.indexOfCommitment(commitmentBig);
    if (idx < 0) throw new Error("commitment_not_in_tree");
    const built = await this._ensure();
    const { siblings, actualDepth } = leanIMTPath(built.levels, idx, LEANIMT_MAX_DEPTH);
    return { siblings, leafIndex: idx, actualDepth };
  }

  async transcriptHash() {
    const built = await this._ensure();
    const enc = [];
    enc.push(new TextEncoder().encode(LEANIMT_TREE_SCHEME));
    pushU32LE(enc, built.depth);
    pushU64LE(enc, this.leaves.length);
    enc.push(bigToLE32(built.root));
    for (let i = 0; i < this.leaves.length; i++) {
      const m = this.meta[i];
      enc.push(bigToLE32(this.leaves[i]));
      pushU64LE(enc, m.count);
      pushLp(enc, m.commitmentHex);
      pushLp(enc, m.sender);
      pushLp(enc, m.depositTxHash);
      pushLp(enc, m.txVersion);
      pushLp(enc, m.sequenceNumber);
    }
    return "0x" + Buffer.from(keccak_256(concat(enc))).toString("hex");
  }

  async serialize() {
    const built = await this._ensure();
    const snap = {
      scheme: LEANIMT_TREE_SCHEME,
      version: 1,
      treeDepth: built.depth,
      leafCount: this.leaves.length,
      leaves: this.leaves.map((b) => le32ToHex(bigToLE32(b))),
      depositMeta: this.meta.map((m) => ({ ...m })),
      latestRootHex: le32ToHex(bigToLE32(built.root)),
      transcriptHash: await this.transcriptHash(),
    };
    assertPublicOnly(snap);
    return snap;
  }

  static async deserialize(obj) {
    if (!obj || obj.scheme !== LEANIMT_TREE_SCHEME) throw new Error(`scheme_mismatch: ${obj?.scheme}`);
    if (!Array.isArray(obj.leaves) || !Array.isArray(obj.depositMeta)) throw new Error("leaves_or_meta_missing");
    if (obj.leaves.length !== obj.depositMeta.length) throw new Error("length_mismatch");
    const t = new LeanIMTTree();
    for (let i = 0; i < obj.leaves.length; i++) {
      t.append(leBytesToBig(hexToLE32(obj.leaves[i])), obj.depositMeta[i]);
    }
    const computed = le32ToHex(bigToLE32(await t.root()));
    if (typeof obj.latestRootHex === "string" && obj.latestRootHex.toLowerCase() !== computed.toLowerCase()) {
      throw new Error(`root_mismatch: declared=${obj.latestRootHex} computed=${computed}`);
    }
    return t;
  }
}
