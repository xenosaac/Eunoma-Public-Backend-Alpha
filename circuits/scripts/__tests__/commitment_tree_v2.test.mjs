// Tests for the M9 append-only Poseidon BN254 commitment tree.
//
// Run: `cd circuits && node --test scripts/__tests__/commitment_tree_v2.test.mjs`
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CommitmentTreeV2,
  COMMITMENT_TREE_SCHEME,
  TREE_DEPTH_DEFAULT,
  singleLeafRoot,
  verifyPathAgainstRoot,
  assertTreeArtifactPublicOnly,
} from "../commitment_tree_v2.mjs";
import { bigToLE32, hash2, hexToLE32, le32ToHex, leBytesToBig } from "../poseidon_merkle.mjs";

const FR_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frHex(seed) {
  // Deterministic Fr-in-range scalar from a string seed via a simple PRNG.
  let v = 0n;
  for (let i = 0; i < seed.length; i++) {
    v = (v * 1099511628211n + BigInt(seed.charCodeAt(i) + i)) & ((1n << 254n) - 1n);
  }
  v %= FR_MOD;
  return { big: v, hex: le32ToHex(bigToLE32(v)) };
}

function leafFromIndex(i) {
  const { big, hex } = frHex(`m9-test-leaf-${i}`);
  return { big, hex };
}

function meta(i, opts = {}) {
  return {
    depositCount: i,
    depositTxHash: opts.depositTxHash ?? `0x${i.toString(16).padStart(64, "0")}`,
    txVersion: opts.txVersion ?? String(1000 + i),
    sequenceNumber: opts.sequenceNumber ?? String(i),
    sender: opts.sender ?? `0x${i.toString(16).padStart(64, "f")}`.toLowerCase(),
    commitmentHex: opts.commitmentHex,
  };
}

describe("CommitmentTreeV2 — algebra", () => {
  it("empty tree root equals zero[depth]", async () => {
    const t = new CommitmentTreeV2(4);
    const r = await t.root();
    // zero[depth] is reachable by computing the zero cascade manually
    let z = 0n;
    for (let k = 0; k < 4; k++) z = await hash2(z, z);
    assert.equal(r, z, "empty-tree root differs from zero cascade");
  });

  it("1-leaf root equals singleLeafRoot(leaf) (multi-leaf is a strict superset of M8 single-leaf)", async () => {
    const t = new CommitmentTreeV2(20);
    const L = leafFromIndex(0);
    t.append(L.big, meta(1, { commitmentHex: L.hex }));
    const r = await t.root();
    const slr = await singleLeafRoot(L.big, 20);
    assert.equal(r, slr, "1-leaf tree root != single-leaf root — M8 helper is not a special case");
  });

  it("2-leaf root differs from both leaves' single-leaf roots", async () => {
    const t = new CommitmentTreeV2(20);
    const L0 = leafFromIndex(0);
    const L1 = leafFromIndex(1);
    t.append(L0.big, meta(1, { commitmentHex: L0.hex }));
    t.append(L1.big, meta(2, { commitmentHex: L1.hex }));
    const r = await t.root();
    const slr0 = await singleLeafRoot(L0.big, 20);
    const slr1 = await singleLeafRoot(L1.big, 20);
    assert.notEqual(r, slr0);
    assert.notEqual(r, slr1);
  });

  it("for N=5, every leafIndex in [0..4] produces a path that hashes back to the root", async () => {
    const t = new CommitmentTreeV2(20);
    const leaves = [];
    for (let i = 1; i <= 5; i++) {
      const L = leafFromIndex(i);
      leaves.push(L);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const r = await t.root();
    for (let i = 0; i < 5; i++) {
      const { path, indices } = await t.pathForIndex(i);
      const ok = await verifyPathAgainstRoot(leaves[i].big, path, indices, r);
      assert.ok(ok, `path for index ${i} did not verify against root`);
    }
  });

  it("for N=8, pathForIndex(7) and pathForCommitment match and verify", async () => {
    const t = new CommitmentTreeV2(20);
    const leaves = [];
    for (let i = 1; i <= 8; i++) {
      const L = leafFromIndex(i);
      leaves.push(L);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const r = await t.root();
    const byIdx = await t.pathForIndex(7);
    const byCommit = await t.pathForCommitment(leaves[7].big);
    assert.equal(byCommit.leafIndex, 7);
    for (let k = 0; k < 20; k++) {
      assert.equal(byCommit.path[k], byIdx.path[k]);
      assert.equal(byCommit.indices[k], byIdx.indices[k]);
    }
    // index 7 binary = 0111 → least-significant 3 bits = 1,1,1, then 0 thereafter
    assert.equal(byIdx.indices[0], 1n);
    assert.equal(byIdx.indices[1], 1n);
    assert.equal(byIdx.indices[2], 1n);
    assert.equal(byIdx.indices[3], 0n);
    const ok = await verifyPathAgainstRoot(leaves[7].big, byIdx.path, byIdx.indices, r);
    assert.ok(ok);
  });

  it("pathForCommitment throws when commitment absent", async () => {
    const t = new CommitmentTreeV2(20);
    const L = leafFromIndex(0);
    t.append(L.big, meta(1, { commitmentHex: L.hex }));
    const Other = leafFromIndex(99);
    await assert.rejects(() => t.pathForCommitment(Other.big), /commitment_not_in_tree/);
  });

  it("append rejects leaf_index gap", async () => {
    const t = new CommitmentTreeV2(20);
    const L0 = leafFromIndex(0);
    const L2 = leafFromIndex(2);
    t.append(L0.big, meta(1, { commitmentHex: L0.hex }));
    assert.throws(() => t.append(L2.big, meta(3, { commitmentHex: L2.hex })), /leaf_index_gap/);
  });

  it("append rejects commitmentHex/commitmentBig mismatch", async () => {
    const t = new CommitmentTreeV2(20);
    const L0 = leafFromIndex(0);
    const L1 = leafFromIndex(1);
    assert.throws(
      () => t.append(L0.big, meta(1, { commitmentHex: L1.hex })),
      /commitmentBig does not match/,
    );
  });
});

describe("CommitmentTreeV2 — serialization + transcriptHash binding", () => {
  it("serialize → deserialize round-trips and preserves transcriptHash", async () => {
    const t = new CommitmentTreeV2(20);
    for (let i = 1; i <= 5; i++) {
      const L = leafFromIndex(i);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const snapshot = await t.serialize();
    const t2 = await CommitmentTreeV2.deserialize(snapshot);
    const r1 = await t.root();
    const r2 = await t2.root();
    assert.equal(r1, r2);
    assert.equal(await t.transcriptHash(), await t2.transcriptHash());
    assert.equal(snapshot.scheme, COMMITMENT_TREE_SCHEME);
    assert.equal(snapshot.leafCount, 5);
    assert.equal(snapshot.treeDepth, 20);
  });

  it("tamper with a leaf hex → deserialize throws", async () => {
    const t = new CommitmentTreeV2(20);
    for (let i = 1; i <= 3; i++) {
      const L = leafFromIndex(i);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const snapshot = await t.serialize();
    const tampered = JSON.parse(JSON.stringify(snapshot));
    // flip a hex char in leaves[1] but leave depositMeta[1].commitmentHex untouched
    tampered.leaves[1] = tampered.leaves[1].slice(0, -1) + (tampered.leaves[1].slice(-1) === "0" ? "1" : "0");
    await assert.rejects(
      () => CommitmentTreeV2.deserialize(tampered),
      /commitmentBig does not match|transcript_hash_mismatch|root_mismatch/,
    );
  });

  it("tamper with depositMeta.sender → deserialize throws (transcriptHash bound)", async () => {
    const t = new CommitmentTreeV2(20);
    for (let i = 1; i <= 3; i++) {
      const L = leafFromIndex(i);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const snapshot = await t.serialize();
    const tampered = JSON.parse(JSON.stringify(snapshot));
    tampered.depositMeta[1].sender = "0x" + "9".repeat(64);
    await assert.rejects(
      () => CommitmentTreeV2.deserialize(tampered),
      /transcript_hash_mismatch/,
    );
  });

  it("tamper with depositMeta.depositTxHash → deserialize throws", async () => {
    const t = new CommitmentTreeV2(20);
    for (let i = 1; i <= 3; i++) {
      const L = leafFromIndex(i);
      t.append(L.big, meta(i, { commitmentHex: L.hex }));
    }
    const snapshot = await t.serialize();
    const tampered = JSON.parse(JSON.stringify(snapshot));
    tampered.depositMeta[2].depositTxHash = "0x" + "deadbeef".repeat(8);
    await assert.rejects(
      () => CommitmentTreeV2.deserialize(tampered),
      /transcript_hash_mismatch/,
    );
  });

  it("scheme mismatch → deserialize throws", async () => {
    await assert.rejects(
      () => CommitmentTreeV2.deserialize({ scheme: "not_a_real_scheme" }),
      /scheme_mismatch/,
    );
  });

  it("leafCount declared inconsistent → deserialize throws", async () => {
    const t = new CommitmentTreeV2(20);
    const L = leafFromIndex(0);
    t.append(L.big, meta(1, { commitmentHex: L.hex }));
    const snapshot = await t.serialize();
    snapshot.leafCount = 99;
    await assert.rejects(
      () => CommitmentTreeV2.deserialize(snapshot),
      /leafCount_mismatch/,
    );
  });
});

describe("CommitmentTreeV2 — privacy guard", () => {
  it("forbidden field name in artifact → assertTreeArtifactPublicOnly throws", () => {
    const bad = { scheme: COMMITMENT_TREE_SCHEME, treeDepth: 4, leafCount: 0, leaves: [], amount: "100" };
    assert.throws(() => assertTreeArtifactPublicOnly(bad), /forbidden_field_in_tree_artifact:\$\.amount/);
    const bad2 = { scheme: COMMITMENT_TREE_SCHEME, leaves: [], nested: { secret: "x" } };
    assert.throws(() => assertTreeArtifactPublicOnly(bad2), /forbidden_field_in_tree_artifact/);
  });

  it("legitimate public field names pass the guard", () => {
    const ok = {
      scheme: COMMITMENT_TREE_SCHEME,
      treeDepth: 20,
      leafCount: 1,
      leaves: ["0x" + "a".repeat(64)],
      depositMeta: [{ depositCount: 1, depositTxHash: "0xabc", sender: "0xdef", commitmentHex: "0x" + "a".repeat(64) }],
      latestRootHex: "0x" + "1".repeat(64),
      transcriptHash: "0x" + "2".repeat(64),
    };
    assert.doesNotThrow(() => assertTreeArtifactPublicOnly(ok));
  });
});
