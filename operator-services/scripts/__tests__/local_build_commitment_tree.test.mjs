// Tests for scripts/local_build_commitment_tree.mjs.
//
// Stubs globalThis.fetch + uses tmp state roots. No network or filesystem outside tmp.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadDepositorTxHashes,
  fetchDepositEventByTxHash,
  validateEvent,
  normalizeAddress,
  ingest,
} from "../local_build_commitment_tree.mjs";
import {
  bigToLE32,
  hash2,
  hexToLE32,
  le32ToHex,
  leBytesToBig,
} from "../../../circuits/scripts/poseidon_merkle.mjs";
import { LeanIMTTree } from "../../../circuits/scripts/leanimt_tree.mjs";
import { leanIMTRootFromPath } from "../../../circuits/scripts/leanimt.mjs";

const BRIDGE = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";
const VAULT = "0x554cd51d88770c83ace72ffbeca7644f00ca32b86c852182b98cc0223c1ac43b";
const ASSET = "0xa";

const FR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frFromSeed(seed) {
  let v = 0n;
  for (let i = 0; i < seed.length; i++) {
    v = (v * 1099511628211n + BigInt(seed.charCodeAt(i) + i)) & ((1n << 254n) - 1n);
  }
  v %= FR_MOD;
  return v;
}

function leafHex(seed) {
  return le32ToHex(bigToLE32(frFromSeed(seed)));
}

function senderHex(i) {
  return ("0x" + i.toString(16).padStart(64, "f")).toLowerCase();
}

function txFor({ depositCount, commitmentHex, sender, txHash, version, sequenceNumber }) {
  return {
    type: "user_transaction",
    success: true,
    vm_status: "Executed successfully",
    hash: txHash,
    version: String(version),
    sender,
    events: [
      {
        type: `${BRIDGE}::eunoma_bridge::DepositConfirmedV2`,
        sequence_number: String(sequenceNumber),
        data: {
          commitment: commitmentHex,
          vault_addr: VAULT,
          asset_type: { inner: ASSET },
          deposit_count: String(depositCount),
        },
      },
    ],
  };
}

function makeFetchStub(txByHash) {
  return vi.fn(async (urlOrReq) => {
    const url = typeof urlOrReq === "string" ? urlOrReq : urlOrReq.url;
    const m = url.match(/\/transactions\/by_hash\/(0x[0-9a-fA-F]+)/);
    if (m) {
      const tx = txByHash[m[1].toLowerCase()];
      if (!tx) return new Response(JSON.stringify({ message: "not_found" }), { status: 404 });
      return new Response(JSON.stringify(tx), { status: 200 });
    }
    return new Response(JSON.stringify({ message: "unmocked" }), { status: 500 });
  });
}

function writeWitness(dir, { txHash, commitmentHex, depositCount }) {
  const id = txHash.slice(2, 10);
  const p = join(dir, `withdraw_witness_${id}.json`);
  writeFileSync(
    p,
    JSON.stringify(
      {
        schema: "v2_depositor_witness_v1",
        commitmentHex,
        depositTxHash: txHash,
        depositCount: String(depositCount),
      },
      null,
      2,
    ),
  );
  return p;
}

let tmpRoot;
let stateDir;
let witnessDir;
beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "m9b-tree-"));
  stateDir = join(tmpRoot, "coordinator");
  witnessDir = join(tmpRoot, "depositor");
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(witnessDir, { recursive: true });
});
afterEach(() => {
  vi.restoreAllMocks();
  if (tmpRoot && existsSync(tmpRoot)) rmSync(tmpRoot, { recursive: true, force: true });
});

const baseArgs = () => [
  "--bridge-package-address", BRIDGE,
  "--vault-address", VAULT,
  "--asset-type", ASSET,
  "--aptos-node-url", "https://stub/v1",
  "--state-dir", stateDir,
  "--depositor-witness-dir", witnessDir,
];

describe("local_build_commitment_tree.mjs — happy path", () => {
  it("ingests 3 confirmed tx hashes in deposit_count order and produces a deterministic tree", async () => {
    const commits = [leafHex("c1"), leafHex("c2"), leafHex("c3")];
    const txes = [
      { txHash: "0x" + "a".repeat(64), depositCount: 1, commitmentHex: commits[0], sender: senderHex(1), version: 1001, sequenceNumber: 0 },
      { txHash: "0x" + "b".repeat(64), depositCount: 2, commitmentHex: commits[1], sender: senderHex(2), version: 1002, sequenceNumber: 1 },
      { txHash: "0x" + "c".repeat(64), depositCount: 3, commitmentHex: commits[2], sender: senderHex(3), version: 1003, sequenceNumber: 2 },
    ];
    const byHash = Object.fromEntries(txes.map((t) => [t.txHash.toLowerCase(), txFor(t)]));
    globalThis.fetch = makeFetchStub(byHash);
    for (const t of txes) writeWitness(witnessDir, t);

    const code = await ingest({ argv: baseArgs() });
    expect(code).toBe(0);

    const out = JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
    expect(out.leafCount).toBe(3);
    expect(out.scheme).toBe("commitment_tree_v2");
    expect(out.depositMeta.map((m) => m.depositCount)).toEqual([1, 2, 3]);
    expect(out.depositMeta.map((m) => m.commitmentHex.toLowerCase())).toEqual(commits.map((c) => c.toLowerCase()));
    expect(out.depositMeta.map((m) => m.sender)).toEqual([senderHex(1), senderHex(2), senderHex(3)]);
    expect(new Set(out.depositMeta.map((m) => m.sender)).size).toBe(3);
  });
});

describe("local_build_commitment_tree.mjs — endian discipline", () => {
  it("decodes commitment as LE-bytes-to-BigInt; not raw BigInt(0x+hex) of LE byte string", async () => {
    // Construct a commitment whose LE interpretation differs from the BE-parsed value.
    const commit = leafHex("endian-edge");
    const leBig = leBytesToBig(hexToLE32(commit));
    // The buggy BE-parse value would be: BigInt(commit) directly (or BigInt of swapped bytes).
    const buggyBig = BigInt(commit);
    expect(buggyBig).not.toBe(leBig); // commitments derived from a Fr-scalar in LE always differ from their raw 0x-hex BE interpretation when high bits set

    const tx = {
      txHash: "0x" + "e".repeat(64),
      depositCount: 1,
      commitmentHex: commit,
      sender: senderHex(7),
      version: 5000,
      sequenceNumber: 0,
    };
    globalThis.fetch = makeFetchStub({ [tx.txHash.toLowerCase()]: txFor(tx) });
    writeWitness(witnessDir, tx);

    await ingest({ argv: baseArgs() });
    const out = JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
    expect(out.leaves[0].toLowerCase()).toBe(commit.toLowerCase());

    // The recorded transcriptHash must match the LE-decoded leaf big, not the buggy one.
    // Recompute root via the LE path; assert latestRootHex matches.
    let cur = leBig;
    let z = 0n;
    for (let k = 0; k < 20; k++) {
      cur = await hash2(cur, z);
      z = await hash2(z, z);
    }
    expect(out.latestRootHex.toLowerCase()).toBe(le32ToHex(bigToLE32(cur)).toLowerCase());
  });
});

describe("local_build_commitment_tree.mjs — negative cases", () => {
  it("rejects deposit_count gap", async () => {
    const txes = [
      { txHash: "0x" + "1".repeat(64), depositCount: 1, commitmentHex: leafHex("g1"), sender: senderHex(1), version: 10, sequenceNumber: 0 },
      { txHash: "0x" + "3".repeat(64), depositCount: 3, commitmentHex: leafHex("g3"), sender: senderHex(3), version: 30, sequenceNumber: 2 },
    ];
    const byHash = Object.fromEntries(txes.map((t) => [t.txHash.toLowerCase(), txFor(t)]));
    globalThis.fetch = makeFetchStub(byHash);
    for (const t of txes) writeWitness(witnessDir, t);

    await expect(ingest({ argv: baseArgs() })).rejects.toThrow(/deposit_count_gap/);
  });

  it("rejects wrong vault", async () => {
    const tx = txFor({
      txHash: "0x" + "2".repeat(64),
      depositCount: 1,
      commitmentHex: leafHex("wv"),
      sender: senderHex(1),
      version: 1,
      sequenceNumber: 0,
    });
    tx.events[0].data.vault_addr = "0x" + "9".repeat(64);
    globalThis.fetch = makeFetchStub({ [tx.hash.toLowerCase()]: tx });
    writeWitness(witnessDir, { txHash: tx.hash, commitmentHex: tx.events[0].data.commitment, depositCount: 1 });
    await expect(ingest({ argv: baseArgs() })).rejects.toThrow(/wrong_vault/);
  });

  it("rejects wrong asset", async () => {
    const tx = txFor({
      txHash: "0x" + "4".repeat(64),
      depositCount: 1,
      commitmentHex: leafHex("wa"),
      sender: senderHex(1),
      version: 1,
      sequenceNumber: 0,
    });
    tx.events[0].data.asset_type = { inner: "0xdeadbeef" };
    globalThis.fetch = makeFetchStub({ [tx.hash.toLowerCase()]: tx });
    writeWitness(witnessDir, { txHash: tx.hash, commitmentHex: tx.events[0].data.commitment, depositCount: 1 });
    await expect(ingest({ argv: baseArgs() })).rejects.toThrow(/wrong_asset/);
  });

  it("rejects failed tx (success:false)", async () => {
    const tx = txFor({
      txHash: "0x" + "5".repeat(64),
      depositCount: 1,
      commitmentHex: leafHex("f"),
      sender: senderHex(1),
      version: 1,
      sequenceNumber: 0,
    });
    tx.success = false;
    globalThis.fetch = makeFetchStub({ [tx.hash.toLowerCase()]: tx });
    writeWitness(witnessDir, { txHash: tx.hash, commitmentHex: tx.events[0].data.commitment, depositCount: 1 });
    await expect(ingest({ argv: baseArgs() })).rejects.toThrow(/tx_failed/);
  });

  it("rejects tx missing DepositConfirmedV2 event", async () => {
    const tx = txFor({
      txHash: "0x" + "6".repeat(64),
      depositCount: 1,
      commitmentHex: leafHex("me"),
      sender: senderHex(1),
      version: 1,
      sequenceNumber: 0,
    });
    tx.events = [];
    globalThis.fetch = makeFetchStub({ [tx.hash.toLowerCase()]: tx });
    writeWitness(witnessDir, { txHash: tx.hash, commitmentHex: leafHex("me"), depositCount: 1 });
    await expect(ingest({ argv: baseArgs() })).rejects.toThrow(/no_deposit_event/);
  });

  it("rejects replay (same tx-hash present in primary set + existing tree state)", async () => {
    // First ingest one tx successfully
    const c1 = leafHex("r1");
    const tx1 = {
      txHash: "0x" + "7".repeat(64),
      depositCount: 1,
      commitmentHex: c1,
      sender: senderHex(1),
      version: 100,
      sequenceNumber: 0,
    };
    globalThis.fetch = makeFetchStub({ [tx1.txHash.toLowerCase()]: txFor(tx1) });
    writeWitness(witnessDir, tx1);
    await ingest({ argv: baseArgs() });

    // Now add a second witness that's actually a duplicate tx (same version/seq) but different hash
    const tx2 = {
      txHash: "0x" + "8".repeat(64),
      depositCount: 2,
      commitmentHex: leafHex("r2"),
      sender: senderHex(2),
      version: 100,                    // same version → replay
      sequenceNumber: 0,
    };
    globalThis.fetch = makeFetchStub({
      [tx1.txHash.toLowerCase()]: txFor(tx1),
      [tx2.txHash.toLowerCase()]: txFor(tx2),
    });
    writeWitness(witnessDir, tx2);
    await expect(ingest({ argv: [...baseArgs(), "--refresh"] })).rejects.toThrow(/replay/);
  });
});

describe("local_build_commitment_tree.mjs — ordering and idempotency", () => {
  it("sorts out-of-order tx hashes by deposit_count before validating monotonicity", async () => {
    const txes = [
      { txHash: "0x" + "a".repeat(64), depositCount: 3, commitmentHex: leafHex("s3"), sender: senderHex(3), version: 30, sequenceNumber: 2 },
      { txHash: "0x" + "b".repeat(64), depositCount: 1, commitmentHex: leafHex("s1"), sender: senderHex(1), version: 10, sequenceNumber: 0 },
      { txHash: "0x" + "c".repeat(64), depositCount: 2, commitmentHex: leafHex("s2"), sender: senderHex(2), version: 20, sequenceNumber: 1 },
    ];
    const byHash = Object.fromEntries(txes.map((t) => [t.txHash.toLowerCase(), txFor(t)]));
    globalThis.fetch = makeFetchStub(byHash);
    for (const t of txes) writeWitness(witnessDir, t);

    const code = await ingest({ argv: baseArgs() });
    expect(code).toBe(0);
    const out = JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
    expect(out.depositMeta.map((m) => m.depositCount)).toEqual([1, 2, 3]);
  });

  it("--dry-run does not write the artifact", async () => {
    const tx = {
      txHash: "0x" + "d".repeat(64),
      depositCount: 1,
      commitmentHex: leafHex("dr"),
      sender: senderHex(1),
      version: 1,
      sequenceNumber: 0,
    };
    globalThis.fetch = makeFetchStub({ [tx.txHash.toLowerCase()]: txFor(tx) });
    writeWitness(witnessDir, tx);
    const code = await ingest({ argv: [...baseArgs(), "--dry-run"] });
    expect(code).toBe(0);
    expect(existsSync(join(stateDir, "commitment_tree_v2.json"))).toBe(false);
  });

  it("--refresh appends only new leaves", async () => {
    const tx1 = { txHash: "0x" + "e".repeat(64), depositCount: 1, commitmentHex: leafHex("r1"), sender: senderHex(1), version: 10, sequenceNumber: 0 };
    const tx2 = { txHash: "0x" + "f".repeat(64), depositCount: 2, commitmentHex: leafHex("r2"), sender: senderHex(2), version: 20, sequenceNumber: 1 };
    const byHash1 = { [tx1.txHash.toLowerCase()]: txFor(tx1) };
    const byHash2 = { ...byHash1, [tx2.txHash.toLowerCase()]: txFor(tx2) };

    globalThis.fetch = makeFetchStub(byHash1);
    writeWitness(witnessDir, tx1);
    await ingest({ argv: baseArgs() });

    globalThis.fetch = makeFetchStub(byHash2);
    writeWitness(witnessDir, tx2);
    await ingest({ argv: [...baseArgs(), "--refresh"] });

    const out = JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
    expect(out.leafCount).toBe(2);
    expect(out.depositMeta.map((m) => m.depositCount)).toEqual([1, 2]);
  });
});

describe("local_build_commitment_tree.mjs — LeanIMT state-tree snapshot", () => {
  it("emits state_leanimt_tree.json whose latestRootHex recomputes from LeanIMTTree.deserialize (root parity)", async () => {
    const commits = [leafHex("L1"), leafHex("L2"), leafHex("L3"), leafHex("L4"), leafHex("L5")];
    const txes = commits.map((c, i) => ({
      // distinct first-8-hex (witness filenames key off txHash.slice(2,10))
      txHash: "0x" + `a${i}`.padEnd(64, "0"),
      depositCount: i + 1,
      commitmentHex: c,
      sender: senderHex(i + 1),
      version: 7000 + i,
      sequenceNumber: i,
    }));
    const byHash = Object.fromEntries(txes.map((t) => [t.txHash.toLowerCase(), txFor(t)]));
    globalThis.fetch = makeFetchStub(byHash);
    for (const t of txes) writeWitness(witnessDir, t);

    const code = await ingest({ argv: baseArgs() });
    expect(code).toBe(0);

    // Both artifacts written.
    expect(existsSync(join(stateDir, "commitment_tree_v2.json"))).toBe(true);
    expect(existsSync(join(stateDir, "state_leanimt_tree.json"))).toBe(true);

    const lean = JSON.parse(readFileSync(join(stateDir, "state_leanimt_tree.json"), "utf8"));
    expect(lean.scheme).toBe("eunoma_leanimt_tree_v1");
    expect(lean.leafCount).toBe(5);
    // dynamic depth (5 leaves → depth 3), NOT a fixed 20.
    expect(lean.treeDepth).toBeGreaterThanOrEqual(1);
    expect(lean.treeDepth).toBeLessThan(20);
    expect(lean.leaves.map((l) => l.toLowerCase())).toEqual(commits.map((c) => c.toLowerCase()));

    // Root parity: deserialize recomputes the root and asserts it equals the declared latestRootHex
    // (deserialize throws on mismatch). Re-derive independently here too.
    const tree = await LeanIMTTree.deserialize(lean);
    const recomputed = le32ToHex(bigToLE32(await tree.root()));
    expect(recomputed.toLowerCase()).toBe(lean.latestRootHex.toLowerCase());
  });

  it("LeanIMT snapshot meta carries the same senders/depositTxHashes as the fixed-20 snapshot", async () => {
    const commits = [leafHex("M1"), leafHex("M2")];
    const txes = commits.map((c, i) => ({
      txHash: "0x" + `b${i}`.padEnd(64, "0"),
      depositCount: i + 1,
      commitmentHex: c,
      sender: senderHex(i + 10),
      version: 8000 + i,
      sequenceNumber: i,
    }));
    const byHash = Object.fromEntries(txes.map((t) => [t.txHash.toLowerCase(), txFor(t)]));
    globalThis.fetch = makeFetchStub(byHash);
    for (const t of txes) writeWitness(witnessDir, t);
    await ingest({ argv: baseArgs() });

    const v2 = JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
    const lean = JSON.parse(readFileSync(join(stateDir, "state_leanimt_tree.json"), "utf8"));
    expect(lean.depositMeta.map((m) => m.sender)).toEqual(v2.depositMeta.map((m) => m.sender));
    expect(lean.depositMeta.map((m) => m.depositTxHash)).toEqual(
      v2.depositMeta.map((m) => m.depositTxHash),
    );
  });
});

describe("LeanIMT snapshot ↔ frontend/circuit consumption parity (CRITICAL GATE)", () => {
  it("deserialize → pathForCommitment → root recomputes via the same convention the frontend + circuit use", async () => {
    // Build a LeanIMTTree with known commitments, serialize, then prove the frontend's expected
    // consumption works against the served snapshot: deserialize, pull the co-path for a known
    // commitment, and recompute the root via leanIMTRootFromPath (the exact propagate-on-zero /
    // carry-above-actualDepth convention frontend lib/protocol/leanimt.ts + the withdraw circuit
    // share — proven byte-identical).
    const known = leBytesToBig(hexToLE32(leafHex("known-commitment")));
    const others = ["o1", "o2", "o3", "o4", "o5"].map((s) => leBytesToBig(hexToLE32(leafHex(s))));
    const tree = new LeanIMTTree();
    // interleave so the known commitment is at a non-trivial index
    const order = [others[0], others[1], known, others[2], others[3], others[4]];
    for (const c of order) tree.append(c, {});
    const snapshot = await tree.serialize();

    // The coordinator serves `snapshot` verbatim. The browser deserializes it:
    const rebuilt = await LeanIMTTree.deserialize(snapshot);
    const declaredRoot = leBytesToBig(hexToLE32(snapshot.latestRootHex));
    expect(await rebuilt.root()).toBe(declaredRoot);

    // pathForCommitment → root recomputes via the shared circuit/frontend convention.
    const { siblings, leafIndex, actualDepth } = await rebuilt.pathForCommitment(known);
    expect(leafIndex).toBe(2);
    const recomputed = await leanIMTRootFromPath(known, siblings, leafIndex, actualDepth);
    expect(recomputed).toBe(declaredRoot);
  });
});

describe("loadDepositorTxHashes", () => {
  it("returns [] when dir absent", () => {
    expect(loadDepositorTxHashes(join(tmpRoot, "nope"))).toEqual([]);
  });

  it("skips non-witness files and wrong-schema files", () => {
    writeFileSync(join(witnessDir, "random.txt"), "x");
    writeFileSync(join(witnessDir, "withdraw_witness_AA.json"), JSON.stringify({ schema: "wrong", depositTxHash: "0x" + "1".repeat(64) }));
    expect(loadDepositorTxHashes(witnessDir)).toEqual([]);
  });

  it("normalizes tx-hash to lowercase", () => {
    writeWitness(witnessDir, { txHash: "0x" + "A".repeat(64), commitmentHex: leafHex("c"), depositCount: 1 });
    const out = loadDepositorTxHashes(witnessDir);
    expect(out).toEqual(["0x" + "a".repeat(64)]);
  });
});
