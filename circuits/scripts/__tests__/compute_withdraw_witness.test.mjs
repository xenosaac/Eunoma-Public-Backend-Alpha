// Tests for circuits/scripts/compute_withdraw_witness.mjs.
//
// Strategy: subprocess-driven. Build a real fixture commitment tree containing the M8 depositor's
// commitment at a known leafIndex, run the witness builder, assert the stdout JSON header (mode,
// leafIndex, treeTranscriptHash) and the on-disk witness JSON (merkle_indices binary encoding of
// the leaf index).
//
// Run: `cd circuits && node --test scripts/__tests__/compute_withdraw_witness.test.mjs`

import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bigToLE32,
  hexToLE32,
  le32ToHex,
  leBytesToBig,
} from "../poseidon_merkle.mjs";
import { CommitmentTreeV2 } from "../commitment_tree_v2.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..", "..");
const SCRIPT_PATH = resolve(SCRIPT_DIR, "..", "compute_withdraw_witness.mjs");

const FR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function frFromSeed(seed) {
  let v = 0n;
  for (let i = 0; i < seed.length; i++) {
    v = (v * 1099511628211n + BigInt(seed.charCodeAt(i) + i)) & ((1n << 254n) - 1n);
  }
  return v % FR_MOD;
}

function decToHex(decStr) {
  return "0x" + BigInt(decStr).toString(16).padStart(64, "0");
}

function runCli(args) {
  return spawnSync("node", [SCRIPT_PATH, ...args], {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
}

function parseStdoutJson(stdout) {
  const m = stdout.match(/\{[\s\S]*\}\s*$/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

// Build a depositor witness JSON whose commitment is computed from the same private inputs the
// witness builder reads. The chain side derives the commitment from Poseidon(Compose5):
//   commitment = Compose5(nullifier, secret, asset_id, amount, POOL_ID=0)
// For testing we don't need cryptographic validity of the deposit chain — we only need the script
// to (a) recompute the same commitment from the witness fields, (b) find it in the tree. So we
// piggyback on the real M8 witness fixture at <repo>/operator-services/.agent-local/eunoma-v2/depositor/.
function loadRealM8Witness() {
  const p = resolve(
    REPO_ROOT,
    "operator-services",
    ".agent-local",
    "eunoma-v2",
    "depositor",
    "withdraw_witness_60b2d94d.json",
  );
  try {
    return { path: p, witness: JSON.parse(readFileSync(p, "utf8")) };
  } catch {
    return null;
  }
}

let tmpRoot;
beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "m9d-witness-"));
});
afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
});

describe("compute_withdraw_witness — flag gates", () => {
  it("--testnet without --commitment-tree → exit 2", () => {
    const w = loadRealM8Witness();
    if (!w) {
      // skip when fixture absent
      return;
    }
    const r = runCli([
      "--depositor-witness", w.path,
      "--recipient", "0x" + "1".repeat(64),
      "--vault-sequence", "0",
      "--root", "0x" + "2".repeat(64),
      "--ca-payload-hash", "0x" + "3".repeat(64),
      "--testnet",
    ]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /testnet_requires_commitment_tree/);
  });
});

describe("compute_withdraw_witness — multi-leaf path", () => {
  it("builds a real-leaf-index witness, returns mode=multi_leaf + correct leafIndex + indices encode binary", async () => {
    const w = loadRealM8Witness();
    if (!w) return; // skip when fixture absent
    const commitmentHex = w.witness.commitmentHex;
    const commitmentBig = leBytesToBig(hexToLE32(commitmentHex));
    // Build a 5-leaf tree with real commitment at leafIndex=3.
    const tree = new CommitmentTreeV2(20);
    const realLeafIndex = 3;
    for (let i = 1; i <= 5; i++) {
      let big, ch;
      if (i === realLeafIndex + 1) {
        big = commitmentBig;
        ch = commitmentHex;
      } else {
        big = frFromSeed("fx-" + i);
        ch = le32ToHex(bigToLE32(big));
      }
      tree.append(big, {
        depositCount: i,
        depositTxHash: i === realLeafIndex + 1 ? w.witness.depositTxHash : "0x" + i.toString(16).padStart(64, "0"),
        txVersion: String(4000 + i),
        sequenceNumber: String(i),
        sender: "0x" + i.toString(16).padStart(64, "a"),
        commitmentHex: ch,
      });
    }
    const snapshot = await tree.serialize();
    const treePath = join(tmpRoot, "commitment_tree_v2.json");
    writeFileSync(treePath, JSON.stringify(snapshot, null, 2));

    const witnessOut = join(tmpRoot, "witness.json");
    const r = runCli([
      "--depositor-witness", w.path,
      "--recipient", "0xee18cffe11d77b85f4ada85e0a4e4b4cb3b4d8d4b59b2dbef38e72c6e527c91f",
      "--vault-sequence", "0",
      "--root", snapshot.latestRootHex,
      "--ca-payload-hash", "0x251deaadb77a0957ef2538b19a3bd359e71f87246d4286c0143055d529b1ba00",
      "--commitment-tree", treePath,
      "--testnet",
      "--output", witnessOut,
    ]);
    if (r.status !== 0) {
      console.error("stderr:", r.stderr);
      console.error("stdout:", r.stdout);
    }
    assert.equal(r.status, 0);
    const summary = parseStdoutJson(r.stdout);
    assert.equal(summary.mode, "multi_leaf");
    assert.equal(summary.leafIndex, realLeafIndex);
    assert.equal(summary.treeRootHex.toLowerCase(), snapshot.latestRootHex.toLowerCase());
    assert.equal(summary.treeTranscriptHash, snapshot.transcriptHash);

    // Verify merkle_indices encodes the leaf index in binary (LSB first).
    const witness = JSON.parse(readFileSync(witnessOut, "utf8"));
    const indices = witness.merkle_indices.map((s) => Number(s));
    let reconstructed = 0;
    for (let k = 0; k < indices.length; k++) {
      reconstructed |= indices[k] << k;
    }
    assert.equal(reconstructed, realLeafIndex);
  });

  it("commitment not in tree → exit 2 with commitment_not_in_tree", async () => {
    const w = loadRealM8Witness();
    if (!w) return;
    // Build a tree with all synthetic leaves; real depositor's commitment is absent.
    const tree = new CommitmentTreeV2(20);
    for (let i = 1; i <= 3; i++) {
      const big = frFromSeed("absent-" + i);
      const ch = le32ToHex(bigToLE32(big));
      tree.append(big, {
        depositCount: i,
        depositTxHash: "0x" + i.toString(16).padStart(64, "0"),
        txVersion: String(5000 + i),
        sequenceNumber: String(i),
        sender: "0x" + i.toString(16).padStart(64, "b"),
        commitmentHex: ch,
      });
    }
    const snapshot = await tree.serialize();
    const treePath = join(tmpRoot, "commitment_tree_v2.json");
    writeFileSync(treePath, JSON.stringify(snapshot, null, 2));

    const r = runCli([
      "--depositor-witness", w.path,
      "--recipient", "0xee18cffe11d77b85f4ada85e0a4e4b4cb3b4d8d4b59b2dbef38e72c6e527c91f",
      "--vault-sequence", "0",
      "--root", snapshot.latestRootHex,
      "--ca-payload-hash", "0x251deaadb77a0957ef2538b19a3bd359e71f87246d4286c0143055d529b1ba00",
      "--commitment-tree", treePath,
      "--testnet",
    ]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /commitment_not_in_tree|pathForCommitment failed/);
  });

  it("tampered tree artifact → exit 2", async () => {
    const w = loadRealM8Witness();
    if (!w) return;
    const tree = new CommitmentTreeV2(20);
    const commitmentBig = leBytesToBig(hexToLE32(w.witness.commitmentHex));
    tree.append(commitmentBig, {
      depositCount: 1,
      depositTxHash: w.witness.depositTxHash,
      txVersion: "6000",
      sequenceNumber: "0",
      sender: "0x" + "c".repeat(64),
      commitmentHex: w.witness.commitmentHex,
    });
    const snapshot = await tree.serialize();
    // Tamper the sender to invalidate the transcript binding.
    snapshot.depositMeta[0].sender = "0x" + "9".repeat(64);
    const treePath = join(tmpRoot, "commitment_tree_v2.json");
    writeFileSync(treePath, JSON.stringify(snapshot, null, 2));

    const r = runCli([
      "--depositor-witness", w.path,
      "--recipient", "0xee18cffe11d77b85f4ada85e0a4e4b4cb3b4d8d4b59b2dbef38e72c6e527c91f",
      "--vault-sequence", "0",
      "--root", snapshot.latestRootHex,
      "--ca-payload-hash", "0x251deaadb77a0957ef2538b19a3bd359e71f87246d4286c0143055d529b1ba00",
      "--commitment-tree", treePath,
      "--testnet",
    ]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /transcript_hash_mismatch|deserialize/);
  });
});

describe("compute_withdraw_witness — legacy single-leaf still works (without --testnet)", () => {
  it("without --commitment-tree + without --testnet → mode=legacy_single_leaf, leafIndex=0", async () => {
    const w = loadRealM8Witness();
    if (!w) return;
    // Reproduce M8 single-leaf root for the depositor's commitment via the legacy helper.
    const { computeMerkleRootAndPathSingleLeaf } = await import("../poseidon_merkle.mjs");
    const big = leBytesToBig(hexToLE32(w.witness.commitmentHex));
    const { rootLE32 } = await computeMerkleRootAndPathSingleLeaf(big, 20);
    const legacyRootHex = le32ToHex(rootLE32);

    const witnessOut = join(tmpRoot, "legacy-witness.json");
    const r = runCli([
      "--depositor-witness", w.path,
      "--recipient", "0xee18cffe11d77b85f4ada85e0a4e4b4cb3b4d8d4b59b2dbef38e72c6e527c91f",
      "--vault-sequence", "0",
      "--root", legacyRootHex,
      "--ca-payload-hash", "0x251deaadb77a0957ef2538b19a3bd359e71f87246d4286c0143055d529b1ba00",
      "--output", witnessOut,
    ]);
    if (r.status !== 0) {
      console.error("stderr:", r.stderr);
      console.error("stdout:", r.stdout);
    }
    assert.equal(r.status, 0);
    const summary = parseStdoutJson(r.stdout);
    assert.equal(summary.mode, "legacy_single_leaf");
    assert.equal(summary.leafIndex, 0);
  });
});
