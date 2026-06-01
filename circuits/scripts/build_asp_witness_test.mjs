#!/usr/bin/env node
// CP1 test-witness generator for the ASP v-next withdraw circuit.
//
// Synthesizes a VALID dual-LeanIMT withdraw witness (commitment in BOTH state and ASP trees),
// or a FORGED variant for the adversarial hardening harness. Standalone (no chain/deposit
// dependency) — proves the circuit + VK are sound. The PRODUCTION witness builder (real tree
// state) is wired in CP5.
//
// Usage: node build_asp_witness_test.mjs [--forge MODE] [--output PATH]
//   MODE ∈ valid | asp_nonmember | wrong_asp_root | forge_shallow | fake_zero_sibling
//          | depth_zero | depth_overflow | wrong_state_root
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLeanIMT, leanIMTPath, LEANIMT_MAX_DEPTH } from "./leanimt.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const { leBytesToBig, bigToLE32 } = await import(`file://${resolve(here, "poseidon_merkle.mjs")}`);

const args = process.argv.slice(2);
const forge = (() => { const i = args.indexOf("--forge"); return i >= 0 ? args[i + 1] : "valid"; })();
const output = (() => { const i = args.indexOf("--output"); return i >= 0 ? args[i + 1] : null; })();

const CHAIN_ID = 2, POOL_ID = 0;

const { buildPoseidon } = await import("circomlibjs");
const poseidon = await buildPoseidon();
const F = poseidon.F;
const frLe = (le) => F.fromRprLE(le, 0);
const toLe = (el) => { const o = new Uint8Array(32); F.toRprLE(o, 0, el); return o; };
const h1 = (a) => toLe(poseidon([frLe(a)]));
const h2 = (a, b) => toLe(poseidon([frLe(a), frLe(b)]));
const h3 = (a, b, c) => toLe(poseidon([frLe(a), frLe(b), frLe(c)]));
const compose5 = (a, b, c, d, e) => h2(h3(a, b, c), h2(d, e));
const compose6 = (a, b, c, d, e, f) => h2(h3(a, b, c), h3(d, e, f));
const compose8 = (x) => h3(h3(x[0], x[1], x[2]), h3(x[3], x[4], x[5]), h2(x[6], x[7]));

function smallLe(n) { const o = new Uint8Array(32); let v = BigInt(n); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
const dec = (le) => leBytesToBig(le).toString();

// --- synthetic secrets ---
const nullifier = smallLe(111111);
const secret = smallLe(222222);
const asset_id = smallLe(333333);
const withdraw_blind = smallLe(444444);
const ca_payload_hash = smallLe(555555);
const vault_sequence = "7";
// amount_p limbs (8 × <2^128); arbitrary
const amount_p_limbs = Array.from({ length: 8 }, (_, i) => smallLe(1000 + i));
const amount_p_digest = compose8(amount_p_limbs);

// recipient_hash (domain || hi || lo) — arbitrary fixed recipient
const recipient_hash = h3(
  (() => { const o = new Uint8Array(32); o.set(new TextEncoder().encode("EUNOMA_RECIPIENT_V2")); return o; })(),
  smallLe(0xabcd), smallLe(0x1234),
);

const commitmentLe = compose5(nullifier, secret, asset_id, amount_p_digest, smallLe(POOL_ID));
const nullifier_hash = h1(nullifier);
const amount_tag = compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, smallLe(CHAIN_ID), smallLe(Number(vault_sequence)));
const request_hash = compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, smallLe(Number(vault_sequence)), smallLe(CHAIN_ID));

const commitmentBig = leBytesToBig(commitmentLe);

// --- build state tree (commitment at index 3 among 9 leaves → depth 4) ---
const stateLeaves = [];
for (let i = 0; i < 9; i++) stateLeaves.push(i === 3 ? commitmentBig : leBytesToBig(h1(smallLe(900000 + i))));
const stateBuilt = await buildLeanIMT(stateLeaves);
let statePath = leanIMTPath(stateBuilt.levels, 3, LEANIMT_MAX_DEPTH);

// --- build ASP tree (commitment at index 1 among 5 approved leaves → depth 3) ---
const aspLeaves = [];
for (let i = 0; i < 5; i++) aspLeaves.push(i === 1 ? commitmentBig : leBytesToBig(h1(smallLe(800000 + i))));
let aspBuilt = await buildLeanIMT(aspLeaves);
let aspPath = leanIMTPath(aspBuilt.levels, 1, LEANIMT_MAX_DEPTH);

let stateRoot = stateBuilt.root;
let aspRoot = aspBuilt.root;
let stateDepth = statePath.actualDepth;
let aspDepth = aspPath.actualDepth;
let stateSibs = statePath.siblings.slice();
let aspSibs = aspPath.siblings.slice();
let aspLeafIndex = aspPath.leafIndex;

// --- forgeries ---
if (forge === "asp_nonmember") {
  // ASP tree that does NOT contain the commitment
  const bad = Array.from({ length: 5 }, (_, i) => leBytesToBig(h1(smallLe(700000 + i))));
  const b = await buildLeanIMT(bad);
  const p = leanIMTPath(b.levels, 1, LEANIMT_MAX_DEPTH);
  aspRoot = b.root; aspSibs = p.siblings.slice(); aspDepth = p.actualDepth; aspLeafIndex = 1;
} else if (forge === "wrong_asp_root") {
  aspRoot = aspRoot + 1n;
} else if (forge === "wrong_state_root") {
  stateRoot = stateRoot + 1n;
} else if (forge === "forge_shallow") {
  stateDepth = stateDepth - 2; // claim a shallower depth than real
} else if (forge === "fake_zero_sibling") {
  aspSibs[aspDepth] = 123456789n; // nonzero sibling above actualDepth (must be rejected)
} else if (forge === "depth_zero") {
  aspDepth = 0;
} else if (forge === "depth_overflow") {
  aspDepth = LEANIMT_MAX_DEPTH + 1;
}

const witness = {
  // publics (12)
  root: stateRoot.toString(),
  nullifier_hash: dec(nullifier_hash),
  asset_id: dec(asset_id),
  recipient_hash: dec(recipient_hash),
  amount_tag: dec(amount_tag),
  ca_payload_hash: dec(ca_payload_hash),
  request_hash: dec(request_hash),
  vault_sequence,
  amount_p_digest: dec(amount_p_digest),
  asp_root: aspRoot.toString(),
  state_tree_depth: String(stateDepth),
  asp_tree_depth: String(aspDepth),
  // privates
  nullifier: dec(nullifier),
  secret: dec(secret),
  withdraw_blind: dec(withdraw_blind),
  amount_p_limbs: amount_p_limbs.map(dec),
  state_siblings: stateSibs.map((b) => b.toString()),
  state_leaf_index: String(statePath.leafIndex),
  asp_siblings: aspSibs.map((b) => b.toString()),
  asp_leaf_index: String(aspLeafIndex),
};

if (output) { writeFileSync(output, JSON.stringify(witness, null, 2) + "\n"); process.stderr.write(`wrote ${output} (forge=${forge})\n`); }
else process.stdout.write(JSON.stringify(witness, null, 2) + "\n");
