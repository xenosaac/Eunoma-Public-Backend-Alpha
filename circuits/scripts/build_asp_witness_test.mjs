#!/usr/bin/env node
// =============================================================================================
// CP1 ADVERSARIAL test-witness generator for the V4 ASP withdraw circuit.
//
// Authored by the INDEPENDENT soundness reviewer (did NOT write the circuit). Synthesizes a VALID
// dual-LeanIMT + B′ partial-withdraw witness, or a FORGED variant for the adversarial hardening
// harness. Standalone (no chain/deposit dependency) — proves the circuit + VK are sound. The
// PRODUCTION witness builder (real tree state) is scripts/compute_withdraw_witness.mjs.
//
// The canonical-accept `valid` case is a PARTIAL spend (has_change=1, A_old=1000, W=600, A_rem=400):
// it exercises EVERY V4 path — dual hardened-LeanIMT inclusion, B′ conservation, the 16-bit chunk
// range checks, the remainder-digest binding, the fresh change-note Compose5, and the has_change
// gating. `valid_fullspend` exercises the full-spend branch (has_change=0, change_commitment=0).
//
// FORGE MODES (each MUST be REJECTED by a sound circuit):
//   LeanIMT hardening (HardenedLeanIMTInclusion):
//     forge_shallow_depth                 claim a shallower actualDepth than the real path
//     forge_deep_depth                    claim a deeper actualDepth than the real path
//     fake_zero_siblings_above_actualDepth nonzero sibling at level i >= actualDepth
//     nonzero_pad_below_root              nonzero pad sibling in the [actualDepth, maxDepth) tail
//     depth_out_of_range_low              actualDepth = 0 (< 1)
//     depth_out_of_range_high             actualDepth = maxDepth+1 (> 32)
//     depth_mismatch_state_vs_asp         swap the state depth onto the ASP inclusion (wrong tree)
//   B′ partial-withdraw conservation (section 9-12):
//     conservation_violation              W + A_rem != A_old (break the linear conservation)
//     rem_chunk_overflow                  a rem chunk >= 2^16 (break Num2Bits(16))
//     rem_negative                        A_rem underflow (negative remainder smuggled as a huge Fr)
//     W_gt_A_old                          W > A_old (break LessEqThan(64))
//     change_commitment_mismatch          public change_commitment != Compose5(claimed remainder)
//     has_change_inconsistent             has_change=1 but A_rem=0 (claim change with nothing to change)
//
// Failure stage: conservation/range/LeanIMT-hardening forgeries fail at WITNESS GENERATION (the
// circom witness calculator evaluates the `===` / Num2Bits / LessEqThan constraints). The verify
// script additionally runs the canonical-accept through groth16 prove+verify (needs the zkey from
// the Setup stage). change_commitment_mismatch ALSO fails at witness-gen because change_commitment
// is bound by `change_commitment === ...` over private inputs.
//
// Usage: node build_asp_witness_test.mjs [--forge MODE] [--output PATH]
//   MODE defaults to `valid`.
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLeanIMT, leanIMTPath, LEANIMT_MAX_DEPTH } from "./leanimt.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const { leBytesToBig } = await import(`file://${resolve(here, "poseidon_merkle.mjs")}`);

const args = process.argv.slice(2);
const forge = (() => { const i = args.indexOf("--forge"); return i >= 0 ? args[i + 1] : "valid"; })();
const output = (() => { const i = args.indexOf("--output"); return i >= 0 ? args[i + 1] : null; })();

const CHAIN_ID = 2, POOL_ID = 0;
const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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
// 4 × 16-bit base-2^16 little-endian chunks of a u64 (matches circuit recompose).
function chunks16(n) { let v = BigInt(n); const c = []; for (let i = 0; i < 4; i++) { c.push((v & 0xffffn).toString()); v >>= 16n; } return c; }

// --- synthetic secrets (spent parent note) ---
const nullifier = smallLe(111111);
const secret = smallLe(222222);
const asset_id = smallLe(333333);
const withdraw_blind = smallLe(444444);
const ca_payload_hash = smallLe(555555);
const vault_sequence = "7";
const amount_p_limbs = Array.from({ length: 8 }, (_, i) => smallLe(1000 + i));
const amount_p_digest = compose8(amount_p_limbs);

const recipient_hash = h3(
  (() => { const o = new Uint8Array(32); o.set(new TextEncoder().encode("EUNOMA_RECIPIENT_V2")); return o; })(),
  smallLe(0xabcd), smallLe(0x1234),
);

const commitmentLe = compose5(nullifier, secret, asset_id, amount_p_digest, smallLe(POOL_ID));
const nullifier_hash = h1(nullifier);
const amount_tag = compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, smallLe(CHAIN_ID), smallLe(Number(vault_sequence)));
const request_hash = compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, smallLe(Number(vault_sequence)), smallLe(CHAIN_ID));
const commitmentBig = leBytesToBig(commitmentLe);

// --- state tree (commitment at index 3 among 9 leaves → depth 4) ---
const stateLeaves = [];
for (let i = 0; i < 9; i++) stateLeaves.push(i === 3 ? commitmentBig : leBytesToBig(h1(smallLe(900000 + i))));
const stateBuilt = await buildLeanIMT(stateLeaves);
const statePath = leanIMTPath(stateBuilt.levels, 3, LEANIMT_MAX_DEPTH);

// --- ASP tree (commitment at index 1 among 5 approved leaves → depth 3) ---
const aspLeaves = [];
for (let i = 0; i < 5; i++) aspLeaves.push(i === 1 ? commitmentBig : leBytesToBig(h1(smallLe(800000 + i))));
const aspBuilt = await buildLeanIMT(aspLeaves);
const aspPath = leanIMTPath(aspBuilt.levels, 1, LEANIMT_MAX_DEPTH);

let stateRoot = stateBuilt.root;
let aspRoot = aspBuilt.root;
let stateDepth = statePath.actualDepth;
let aspDepth = aspPath.actualDepth;
let stateSibs = statePath.siblings.slice();
let aspSibs = aspPath.siblings.slice();
let stateLeafIndex = statePath.leafIndex;
let aspLeafIndex = aspPath.leafIndex;

// --- V4 B′ partial-withdraw honest values (canonical PARTIAL spend) ---
// A_old = 1000, W = 600, A_rem = 400 → has_change = 1.
let A_old = 1000n, W = 600n, A_rem = 400n;
let has_change = 1;
const new_nullifier = smallLe(666666);
const new_secret = smallLe(777777);
const rem_amount_p_limbs = Array.from({ length: 8 }, (_, i) => smallLe(2000 + i));
let amount_p_digest_rem = compose8(rem_amount_p_limbs);
// honest change_commitment for the partial spend
let change_commitmentBig = leBytesToBig(compose5(new_nullifier, new_secret, asset_id, amount_p_digest_rem, smallLe(POOL_ID)));

let old_chunks = chunks16(A_old);
let wd_chunks = chunks16(W);
let rem_chunks = chunks16(A_rem);

// ============================================================================================
// FORGERIES
// ============================================================================================
if (forge === "valid") {
  // canonical-accept (partial spend) — no mutation.
} else if (forge === "valid_fullspend") {
  // full spend: W === A_old, A_rem === 0, has_change = 0, change_commitment = 0 (EMPTY_CHANGE).
  W = A_old; A_rem = 0n; has_change = 0;
  wd_chunks = chunks16(W); rem_chunks = chunks16(A_rem);
  change_commitmentBig = 0n;

// ---- LeanIMT hardening (7) ----
} else if (forge === "forge_shallow_depth") {
  // claim a shallower depth than the real path (smuggle siblings below the claimed root)
  stateDepth = stateDepth - 2;
} else if (forge === "forge_deep_depth") {
  // claim a DEEPER depth than the real path AND smuggle a NONZERO sibling at the now-active level
  // (the first level >= the real depth). Over-claiming with a *zero* pad is genuinely a valid
  // alternate proof of the SAME root in LeanIMT (empty siblings propagate) — NOT a forgery — so a
  // bare depth bump is correctly accepted. The real attack is to make the extra active level carry
  // a real sibling: that forces an extra Poseidon hash, so node[maxDepth] != asp_root → reject.
  aspSibs[aspDepth] = 0x5151515151n; // nonzero sibling at the previously-inactive level
  aspDepth = aspDepth + 1;           // claim it as active
} else if (forge === "fake_zero_siblings_above_actualDepth") {
  // nonzero sibling exactly AT actualDepth (first inactive level) — hardening must zero it.
  aspSibs[aspDepth] = 123456789n;
} else if (forge === "nonzero_pad_below_root") {
  // nonzero sibling deeper in the inactive tail [actualDepth, maxDepth) — same guard, far level.
  stateSibs[stateDepth + 3] = 987654321n;
} else if (forge === "depth_out_of_range_low") {
  // actualDepth = 0 (< 1): violates the GreaterEqThan(8) depth floor.
  aspDepth = 0;
} else if (forge === "depth_out_of_range_high") {
  // actualDepth = maxDepth + 1 (> 32): violates the LessEqThan(8) depth ceiling.
  aspDepth = LEANIMT_MAX_DEPTH + 1;
} else if (forge === "depth_mismatch_state_vs_asp") {
  // Feed the ASP tree's depth (real 3) onto the STATE inclusion (real depth 4): an UNDER-claim that
  // truncates the last real climb of the deeper state path. The state path's level-3 sibling is
  // nonzero, so dropping that level changes node[maxDepth] → state_incl.root != root → reject. (An
  // OVER-claim with a zero pad would propagate harmlessly and is correctly accepted; the soundness
  // bite is the under-claim that omits a real hash.) Demonstrates the two trees' depths are NOT
  // interchangeable — each inclusion's actualDepth must match its OWN path.
  stateDepth = aspDepth;

// ---- B′ partial-withdraw conservation (6) ----
} else if (forge === "conservation_violation") {
  // W + A_rem != A_old: keep A_old=1000, W=600 but claim A_rem=399 (sum 999 != 1000).
  A_rem = 399n; rem_chunks = chunks16(A_rem);
  // recompute the remainder digest + change_commitment honestly for the FORGED A_rem so the ONLY
  // broken constraint is the conservation identity (not a collateral commitment mismatch).
  amount_p_digest_rem = compose8(rem_amount_p_limbs);
  change_commitmentBig = leBytesToBig(compose5(new_nullifier, new_secret, asset_id, amount_p_digest_rem, smallLe(POOL_ID)));
} else if (forge === "rem_chunk_overflow") {
  // a rem chunk >= 2^16: set chunk[0] = 2^16 (65536). Num2Bits(16) must reject. Keep conservation
  // numerically satisfiable by NOT also fixing the sum here — the range check fires first regardless.
  rem_chunks = chunks16(A_rem);
  rem_chunks[0] = (65536).toString(); // out of [0, 2^16)
} else if (forge === "rem_negative") {
  // A_rem underflow: A_old=600, W=1000 (so A_rem should be -400). We represent A_rem as the field
  // element (-400 mod p) and chunk-decompose A_old/W honestly. Conservation A_old===W+A_rem holds
  // in the field (600 === 1000 + (-400)), but A_rem is NOT a valid u64 — LessEqThan(64)/Num2Bits(16)
  // on rem must reject the negative-as-huge-Fr remainder.
  A_old = 600n; W = 1000n;
  old_chunks = chunks16(A_old); wd_chunks = chunks16(W);
  const remNeg = (BN254_P - 400n) % BN254_P; // -400 mod p
  // decompose remNeg into 4 chunks the same way the field value would not fit u64; we emit the
  // low 16-bit limbs of remNeg so the recompose yields remNeg (huge) → range check fails.
  let v = remNeg; const c = [];
  for (let i = 0; i < 4; i++) { c.push((v & 0xffffn).toString()); v >>= 16n; }
  rem_chunks = c;
} else if (forge === "W_gt_A_old") {
  // W > A_old with a self-consistent (wrapped) A_rem so conservation could pass but W<=A_old fails.
  // A_old=1000, W=1001, A_rem = (1000-1001) mod p = -1 mod p. LessEqThan(64) on W must reject.
  A_old = 1000n; W = 1001n;
  old_chunks = chunks16(A_old); wd_chunks = chunks16(W);
  const remNeg = (BN254_P - 1n) % BN254_P;
  let v = remNeg; const c = [];
  for (let i = 0; i < 4; i++) { c.push((v & 0xffffn).toString()); v >>= 16n; }
  rem_chunks = c;
} else if (forge === "change_commitment_mismatch") {
  // public change_commitment != Compose5(claimed remainder). Keep all privates honest (partial
  // spend) but corrupt the PUBLIC change_commitment. `change_commitment === ...` must reject.
  change_commitmentBig = (change_commitmentBig + 1n) % BN254_P;
} else if (forge === "has_change_inconsistent") {
  // has_change=1 but A_rem=0 (claim a change note with nothing to change). Make it a FULL spend
  // (W=A_old, A_rem=0) yet flip has_change to 1. The circuit's change_commitment gating then
  // demands change_commitment === Compose5(rem with digest of all-zero remainder); we leave
  // change_commitment = 0 (the empty sentinel). Sound circuit: has_change=1 ⇒ change_commitment
  // must equal the fresh leaf (nonzero) ≠ 0 → reject. (Also the dual: a 0-value change note is
  // economically meaningless.)
  W = A_old; A_rem = 0n; has_change = 1;
  wd_chunks = chunks16(W); rem_chunks = chunks16(A_rem);
  change_commitmentBig = 0n; // empty sentinel while claiming has_change=1 → inconsistent
} else if (forge === "has_change_inconsistent_fullspend_mismatch") {
  // The OTHER disjunct of the has_change inconsistency: has_change=0 (claim full spend) but the
  // amounts are a PARTIAL spend (W=600 != A_old=1000, A_rem=400). The full-spend gate
  // `(1 - has_change) * (A_old - W) === 0` must reject because A_old - W = 400 != 0.
  has_change = 0;
  change_commitmentBig = 0n; // full-spend sentinel
  // keep the partial amounts (A_old=1000, W=600, A_rem=400, *_chunks already partial)
} else {
  process.stderr.write(`unknown forge mode: ${forge}\n`);
  process.exit(2);
}

const witness = {
  // publics (9, pruned to stay below Aptos execution limits)
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
  change_commitment: change_commitmentBig.toString(),
  // privates — dual-inclusion
  nullifier: dec(nullifier),
  secret: dec(secret),
  withdraw_blind: dec(withdraw_blind),
  amount_p_limbs: amount_p_limbs.map(dec),
  state_siblings: stateSibs.map((b) => b.toString()),
  state_leaf_index: String(stateLeafIndex),
  asp_siblings: aspSibs.map((b) => b.toString()),
  asp_leaf_index: String(aspLeafIndex),
  // privates — V4 B′ partial-withdraw
  new_nullifier: dec(new_nullifier),
  new_secret: dec(new_secret),
  wd_amount_p_limbs: Array.from({ length: 8 }, () => "0"),
  rem_amount_p_limbs: rem_amount_p_limbs.map(dec),
  old_amount_chunks: old_chunks,
  wd_chunks: wd_chunks,
  rem_chunks: rem_chunks,
  has_change: String(has_change),
};

if (output) { writeFileSync(output, JSON.stringify(witness, null, 2) + "\n"); process.stderr.write(`wrote ${output} (forge=${forge})\n`); }
else process.stdout.write(JSON.stringify(witness, null, 2) + "\n");
