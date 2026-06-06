//! Milestone 4a / commit 4 — byte-for-byte parity tests for the single-party
//! Aptos CA range-proof reference port.
//!
//! Strategy: the Aptos WASM build's `rand::thread_rng()` is a
//! `ReseedingRng<ChaCha12Core, OsRng>` whose initial 32-byte seed is drawn
//! from `OsRng` (the deterministic PRNG hook). For a single
//! `batchRangeProof` aggregated proof of 4 or 8 16-bit values, the byte
//! consumption stays under the 64 KB reseed threshold, so the ChaCha12
//! stream produced after init *is* the stream the WASM consumes for both
//! range proofs back-to-back.
//!
//! We replicate that by:
//!   1. Replaying the deterministic PRNG up to the WASM-init point (after the
//!      20 randomness scalars consumed by the noble side).
//!   2. Pulling 32 bytes for the WASM thread_rng seed.
//!   3. Constructing `ChaCha12Rng::from_seed(seed)` — the bit-equivalent of
//!      `ReseedingRng<ChaCha12Core, OsRng>::new(ChaCha12Core::from_rng(OsRng)?, 64KB, OsRng)`
//!      as long as we stay under the 64 KB threshold.
//!   4. Calling `prove_range_with_rng(...)` twice — first for `amount` (4
//!      values), then for `newBalance` (8 values) — sharing the same RNG so
//!      the second proof continues consuming where the first left off.
//!
//! If the resulting proof bytes match the committed fixture verbatim, the
//! Aptos WASM ↔ native Rust byte parity is established.
//!
//! Milestone 4d — threshold collaborative Bulletproof primitives. Tests at
//! the bottom of this file (`threshold_*`) extend the M4a parity invariant
//! to the additive-shared-blinding form: Σ partials over additive r-shares
//! must produce the same range-proof bytes as the single-party M4a fixture
//! for both `amount` (4 chunks) and `newBalance` (8 chunks).

use std::{fs, path::PathBuf};

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use eunoma_crypto_worker::{
    bulletproof_reference::{
        aptos_commit, prove_range_with_rng,
        threshold::{
            aggregate_blinding_shares, aggregate_partial_range_commitments,
            compute_partial_range_blinding_share, prove_threshold_range_multi,
            verify_partial_against_shares, ThresholdRangePartial,
        },
        verify_range_single_party, APTOS_NUM_BITS,
    },
    transfer_sigma_reference::{prng_next_scalar_list, CounterPrng},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use serde::Deserialize;

const FIXTURE_REL_PATH: &str = "../deop-protocol/tests/fixtures/aptos_ca_transfer_v1_fixture.json";

const SDK_TRANSCRIPT_LABEL: &str = "AptosConfidentialAsset/BulletproofRangeProof";

// =============================================================================
// Fixture wire types
// =============================================================================

#[derive(Debug, Deserialize)]
struct Fixture {
    generator: GeneratorInfo,
    params: Params,
    #[serde(rename = "plaintextChunks")]
    plaintext_chunks: PlaintextChunks,
    randomness: Randomness,
    #[serde(rename = "rangeProofs")]
    range_proofs: RangeProofs,
}

#[derive(Debug, Deserialize)]
struct GeneratorInfo {
    #[serde(rename = "outerTranscriptLabel")]
    outer_transcript_label: String,
    #[serde(rename = "bulletproofsCrate")]
    bulletproofs_crate: String,
    #[serde(rename = "merlinCrate")]
    merlin_crate: String,
    #[serde(rename = "prngSeed")]
    prng_seed: String,
}

#[derive(Debug, Deserialize)]
struct Params {
    ell: usize,
    n: usize,
    #[serde(rename = "chunkBits")]
    chunk_bits: usize,
}

#[derive(Debug, Deserialize)]
struct PlaintextChunks {
    #[serde(rename = "newBalance")]
    new_balance: Vec<String>,
    #[serde(rename = "transferAmount")]
    transfer_amount: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Randomness {
    #[serde(rename = "transferAmount")]
    transfer_amount: Vec<String>,
    #[serde(rename = "newBalance")]
    new_balance: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RangeProofs {
    amount: RangeProofSection,
    #[serde(rename = "newBalance")]
    new_balance: RangeProofSection,
}

#[derive(Debug, Deserialize)]
struct RangeProofSection {
    #[serde(rename = "numValues")]
    num_values: usize,
    #[serde(rename = "numBits")]
    num_bits: usize,
    proof: String,
    comms: Vec<String>,
}

// =============================================================================
// Helpers
// =============================================================================

fn hex_decode(s: &str) -> Vec<u8> {
    let raw = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut out = Vec::with_capacity(raw.len() / 2);
    for i in (0..raw.len()).step_by(2) {
        out.push(u8::from_str_radix(&raw[i..i + 2], 16).expect("hex byte"));
    }
    out
}

fn hex_32(s: &str) -> [u8; 32] {
    let bytes = hex_decode(s);
    assert_eq!(bytes.len(), 32, "expected 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load_fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL_PATH);
    let bytes =
        fs::read(&path).unwrap_or_else(|err| panic!("read fixture at {}: {err}", path.display()));
    serde_json::from_slice(&bytes).expect("parse fixture json")
}

fn decimal_to_u64(values: &[String]) -> Vec<u64> {
    values
        .iter()
        .map(|s| u64::from_str_radix(s, 10).expect("decimal chunk"))
        .collect()
}

fn le_hex_to_scalars(values: &[String]) -> Vec<Scalar> {
    values
        .iter()
        .map(|h| Scalar::from_bytes_mod_order(hex_32(h)))
        .collect()
}

/// Build the WASM-seeded ChaCha12 RNG that the Aptos bulletproofs WASM uses.
///
/// Per `rand-0.8.5/src/rngs/thread.rs:67-78`, `thread_rng` is lazily
/// initialized as `Core::from_rng(OsRng)` which reads 32 bytes from `OsRng`
/// (= `getRandomValues`) and seeds `ChaCha12Core` from them. We replicate
/// that exact byte path.
///
/// The 20-scalar prologue (ell + n + ell = 20 noble randomness scalars)
/// happens BEFORE the WASM is ever called — those bytes are consumed by
/// `genListOfDeterministicScalars`, not by the WASM RNG.
fn build_wasm_chacha(prng_seed: &str, ell: usize, n: usize) -> ([u8; 32], ChaCha12Rng) {
    let mut prng = CounterPrng::new(prng_seed);
    // Mirror `aptos_ca_transfer_parity.test.ts` line 238-240: three calls to
    // `genListOfDeterministicScalars` consuming `ell`, `n`, `ell` scalars.
    let _ = prng_next_scalar_list(&mut prng, ell);
    let _ = prng_next_scalar_list(&mut prng, n);
    let _ = prng_next_scalar_list(&mut prng, ell);

    let mut seed = [0u8; 32];
    prng.read(&mut seed);
    let rng = ChaCha12Rng::from_seed(seed);
    (seed, rng)
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn fixture_constants_match_aptos_bulletproof_protocol() {
    let fix = load_fixture();
    assert_eq!(fix.generator.outer_transcript_label, SDK_TRANSCRIPT_LABEL);
    assert_eq!(fix.generator.bulletproofs_crate, "bulletproofs-5.0.0");
    assert_eq!(fix.generator.merlin_crate, "merlin-3.0.0");
    assert_eq!(fix.params.chunk_bits, APTOS_NUM_BITS);
    assert_eq!(fix.range_proofs.amount.num_bits, APTOS_NUM_BITS);
    assert_eq!(fix.range_proofs.amount.num_values, fix.params.n);
    assert_eq!(fix.range_proofs.new_balance.num_bits, APTOS_NUM_BITS);
    assert_eq!(fix.range_proofs.new_balance.num_values, fix.params.ell);
}

#[test]
fn aptos_ca_bulletproof_byte_parity_with_aptos_sdk() {
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;

    let amount_values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amount_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let new_balance_values = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    let new_balance_blindings = le_hex_to_scalars(&fix.randomness.new_balance);
    assert_eq!(amount_values.len(), n);
    assert_eq!(amount_blindings.len(), n);
    assert_eq!(new_balance_values.len(), ell);
    assert_eq!(new_balance_blindings.len(), ell);

    // Replay the WASM's thread_rng init: same 32 bytes the WASM consumes
    // from getRandomValues on its first call → seeds ChaCha12.
    let (_seed_bytes, mut rng) = build_wasm_chacha(&fix.generator.prng_seed, ell, n);

    // The same RNG instance is shared across both batchRangeProof calls
    // because the WASM caches thread_rng across calls.
    let (amount_proof_bytes, amount_comms) = prove_range_with_rng(
        &amount_values,
        &amount_blindings,
        APTOS_NUM_BITS,
        n,
        &mut rng,
    )
    .expect("amount range proof");
    let (new_balance_proof_bytes, new_balance_comms) = prove_range_with_rng(
        &new_balance_values,
        &new_balance_blindings,
        APTOS_NUM_BITS,
        ell,
        &mut rng,
    )
    .expect("newBalance range proof");

    // -------- Commitment sanity --------
    // Aptos commits use C = G*v + H*r (Pedersen against `(G, H_RISTRETTO)`).
    let expected_amount_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .amount
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(amount_comms, expected_amount_comms);
    let expected_new_balance_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .new_balance
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(new_balance_comms, expected_new_balance_comms);
    // And the same can be derived independently:
    let derived_amount_comms = aptos_commit(&amount_values, &amount_blindings).unwrap();
    assert_eq!(derived_amount_comms, expected_amount_comms);

    // -------- The actual byte-parity assertion --------
    let expected_amount_proof = hex_decode(&fix.range_proofs.amount.proof);
    assert_eq!(
        hex_encode(&amount_proof_bytes),
        hex_encode(&expected_amount_proof),
        "amount range proof byte mismatch (bulletproofs-5.0.0, label={SDK_TRANSCRIPT_LABEL})"
    );

    let expected_new_balance_proof = hex_decode(&fix.range_proofs.new_balance.proof);
    assert_eq!(
        hex_encode(&new_balance_proof_bytes),
        hex_encode(&expected_new_balance_proof),
        "newBalance range proof byte mismatch (bulletproofs-5.0.0, label={SDK_TRANSCRIPT_LABEL})"
    );
}

#[test]
fn verify_range_byte_parity() {
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;

    let amount_proof = hex_decode(&fix.range_proofs.amount.proof);
    let amount_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .amount
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert!(
        verify_range_single_party(&amount_proof, &amount_comms, APTOS_NUM_BITS, n)
            .expect("verify amount"),
        "Aptos SDK amount range proof must verify"
    );

    let nb_proof = hex_decode(&fix.range_proofs.new_balance.proof);
    let nb_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .new_balance
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert!(
        verify_range_single_party(&nb_proof, &nb_comms, APTOS_NUM_BITS, ell)
            .expect("verify newBalance"),
        "Aptos SDK newBalance range proof must verify"
    );
}

#[test]
fn tampered_value_diverges() {
    let fix = load_fixture();
    let n = fix.params.n;

    let mut values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);

    // Flip the value of chunk 0 from 100 to 101 — must change the proof bytes
    // (and the commitments) but with a fresh RNG so we know it's the value
    // change, not RNG drift.
    let (_, mut rng_good) = build_wasm_chacha(&fix.generator.prng_seed, fix.params.ell, n);
    let (good_proof, _good_comms) =
        prove_range_with_rng(&values, &blindings, APTOS_NUM_BITS, n, &mut rng_good)
            .expect("good prove");

    values[0] += 1;
    let (_, mut rng_bad) = build_wasm_chacha(&fix.generator.prng_seed, fix.params.ell, n);
    let (bad_proof, _bad_comms) =
        prove_range_with_rng(&values, &blindings, APTOS_NUM_BITS, n, &mut rng_bad)
            .expect("bad prove");

    assert_ne!(
        good_proof, bad_proof,
        "changing one chunk value must change the proof bytes"
    );
}

// =============================================================================
// Milestone 4d — threshold collaborative Bulletproof primitive byte-parity tests
//
// These exercise the load-bearing invariant of the threshold construction:
// additive sharing of the per-chunk blinding scalars across 5 parties + per-party
// partial-commitment computation + aggregated prove MUST byte-match the
// single-party M4a fixture for both `amount` (4 chunks) and `newBalance` (8 chunks).
// =============================================================================

const NUM_PARTIES: usize = 5;

/// Deterministic test scalar from a label. Same construction as the
/// twisted_elgamal/transfer_sigma threshold tests, with a distinct domain so
/// the M4d split is independent of the M4b/M4c splits and we can detect any
/// cross-domain coupling immediately.
fn det_scalar(label: &[u8]) -> Scalar {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"EUNOMA_M4D_BULLETPROOF_TEST_DET_SCALAR_V1");
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Split a vector of scalars (per-chunk blindings) into `NUM_PARTIES` additive
/// shares per chunk. Each party gets a full chunk-length vector; the per-index
/// sum across parties equals the input. Four pseudorandom shares plus a
/// balancing fifth. Deterministic per `domain_label`.
fn split_blindings_into_five_additive_shares(
    blindings: &[Scalar],
    domain_label: &[u8],
) -> [Vec<Scalar>; NUM_PARTIES] {
    let chunk_count = blindings.len();
    let mut shares: [Vec<Scalar>; NUM_PARTIES] = [
        vec![Scalar::ZERO; chunk_count],
        vec![Scalar::ZERO; chunk_count],
        vec![Scalar::ZERO; chunk_count],
        vec![Scalar::ZERO; chunk_count],
        vec![Scalar::ZERO; chunk_count],
    ];
    for i in 0..chunk_count {
        let mut sum_pseudorandom = Scalar::ZERO;
        for j in 0..(NUM_PARTIES - 1) {
            let label = format!("party/{j}/chunk/{i}").into_bytes();
            let s = det_scalar(&[domain_label, b"/", label.as_slice()].concat());
            shares[j][i] = s;
            sum_pseudorandom += s;
        }
        shares[NUM_PARTIES - 1][i] = blindings[i] - sum_pseudorandom;
    }
    shares
}

#[test]
fn threshold_split_actually_sums_to_blindings() {
    // Sanity test: the additive split helper itself works before we hold the
    // full pipeline accountable to byte-parity. Catch any split bug locally so
    // a downstream mismatch points at the bulletproof MPC, not the test harness.
    let fix = load_fixture();
    let amt_r = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let nb_r = le_hex_to_scalars(&fix.randomness.new_balance);

    let amt_shares =
        split_blindings_into_five_additive_shares(&amt_r, b"M4D_RANGE_BLINDING_AMOUNT_V1");
    for i in 0..amt_r.len() {
        let sum: Scalar = (0..NUM_PARTIES).map(|j| amt_shares[j][i]).sum();
        assert_eq!(
            sum, amt_r[i],
            "amount blinding[{i}] additive split mismatch"
        );
    }
    let nb_shares =
        split_blindings_into_five_additive_shares(&nb_r, b"M4D_RANGE_BLINDING_NEWBAL_V1");
    for i in 0..nb_r.len() {
        let sum: Scalar = (0..NUM_PARTIES).map(|j| nb_shares[j][i]).sum();
        assert_eq!(
            sum, nb_r[i],
            "newBalance blinding[{i}] additive split mismatch"
        );
    }
}

#[test]
fn threshold_partial_commitment_aggregates_to_aptos_commit() {
    // Stage 1 of the threshold pipeline: each party publishes its
    // per-chunk `H * r_share[i]` partial; the dealer aggregates with the
    // public value term to recover V[i] = G*v[i] + H*r[i]. The aggregated
    // value commitments MUST byte-match the M4a fixture's `comms` array (and
    // therefore the single-party `aptos_commit` output) before we can hold
    // the proof bytes accountable to byte-parity downstream.
    let fix = load_fixture();
    let amt_values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amt_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);

    let shares =
        split_blindings_into_five_additive_shares(&amt_blindings, b"M4D_RANGE_BLINDING_AMOUNT_V1");

    let partials: Vec<ThresholdRangePartial> = (0..NUM_PARTIES)
        .map(|p| compute_partial_range_blinding_share(&shares[p]).expect("compute partial"))
        .collect();

    let aggregated_comms =
        aggregate_partial_range_commitments(&partials, &amt_values).expect("aggregate commitments");

    let expected_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .amount
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(aggregated_comms, expected_comms);
    // And consistent with the single-party aptos_commit helper.
    let single_party_comms = aptos_commit(&amt_values, &amt_blindings).expect("aptos_commit");
    assert_eq!(aggregated_comms, single_party_comms);
}

#[test]
fn threshold_bulletproof_byte_parity_with_m4a_fixture_amount() {
    // KILLER TEST 1: 5-party additive blinding split + threshold prove on the
    // M4a `amount` fixture (4 × 16-bit chunks). The aggregated range-proof
    // bytes MUST byte-match the M4a fixture's `rangeProofs.amount.proof`.
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;

    let amount_values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amount_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let new_balance_values = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    let new_balance_blindings = le_hex_to_scalars(&fix.randomness.new_balance);

    let amount_shares = split_blindings_into_five_additive_shares(
        &amount_blindings,
        b"M4D_RANGE_BLINDING_AMOUNT_V1",
    );
    let new_balance_shares = split_blindings_into_five_additive_shares(
        &new_balance_blindings,
        b"M4D_RANGE_BLINDING_NEWBAL_V1",
    );

    // Same WASM-seeded ChaCha12 instance the M4a fixture was generated with
    // — the RNG must be shared across both proofs (amount → newBalance)
    // because the WASM thread_rng caches state across calls.
    let (_seed_bytes, mut rng) = build_wasm_chacha(&fix.generator.prng_seed, ell, n);

    let (amount_proof_bytes, amount_comms) =
        prove_threshold_range_multi(&amount_values, &amount_shares, APTOS_NUM_BITS, n, &mut rng)
            .expect("threshold amount range proof");
    let (new_balance_proof_bytes, new_balance_comms) = prove_threshold_range_multi(
        &new_balance_values,
        &new_balance_shares,
        APTOS_NUM_BITS,
        ell,
        &mut rng,
    )
    .expect("threshold newBalance range proof");

    // Commitment sanity (the same V[i] math the prover produces internally).
    let expected_amount_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .amount
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(amount_comms, expected_amount_comms);
    let expected_new_balance_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .new_balance
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(new_balance_comms, expected_new_balance_comms);

    // -------- The actual byte-parity assertion --------
    let expected_amount_proof = hex_decode(&fix.range_proofs.amount.proof);
    assert_eq!(
        hex_encode(&amount_proof_bytes),
        hex_encode(&expected_amount_proof),
        "threshold amount range proof byte mismatch (5-party additive blinding split, \
         bulletproofs-5.0.0, label={SDK_TRANSCRIPT_LABEL})"
    );
    // Same prover continues consuming the RNG → newBalance proof must also match.
    let expected_new_balance_proof = hex_decode(&fix.range_proofs.new_balance.proof);
    assert_eq!(
        hex_encode(&new_balance_proof_bytes),
        hex_encode(&expected_new_balance_proof),
        "threshold newBalance range proof byte mismatch on the same prover-side RNG \
         (catches RNG state drift between the two consecutive proofs)"
    );
}

#[test]
fn threshold_bulletproof_byte_parity_with_m4a_fixture_new_balance() {
    // KILLER TEST 2: same 5-party additive blinding split but the assertion
    // focuses on the M4a `newBalance` fixture (8 × 16-bit chunks). The two
    // proofs MUST be byte-identical to the M4a single-party fixture.
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;

    let amount_values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amount_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let new_balance_values = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    let new_balance_blindings = le_hex_to_scalars(&fix.randomness.new_balance);

    let amount_shares = split_blindings_into_five_additive_shares(
        &amount_blindings,
        b"M4D_RANGE_BLINDING_AMOUNT_V1",
    );
    let new_balance_shares = split_blindings_into_five_additive_shares(
        &new_balance_blindings,
        b"M4D_RANGE_BLINDING_NEWBAL_V1",
    );

    let (_seed_bytes, mut rng) = build_wasm_chacha(&fix.generator.prng_seed, ell, n);

    let (_amount_proof_bytes, _amount_comms) =
        prove_threshold_range_multi(&amount_values, &amount_shares, APTOS_NUM_BITS, n, &mut rng)
            .expect("threshold amount range proof (pre-roll RNG)");
    let (new_balance_proof_bytes, new_balance_comms) = prove_threshold_range_multi(
        &new_balance_values,
        &new_balance_shares,
        APTOS_NUM_BITS,
        ell,
        &mut rng,
    )
    .expect("threshold newBalance range proof");
    let expected_new_balance_comms: Vec<[u8; 32]> = fix
        .range_proofs
        .new_balance
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert_eq!(new_balance_comms, expected_new_balance_comms);

    let expected_new_balance_proof = hex_decode(&fix.range_proofs.new_balance.proof);
    assert_eq!(
        hex_encode(&new_balance_proof_bytes),
        hex_encode(&expected_new_balance_proof),
        "threshold newBalance range proof byte mismatch (5-party additive blinding split, \
         bulletproofs-5.0.0, label={SDK_TRANSCRIPT_LABEL})"
    );

    // The aggregated proof MUST also verify under the standard single-party
    // verifier — confirms the threshold construction is structurally valid.
    let comms_bytes: Vec<[u8; 32]> = fix
        .range_proofs
        .new_balance
        .comms
        .iter()
        .map(|h| hex_32(h))
        .collect();
    assert!(
        verify_range_single_party(&new_balance_proof_bytes, &comms_bytes, APTOS_NUM_BITS, ell)
            .expect("verify threshold newBalance"),
        "Threshold-produced newBalance range proof must verify"
    );
}

#[test]
fn threshold_bulletproof_collapses_to_single_party_when_one_holds_all_blinding() {
    // N=5 where party 0 carries the FULL blinding for every chunk and parties
    // 1..4 contribute zero. The aggregated proof MUST byte-match the
    // single-party `prove_range_with_rng` output verbatim. Confirms the
    // threshold API has no per-party RNG side channel that would diverge when
    // the additive split collapses.
    let fix = load_fixture();
    let n = fix.params.n;
    let amount_values = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amount_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);

    let mut shares: Vec<Vec<Scalar>> = vec![vec![Scalar::ZERO; n]; NUM_PARTIES];
    shares[0] = amount_blindings.clone();

    // Sanity: per-chunk sum equals the original blinding (degenerate split).
    for i in 0..n {
        let sum: Scalar = (0..NUM_PARTIES).map(|j| shares[j][i]).sum();
        assert_eq!(sum, amount_blindings[i], "degenerate split[{i}] mismatch");
    }

    let (_seed1, mut rng_threshold) =
        build_wasm_chacha(&fix.generator.prng_seed, fix.params.ell, n);
    let (threshold_proof, threshold_comms) = prove_threshold_range_multi(
        &amount_values,
        &shares,
        APTOS_NUM_BITS,
        n,
        &mut rng_threshold,
    )
    .expect("threshold prove");

    let (_seed2, mut rng_single) = build_wasm_chacha(&fix.generator.prng_seed, fix.params.ell, n);
    let (single_proof, single_comms) = prove_range_with_rng(
        &amount_values,
        &amount_blindings,
        APTOS_NUM_BITS,
        n,
        &mut rng_single,
    )
    .expect("single-party prove");

    assert_eq!(
        hex_encode(&threshold_proof),
        hex_encode(&single_proof),
        "degenerate threshold split (party 0 = full blinding) must produce byte-identical \
         proof to single-party prove_range_with_rng"
    );
    assert_eq!(threshold_comms, single_comms);
}

#[test]
fn threshold_partial_verification_round_trip() {
    // verify_partial_against_shares MUST accept the exact shares used to
    // compute the partial, and reject any single-byte mutation.
    let fix = load_fixture();
    let amt_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let shares =
        split_blindings_into_five_additive_shares(&amt_blindings, b"M4D_VERIFY_PARTIAL_V1");

    for p in 0..NUM_PARTIES {
        let partial = compute_partial_range_blinding_share(&shares[p]).expect("compute partial");
        assert!(
            verify_partial_against_shares(&partial, &shares[p]).expect("verify"),
            "partial from party {p} must verify against its own shares"
        );

        // Tamper with a single share (party 0): partial must no longer verify.
        let mut wrong = shares[p].clone();
        wrong[0] += Scalar::ONE;
        assert!(
            !verify_partial_against_shares(&partial, &wrong).expect("verify wrong"),
            "partial from party {p} must NOT verify against perturbed shares"
        );
    }
}

#[test]
fn threshold_aggregate_blinding_shares_byte_parity() {
    // The aggregate of N additive shares MUST equal the original blinding
    // scalar — confirms aggregate_blinding_shares isn't masking a mismatch
    // before it reaches prove_threshold_range_multi.
    let fix = load_fixture();
    let amt_blindings = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let shares =
        split_blindings_into_five_additive_shares(&amt_blindings, b"M4D_AGGREGATE_TEST_V1");
    let agg = aggregate_blinding_shares(&shares).expect("aggregate");
    for i in 0..amt_blindings.len() {
        assert_eq!(
            agg[i], amt_blindings[i],
            "aggregated blinding[{i}] mismatch"
        );
    }
}

#[test]
fn threshold_rejects_mismatched_share_lengths() {
    // Defensive: a deoperator that submits a wrong-length share vector MUST
    // fail closed at aggregate, BEFORE we ever invoke the bulletproof MPC.
    let bad_shares: Vec<Vec<Scalar>> = vec![
        vec![Scalar::ONE, Scalar::ONE],
        vec![Scalar::ONE], // wrong length
    ];
    let err = aggregate_blinding_shares(&bad_shares).unwrap_err();
    match err {
        eunoma_crypto_worker::WorkerError::InvalidRequest(msg) => {
            assert!(
                msg.contains("aggregate_blinding_shares"),
                "error message should identify aggregate_blinding_shares: {msg}"
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    let mismatched_partials = vec![
        ThresholdRangePartial {
            h_blinding_partials: vec![CompressedRistretto::default()
                .decompress()
                .unwrap_or_default()],
        },
        ThresholdRangePartial {
            h_blinding_partials: vec![
                CompressedRistretto::default()
                    .decompress()
                    .unwrap_or_default(),
                CompressedRistretto::default()
                    .decompress()
                    .unwrap_or_default(),
            ],
        },
    ];
    let err = aggregate_partial_range_commitments(&mismatched_partials, &[0]).unwrap_err();
    match err {
        eunoma_crypto_worker::WorkerError::InvalidRequest(msg) => {
            assert!(
                msg.contains("aggregate_partial_range_commitments"),
                "error should identify aggregate_partial_range_commitments: {msg}"
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}
