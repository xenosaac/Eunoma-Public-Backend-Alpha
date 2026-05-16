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

use std::{fs, path::PathBuf};

use curve25519_dalek::scalar::Scalar;
use eunoma_crypto_worker::{
    bulletproof_reference::{
        aptos_commit, prove_range_with_rng, verify_range_single_party, APTOS_NUM_BITS,
    },
    transfer_sigma_reference::{prng_next_scalar_list, CounterPrng},
};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use serde::Deserialize;

const FIXTURE_REL_PATH: &str =
    "../deop-protocol/tests/fixtures/aptos_ca_transfer_v1_fixture.json";

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
    let raw = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
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
    let bytes = fs::read(&path)
        .unwrap_or_else(|err| panic!("read fixture at {}: {err}", path.display()));
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
    let expected_amount_comms: Vec<[u8; 32]> =
        fix.range_proofs.amount.comms.iter().map(|h| hex_32(h)).collect();
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
    let amount_comms: Vec<[u8; 32]> =
        fix.range_proofs.amount.comms.iter().map(|h| hex_32(h)).collect();
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
