//! Milestone 4a / commit 4 — single-party reference port of Aptos
//! Confidential Asset range proofs (Bulletproofs).
//!
//! Aptos uses the upstream `bulletproofs-5.0.0` + `curve25519-dalek-4.1.3` +
//! `merlin-3.0.0` crates, with two protocol-locked parameters:
//!
//!   * Outer Merlin transcript label = `"AptosConfidentialAsset/BulletproofRangeProof"`
//!     (verified in the WASM string table at
//!     `node_modules/@aptos-labs/confidential-asset-bindings/dist/aptos_confidential_asset_wasm_bg.wasm`).
//!   * Pedersen generators: `B = G` (RistrettoBASE) and `B_blinding = H` where
//!     `H = H_RISTRETTO` (mirroring the SDK's `valBase`/`randBase` parameters
//!     to `batchRangeProof` at
//!     `@aptos-labs/confidential-asset-bindings/src/web/shared.ts:54-77`).
//!   * `num_bits = 16` (CHUNK_BITS) for the transfer chunk values.
//!
//! Byte-parity claim: given identical RNG bytes feeding
//! `RangeProof::prove_multiple_with_rng`, this module produces byte-identical
//! proof bytes against the Aptos SDK's `batchRangeProof(...)` output.
//!
//! WASM RNG mirror: the Aptos WASM build uses `rand::thread_rng()`, which
//! lazily initializes a `ReseedingRng<ChaCha12Core, OsRng>` by reading 32
//! bytes from `OsRng` and using them as the ChaCha12 seed (see
//! `rand-0.8.5/src/rngs/thread.rs:67-78`). Under the deterministic
//! `globalThis.crypto.getRandomValues` hook installed by the TS fixture
//! generator, those first 32 bytes come straight out of the
//! SHA-256-counter-mode PRNG. We replicate that here by seeding
//! `ChaCha12Rng::from_seed(seed_bytes)` with the same 32 bytes.

use crate::{h_ristretto, WorkerError, WorkerResult};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Aptos outer transcript label — *do not change*; the WASM has it hard-coded.
pub const OUTER_TRANSCRIPT_LABEL: &[u8] = b"AptosConfidentialAsset/BulletproofRangeProof";

/// Aptos chunk bit width (16) — locked by the Move struct definition.
pub const APTOS_NUM_BITS: usize = 16;

// =============================================================================
// Pedersen generators wired for Aptos
// =============================================================================

/// Construct the `PedersenGens` Aptos uses: `B = G_base`, `B_blinding = H_RISTRETTO`.
/// Mirrors what `batchRangeProof` passes through `valBase` / `randBase`.
pub fn aptos_pedersen_gens() -> WorkerResult<PedersenGens> {
    Ok(PedersenGens {
        B: RISTRETTO_BASEPOINT_POINT,
        B_blinding: h_ristretto()?,
    })
}

// =============================================================================
// Prover (byte-parity, caller-supplied RNG)
// =============================================================================

/// Prove an aggregated Bulletproof range proof matching the Aptos SDK shape.
///
/// * `values` and `blindings` must have the same length and must be a power of
///   two (Aptos uses 4 or 8).
/// * `num_bits` is the per-value bit width; Aptos uses 16.
/// * `capacity` is the `BulletproofGens` party_capacity (≥ values.len()); the
///   SDK uses `values.len()` directly.
///
/// Returns the serialized proof bytes (matches `RangeProof::to_bytes()`).
///
/// Byte-parity: with a properly-seeded `ChaCha12Rng` matching the WASM's
/// `thread_rng` state, the returned bytes equal the SDK's `result.proof()`.
pub fn prove_range_with_rng<R: RngCore + CryptoRng>(
    values: &[u64],
    blindings: &[Scalar],
    num_bits: usize,
    capacity: usize,
    rng: &mut R,
) -> WorkerResult<(Vec<u8>, Vec<[u8; 32]>)> {
    if values.len() != blindings.len() {
        return Err(WorkerError::InvalidRequest(format!(
            "values.len() {} != blindings.len() {}",
            values.len(),
            blindings.len()
        )));
    }
    if !values.len().is_power_of_two() {
        return Err(WorkerError::InvalidRequest(format!(
            "values.len() must be a power of two, got {}",
            values.len()
        )));
    }
    if !(num_bits == 8 || num_bits == 16 || num_bits == 32 || num_bits == 64) {
        return Err(WorkerError::InvalidRequest(format!(
            "num_bits must be 8|16|32|64, got {num_bits}"
        )));
    }
    if capacity < values.len() {
        return Err(WorkerError::InvalidRequest(format!(
            "capacity {capacity} < values.len() {}",
            values.len()
        )));
    }

    let pc_gens = aptos_pedersen_gens()?;
    let bp_gens = BulletproofGens::new(num_bits, capacity);
    let mut transcript = Transcript::new(OUTER_TRANSCRIPT_LABEL);

    let (proof, commitments) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        values,
        blindings,
        num_bits,
        rng,
    )
    .map_err(|err| WorkerError::Crypto(format!("bulletproof prove_multiple: {err:?}")))?;

    let proof_bytes = proof.to_bytes();
    let comm_bytes: Vec<[u8; 32]> = commitments.iter().map(|c| c.to_bytes()).collect();
    Ok((proof_bytes, comm_bytes))
}

// =============================================================================
// Verifier
// =============================================================================

pub fn verify_range_single_party(
    proof_bytes: &[u8],
    commitments: &[[u8; 32]],
    num_bits: usize,
    capacity: usize,
) -> WorkerResult<bool> {
    if !commitments.len().is_power_of_two() {
        return Err(WorkerError::InvalidRequest(format!(
            "commitments.len() must be a power of two, got {}",
            commitments.len()
        )));
    }
    let proof = RangeProof::from_bytes(proof_bytes)
        .map_err(|err| WorkerError::Crypto(format!("RangeProof::from_bytes: {err:?}")))?;
    let pc_gens = aptos_pedersen_gens()?;
    let bp_gens = BulletproofGens::new(num_bits, capacity);
    let mut transcript = Transcript::new(OUTER_TRANSCRIPT_LABEL);
    let compressed: Vec<CompressedRistretto> = commitments
        .iter()
        .map(|c| CompressedRistretto(*c))
        .collect();

    match proof.verify_multiple(&bp_gens, &pc_gens, &mut transcript, &compressed, num_bits) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// =============================================================================
// Convenience: compute the value commitments that match the proof
// =============================================================================

/// Compute Aptos-style Pedersen commitments `C_i = G * v_i + H * r_i` so the
/// caller can cross-check the WASM-returned `comms` array against ours.
pub fn aptos_commit(values: &[u64], blindings: &[Scalar]) -> WorkerResult<Vec<[u8; 32]>> {
    if values.len() != blindings.len() {
        return Err(WorkerError::InvalidRequest(
            "values/blindings length mismatch".to_string(),
        ));
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = h_ristretto()?;
    Ok(values
        .iter()
        .zip(blindings.iter())
        .map(|(v, r)| {
            let point = g * Scalar::from(*v) + h * r;
            point.compress().to_bytes()
        })
        .collect())
}
