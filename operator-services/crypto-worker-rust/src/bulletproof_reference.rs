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
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
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

// =============================================================================
// Milestone 4d — threshold collaborative Bulletproof range-proof primitives
// =============================================================================
//
// PURPOSE
// -------
// The M4a reference port computes a Bulletproof aggregated range proof over a
// vector of cleartext chunks `v[0..m]` with per-chunk blindings `r[0..m]`. In
// the deoperator deployment, the per-chunk blindings are additively shared
// across P deoperators:
//
//   r[i] = Σ_p r_share[p][i]     (additive over the scalar field)
//
// Each deoperator p publishes a per-chunk partial Pedersen-blinding share
//
//   c_blinding_partial[p][i] = H * r_share[p][i]
//
// The chunk value G-term is public and added once during aggregation:
//
//   V[i] = G * v[i] + Σ_p c_blinding_partial[p][i]
//        = G * v[i] + H * Σ_p r_share[p][i]
//        = G * v[i] + H * r[i]
//
// When Σ_p r_share[p][i] equals the original M4a `r[i]`, the proof generated
// by [`prove_threshold_range_multi`] is byte-identical to the M4a
// single-party fixture for that chunk vector — this is the byte-parity
// invariant exercised by the killer tests at the bottom of
// `tests/aptos_ca_bulletproof_parity.rs`.
//
// WHY VALUES ARE PUBLIC (NOT ADDITIVELY SHARED)
// ---------------------------------------------
// The Bulletproof prover commits to the BIT DECOMPOSITION of each chunk
// value:
//   a_L_i = (v_j >> i) & 1                 (bulletproofs-5.0.0/party.rs:107)
//   a_R_i = a_L_i - 1
// Bit extraction `>>` and `&` are non-linear over the curve-scalar field, so
// `(v1 + v2) >> i != (v1 >> i) + (v2 >> i)`. Additively sharing `v` across
// parties is therefore incompatible with byte-parity against single-party
// `prove_multiple_with_rng` unless a secure bit-decomposition MPC is used
// (out of scope for M4d's reference primitive).
//
// The deployment compensates for this at a higher protocol layer: chunk
// values `v[i]` reach the prover side via the same E.1 channel that delivers
// them to the M4b twisted-ElGamal threshold (commit + open, or threshold
// decrypt of a `vault_ek` ciphertext). This module's E.1-independence claim
// is identical to M4b/M4c: the math is unchanged whether `v[i]` came from
// MPC reconstruction, a user commit-open, or a fixture.
//
// LINEARITY CHECK INSIDE THE BULLETPROOF MPC
// -------------------------------------------
// The bulletproofs-5.0.0 crate's `range_proof::party` MPC exposes a per-CHUNK
// Party (one Party for each chunk position j), not a per-DEOPERATOR Party.
// `v_blinding` is consumed in exactly two linear places inside the bulletproof
// proof (bulletproofs-5.0.0/range_proof/party.rs:50, 287-291):
//
//   V_j         = G * v_j + H * v_blinding              — linear in v_blinding
//   t_x_blinding = (offset_zz * v_blinding) + (linear in t_1_blinding, t_2_blinding)
//                                                       — linear in v_blinding
//
// So aggregating `r_share[p]` ADDITIVELY (i.e. summing the shares before
// invoking `Party::new`) yields the SAME proof bytes as if a single party
// held the full blinding from the start. The threshold layer is therefore a
// thin pre-aggregation step over the crate's existing aggregated-prove API;
// no patch to the crate's `pub(crate)` surface is required.
//
// E.1-INDEPENDENCE
// ----------------
// The primitives below take `public_values: &[u64]` directly and produce the
// proof. They make NO statement about where `public_values` come from at the
// protocol level — the wire plumbing (Phase E.1 of M4) is out of scope for
// this commit, identical to M4b/M4c.
pub mod threshold {
    use super::*;

    /// One deoperator's contribution to the per-chunk Pedersen blinding terms.
    ///
    /// `h_blinding_partials[i] = H * r_share[i]` for each chunk index `i`.
    ///
    /// The plaintext term `G * v[i]` is intentionally NOT carried here: it is
    /// public and added once during aggregation (consistent with M4b
    /// `ThresholdPartial`'s split between blinding-base and value-base terms).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ThresholdRangePartial {
        /// Per-chunk `H * r_share[i]`. Length must equal the chunk vector
        /// length that this partial is contributing to.
        pub h_blinding_partials: Vec<RistrettoPoint>,
    }

    /// Compute one deoperator's per-chunk blinding partials.
    ///
    /// `blinding_shares[i]` is this deoperator's additive share of the
    /// chunk-i blinding scalar `r[i]`. The returned partial contains
    /// `H * blinding_shares[i]` for each chunk index — the curve-side
    /// contribution to that chunk's Pedersen commitment.
    ///
    /// Pure function (no I/O, no RNG). Errors only when `h_ristretto()` fails
    /// or `blinding_shares` is empty.
    pub fn compute_partial_range_blinding_share(
        blinding_shares: &[Scalar],
    ) -> WorkerResult<ThresholdRangePartial> {
        if blinding_shares.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "compute_partial_range_blinding_share: blinding_shares is empty".to_string(),
            ));
        }
        let h = h_ristretto()?;
        let h_blinding_partials = blinding_shares.iter().map(|r| h * r).collect();
        Ok(ThresholdRangePartial {
            h_blinding_partials,
        })
    }

    /// Aggregate per-deoperator partial blinding contributions into the
    /// per-chunk Pedersen commitments.
    ///
    /// `partials[p]` is deoperator `p`'s contribution (length = num chunks).
    /// `public_values[i]` is the public chunk value for chunk `i`.
    ///
    /// Returns `V[i] = G * public_values[i] + Σ_p partials[p].h_blinding_partials[i]`
    /// as compressed Ristretto bytes. When `Σ_p r_share[p][i]` equals a known
    /// chunk blinding `r[i]`, the result is byte-identical to the M4a
    /// `aptos_commit(values, blindings)` for that chunk.
    ///
    /// Validates:
    /// - `partials` is non-empty,
    /// - every partial has the same chunk-vector length,
    /// - `public_values.len()` matches that length.
    pub fn aggregate_partial_range_commitments(
        partials: &[ThresholdRangePartial],
        public_values: &[u64],
    ) -> WorkerResult<Vec<[u8; 32]>> {
        if partials.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "aggregate_partial_range_commitments: empty partial set".to_string(),
            ));
        }
        let chunk_count = partials[0].h_blinding_partials.len();
        if chunk_count == 0 {
            return Err(WorkerError::InvalidRequest(
                "aggregate_partial_range_commitments: partial[0] is empty".to_string(),
            ));
        }
        for (p, part) in partials.iter().enumerate() {
            if part.h_blinding_partials.len() != chunk_count {
                return Err(WorkerError::InvalidRequest(format!(
                    "aggregate_partial_range_commitments: partial[{p}] has {} chunks, \
                     expected {chunk_count} (matching partial[0])",
                    part.h_blinding_partials.len()
                )));
            }
        }
        if public_values.len() != chunk_count {
            return Err(WorkerError::InvalidRequest(format!(
                "aggregate_partial_range_commitments: public_values.len() {} != \
                 partial chunk count {chunk_count}",
                public_values.len()
            )));
        }

        let g = RISTRETTO_BASEPOINT_POINT;
        let mut out = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let mut h_sum = RistrettoPoint::default();
            for part in partials {
                h_sum += part.h_blinding_partials[i];
            }
            let v_term = g * Scalar::from(public_values[i]);
            out.push((v_term + h_sum).compress().to_bytes());
        }
        Ok(out)
    }

    /// Aggregate per-deoperator additive blinding shares into the per-chunk
    /// effective blinding vector.
    ///
    /// `blinding_shares[p][i]` is deoperator `p`'s share of chunk-`i`'s
    /// blinding. The returned vector contains `Σ_p blinding_shares[p][i]` for
    /// each chunk index.
    ///
    /// Validates:
    /// - `blinding_shares` is non-empty,
    /// - every per-deoperator vector has the same length.
    pub fn aggregate_blinding_shares(
        blinding_shares: &[Vec<Scalar>],
    ) -> WorkerResult<Vec<Scalar>> {
        if blinding_shares.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "aggregate_blinding_shares: empty share set".to_string(),
            ));
        }
        let chunk_count = blinding_shares[0].len();
        if chunk_count == 0 {
            return Err(WorkerError::InvalidRequest(
                "aggregate_blinding_shares: shares[0] is empty".to_string(),
            ));
        }
        for (p, shares) in blinding_shares.iter().enumerate() {
            if shares.len() != chunk_count {
                return Err(WorkerError::InvalidRequest(format!(
                    "aggregate_blinding_shares: shares[{p}].len() {} != \
                     shares[0].len() {chunk_count}",
                    shares.len()
                )));
            }
        }

        let mut out = vec![Scalar::ZERO; chunk_count];
        for shares in blinding_shares {
            for (i, s) in shares.iter().enumerate() {
                out[i] += s;
            }
        }
        Ok(out)
    }

    /// End-to-end collaborative-prove: aggregate per-deoperator blinding
    /// shares into per-chunk blindings, then drive the bulletproofs MPC
    /// aggregated prover to produce a byte-identical aggregated range proof.
    ///
    /// `public_values[i]` is the cleartext value of chunk `i` (must fit in
    /// `num_bits`). `blinding_shares[p][i]` is deoperator `p`'s additive share
    /// of chunk-`i`'s blinding scalar. The aggregated blinding for chunk `i`
    /// is `Σ_p blinding_shares[p][i]`.
    ///
    /// `num_bits` and `capacity` mirror the single-party
    /// [`prove_range_with_rng`] parameters. The transcript label is the
    /// Aptos-locked `"AptosConfidentialAsset/BulletproofRangeProof"`.
    ///
    /// Returns `(proof_bytes, value_commitment_bytes)`.
    ///
    /// Byte-parity contract: when `Σ_p blinding_shares[p][i]` equals the M4a
    /// fixture's `r[i]` for every chunk and the RNG matches the WASM's
    /// thread_rng stream, the returned `proof_bytes` equals the SDK's
    /// `result.proof()`.
    pub fn prove_threshold_range_multi<R: RngCore + CryptoRng>(
        public_values: &[u64],
        blinding_shares: &[Vec<Scalar>],
        num_bits: usize,
        capacity: usize,
        rng: &mut R,
    ) -> WorkerResult<(Vec<u8>, Vec<[u8; 32]>)> {
        if public_values.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "prove_threshold_range_multi: public_values is empty".to_string(),
            ));
        }
        let aggregated_blindings = aggregate_blinding_shares(blinding_shares)?;
        if aggregated_blindings.len() != public_values.len() {
            return Err(WorkerError::InvalidRequest(format!(
                "prove_threshold_range_multi: aggregated blindings len {} != \
                 public_values len {}",
                aggregated_blindings.len(),
                public_values.len()
            )));
        }
        prove_range_with_rng(
            public_values,
            &aggregated_blindings,
            num_bits,
            capacity,
            rng,
        )
    }

    /// Verify a `ThresholdRangePartial` was computed from a single scalar
    /// share (i.e. that the partial vector lies on the line `H * x` for some
    /// unique `x` per chunk).
    ///
    /// Given the deoperator's claimed per-chunk shares, recompute each
    /// `H * r_share[i]` and assert equality with the partial. Returns `true`
    /// iff every chunk position matches. Used by tests and (eventually) by
    /// the dealer to audit a complaining deoperator.
    pub fn verify_partial_against_shares(
        partial: &ThresholdRangePartial,
        claimed_shares: &[Scalar],
    ) -> WorkerResult<bool> {
        if partial.h_blinding_partials.len() != claimed_shares.len() {
            return Ok(false);
        }
        let h = h_ristretto()?;
        for (i, r) in claimed_shares.iter().enumerate() {
            if h * r != partial.h_blinding_partials[i] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
