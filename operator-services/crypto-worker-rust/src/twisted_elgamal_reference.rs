//! Milestone 4a / commit 5 — single-party reference port of the Aptos
//! Confidential Asset chunked-amount + Twisted ElGamal primitives.
//!
//! Cross-references (file:line):
//!   * `chunkedAmount.ts:62-90`   — amount → chunk decomposition.
//!   * `chunkedAmount.ts:48-52`   — chunks → amount recomposition.
//!   * `chunkedAmount.ts:6-18`    — `AVAILABLE_BALANCE_CHUNK_COUNT = 8`,
//!                                   `TRANSFER_AMOUNT_CHUNK_COUNT = 4`,
//!                                   `CHUNK_BITS = 16`.
//!   * `twistedElGamal.ts:64-80`  — `encryptWithPK(amount, ek, random)`
//!                                   produces `(C, D)` where:
//!                                     C = G * amount + H * r,  D = ek * r
//!                                   `G = RistrettoBASE`, `H = H_RISTRETTO`.
//!
//! The Eunoma deployment uses no auditors (`hasEffective = false`,
//! `numVolun = 0`). `assert_no_auditor` exists as a defense-in-depth guard so
//! milestone 4b can rely on the no-auditor invariant when wiring MPC.

use crate::{h_ristretto, WorkerError, WorkerResult};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

/// Aptos balance chunk count (8 × 16 bits = 128-bit balance).
/// See `chunkedAmount.ts:6`.
pub const AVAILABLE_BALANCE_CHUNK_COUNT: usize = 8;

/// Aptos transfer chunk count (4 × 16 bits = 64-bit transfer).
/// See `chunkedAmount.ts:18`.
pub const TRANSFER_AMOUNT_CHUNK_COUNT: usize = 4;

/// Aptos chunk bit width.
/// See `chunkedAmount.ts:11`.
pub const CHUNK_BITS: usize = 16;

/// A Twisted ElGamal ciphertext under the Aptos scheme.
/// `C = G * m + H * r`, `D = pk * r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwistedElGamalCiphertext {
    pub c: [u8; 32],
    pub d: [u8; 32],
}

// =============================================================================
// Chunk math (mirrors `chunkedAmount.ts`)
// =============================================================================

/// Split a u128 amount into `chunks_count` chunks of `chunk_bits` bits each
/// (least-significant first). Mirrors `amountToChunks` in
/// `chunkedAmount.ts:62-90`.
///
/// Returns u64 because each chunk is at most 16 bits in the Aptos deployment;
/// larger chunk widths up to 64 bits are supported here for symmetry.
pub fn chunked_amount_to_chunks(
    amount: u128,
    chunks_count: usize,
    chunk_bits: usize,
) -> WorkerResult<Vec<u64>> {
    if chunk_bits == 0 || chunk_bits > 64 {
        return Err(WorkerError::InvalidRequest(format!(
            "chunk_bits must be in (0, 64], got {chunk_bits}"
        )));
    }
    // Reject silently-truncating inputs: amount must fit in `chunks_count * chunk_bits` bits.
    let total_bits = chunks_count.saturating_mul(chunk_bits);
    if total_bits < 128 {
        let max = 1u128 << total_bits;
        if amount >= max {
            return Err(WorkerError::InvalidRequest(format!(
                "amount {amount} does not fit in {chunks_count} chunks of {chunk_bits} bits"
            )));
        }
    }

    let mask: u128 = if chunk_bits == 128 {
        u128::MAX
    } else {
        (1u128 << chunk_bits) - 1
    };
    let mut chunks = Vec::with_capacity(chunks_count);
    for i in 0..chunks_count {
        let shifted = amount >> (chunk_bits * i);
        let chunk = (shifted & mask) as u64;
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Inverse: recompose an amount from chunks. Mirrors `chunksToAmount` in
/// `chunkedAmount.ts:48-52`.
pub fn chunks_to_amount(chunks: &[u64], chunk_bits: usize) -> WorkerResult<u128> {
    if chunk_bits == 0 || chunk_bits > 64 {
        return Err(WorkerError::InvalidRequest(format!(
            "chunk_bits must be in (0, 64], got {chunk_bits}"
        )));
    }
    let mut acc: u128 = 0;
    for (i, c) in chunks.iter().enumerate() {
        acc = acc
            .checked_add((*c as u128) << (chunk_bits * i))
            .ok_or_else(|| WorkerError::InvalidRequest("chunks overflow u128".to_string()))?;
    }
    Ok(acc)
}

// =============================================================================
// Twisted ElGamal encrypt-with-pk (mirrors `twistedElGamal.ts:64-80`)
// =============================================================================

/// Twisted-ElGamal encrypt: `C = G * amount + H * r`, `D = pk * r`.
///
/// `amount` is taken as a u64 (matching Aptos chunked encryption); larger
/// scalar amounts can be encoded by callers if needed.
pub fn encrypt_with_pk(
    amount: u64,
    pk: &[u8; 32],
    r: &Scalar,
) -> WorkerResult<TwistedElGamalCiphertext> {
    let pk_point = CompressedRistretto(*pk).decompress().ok_or_else(|| {
        WorkerError::InvalidRequest("pk: not a valid compressed Ristretto".to_string())
    })?;
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = h_ristretto()?;

    // Aptos uses an explicit zero-check before scalar multiplication, but
    // RistrettoPoint multiplication by Scalar::ZERO yields ZERO anyway. Result
    // is identical, the special case is purely for performance.
    let m_g = g * Scalar::from(amount);
    let r_h = h * r;
    let c = m_g + r_h;
    let d = pk_point * r;

    Ok(TwistedElGamalCiphertext {
        c: c.compress().to_bytes(),
        d: d.compress().to_bytes(),
    })
}

/// Convenience: encrypt a batch of chunk values, one ciphertext per chunk.
/// Equivalent to the TS test fixture's `encryptChunks` helper.
pub fn encrypt_chunks_with_pk(
    chunks: &[u64],
    pk: &[u8; 32],
    blindings: &[Scalar],
) -> WorkerResult<Vec<TwistedElGamalCiphertext>> {
    if chunks.len() != blindings.len() {
        return Err(WorkerError::InvalidRequest(format!(
            "chunks.len() {} != blindings.len() {}",
            chunks.len(),
            blindings.len()
        )));
    }
    chunks
        .iter()
        .zip(blindings.iter())
        .map(|(v, r)| encrypt_with_pk(*v, pk, r))
        .collect()
}

// =============================================================================
// No-auditor guard
// =============================================================================

/// Reject any caller that flips on auditor branches. Eunoma's deployment is
/// no-auditor today; the single-party reference port has no auditor logic,
/// and milestone 4b+ MPC will need this invariant explicit.
pub fn assert_no_auditor(
    has_effective_auditor: bool,
    num_voluntary_auditors: usize,
) -> WorkerResult<()> {
    if has_effective_auditor {
        return Err(WorkerError::InvalidRequest(
            "Eunoma reference port forbids effective auditor".to_string(),
        ));
    }
    if num_voluntary_auditors > 0 {
        return Err(WorkerError::InvalidRequest(format!(
            "Eunoma reference port forbids voluntary auditors (got {num_voluntary_auditors})"
        )));
    }
    Ok(())
}

// =============================================================================
// Internal helper to expose the H point for tests / cross-checks
// =============================================================================

/// Decompressed H_RISTRETTO. Re-exported for parity tests / cross-module use.
pub fn h_ristretto_point() -> WorkerResult<RistrettoPoint> {
    h_ristretto()
}
