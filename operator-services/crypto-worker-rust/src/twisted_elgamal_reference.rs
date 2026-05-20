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

// =============================================================================
// Milestone 4b commit 2 — threshold partial-ciphertext primitives
// =============================================================================
//
// PURPOSE
// -------
// In M4a, a single party owned `r` and computed `(C, D) = (G*v + H*r, ek*r)`.
// In M4b, randomness is additively shared across deoperators:
//   r = Σ_j r_share_j     (additive over the scalar field)
//
// Each party j publishes a partial ciphertext share
//   c_partial_j   = H * r_share_j
//   d_sender_j    = ek_sender   * r_share_j
//   d_recip_j     = ek_recip    * r_share_j   (transfer-amount only)
//
// Aggregation is point addition + the public plaintext term on C only:
//   C        = G * v + Σ_j c_partial_j   = G * v + H * (Σ_j r_share_j)
//   D_sender = Σ_j d_sender_j            = ek_sender * (Σ_j r_share_j)
//   D_recip  = Σ_j d_recip_j             = ek_recip  * (Σ_j r_share_j)   (optional)
//
// When Σ_j r_share_j equals the original M4a `r`, the aggregated (C, D_sender)
// is byte-identical with the M4a fixture's `(C, D)` for that chunk — this is
// the byte-parity invariant exercised by the killer tests.
//
// E.1-INDEPENDENCE
// ----------------
// The primitives below take `public_v` as an explicit `u64` parameter on
// aggregation. This module makes NO statement about where `public_v` comes
// from at the protocol level: the math is identical whether the chunk
// originated from MPC reconstruction, a user-side commit-open, or a fixture.
// The wire plumbing (Phase E.1 of M4b) is out of scope for this commit.
pub mod threshold {
    use super::*;
    use sha2::{Digest, Sha512};

    /// Domain separation tag for the multi-base Schnorr POK challenge.
    /// LOCKED for M4b commit 2; any change must bump the version suffix.
    const RSHARE_POK_DOMAIN: &[u8] = b"EUNOMA_M4B_RSHARE_POK_V1";

    /// One deoperator's share of a Twisted-ElGamal ciphertext on a single chunk.
    ///
    /// The plaintext term `G * v` is intentionally NOT carried here: it is
    /// public and added once during aggregation, not per share.
    ///
    /// `d_recip_partial` is `Some` for transfer-amount chunks (which encrypt
    /// under both sender and recipient ek) and `None` for newBalance chunks
    /// (sender ek only). Mixing the two shapes within a single aggregation is
    /// rejected by [`aggregate_partial_ciphertext_shares`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ThresholdPartial {
        /// `H * r_share` — the blinding-base partial.
        pub c_partial: RistrettoPoint,
        /// `ek_sender * r_share` — the sender-side D partial.
        pub d_sender_partial: RistrettoPoint,
        /// `ek_recip * r_share` for transfer-amount chunks; `None` for
        /// newBalance chunks.
        pub d_recip_partial: Option<RistrettoPoint>,
    }

    /// The aggregated Twisted-ElGamal ciphertext on a single chunk, equivalent
    /// to the single-party `(C, D)` pair when Σ r_share_j equals the original
    /// r for that chunk.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ThresholdCiphertext {
        /// `G * public_v + H * Σ r_share_j`.
        pub c: RistrettoPoint,
        /// `ek_sender * Σ r_share_j`.
        pub d_sender: RistrettoPoint,
        /// `ek_recip * Σ r_share_j`; `Some` iff all partials had `d_recip_partial = Some`.
        pub d_recip: Option<RistrettoPoint>,
    }

    /// Multi-base Schnorr proof of knowledge: the prover proves that the same
    /// scalar `r_share` underlies `(c_partial, d_sender_partial, d_recip_partial?)`
    /// across the three (or two) bases `(H, ek_sender, ek_recip?)`.
    ///
    /// Soundness: the verifier checks each base independently against the same
    /// response `z`, so a prover that used different r-values per base will fail
    /// at least one of the three (or two) equations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MultiBaseSchnorrPok {
        /// `H * k`.
        pub a_h: RistrettoPoint,
        /// `ek_sender * k`.
        pub a_sender: RistrettoPoint,
        /// `ek_recip * k`; `Some` iff the partial includes a recipient leg.
        pub a_recip: Option<RistrettoPoint>,
        /// `k + e * r_share` where `e` is the Fiat-Shamir challenge.
        pub z: Scalar,
    }

    /// Compute one party's partial ciphertext share. The caller supplies the
    /// scalar share `r_share` (so this is a pure function — useful for
    /// byte-parity testing against the M4a fixture).
    ///
    /// `ek_sender` and `ek_recip_opt` must be valid Ristretto points; this
    /// function does NOT decompress hex — callers wire the decoded points in.
    pub fn compute_partial_ciphertext_share(
        r_share: &Scalar,
        ek_sender: &RistrettoPoint,
        ek_recip_opt: Option<&RistrettoPoint>,
    ) -> WorkerResult<ThresholdPartial> {
        let h = h_ristretto()?;
        Ok(ThresholdPartial {
            c_partial: h * r_share,
            d_sender_partial: ek_sender * r_share,
            d_recip_partial: ek_recip_opt.map(|ek| ek * r_share),
        })
    }

    /// Aggregate partial ciphertext shares into a full ciphertext.
    ///
    /// Validates that ALL partials agree on whether `d_recip_partial` is
    /// present — a mismatch (e.g., some shares with `Some`, others with `None`)
    /// is an InvalidRequest. Validates `ek_recip_opt` is present iff the
    /// partials carry a recipient leg.
    pub fn aggregate_partial_ciphertext_shares(
        partials: &[ThresholdPartial],
        public_v: u64,
        g: &RistrettoPoint,
        _ek_sender: &RistrettoPoint,
        ek_recip_opt: Option<&RistrettoPoint>,
    ) -> WorkerResult<ThresholdCiphertext> {
        if partials.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "aggregate_partial_ciphertext_shares: empty partial set".to_string(),
            ));
        }
        let want_recip = partials[0].d_recip_partial.is_some();
        for (i, p) in partials.iter().enumerate() {
            if p.d_recip_partial.is_some() != want_recip {
                return Err(WorkerError::InvalidRequest(format!(
                    "aggregate_partial_ciphertext_shares: partial[{i}].d_recip_partial \
                     presence ({}) disagrees with partial[0] ({})",
                    p.d_recip_partial.is_some(),
                    want_recip
                )));
            }
        }
        if want_recip != ek_recip_opt.is_some() {
            return Err(WorkerError::InvalidRequest(format!(
                "aggregate_partial_ciphertext_shares: ek_recip_opt.is_some() = {} \
                 disagrees with partials' d_recip_partial presence = {want_recip}",
                ek_recip_opt.is_some()
            )));
        }

        // Σ_j c_partial_j and Σ_j d_sender_j.
        let mut c_sum = RistrettoPoint::default();
        let mut d_sender_sum = RistrettoPoint::default();
        let mut d_recip_sum = if want_recip {
            Some(RistrettoPoint::default())
        } else {
            None
        };
        for p in partials {
            c_sum += p.c_partial;
            d_sender_sum += p.d_sender_partial;
            if let (Some(acc), Some(part)) = (d_recip_sum.as_mut(), p.d_recip_partial) {
                *acc += part;
            }
        }

        // C also carries the public plaintext term G * v.
        let c = g * Scalar::from(public_v) + c_sum;
        Ok(ThresholdCiphertext {
            c,
            d_sender: d_sender_sum,
            d_recip: d_recip_sum,
        })
    }

    /// Prove that the same `r_share` underlies the partial's (c, d_sender, [d_recip])
    /// across the bases (H, ek_sender, [ek_recip]).
    ///
    /// The caller supplies `k` (the prover's per-proof nonce) so this function is
    /// deterministic and unit-testable. Production callers MUST sample `k`
    /// uniformly with a CSPRNG and never reuse it.
    ///
    /// `transcript_bind` is application-level binding context (e.g., a chunk
    /// index, sender address, asset id) folded into the Fiat-Shamir hash so the
    /// proof is non-malleable across protocol instances.
    pub fn prove_multibase_schnorr_pok(
        r_share: &Scalar,
        k: &Scalar,
        ek_sender: &RistrettoPoint,
        ek_recip_opt: Option<&RistrettoPoint>,
        transcript_bind: &[u8],
    ) -> WorkerResult<MultiBaseSchnorrPok> {
        let h = h_ristretto()?;
        let a_h = h * k;
        let a_sender = ek_sender * k;
        let a_recip = ek_recip_opt.map(|ek| ek * k);

        // The challenge binds to (domain, transcript_bind, all A points, all
        // partial points). We recompute the partial inline rather than asking
        // the caller for it: cheaper for the prover, and guarantees the prover's
        // and verifier's transcripts agree on what's being bound.
        let c_partial = h * r_share;
        let d_sender_partial = ek_sender * r_share;
        let d_recip_partial = ek_recip_opt.map(|ek| ek * r_share);

        let e = challenge_scalar(
            transcript_bind,
            &a_h,
            &a_sender,
            a_recip.as_ref(),
            &c_partial,
            &d_sender_partial,
            d_recip_partial.as_ref(),
        );
        let z = k + e * r_share;
        Ok(MultiBaseSchnorrPok {
            a_h,
            a_sender,
            a_recip,
            z,
        })
    }

    /// Verify a multi-base Schnorr POK against a partial ciphertext share.
    ///
    /// Returns `true` iff:
    /// - the proof and partial agree on whether a recipient leg is present, AND
    /// - the `ek_recip_opt` argument matches that presence, AND
    /// - `H * z == a_h + c_partial * e`, AND
    /// - `ek_sender * z == a_sender + d_sender_partial * e`, AND
    /// - (if applicable) `ek_recip * z == a_recip + d_recip_partial * e`.
    ///
    /// Returns `false` on any check failure. Errors are returned only for the
    /// non-cryptographic precondition `h_ristretto()`.
    pub fn verify_multibase_schnorr_pok(
        pok: &MultiBaseSchnorrPok,
        partial: &ThresholdPartial,
        ek_sender: &RistrettoPoint,
        ek_recip_opt: Option<&RistrettoPoint>,
        transcript_bind: &[u8],
    ) -> WorkerResult<bool> {
        // Shape agreement: the proof, the partial, and the ek_recip_opt argument
        // must all agree on whether there's a recipient leg.
        if pok.a_recip.is_some() != partial.d_recip_partial.is_some() {
            return Ok(false);
        }
        if ek_recip_opt.is_some() != partial.d_recip_partial.is_some() {
            return Ok(false);
        }

        let h = h_ristretto()?;
        let e = challenge_scalar(
            transcript_bind,
            &pok.a_h,
            &pok.a_sender,
            pok.a_recip.as_ref(),
            &partial.c_partial,
            &partial.d_sender_partial,
            partial.d_recip_partial.as_ref(),
        );

        if h * pok.z != pok.a_h + partial.c_partial * e {
            return Ok(false);
        }
        if ek_sender * pok.z != pok.a_sender + partial.d_sender_partial * e {
            return Ok(false);
        }
        if let (Some(ek_recip), Some(a_recip), Some(d_recip_partial)) =
            (ek_recip_opt, pok.a_recip, partial.d_recip_partial)
        {
            if ek_recip * pok.z != a_recip + d_recip_partial * e {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Fiat-Shamir challenge scalar, locked to `RSHARE_POK_DOMAIN` and uniform
    /// over the 64-byte SHA-512 expansion.
    ///
    /// Binding order is fixed and MUST NOT change without bumping the domain
    /// version suffix:
    ///   domain || transcript_bind ||
    ///   a_h || a_sender || (a_recip if present) ||
    ///   c_partial || d_sender_partial || (d_recip_partial if present)
    ///
    /// "If present" means the byte sequence simply omits that 32-byte block
    /// when the recipient leg is absent — there is no length prefix, because
    /// the protocol fixes the leg-presence per chunk class (newBalance →
    /// no recip, transferAmount → recip), and the verifier reconstructs the
    /// exact same bytes from the same inputs.
    fn challenge_scalar(
        transcript_bind: &[u8],
        a_h: &RistrettoPoint,
        a_sender: &RistrettoPoint,
        a_recip_opt: Option<&RistrettoPoint>,
        c_partial: &RistrettoPoint,
        d_sender_partial: &RistrettoPoint,
        d_recip_partial_opt: Option<&RistrettoPoint>,
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(RSHARE_POK_DOMAIN);
        hasher.update(transcript_bind);
        hasher.update(a_h.compress().as_bytes());
        hasher.update(a_sender.compress().as_bytes());
        if let Some(a_recip) = a_recip_opt {
            hasher.update(a_recip.compress().as_bytes());
        }
        hasher.update(c_partial.compress().as_bytes());
        hasher.update(d_sender_partial.compress().as_bytes());
        if let Some(d_recip_partial) = d_recip_partial_opt {
            hasher.update(d_recip_partial.compress().as_bytes());
        }
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hasher.finalize());
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}
