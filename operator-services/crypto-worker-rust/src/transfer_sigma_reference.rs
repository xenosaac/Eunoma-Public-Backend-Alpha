//! Milestone 4a / commit 3 — single-party reference port of Aptos Confidential
//! Asset `TransferV1` sigma proof.
//!
//! This module is a *reference implementation*: it mirrors the TS prover in
//! `@aptos-labs/confidential-asset/src/crypto/sigmaProtocolTransfer.ts` line by
//! line so that, given the same witness vector and the same `alpha` nonce
//! vector, it produces byte-identical commitment points and response scalars
//! against the Aptos SDK's output (`aptos_ca_transfer_v1_fixture.json`).
//!
//! Cross-references (file:line):
//!   * Sigma generic prover:    sigmaProtocol.ts:171-285
//!   * Transfer psi (30-out):   sigmaProtocolTransfer.ts:311-398
//!   * Transfer f (30-out):     sigmaProtocolTransfer.ts:405-477
//!   * BCS TransferSession:     sigmaProtocolTransfer.ts:57-75
//!   * BCS FiatShamirInputs:    sigmaProtocol.ts:120-153
//!   * Domain separator (V1):   sigmaProtocol.ts:27-61
//!
//! Single-party: there is NO threshold/MPC logic here; that's milestone 4b+.

use crate::{h_ristretto, WorkerError, WorkerResult};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha512};

// =============================================================================
// Protocol-id constants (locked to Aptos SDK 1.1.1)
// =============================================================================

/// Sigma protocol identifier — must match the byte string in the Move source.
/// See `sigmaProtocolTransfer.ts:38`.
pub const PROTOCOL_ID: &str = "AptosConfidentialAsset/TransferV1";

/// Fully-qualified Move phantom type name — must match `type_info::type_name<Transfer>()`.
/// See `sigmaProtocolTransfer.ts:41`.
pub const TYPE_NAME: &str = "0x1::sigma_protocol_transfer::Transfer";

/// `@aptos_framework` 0x1 address as 32 raw bytes, last byte 0x01.
/// See `sigmaProtocol.ts:27-31`.
pub const APTOS_FRAMEWORK_ADDRESS: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x01;
    bytes
};

// =============================================================================
// Domain separator (mirrors `BcsDomainSeparator` enum V1 variant)
// =============================================================================

/// BCS-encoded `DomainSeparator::V1`.
///
/// Move enum layout (sigmaProtocol.ts:49-61):
/// ```text
/// ULEB128(0)              // variant tag
/// FixedBytes(contract_addr)  // 32 bytes
/// u8(chain_id)
/// vector<u8>(protocol_id)    // ULEB128 len || bytes
/// vector<u8>(session_id)     // ULEB128 len || bytes
/// ```
#[derive(Debug, Clone)]
pub struct DomainSeparator {
    pub contract_address: [u8; 32],
    pub chain_id: u8,
    pub protocol_id: Vec<u8>,
    pub session_id: Vec<u8>,
}

impl DomainSeparator {
    fn write_bcs(&self, out: &mut Vec<u8>) {
        write_uleb128(out, 0); // V1 variant
        out.extend_from_slice(&self.contract_address);
        out.push(self.chain_id);
        write_byte_vector(out, &self.protocol_id);
        write_byte_vector(out, &self.session_id);
    }
}

// =============================================================================
// Public types: Statement + Proof
// =============================================================================

/// Public statement for the transfer relation.
///
/// `points` and `compressed_points` are kept in lock-step. For positions
/// `[0..4]` they are `[G, H, ek_sid, ek_rid]`; subsequent positions follow
/// `sigmaProtocolTransfer.ts:243-271`.
#[derive(Debug, Clone)]
pub struct Statement {
    pub points: Vec<RistrettoPoint>,
    pub compressed_points: Vec<[u8; 32]>,
    pub scalars: Vec<[u8; 32]>,
}

/// Compressed sigma proof shape: 30 commitment points + 25 response scalars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaProtocolProof {
    pub commitment: Vec<[u8; 32]>,
    pub response: Vec<[u8; 32]>,
}

// =============================================================================
// BCS helpers — minimal Aptos BCS subset (ULEB128 lengths, U64 LE, bytes vector)
// =============================================================================

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push((value & 0x7f) as u8);
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_byte_vector(out: &mut Vec<u8>, bytes: &[u8]) {
    write_uleb128(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Mirrors `bcsSerializeTransferSession(sender, recipient, asset, ell, n, has_eff, num_volun)`
/// from `sigmaProtocolTransfer.ts:57-75`.
pub fn bcs_serialize_transfer_session(
    sender: &[u8; 32],
    recipient: &[u8; 32],
    asset: &[u8; 32],
    ell: u64,
    n: u64,
    has_effective_auditor: bool,
    num_volun_auditors: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 3 + 8 * 3 + 1);
    out.extend_from_slice(sender);
    out.extend_from_slice(recipient);
    out.extend_from_slice(asset);
    write_u64(&mut out, ell);
    write_u64(&mut out, n);
    out.push(if has_effective_auditor { 1 } else { 0 });
    write_u64(&mut out, num_volun_auditors);
    out
}

/// Mirrors `BcsFiatShamirInputs` serialization (sigmaProtocol.ts:120-153).
///
/// Layout:
/// ```text
/// DomainSeparator BCS
/// vector<u8>(type_name utf8 bytes)
/// u64(k)
/// vector(vector<u8>)(stmt_X compressed points)
/// vector(vector<u8>)(stmt_x scalar bytes)
/// vector(vector<u8>)(proof_A compressed points)
/// ```
pub fn bcs_fiat_shamir_inputs(
    dst: &DomainSeparator,
    type_name: &str,
    k: u64,
    stmt_x: &[[u8; 32]],
    stmt_scalars: &[[u8; 32]],
    proof_a: &[[u8; 32]],
) -> Vec<u8> {
    let mut out = Vec::new();
    dst.write_bcs(&mut out);
    write_byte_vector(&mut out, type_name.as_bytes());
    write_u64(&mut out, k);

    write_uleb128(&mut out, stmt_x.len() as u32);
    for p in stmt_x {
        write_byte_vector(&mut out, p);
    }
    write_uleb128(&mut out, stmt_scalars.len() as u32);
    for s in stmt_scalars {
        write_byte_vector(&mut out, s);
    }
    write_uleb128(&mut out, proof_a.len() as u32);
    for a in proof_a {
        write_byte_vector(&mut out, a);
    }
    out
}

// =============================================================================
// Fiat-Shamir challenge (mirrors sigmaProtocol.ts:171-215)
// =============================================================================

/// Returns `(e, beta)` derived from a seed via the Move-style hash chain:
/// `seed = SHA512(bcs); e = scalar_uniform(SHA512(seed || 0x00)); beta = scalar_uniform(SHA512(seed || 0x01))`.
pub fn sigma_fiat_shamir_seed(bcs: &[u8]) -> (Scalar, Scalar) {
    let seed = Sha512::digest(bcs);
    let mut e_input = [0u8; 65];
    e_input[..64].copy_from_slice(&seed);

    e_input[64] = 0x00;
    let e_hash = Sha512::digest(e_input);
    let mut e_buf = [0u8; 64];
    e_buf.copy_from_slice(&e_hash);
    let e = Scalar::from_bytes_mod_order_wide(&e_buf);

    e_input[64] = 0x01;
    let beta_hash = Sha512::digest(e_input);
    let mut beta_buf = [0u8; 64];
    beta_buf.copy_from_slice(&beta_hash);
    let beta = Scalar::from_bytes_mod_order_wide(&beta_buf);

    (e, beta)
}

// =============================================================================
// Chunk base powers (mirrors `computeBPowers` in sigmaProtocolTransfer.ts:80-87)
// =============================================================================

fn compute_b_powers(count: usize) -> Vec<Scalar> {
    let b = Scalar::from(1u64 << 16);
    let mut powers = Vec::with_capacity(count);
    powers.push(Scalar::ONE);
    for i in 1..count {
        powers.push(powers[i - 1] * b);
    }
    powers
}

// =============================================================================
// Statement layout offsets (mirrors sigmaProtocolTransfer.ts:104-135)
// =============================================================================

const IDX_G: usize = 0;
const IDX_H: usize = 1;
const IDX_EK_SID: usize = 2;
const IDX_EK_RID: usize = 3;
const START_IDX_OLD_P: usize = 4;

fn start_idx_old_r(ell: usize) -> usize {
    START_IDX_OLD_P + ell
}

// =============================================================================
// Building the statement
// =============================================================================

/// Input record for `build_statement` and the prover.
#[derive(Debug, Clone)]
pub struct TransferStatementInputs {
    pub sender_ek: [u8; 32],
    pub recipient_ek: [u8; 32],
    pub old_balance_c: Vec<[u8; 32]>,
    pub old_balance_d: Vec<[u8; 32]>,
    pub new_balance_c: Vec<[u8; 32]>,
    pub new_balance_d: Vec<[u8; 32]>,
    pub transfer_amount_c: Vec<[u8; 32]>,
    pub transfer_amount_d_sender: Vec<[u8; 32]>,
    pub transfer_amount_d_recipient: Vec<[u8; 32]>,
}

/// Build the public statement from compressed ciphertext bytes.
/// Layout mirrors sigmaProtocolTransfer.ts:243-271 (the no-auditor branch).
pub fn build_statement(inputs: &TransferStatementInputs) -> WorkerResult<Statement> {
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = h_ristretto()?;
    let ek_sid = decompress(&inputs.sender_ek, "sender_ek")?;
    let ek_rid = decompress(&inputs.recipient_ek, "recipient_ek")?;

    let mut points = vec![g, h, ek_sid, ek_rid];
    let mut compressed_points: Vec<[u8; 32]> = vec![
        g.compress().to_bytes(),
        h.compress().to_bytes(),
        inputs.sender_ek,
        inputs.recipient_ek,
    ];

    fn push_all(
        comp: &[[u8; 32]],
        points: &mut Vec<RistrettoPoint>,
        compressed: &mut Vec<[u8; 32]>,
        label: &'static str,
    ) -> WorkerResult<()> {
        for (idx, bytes) in comp.iter().enumerate() {
            points.push(decompress(bytes, label).map_err(|err| match err {
                WorkerError::InvalidRequest(msg) => {
                    WorkerError::InvalidRequest(format!("{msg} (idx {idx})"))
                }
                other => other,
            })?);
            compressed.push(*bytes);
        }
        Ok(())
    }

    push_all(
        &inputs.old_balance_c,
        &mut points,
        &mut compressed_points,
        "old_balance_c",
    )?;
    push_all(
        &inputs.old_balance_d,
        &mut points,
        &mut compressed_points,
        "old_balance_d",
    )?;
    push_all(
        &inputs.new_balance_c,
        &mut points,
        &mut compressed_points,
        "new_balance_c",
    )?;
    push_all(
        &inputs.new_balance_d,
        &mut points,
        &mut compressed_points,
        "new_balance_d",
    )?;
    push_all(
        &inputs.transfer_amount_c,
        &mut points,
        &mut compressed_points,
        "transfer_amount_c",
    )?;
    push_all(
        &inputs.transfer_amount_d_sender,
        &mut points,
        &mut compressed_points,
        "transfer_amount_d_sender",
    )?;
    push_all(
        &inputs.transfer_amount_d_recipient,
        &mut points,
        &mut compressed_points,
        "transfer_amount_d_recipient",
    )?;

    Ok(Statement {
        points,
        compressed_points,
        scalars: Vec::new(),
    })
}

fn decompress(bytes: &[u8; 32], label: &'static str) -> WorkerResult<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress().ok_or_else(|| {
        WorkerError::InvalidRequest(format!("{label}: not a valid compressed Ristretto"))
    })
}

// =============================================================================
// psi homomorphism (sigmaProtocolTransfer.ts:311-398)
//
// Outputs 30 group elements for the no-auditor Eunoma case
// (ell=8, n=4, has_effective=false, num_volun=0):
//
//   index 0       : ek_sid * dk
//   index 1..9    : G*new_a[i] + H*new_r[i]    for i in [8]
//   index 9..17   : ek_sid * new_r[i]          for i in [8]
//   index 17      : balance equation
//   index 18..22  : G*v[j] + H*r[j]            for j in [4]
//   index 22..26  : ek_sid * r[j]              for j in [4]
//   index 26..30  : ek_rid * r[j]              for j in [4]
// =============================================================================

fn psi_transfer(
    stmt: &Statement,
    witness: &[Scalar],
    ell: usize,
    n: usize,
    has_effective: bool,
    num_volun: usize,
) -> WorkerResult<Vec<RistrettoPoint>> {
    if has_effective || num_volun > 0 {
        return Err(WorkerError::InvalidRequest(
            "auditor branches are not supported by the single-party reference port"
                .to_string(),
        ));
    }
    if witness.len() != 1 + 2 * ell + 2 * n {
        return Err(WorkerError::InvalidRequest(format!(
            "witness length {} != 1 + 2*ell + 2*n (= {})",
            witness.len(),
            1 + 2 * ell + 2 * n
        )));
    }

    let dk = witness[0];
    let new_a = &witness[1..1 + ell];
    let new_r = &witness[1 + ell..1 + 2 * ell];
    let v = &witness[1 + 2 * ell..1 + 2 * ell + n];
    let r_xfer = &witness[1 + 2 * ell + n..1 + 2 * ell + 2 * n];

    let g = stmt.points[IDX_G];
    let h = stmt.points[IDX_H];
    let ek_sid = stmt.points[IDX_EK_SID];
    let ek_rid = stmt.points[IDX_EK_RID];

    let mut out: Vec<RistrettoPoint> = Vec::with_capacity(1 + ell + ell + 1 + n + n + n);

    // 1. dk * ek_sid
    out.push(ek_sid * dk);

    // 2. G*new_a[i] + H*new_r[i]
    for i in 0..ell {
        out.push(g * new_a[i] + h * new_r[i]);
    }
    // 3. new_r[i] * ek_sid
    for i in 0..ell {
        out.push(ek_sid * new_r[i]);
    }

    // 4. Balance equation: dk*<B, old_R> + (<B, new_a> + <B, v>)*G
    let b_pow_ell = compute_b_powers(ell);
    let b_pow_n = compute_b_powers(n);
    let mut balance = RistrettoPoint::identity();
    let start_old_r = start_idx_old_r(ell);
    for i in 0..ell {
        balance += stmt.points[start_old_r + i] * (dk * b_pow_ell[i]);
    }
    for i in 0..ell {
        balance += g * (new_a[i] * b_pow_ell[i]);
    }
    for j in 0..n {
        balance += g * (v[j] * b_pow_n[j]);
    }
    out.push(balance);

    // 5. G*v[j] + H*r[j]
    for j in 0..n {
        out.push(g * v[j] + h * r_xfer[j]);
    }
    // 6. r[j] * ek_sid
    for j in 0..n {
        out.push(ek_sid * r_xfer[j]);
    }
    // 7. r[j] * ek_rid
    for j in 0..n {
        out.push(ek_rid * r_xfer[j]);
    }

    Ok(out)
}

// =============================================================================
// f transformation (sigmaProtocolTransfer.ts:405-477)
//
// Returns the 30 target points such that psi(sigma) == A + e * f(stmt).
// =============================================================================

fn f_transfer(
    stmt: &Statement,
    ell: usize,
    n: usize,
    has_effective: bool,
    num_volun: usize,
) -> WorkerResult<Vec<RistrettoPoint>> {
    if has_effective || num_volun > 0 {
        return Err(WorkerError::InvalidRequest(
            "auditor branches are not supported by the single-party reference port"
                .to_string(),
        ));
    }
    let g = stmt.points[IDX_G];
    let h = stmt.points[IDX_H];

    let mut out: Vec<RistrettoPoint> = Vec::with_capacity(1 + ell + ell + 1 + n + n + n);

    // 1. H
    out.push(h);

    // 2. new_P[i] = new_balance_C[i]
    let start_new_p = START_IDX_OLD_P + 2 * ell;
    for i in 0..ell {
        out.push(stmt.points[start_new_p + i]);
    }
    // 3. new_R[i] = new_balance_D[i]
    let start_new_r = START_IDX_OLD_P + 3 * ell;
    for i in 0..ell {
        out.push(stmt.points[start_new_r + i]);
    }

    // 4. Balance equation target: <B, old_P>
    let b_pow_ell = compute_b_powers(ell);
    let mut target = RistrettoPoint::identity();
    for i in 0..ell {
        target += stmt.points[START_IDX_OLD_P + i] * b_pow_ell[i];
    }
    out.push(target);

    // 5. P[j] = transfer_amount_C[j]
    let start_p = START_IDX_OLD_P + 4 * ell;
    for j in 0..n {
        out.push(stmt.points[start_p + j]);
    }
    // 6. R_sid[j] = transfer_amount_D_sender[j]
    let start_r_sid = START_IDX_OLD_P + 4 * ell + n;
    for j in 0..n {
        out.push(stmt.points[start_r_sid + j]);
    }
    // 7. R_rid[j] = transfer_amount_D_recipient[j]
    let start_r_rid = START_IDX_OLD_P + 4 * ell + 2 * n;
    for j in 0..n {
        out.push(stmt.points[start_r_rid + j]);
    }
    // Drop unused `g` warning: it's the basepoint, referenced in `psi_transfer`,
    // not in `f_transfer`. Keep the binding for symmetry with the TS port.
    let _ = g;

    Ok(out)
}

// =============================================================================
// Prover (sigmaProtocol.ts:257-285)
// =============================================================================

/// Prove a confidential transfer with caller-supplied randomness `alpha`.
///
/// Byte-parity contract: given the same `witness`, `statement`, `alpha`, and
/// domain separator as the TS prover, this function produces the same 30
/// commitment bytes and 25 response bytes as the Aptos SDK.
pub fn prove_transfer_single_party(
    witness: &[Scalar],
    statement: &Statement,
    alpha: &[Scalar],
    dst: &DomainSeparator,
    ell: usize,
    n: usize,
    has_effective_auditor: bool,
    num_voluntary_auditors: usize,
) -> WorkerResult<SigmaProtocolProof> {
    if has_effective_auditor || num_voluntary_auditors > 0 {
        return Err(WorkerError::InvalidRequest(
            "auditor branches are not supported by the single-party reference port"
                .to_string(),
        ));
    }
    if witness.len() != 1 + 2 * ell + 2 * n {
        return Err(WorkerError::InvalidRequest(format!(
            "witness length {} != 1 + 2*ell + 2*n (= {})",
            witness.len(),
            1 + 2 * ell + 2 * n
        )));
    }
    if alpha.len() != witness.len() {
        return Err(WorkerError::InvalidRequest(format!(
            "alpha length {} != witness length {}",
            alpha.len(),
            witness.len()
        )));
    }

    let k = witness.len() as u64;

    let a_points = psi_transfer(statement, alpha, ell, n, false, 0)?;
    let compressed_a: Vec<[u8; 32]> = a_points
        .iter()
        .map(|p| p.compress().to_bytes())
        .collect();

    let bcs = bcs_fiat_shamir_inputs(
        dst,
        TYPE_NAME,
        k,
        &statement.compressed_points,
        &statement.scalars,
        &compressed_a,
    );
    let (e, _beta) = sigma_fiat_shamir_seed(&bcs);

    let response: Vec<[u8; 32]> = witness
        .iter()
        .zip(alpha.iter())
        .map(|(w_i, alpha_i)| (*alpha_i + e * w_i).to_bytes())
        .collect();

    Ok(SigmaProtocolProof {
        commitment: compressed_a,
        response,
    })
}

// =============================================================================
// Verifier (sigmaProtocol.ts:307-351)
// =============================================================================

pub fn verify_transfer_single_party(
    proof: &SigmaProtocolProof,
    statement: &Statement,
    dst: &DomainSeparator,
    ell: usize,
    n: usize,
    has_effective_auditor: bool,
    num_voluntary_auditors: usize,
) -> WorkerResult<bool> {
    if has_effective_auditor || num_voluntary_auditors > 0 {
        return Err(WorkerError::InvalidRequest(
            "auditor branches are not supported by the single-party reference port"
                .to_string(),
        ));
    }
    if proof.commitment.is_empty() {
        return Ok(false);
    }
    let k = proof.response.len() as u64;

    let sigma: Vec<Scalar> = proof
        .response
        .iter()
        .map(|bytes| Scalar::from_bytes_mod_order(*bytes))
        .collect();

    let bcs = bcs_fiat_shamir_inputs(
        dst,
        TYPE_NAME,
        k,
        &statement.compressed_points,
        &statement.scalars,
        &proof.commitment,
    );
    let (e, _beta) = sigma_fiat_shamir_seed(&bcs);

    let psi_sigma = psi_transfer(
        statement,
        &sigma,
        ell,
        n,
        has_effective_auditor,
        num_voluntary_auditors,
    )?;
    let f_stmt = f_transfer(
        statement,
        ell,
        n,
        has_effective_auditor,
        num_voluntary_auditors,
    )?;

    if psi_sigma.len() != proof.commitment.len() || f_stmt.len() != proof.commitment.len() {
        return Ok(false);
    }

    for i in 0..proof.commitment.len() {
        let a_i = decompress(&proof.commitment[i], "commitment")?;
        let rhs = a_i + f_stmt[i] * e;
        if psi_sigma[i] != rhs {
            return Ok(false);
        }
    }
    Ok(true)
}

// =============================================================================
// Deterministic PRNG mirror (used by the byte-parity test to reconstruct alpha)
// =============================================================================

/// SHA-256-counter-mode PRNG matching the TS fixture generator at
/// `operator-services/deop-protocol/tests/aptos_ca_transfer_parity.test.ts:81-115`.
///
/// `seed_str` is the UTF-8 fixture seed (e.g.
/// `"EUNOMA_APTOS_CA_TRANSFER_V1_FIXTURE_PRNG_SEED"`).
pub struct CounterPrng {
    seed: Vec<u8>,
    blocks: Vec<[u8; 32]>,
    consumed: usize,
}

impl CounterPrng {
    pub fn new(seed_str: &str) -> Self {
        Self {
            seed: seed_str.as_bytes().to_vec(),
            blocks: Vec::new(),
            consumed: 0,
        }
    }

    fn ensure_block(&mut self, idx: usize) {
        while self.blocks.len() <= idx {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&self.seed);
            let counter = (self.blocks.len() as u64).to_be_bytes();
            hasher.update(counter);
            let digest = hasher.finalize();
            let mut block = [0u8; 32];
            block.copy_from_slice(&digest);
            self.blocks.push(block);
        }
    }

    /// Consume `n` bytes, advancing the stream cursor.
    pub fn read(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            let block_idx = self.consumed / 32;
            let in_block = self.consumed % 32;
            self.ensure_block(block_idx);
            *byte = self.blocks[block_idx][in_block];
            self.consumed += 1;
        }
    }

    /// Number of bytes consumed so far. Useful for verifying determinism contracts.
    pub fn bytes_consumed(&self) -> usize {
        self.consumed
    }

    /// Skip ahead `n` bytes (e.g. to jump over the 32 bytes the Aptos WASM
    /// consumes during `thread_rng` initialization, or the 20×32 bytes consumed
    /// before the sigma `alpha` block).
    pub fn skip(&mut self, n: usize) {
        self.consumed += n;
    }
}

/// Curve order ℓ for ed25519 (LE bytes), used in the rejection-sample loop.
const CURVE_ORDER_BE: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

/// Mirrors TS `ed25519GenRandom()`:
/// ```text
/// do { rand = bytesToNumberBE(randomBytes(32)) } while (rand > ed25519.CURVE.n)
/// return rand;
/// ```
///
/// Returns the scalar reduced into canonical LE form. Note: TS interprets the
/// 32 bytes as big-endian and rejection-samples against `n` (NOT `n-1`), so a
/// single edge case `rand == n` would be accepted by TS but yields a scalar of
/// 0 (since `n` ≡ 0 mod n). We honor the same accept rule for byte-exact
/// determinism.
pub fn prng_next_scalar(prng: &mut CounterPrng) -> Scalar {
    loop {
        let mut be = [0u8; 32];
        prng.read(&mut be);
        // Compare big-endian to curve order.
        if !bigint_be_gt(&be, &CURVE_ORDER_BE) {
            // Accept. Reverse to LE, reduce mod ℓ (handles the rand == n case
            // by mapping it to zero exactly as TS's bigint-to-LE-mod-n would).
            let mut le = [0u8; 32];
            for i in 0..32 {
                le[i] = be[31 - i];
            }
            return Scalar::from_bytes_mod_order(le);
        }
    }
}

/// Compare two 32-byte big-endian unsigned integers: returns `a > b`.
fn bigint_be_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}

/// Convenience wrapper: generate a list of `count` scalars in the same order as
/// the TS `ed25519GenListOfRandom(count)`.
pub fn prng_next_scalar_list(prng: &mut CounterPrng, count: usize) -> Vec<Scalar> {
    (0..count).map(|_| prng_next_scalar(prng)).collect()
}
