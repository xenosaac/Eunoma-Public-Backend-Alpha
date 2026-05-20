//! Milestone 4a / commit 5 — byte-for-byte parity tests for the Rust port of
//! Aptos CA chunk math + Twisted ElGamal `encryptWithPK`.
//!
//! Milestone 4b / commit 2 — threshold partial-ciphertext primitives. Tests at
//! the bottom of this file (`threshold_*` and `multibase_*`) extend the M4a
//! parity invariant to the additive-shared form: Σ partials over additive
//! r-shares must produce the same `(C, D)` bytes as the single-party M4a
//! fixture for both newBalance (sender-only) and transferAmount (sender +
//! recipient) chunks.

use std::{fs, path::PathBuf};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::CompressedRistretto,
    scalar::Scalar,
};
use eunoma_crypto_worker::twisted_elgamal_reference::{
    assert_no_auditor, chunked_amount_to_chunks, chunks_to_amount, encrypt_chunks_with_pk,
    encrypt_with_pk, h_ristretto_point,
    threshold::{
        aggregate_partial_ciphertext_shares, compute_partial_ciphertext_share,
        prove_multibase_schnorr_pok, verify_multibase_schnorr_pok, ThresholdPartial,
    },
    TwistedElGamalCiphertext, AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS,
    TRANSFER_AMOUNT_CHUNK_COUNT,
};
use serde::Deserialize;

const FIXTURE_REL_PATH: &str =
    "../deop-protocol/tests/fixtures/aptos_ca_transfer_v1_fixture.json";

const SDK_FILE_REF: &str = "@aptos-labs/confidential-asset/src/crypto/twistedElGamal.ts";

// =============================================================================
// Fixture wire types
// =============================================================================

#[derive(Debug, Deserialize)]
struct Fixture {
    params: Params,
    statement: StatementFixture,
    #[serde(rename = "plaintextChunks")]
    plaintext_chunks: PlaintextChunks,
    randomness: Randomness,
    ciphertexts: Ciphertexts,
}

#[derive(Debug, Deserialize)]
struct Params {
    ell: usize,
    n: usize,
    #[serde(rename = "chunkBits")]
    chunk_bits: usize,
    amount: u64,
    #[serde(rename = "oldBalance")]
    old_balance: u64,
    #[serde(rename = "newBalance")]
    new_balance: u64,
}

#[derive(Debug, Deserialize)]
struct StatementFixture {
    #[serde(rename = "senderEk")]
    sender_ek: String,
    #[serde(rename = "recipientEk")]
    recipient_ek: String,
}

#[derive(Debug, Deserialize)]
struct PlaintextChunks {
    #[serde(rename = "oldBalance")]
    old_balance: Vec<String>,
    #[serde(rename = "newBalance")]
    new_balance: Vec<String>,
    #[serde(rename = "transferAmount")]
    transfer_amount: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Randomness {
    #[serde(rename = "oldBalance")]
    old_balance: Vec<String>,
    #[serde(rename = "transferAmount")]
    transfer_amount: Vec<String>,
    #[serde(rename = "newBalance")]
    new_balance: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Ciphertexts {
    #[serde(rename = "oldBalanceC")]
    old_balance_c: Vec<String>,
    #[serde(rename = "oldBalanceD")]
    old_balance_d: Vec<String>,
    #[serde(rename = "newBalanceC")]
    new_balance_c: Vec<String>,
    #[serde(rename = "newBalanceD")]
    new_balance_d: Vec<String>,
    #[serde(rename = "amountC")]
    amount_c: Vec<String>,
    #[serde(rename = "amountDSender")]
    amount_d_sender: Vec<String>,
    #[serde(rename = "amountDRecipient")]
    amount_d_recipient: Vec<String>,
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

fn ct_pairs(c_list: &[String], d_list: &[String]) -> Vec<TwistedElGamalCiphertext> {
    assert_eq!(c_list.len(), d_list.len());
    c_list
        .iter()
        .zip(d_list.iter())
        .map(|(c, d)| TwistedElGamalCiphertext {
            c: hex_32(c),
            d: hex_32(d),
        })
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn chunk_constants_match_aptos_sdk() {
    let fix = load_fixture();
    assert_eq!(AVAILABLE_BALANCE_CHUNK_COUNT, 8);
    assert_eq!(TRANSFER_AMOUNT_CHUNK_COUNT, 4);
    assert_eq!(CHUNK_BITS, 16);
    assert_eq!(fix.params.ell, AVAILABLE_BALANCE_CHUNK_COUNT);
    assert_eq!(fix.params.n, TRANSFER_AMOUNT_CHUNK_COUNT);
    assert_eq!(fix.params.chunk_bits, CHUNK_BITS);
}

#[test]
fn chunk_split_parity() {
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;

    // oldBalance = 1000 → [1000, 0, 0, 0, 0, 0, 0, 0]
    let chunks = chunked_amount_to_chunks(fix.params.old_balance as u128, ell, CHUNK_BITS)
        .expect("split oldBalance");
    let expected_old: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.old_balance);
    assert_eq!(chunks, expected_old);

    // newBalance = 900 → [900, 0, 0, 0, 0, 0, 0, 0]
    let chunks = chunked_amount_to_chunks(fix.params.new_balance as u128, ell, CHUNK_BITS)
        .expect("split newBalance");
    let expected_new: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    assert_eq!(chunks, expected_new);

    // transferAmount = 100 → [100, 0, 0, 0]
    let chunks = chunked_amount_to_chunks(fix.params.amount as u128, n, CHUNK_BITS)
        .expect("split transferAmount");
    let expected_amount: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    assert_eq!(chunks, expected_amount);

    // Round-trip: chunks → amount.
    let round_trip = chunks_to_amount(&expected_amount, CHUNK_BITS).unwrap();
    assert_eq!(round_trip, fix.params.amount as u128);
}

#[test]
fn chunk_split_rejects_overflow() {
    // 2^32 with 2 chunks of 16 bits = 2^32 overflows the 32-bit budget.
    let err = chunked_amount_to_chunks(1u128 << 32, 2, 16).unwrap_err();
    let s = format!("{err:?}");
    assert!(s.contains("does not fit"), "{s}");
}

#[test]
fn encrypt_with_pk_byte_parity() {
    let fix = load_fixture();
    let ell = fix.params.ell;
    let n = fix.params.n;
    let sender_ek = hex_32(&fix.statement.sender_ek);
    let recipient_ek = hex_32(&fix.statement.recipient_ek);

    // oldBalance ciphertexts under sender_ek
    let old_chunks: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.old_balance);
    let old_r: Vec<Scalar> = le_hex_to_scalars(&fix.randomness.old_balance);
    let mine_old = encrypt_chunks_with_pk(&old_chunks, &sender_ek, &old_r).expect("enc old");
    let expected_old = ct_pairs(&fix.ciphertexts.old_balance_c, &fix.ciphertexts.old_balance_d);
    for i in 0..ell {
        assert_eq!(
            hex_encode(&mine_old[i].c),
            hex_encode(&expected_old[i].c),
            "oldBalance C[{i}] byte mismatch ({SDK_FILE_REF}:73-77)"
        );
        assert_eq!(
            hex_encode(&mine_old[i].d),
            hex_encode(&expected_old[i].d),
            "oldBalance D[{i}] byte mismatch ({SDK_FILE_REF}:76)"
        );
    }

    // newBalance ciphertexts under sender_ek
    let new_chunks: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    let new_r: Vec<Scalar> = le_hex_to_scalars(&fix.randomness.new_balance);
    let mine_new = encrypt_chunks_with_pk(&new_chunks, &sender_ek, &new_r).expect("enc new");
    let expected_new = ct_pairs(&fix.ciphertexts.new_balance_c, &fix.ciphertexts.new_balance_d);
    for i in 0..ell {
        assert_eq!(
            hex_encode(&mine_new[i].c),
            hex_encode(&expected_new[i].c),
            "newBalance C[{i}] byte mismatch"
        );
        assert_eq!(
            hex_encode(&mine_new[i].d),
            hex_encode(&expected_new[i].d),
            "newBalance D[{i}] byte mismatch"
        );
    }

    // transferAmount ciphertexts: encrypt under sender_ek and under recipient_ek.
    let amt_chunks: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amt_r: Vec<Scalar> = le_hex_to_scalars(&fix.randomness.transfer_amount);
    let mine_sender = encrypt_chunks_with_pk(&amt_chunks, &sender_ek, &amt_r).expect("amt sid");
    let mine_recipient =
        encrypt_chunks_with_pk(&amt_chunks, &recipient_ek, &amt_r).expect("amt rid");

    let expected_sender = ct_pairs(&fix.ciphertexts.amount_c, &fix.ciphertexts.amount_d_sender);
    let expected_recipient = ct_pairs(
        &fix.ciphertexts.amount_c,
        &fix.ciphertexts.amount_d_recipient,
    );
    for j in 0..n {
        // Sender-keyed: C must match the canonical amount_c, D must match amount_d_sender.
        assert_eq!(hex_encode(&mine_sender[j].c), hex_encode(&expected_sender[j].c));
        assert_eq!(hex_encode(&mine_sender[j].d), hex_encode(&expected_sender[j].d));
        // Recipient-keyed: C must STILL match canonical amount_c (same v, same r → same G*v+H*r),
        // but D differs because pk differs.
        assert_eq!(
            hex_encode(&mine_recipient[j].c),
            hex_encode(&expected_recipient[j].c),
            "sender + recipient C must agree (same v·G + r·H)"
        );
        assert_eq!(
            hex_encode(&mine_recipient[j].d),
            hex_encode(&expected_recipient[j].d)
        );
    }
}

#[test]
fn single_encrypt_byte_parity_against_fixture() {
    let fix = load_fixture();
    let sender_ek = hex_32(&fix.statement.sender_ek);
    let amt = fix.params.amount;
    let r0 = Scalar::from_bytes_mod_order(hex_32(&fix.randomness.transfer_amount[0]));
    let mine = encrypt_with_pk(amt, &sender_ek, &r0).expect("encrypt");

    let expected_c = hex_32(&fix.ciphertexts.amount_c[0]);
    let expected_d = hex_32(&fix.ciphertexts.amount_d_sender[0]);
    assert_eq!(mine.c, expected_c);
    assert_eq!(mine.d, expected_d);
}

#[test]
fn auditor_branch_rejected() {
    let err = assert_no_auditor(true, 0).expect_err("hasEffective=true must reject");
    assert!(format!("{err:?}").contains("effective auditor"));

    let err = assert_no_auditor(false, 1).expect_err("numVolun=1 must reject");
    assert!(format!("{err:?}").contains("voluntary"));

    assert!(assert_no_auditor(false, 0).is_ok());
}

// =============================================================================
// Milestone 4b commit 2 — threshold partial-ciphertext byte-parity + POK tests
// =============================================================================

/// Decompress a 32-byte hex Ristretto point. Panics on bad input.
fn ristretto_from_hex(hex: &str) -> curve25519_dalek::ristretto::RistrettoPoint {
    CompressedRistretto(hex_32(hex))
        .decompress()
        .expect("hex must decompress as Ristretto")
}

/// Deterministic scalar from a label, for tests only. We use a length-prefixed
/// byte stream so different labels produce non-colliding scalars without
/// depending on any hash crate beyond what the test already pulls in.
fn det_scalar(label: &[u8]) -> Scalar {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"EUNOMA_M4B_TEST_DET_SCALAR_V1");
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Split a scalar `r` into 5 additive shares whose sum equals `r`:
/// four pseudorandom shares plus a balancing share. Deterministic per `chunk_label`.
fn split_into_five_additive_shares(r: &Scalar, chunk_label: &[u8]) -> [Scalar; 5] {
    let s0 = det_scalar(&[chunk_label, b"/share/0"].concat());
    let s1 = det_scalar(&[chunk_label, b"/share/1"].concat());
    let s2 = det_scalar(&[chunk_label, b"/share/2"].concat());
    let s3 = det_scalar(&[chunk_label, b"/share/3"].concat());
    let s4 = r - (s0 + s1 + s2 + s3);
    [s0, s1, s2, s3, s4]
}

#[test]
fn threshold_aggregation_byte_parity_with_m4a_fixture_new_balance() {
    let fix = load_fixture();
    let ell = fix.params.ell;

    let sender_ek_point = ristretto_from_hex(&fix.statement.sender_ek);
    let g = RISTRETTO_BASEPOINT_POINT;

    let new_chunks: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.new_balance);
    let new_r: Vec<Scalar> = le_hex_to_scalars(&fix.randomness.new_balance);

    // Sanity vs. M4a single-party fixture before the threshold test.
    let single_party = encrypt_chunks_with_pk(&new_chunks, &hex_32(&fix.statement.sender_ek), &new_r)
        .expect("M4a single-party encrypt");

    for i in 0..ell {
        // Additive 5-of-5 split: Σ shares = original r_i (mod q).
        let chunk_label = format!("newBalance/{i}").into_bytes();
        let shares = split_into_five_additive_shares(&new_r[i], &chunk_label);

        // Each party computes its partial; newBalance has no recipient leg.
        let partials: Vec<ThresholdPartial> = shares
            .iter()
            .map(|s| {
                compute_partial_ciphertext_share(s, &sender_ek_point, None)
                    .expect("compute partial")
            })
            .collect();

        let agg = aggregate_partial_ciphertext_shares(
            &partials,
            new_chunks[i],
            &g,
            &sender_ek_point,
            None,
        )
        .expect("aggregate newBalance partials");

        // Byte-parity vs. the M4a fixture for this chunk.
        let agg_c = agg.c.compress().to_bytes();
        let agg_d = agg.d_sender.compress().to_bytes();
        let expected_c = hex_32(&fix.ciphertexts.new_balance_c[i]);
        let expected_d = hex_32(&fix.ciphertexts.new_balance_d[i]);

        assert_eq!(
            hex_encode(&agg_c),
            hex_encode(&expected_c),
            "threshold newBalance C[{i}] disagrees with M4a fixture"
        );
        assert_eq!(
            hex_encode(&agg_d),
            hex_encode(&expected_d),
            "threshold newBalance D[{i}] disagrees with M4a fixture"
        );

        // And vs. single-party encrypt_chunks_with_pk: the entire chain must match.
        assert_eq!(hex_encode(&agg_c), hex_encode(&single_party[i].c));
        assert_eq!(hex_encode(&agg_d), hex_encode(&single_party[i].d));

        assert!(
            agg.d_recip.is_none(),
            "newBalance aggregation must not carry a recipient leg"
        );
    }
}

#[test]
fn threshold_aggregation_byte_parity_with_m4a_fixture_transfer_amount() {
    let fix = load_fixture();
    let n = fix.params.n;

    let sender_ek_point = ristretto_from_hex(&fix.statement.sender_ek);
    let recipient_ek_point = ristretto_from_hex(&fix.statement.recipient_ek);
    let g = RISTRETTO_BASEPOINT_POINT;

    let amt_chunks: Vec<u64> = decimal_to_u64(&fix.plaintext_chunks.transfer_amount);
    let amt_r: Vec<Scalar> = le_hex_to_scalars(&fix.randomness.transfer_amount);

    for j in 0..n {
        let chunk_label = format!("transferAmount/{j}").into_bytes();
        let shares = split_into_five_additive_shares(&amt_r[j], &chunk_label);

        // transferAmount has BOTH sender and recipient legs.
        let partials: Vec<ThresholdPartial> = shares
            .iter()
            .map(|s| {
                compute_partial_ciphertext_share(s, &sender_ek_point, Some(&recipient_ek_point))
                    .expect("compute transfer partial")
            })
            .collect();

        let agg = aggregate_partial_ciphertext_shares(
            &partials,
            amt_chunks[j],
            &g,
            &sender_ek_point,
            Some(&recipient_ek_point),
        )
        .expect("aggregate transferAmount partials");

        let agg_c = agg.c.compress().to_bytes();
        let agg_d_sender = agg.d_sender.compress().to_bytes();
        let agg_d_recip = agg
            .d_recip
            .expect("transferAmount aggregation must carry recipient leg")
            .compress()
            .to_bytes();

        let expected_c = hex_32(&fix.ciphertexts.amount_c[j]);
        let expected_d_sender = hex_32(&fix.ciphertexts.amount_d_sender[j]);
        let expected_d_recip = hex_32(&fix.ciphertexts.amount_d_recipient[j]);

        assert_eq!(
            hex_encode(&agg_c),
            hex_encode(&expected_c),
            "threshold transferAmount C[{j}] disagrees with M4a fixture amount_c"
        );
        assert_eq!(
            hex_encode(&agg_d_sender),
            hex_encode(&expected_d_sender),
            "threshold transferAmount D_sender[{j}] disagrees with amount_d_sender"
        );
        assert_eq!(
            hex_encode(&agg_d_recip),
            hex_encode(&expected_d_recip),
            "threshold transferAmount D_recip[{j}] disagrees with amount_d_recipient"
        );
    }
}

#[test]
fn multibase_schnorr_pok_verifies_when_same_r_share_used() {
    let fix = load_fixture();
    let sender_ek_point = ristretto_from_hex(&fix.statement.sender_ek);
    let recipient_ek_point = ristretto_from_hex(&fix.statement.recipient_ek);

    let r_share = det_scalar(b"pok/positive/r_share");
    let k = det_scalar(b"pok/positive/k");
    let transcript_bind = b"unit-test-positive-case";

    // Newbalance shape: sender-only leg.
    let partial_no_recip = compute_partial_ciphertext_share(&r_share, &sender_ek_point, None)
        .expect("compute partial no-recip");
    let pok_no_recip =
        prove_multibase_schnorr_pok(&r_share, &k, &sender_ek_point, None, transcript_bind)
            .expect("prove no-recip POK");
    assert!(
        verify_multibase_schnorr_pok(
            &pok_no_recip,
            &partial_no_recip,
            &sender_ek_point,
            None,
            transcript_bind,
        )
        .expect("verify no-recip POK"),
        "newBalance-shape multi-base POK must verify when same r_share is used"
    );

    // Transfer-amount shape: sender + recipient leg.
    let partial_with_recip = compute_partial_ciphertext_share(
        &r_share,
        &sender_ek_point,
        Some(&recipient_ek_point),
    )
    .expect("compute partial with-recip");
    let pok_with_recip = prove_multibase_schnorr_pok(
        &r_share,
        &k,
        &sender_ek_point,
        Some(&recipient_ek_point),
        transcript_bind,
    )
    .expect("prove with-recip POK");
    assert!(
        verify_multibase_schnorr_pok(
            &pok_with_recip,
            &partial_with_recip,
            &sender_ek_point,
            Some(&recipient_ek_point),
            transcript_bind,
        )
        .expect("verify with-recip POK"),
        "transferAmount-shape multi-base POK must verify when same r_share is used"
    );

    // Soundness sanity: tampering with the transcript_bind invalidates the proof
    // (Fiat-Shamir is binding to the transcript).
    assert!(
        !verify_multibase_schnorr_pok(
            &pok_with_recip,
            &partial_with_recip,
            &sender_ek_point,
            Some(&recipient_ek_point),
            b"different-transcript-bind",
        )
        .expect("verify with mutated bind"),
        "POK must reject under a different transcript_bind"
    );
}

#[test]
fn multibase_schnorr_pok_rejects_when_r_share_mismatched_between_bases() {
    let fix = load_fixture();
    let sender_ek_point = ristretto_from_hex(&fix.statement.sender_ek);

    let h = h_ristretto_point().expect("decompress H_RISTRETTO");
    let r1 = det_scalar(b"pok/mismatch/r1");
    let r2 = det_scalar(b"pok/mismatch/r2");
    assert_ne!(r1, r2, "test sanity: r1 != r2");

    // Construct a malicious partial: C uses r1, but D_sender uses r2. A correct
    // prover could not produce this from a single r — a verifier MUST reject.
    let bad_partial = ThresholdPartial {
        c_partial: h * r1,
        d_sender_partial: sender_ek_point * r2,
        d_recip_partial: None,
    };

    let k = det_scalar(b"pok/mismatch/k");
    let transcript_bind = b"unit-test-mismatch-case";

    // Prover follows the protocol with r = r1 (the one matching c_partial). The
    // POK then satisfies the H-leg but cannot satisfy the ek_sender-leg because
    // d_sender_partial = ek_sender * r2 ≠ ek_sender * r1.
    let pok = prove_multibase_schnorr_pok(&r1, &k, &sender_ek_point, None, transcript_bind)
        .expect("prove POK with r1");

    let verified = verify_multibase_schnorr_pok(
        &pok,
        &bad_partial,
        &sender_ek_point,
        None,
        transcript_bind,
    )
    .expect("verify must not error");
    assert!(
        !verified,
        "multi-base POK MUST reject when r underlying C differs from r underlying D_sender"
    );

    // Symmetric check: a prover that uses r2 would satisfy the ek_sender-leg
    // but fail the H-leg. Either way, the proof cannot pass.
    let pok2 = prove_multibase_schnorr_pok(&r2, &k, &sender_ek_point, None, transcript_bind)
        .expect("prove POK with r2");
    let verified2 = verify_multibase_schnorr_pok(
        &pok2,
        &bad_partial,
        &sender_ek_point,
        None,
        transcript_bind,
    )
    .expect("verify (r2) must not error");
    assert!(
        !verified2,
        "the symmetric prover that targets D's r also fails — neither r passes both bases"
    );
}

#[test]
fn aggregate_rejects_d_recip_mismatch() {
    let fix = load_fixture();
    let sender_ek_point = ristretto_from_hex(&fix.statement.sender_ek);
    let recipient_ek_point = ristretto_from_hex(&fix.statement.recipient_ek);
    let g = RISTRETTO_BASEPOINT_POINT;

    let r0 = det_scalar(b"mismatch/r0");
    let r1 = det_scalar(b"mismatch/r1");

    // p0 carries a recipient leg, p1 does NOT — aggregation must reject.
    let p0 = compute_partial_ciphertext_share(&r0, &sender_ek_point, Some(&recipient_ek_point))
        .expect("p0 with recip");
    let p1 = compute_partial_ciphertext_share(&r1, &sender_ek_point, None)
        .expect("p1 without recip");

    let err = aggregate_partial_ciphertext_shares(
        &[p0, p1],
        100u64,
        &g,
        &sender_ek_point,
        Some(&recipient_ek_point),
    )
    .expect_err("mixed-shape partials must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("d_recip_partial") && msg.contains("disagrees"),
        "error must explain the d_recip mismatch, got: {msg}"
    );

    // Also: all partials Some, but ek_recip_opt = None → rejected.
    let p_both_with = compute_partial_ciphertext_share(
        &r0,
        &sender_ek_point,
        Some(&recipient_ek_point),
    )
    .expect("p both with recip");
    let err = aggregate_partial_ciphertext_shares(
        &[p_both_with, p_both_with],
        100u64,
        &g,
        &sender_ek_point,
        None,
    )
    .expect_err("ek_recip_opt absent but partials have recip leg → rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ek_recip_opt") && msg.contains("disagrees"),
        "error must explain ek_recip_opt mismatch, got: {msg}"
    );

    // And: all partials None, but ek_recip_opt = Some → rejected (symmetric).
    let p_no_recip = compute_partial_ciphertext_share(&r0, &sender_ek_point, None)
        .expect("p no recip");
    let err = aggregate_partial_ciphertext_shares(
        &[p_no_recip, p_no_recip],
        100u64,
        &g,
        &sender_ek_point,
        Some(&recipient_ek_point),
    )
    .expect_err("ek_recip_opt Some but partials have no recip leg → rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ek_recip_opt") && msg.contains("disagrees"),
        "error must explain ek_recip_opt mismatch, got: {msg}"
    );
}
