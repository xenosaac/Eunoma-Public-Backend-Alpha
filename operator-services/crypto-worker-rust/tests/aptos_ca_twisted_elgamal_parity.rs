//! Milestone 4a / commit 5 — byte-for-byte parity tests for the Rust port of
//! Aptos CA chunk math + Twisted ElGamal `encryptWithPK`.

use std::{fs, path::PathBuf};

use curve25519_dalek::scalar::Scalar;
use eunoma_crypto_worker::twisted_elgamal_reference::{
    assert_no_auditor, chunked_amount_to_chunks, chunks_to_amount, encrypt_chunks_with_pk,
    encrypt_with_pk, TwistedElGamalCiphertext, AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS,
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
