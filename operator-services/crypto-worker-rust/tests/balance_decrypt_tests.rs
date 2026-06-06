// M10-b: integration tests for the worker partial-decryption endpoint.
//
// These tests exercise the pure `balance_decrypt::handle` core (chain re-fetch
// is bypassed via the `chain_d_override` test-injection point). The 5
// scenarios mandated by the plan:
//   1. happy_path_partial_decrypt — synthetic ell=8 balance + known DKG share;
//      asserts response shape and that partial[0] equals dk_share · D[0].
//   2. chain_d_mismatch_rejects — request with forged D differing from chain
//      D MUST surface `d_mismatch_at_chunk_<k>`.
//   3. wrong_dkg_epoch_rejects — request whose dkgEpoch doesn't match the
//      share file's dkgEpoch MUST be rejected.
//   4. ell_mismatch_rejects — request whose oldBalanceD length doesn't match
//      the chain's ell MUST be rejected with `ell_mismatch:...`.
//   5. signature_verifies — the response's `signature` field MUST be the
//      SHA-256 of the canonical transcript bytes (orchestrator-recomputable).
//
// All synthetic CA DKG V2 share files use the same Pedersen-VSS scaffolding
// the existing vault_state_v2 / mpcca_withdraw_v2 tests use, so the share
// file passes the loader's full `verify_pedersen_share` round-trip.

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::balance_decrypt::{
    canonical_transcript_bytes, handle, BalanceDecryptError, BalanceDecryptPartialRequest,
    M10B_TRANSCRIPT_DOMAIN,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DKG_EPOCH: &str = "11";
const VAULT_ADDR: &str = "0xfeed";
const ASSET_TYPE: &str = "0x1::test_asset::T";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect()
}

fn scalar_hex(scalar: &Scalar) -> String {
    hex_encode(scalar.to_bytes().as_slice())
}

fn compressed_hex(point: &RistrettoPoint) -> String {
    hex_encode(point.compress().as_bytes())
}

fn det_scalar(seed: u64) -> Scalar {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

const H_RISTRETTO_HEX: &str = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

fn h_point() -> RistrettoPoint {
    let bytes = hex_decode(H_RISTRETTO_HEX);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    curve25519_dalek::ristretto::CompressedRistretto(arr)
        .decompress()
        .expect("valid H")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V2ShareFileLayout {
    scheme: String,
    slot: usize,
    threshold: usize,
    count: usize,
    dkg_epoch: String,
    dk_share: String,
    blind_share: String,
    valid_dealers: Vec<usize>,
    aggregate_commitments: Vec<String>,
    transcript_hash: String,
    created_at_unix_ms: u128,
}

fn temp_state_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("eunoma-m10b-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

/// Build a 5-of-7 Pedersen-VSS polynomial. Returns
/// `(secret coeffs, blind coeffs, aggregate commitments)` so the test can
/// write each slot's share with the same polynomial AND derive `real_dk =
/// coeffs[0]`.
fn make_vss_polynomial(seed: u64) -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(seed + 0),
        det_scalar(seed + 1),
        det_scalar(seed + 2),
        det_scalar(seed + 3),
        det_scalar(seed + 4),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(seed + 100),
        det_scalar(seed + 101),
        det_scalar(seed + 102),
        det_scalar(seed + 103),
        det_scalar(seed + 104),
    ];
    let h = h_point();
    let aggregate_commitments: [String; 5] = [
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[0] + h * blind_coeffs[0])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[1] + h * blind_coeffs[1])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[2] + h * blind_coeffs[2])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[3] + h * blind_coeffs[3])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[4] + h * blind_coeffs[4])),
    ];
    (coeffs, blind_coeffs, aggregate_commitments)
}

/// Evaluate the 5-of-7 polynomial at `x = slot + 1` to get this slot's
/// `dk_share` and `blind_share`, then write the share file in the layout the
/// loader expects.
fn write_v2_share(
    state_dir: &Path,
    slot: usize,
    coeffs: &[Scalar; 5],
    blind_coeffs: &[Scalar; 5],
    aggregate_commitments: &[String; 5],
    dkg_epoch: &str,
) -> Scalar {
    fs::create_dir_all(state_dir).expect("create state_dir");
    let x = Scalar::from((slot as u64) + 1);
    let mut dk_share = coeffs[4];
    let mut blind_share = blind_coeffs[4];
    for i in (0..4).rev() {
        dk_share = dk_share * x + coeffs[i];
        blind_share = blind_share * x + blind_coeffs[i];
    }
    let layout = V2ShareFileLayout {
        scheme: "ca_dkg_v2".to_string(),
        slot,
        threshold: 5,
        count: 7,
        dkg_epoch: dkg_epoch.to_string(),
        dk_share: scalar_hex(&dk_share),
        blind_share: scalar_hex(&blind_share),
        valid_dealers: vec![0, 1, 2, 3, 4, 5, 6],
        aggregate_commitments: aggregate_commitments.to_vec(),
        transcript_hash: "44".repeat(32),
        created_at_unix_ms: 1_700_000_000_000,
    };
    let path = state_dir.join("ca_dkg_share_v2.json");
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap()).expect("write share file");
    dk_share
}

/// Build a synthetic `oldBalanceD[]` vector of length `ell`. For these tests
/// the actual byte values don't matter (the orchestrator computes
/// `oldBalanceD = D` from chain anyway); we just need 8 distinct, valid
/// Ristretto points.
fn synthetic_chain_d(ell: usize, seed: u64) -> Vec<RistrettoPoint> {
    (0..ell)
        .map(|i| RISTRETTO_BASEPOINT_POINT * Scalar::from((seed + i as u64) * 7919))
        .collect()
}

#[tokio::test]
async fn happy_path_partial_decrypt() {
    let state_root = temp_state_dir("happy");
    let slot = 0usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_b001);
    let dk_share_expected = write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let ell = 8usize;
    let chain_d = synthetic_chain_d(ell, 1);
    let old_balance_d_hex: Vec<String> = chain_d.iter().map(compressed_hex).collect();

    let req = BalanceDecryptPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        old_balance_d_hex: old_balance_d_hex.clone(),
        request_id: "happy-req-1".to_string(),
        slot,
    };

    let resp = handle(
        &slot_dir,
        "",
        VAULT_ADDR,
        ASSET_TYPE,
        req,
        Some(chain_d.clone()),
    )
    .await
    .expect("happy-path partial decrypt");

    assert_eq!(resp.slot, slot);
    assert_eq!(resp.partial_hex.len(), ell, "ell=8 partials returned");
    assert_eq!(resp.transcript_domain, M10B_TRANSCRIPT_DOMAIN);

    // Reference: partial[0] MUST equal dk_share · D[0].
    let expected_partial0 = chain_d[0] * dk_share_expected;
    assert_eq!(
        resp.partial_hex[0],
        compressed_hex(&expected_partial0),
        "partial[0] != dk_share · D[0]"
    );
    // Sanity-check the last partial too.
    let expected_partial_last = chain_d[ell - 1] * dk_share_expected;
    assert_eq!(
        resp.partial_hex[ell - 1],
        compressed_hex(&expected_partial_last),
        "partial[ell-1] != dk_share · D[ell-1]"
    );
}

#[tokio::test]
async fn chain_d_mismatch_rejects() {
    let state_root = temp_state_dir("mismatch");
    let slot = 1usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_b002);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let ell = 8usize;
    let chain_d = synthetic_chain_d(ell, 2);

    // Forge: caller-supplied D[3] differs from chain D[3].
    let mut forged_hex: Vec<String> = chain_d.iter().map(compressed_hex).collect();
    let forged_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(999_999u64);
    forged_hex[3] = compressed_hex(&forged_point);

    let req = BalanceDecryptPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        old_balance_d_hex: forged_hex,
        request_id: "mismatch-req".to_string(),
        slot,
    };

    let err = handle(&slot_dir, "", VAULT_ADDR, ASSET_TYPE, req, Some(chain_d))
        .await
        .expect_err("forged D must be rejected");
    let code = err.to_string();
    assert!(
        code.contains("d_mismatch"),
        "expected d_mismatch error, got {code}"
    );
    assert!(
        code.contains("3"),
        "expected chunk index 3 in error, got {code}"
    );
    assert!(matches!(err, BalanceDecryptError::DMismatch { chunk: 3 }));
}

#[tokio::test]
async fn wrong_dkg_epoch_rejects() {
    let state_root = temp_state_dir("epoch");
    let slot = 2usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_b003);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let ell = 8usize;
    let chain_d = synthetic_chain_d(ell, 3);
    let old_balance_d_hex: Vec<String> = chain_d.iter().map(compressed_hex).collect();

    // Request with a non-matching dkg_epoch.
    let req = BalanceDecryptPartialRequest {
        dkg_epoch: "epoch-DOES-NOT-MATCH".to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        old_balance_d_hex,
        request_id: "wrong-epoch".to_string(),
        slot,
    };

    let err = handle(&slot_dir, "", VAULT_ADDR, ASSET_TYPE, req, Some(chain_d))
        .await
        .expect_err("mismatched dkgEpoch must be rejected");
    let code = err.to_string();
    assert!(
        code.contains("dkg_epoch_mismatch"),
        "expected dkg_epoch_mismatch error, got {code}"
    );
    assert!(matches!(err, BalanceDecryptError::MissingShare(_)));
}

#[tokio::test]
async fn ell_mismatch_rejects() {
    let state_root = temp_state_dir("ell");
    let slot = 3usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_b004);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let chain_d = synthetic_chain_d(8, 4); // chain says ell=8
                                           // Request supplies only ell=4.
    let short_hex: Vec<String> = chain_d.iter().take(4).map(compressed_hex).collect();

    let req = BalanceDecryptPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        old_balance_d_hex: short_hex,
        request_id: "ell-mismatch".to_string(),
        slot,
    };

    let err = handle(&slot_dir, "", VAULT_ADDR, ASSET_TYPE, req, Some(chain_d))
        .await
        .expect_err("ell mismatch must be rejected");
    let code = err.to_string();
    assert!(
        code.contains("ell_mismatch"),
        "expected ell_mismatch error, got {code}"
    );
    assert!(matches!(
        err,
        BalanceDecryptError::EllMismatch {
            request: 4,
            chain: 8
        }
    ));
}

#[tokio::test]
async fn signature_verifies() {
    let state_root = temp_state_dir("sig");
    let slot = 4usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_b005);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let ell = 8usize;
    let chain_d = synthetic_chain_d(ell, 5);
    let old_balance_d_hex: Vec<String> = chain_d.iter().map(compressed_hex).collect();

    let req = BalanceDecryptPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        old_balance_d_hex: old_balance_d_hex.clone(),
        request_id: "sig-verify-req".to_string(),
        slot,
    };

    let resp = handle(&slot_dir, "", VAULT_ADDR, ASSET_TYPE, req, Some(chain_d))
        .await
        .expect("happy-path for signature test");

    // Orchestrator-side verification: re-derive the canonical transcript from
    // the (known) inputs + the returned partials, recompute SHA-256, compare
    // hex byte-for-byte with `resp.signature`.
    let expected_bytes = canonical_transcript_bytes(
        DKG_EPOCH,
        VAULT_ADDR,
        ASSET_TYPE,
        slot,
        "sig-verify-req",
        &resp.partial_hex,
    );
    let expected_sig = hex_encode(Sha256::digest(&expected_bytes).as_slice());
    assert_eq!(
        resp.signature, expected_sig,
        "transcript signature mismatch — orchestrator could not re-verify"
    );

    // Tamper sanity-check: flipping a single partial byte MUST break the
    // recomputed signature, proving the transcript actually binds the
    // returned partials.
    let mut tampered_hex = resp.partial_hex.clone();
    let first = tampered_hex[0].clone();
    let mut bytes = hex_decode(&first);
    bytes[0] ^= 0x01;
    tampered_hex[0] = hex_encode(&bytes);
    let tampered_bytes = canonical_transcript_bytes(
        DKG_EPOCH,
        VAULT_ADDR,
        ASSET_TYPE,
        slot,
        "sig-verify-req",
        &tampered_hex,
    );
    let tampered_sig = hex_encode(Sha256::digest(&tampered_bytes).as_slice());
    assert_ne!(
        resp.signature, tampered_sig,
        "transcript signature was insensitive to partial mutation — guard broken"
    );
}
