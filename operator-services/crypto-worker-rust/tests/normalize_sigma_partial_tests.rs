// Normalize ceremony — integration tests for the worker partial endpoint.
//
// Exercises the pure `normalize_sigma_partial::handle` core. The scenarios:
//   1. happy_path_partial — synthetic dk_share; asserts response equals
//      `alpha_share + e · λ_i · dk_share_i` in the Ed25519 scalar field.
//   2. wrong_slot_rejects — request slot != share-file slot MUST fail closed.
//   3. wrong_dkg_epoch_rejects — request epoch != share-file epoch MUST fail.
//   4. non_canonical_alpha_rejects — non-canonical alpha-share plaintext MUST fail.
//   5. zero_challenge_rejects — defense-in-depth fail-closed at e = 0.
//   6. wrong_aad_rejects / wrong_roster_rejects — the HPKE AAD binding MUST
//      fail closed before decrypting a share for a different transcript.
//
// The synthetic share file uses the same minimal layout balance_decrypt_tests.rs
// uses (only the loader's serde fields matter — verify_pedersen_share is NOT
// called by the normalize handler's load path).

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::ca_dkg_v2::init_hpke_local;
use eunoma_crypto_worker::normalize_sigma_partial::{
    handle, normalize_alpha_share_aad, seal_normalize_alpha_share_for_test,
    NormalizeSigmaPartialError, NormalizeSigmaPartialRequest,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;

const DKG_EPOCH: &str = "11";
const VAULT_ADDR: &str = "0xfeed";
const ASSET_TYPE: &str = "0x1::test_asset::T";
const ROSTER_HASH: &str = "44";

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

fn lambda_for_slot(selected_slots: &[usize], slot: usize) -> Scalar {
    let x_i = Scalar::from((slot as u64) + 1);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for other in selected_slots {
        if *other == slot {
            continue;
        }
        let x_j = Scalar::from((*other as u64) + 1);
        num *= -x_j;
        den *= x_i - x_j;
    }
    num * den.invert()
}

const H_RISTRETTO_HEX: &str =
    "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

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
    path.push(format!("eunoma-normalize-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

/// Build a 5-of-7 Pedersen-VSS polynomial. Mirror of the helper in
/// balance_decrypt_tests.rs.
fn make_vss_polynomial(seed: u64) -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(seed),
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

/// Evaluate the 5-of-7 polynomial at `x = slot + 1` and write the share file.
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
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap())
        .expect("write share file");
    dk_share
}

fn make_alpha_hpke(
    state_root: &Path,
    slot: usize,
    request_id: &str,
    e_hex: &str,
    selected_slots: &[usize],
    plaintext: &[u8],
) -> eunoma_crypto_worker::normalize_sigma_partial::HpkeEnvelope {
    let hpke = init_hpke_local(state_root, false).expect("init hpke");
    let pubkey = hpke
        .slots
        .iter()
        .find(|entry| entry.slot == slot)
        .expect("slot hpke")
        .hpke_public_key
        .clone();
    let aad = normalize_alpha_share_aad(
        request_id,
        DKG_EPOCH,
        &ROSTER_HASH.repeat(32),
        VAULT_ADDR,
        ASSET_TYPE,
        e_hex,
        selected_slots,
        slot,
    )
    .expect("aad");
    seal_normalize_alpha_share_for_test(&pubkey, &aad, plaintext).expect("seal alpha share")
}

fn make_req(
    state_root: &Path,
    slot: usize,
    e_scalar: Scalar,
    alpha_share: Scalar,
    request_id: &str,
    selected_slots: Vec<usize>,
) -> NormalizeSigmaPartialRequest {
    let e_hex = scalar_hex(&e_scalar);
    let alpha_hpke = make_alpha_hpke(
        state_root,
        slot,
        request_id,
        &e_hex,
        &selected_slots,
        alpha_share.to_bytes().as_slice(),
    );
    NormalizeSigmaPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        slot,
        roster_hash: ROSTER_HASH.repeat(32),
        selected_slots,
        fiat_shamir_challenge_hex: e_hex,
        alpha_share_hpke: alpha_hpke,
        request_id: request_id.to_string(),
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_partial() {
    let state_root = temp_state_dir("happy");
    let slot = 0usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c001);
    let dk_share_expected = write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    // Pick non-zero scalars for e + α[0]; canonical to round-trip.
    let e_scalar = det_scalar(0xfeed_0001);
    let alpha_scalar = det_scalar(0xcafe_0001);

    let selected_slots = vec![0, 1, 2, 3, 4];
    let req = make_req(
        &state_root,
        slot,
        e_scalar,
        alpha_scalar,
        "happy-req-1",
        selected_slots.clone(),
    );

    let resp = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect("happy-path partial");

    assert_eq!(resp.slot, slot);

    // Reference: partial = α_share + e · λ_i · dk_share_i (mod q).
    let expected_partial =
        alpha_scalar + e_scalar * (lambda_for_slot(&selected_slots, slot) * dk_share_expected);
    assert_eq!(
        resp.partial_s0_hex,
        scalar_hex(&expected_partial),
        "partial != alpha_share + e · lambda · dk_share"
    );

    // Sanity: the response decodes to a canonical scalar.
    let bytes = hex_decode(&resp.partial_s0_hex);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let decoded = Scalar::from_canonical_bytes(arr);
    assert!(
        bool::from(decoded.is_some()),
        "partial_s0_hex is not a canonical Ed25519 scalar"
    );
    assert_eq!(decoded.unwrap(), expected_partial);
}

#[tokio::test]
async fn wrong_slot_rejects() {
    let state_root = temp_state_dir("slot");
    let slot = 1usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c002);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let e_scalar = det_scalar(0xfeed_0002);
    let alpha_scalar = det_scalar(0xcafe_0002);

    // Request claims slot=4, share file holds slot=1.
    let mut req = make_req(
        &state_root,
        slot,
        e_scalar,
        alpha_scalar,
        "wrong-slot",
        vec![0, 1, 2, 3, 4],
    );
    req.slot = 4;

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("slot mismatch must be rejected");
    let code = err.to_string();
    assert!(
        code.contains("slot_mismatch"),
        "expected slot_mismatch error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}

#[tokio::test]
async fn wrong_dkg_epoch_rejects() {
    let state_root = temp_state_dir("epoch");
    let slot = 2usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c003);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let mut req = make_req(
        &state_root,
        slot,
        det_scalar(0xfeed_0003),
        det_scalar(0xcafe_0003),
        "wrong-epoch",
        vec![0, 1, 2, 3, 4],
    );
    req.dkg_epoch = "epoch-DOES-NOT-MATCH".to_string();

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("mismatched dkgEpoch must be rejected");
    let code = err.to_string();
    assert!(
        code.contains("dkg_epoch_mismatch"),
        "expected dkg_epoch_mismatch error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::MissingShare(_)));
}

#[tokio::test]
async fn wrong_aad_rejects() {
    let state_root = temp_state_dir("wrong-aad");
    let slot = 0usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c0a1);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let mut req = make_req(
        &state_root,
        slot,
        det_scalar(0xfeed_00a1),
        det_scalar(0xcafe_00a1),
        "aad-original",
        vec![0, 1, 2, 3, 4],
    );
    req.request_id = "aad-mutated".to_string();

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("AAD mismatch MUST be rejected");
    let code = err.to_string();
    assert!(
        code.contains("alphaShareHpke aadHash mismatch"),
        "expected AAD hash mismatch error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}

#[tokio::test]
async fn wrong_roster_rejects() {
    let state_root = temp_state_dir("wrong-roster");
    let slot = 1usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c0a2);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let mut req = make_req(
        &state_root,
        slot,
        det_scalar(0xfeed_00a2),
        det_scalar(0xcafe_00a2),
        "wrong-roster",
        vec![0, 1, 2, 3, 4],
    );
    req.roster_hash = "55".repeat(32);

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("roster-bound AAD mismatch MUST be rejected");
    let code = err.to_string();
    assert!(
        code.contains("alphaShareHpke aadHash mismatch"),
        "expected roster/AAD hash mismatch error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}

#[tokio::test]
async fn non_canonical_alpha_rejects() {
    let state_root = temp_state_dir("noncanon-alpha");
    let slot = 3usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c004);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    // 32-byte LE with high bit set on the last byte — overflows q, so
    // Scalar::from_canonical_bytes returns None.
    let non_canonical_alpha = "ff".repeat(32);

    let e_scalar = det_scalar(0xfeed_0004);
    let e_hex = scalar_hex(&e_scalar);
    let selected_slots = vec![0, 1, 2, 3, 4];
    let alpha_hpke = make_alpha_hpke(
        &state_root,
        slot,
        "non-canon-alpha",
        &e_hex,
        &selected_slots,
        &hex_decode(&non_canonical_alpha),
    );
    let req = NormalizeSigmaPartialRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        vault_address: VAULT_ADDR.to_string(),
        asset_type: ASSET_TYPE.to_string(),
        slot,
        roster_hash: ROSTER_HASH.repeat(32),
        selected_slots,
        fiat_shamir_challenge_hex: e_hex,
        alpha_share_hpke: alpha_hpke,
        request_id: "non-canon-alpha".to_string(),
    };

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("non-canonical α MUST be rejected");
    let code = err.to_string();
    assert!(
        code.contains("alpha_share_non_canonical"),
        "expected alpha_share_non_canonical error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}

#[tokio::test]
async fn zero_challenge_rejects() {
    let state_root = temp_state_dir("zero-e");
    let slot = 4usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c005);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let zero_e = scalar_hex(&Scalar::ZERO);

    let mut req = make_req(
        &state_root,
        slot,
        Scalar::ONE,
        det_scalar(0xcafe_0005),
        "zero-e",
        vec![0, 1, 2, 3, 4],
    );
    req.fiat_shamir_challenge_hex = zero_e;

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("e = 0 MUST be rejected (defense-in-depth)");
    let code = err.to_string();
    assert!(
        code.contains("fiatShamirChallenge_zero_rejected"),
        "expected zero-rejection error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}

#[tokio::test]
async fn vault_address_mismatch_rejects() {
    let state_root = temp_state_dir("vault-bind");
    let slot = 5usize;
    let slot_dir = state_root.join(format!("slot-{slot}"));
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial(0x10_c006);
    write_v2_share(
        &slot_dir,
        slot,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        DKG_EPOCH,
    );

    let mut req = make_req(
        &state_root,
        slot,
        det_scalar(0xfeed_0006),
        det_scalar(0xcafe_0006),
        "wrong-vault",
        vec![1, 2, 3, 4, 5],
    );
    req.vault_address = "0xbad".to_string();

    let err = handle(&slot_dir, VAULT_ADDR, ASSET_TYPE, req)
        .await
        .expect_err("vault-address mismatch MUST be rejected");
    let code = err.to_string();
    assert!(
        code.contains("vault_address_does_not_match_configured_bridge_vault"),
        "expected vault-binding error, got {code}"
    );
    assert!(matches!(err, NormalizeSigmaPartialError::BadRequest(_)));
}
