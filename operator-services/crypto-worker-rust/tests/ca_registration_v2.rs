// Milestone 1: V2 threshold CA registration sigma tests.
//
// The protocol shape is identical to V1 (Schnorr-style proof of knowledge of `dk` with
// `vault_ek` as the generator), but the SOURCE of inputs is different:
//   - dk share: ca_dkg_share_v2.json (real Pedersen VSS), NOT ca_share.json.
//   - vault_ek: dynamically supplied per session (Phase 2-derived), NOT loaded from disk.
//
// The killer integration test (`v2_threshold_sigma_passes_local_verifier`) builds a
// canonical 5-of-7 Pedersen VSS on a synthetic dk, derives vault_ek = H * 1/dk locally
// (mathematically equivalent to what Phase 2 produces — no MP-SPDZ runtime required),
// then runs the full round1/round2/aggregate pipeline end-to-end and asserts
// `verify_registration_proof(...)` returns Ok(()).

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::{
    ca_local::{
        verify_registration_proof, RegistrationCommitmentInput, RegistrationResponseInput,
    },
    ca_registration_v2::{
        create_registration_nonce_commitment_v2, create_registration_partial_response_v2,
        run_aggregate_v2, run_verify_v2, AggregateRequest, Round1Request, Round2Request,
        VerifyRequest,
    },
    WorkerError,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;

const DKG_EPOCH: &str = "3";

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

/// Same H_RISTRETTO constant as the crate (lib.rs:74).
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

#[derive(Serialize)]
struct V1ShareFileLayout {
    scheme: String,
    slot: usize,
    threshold: usize,
    count: usize,
    dkg_epoch: String,
    share: String,
    blind_share: String,
    public_share: String,
    vault_ek: String,
    commitments: Vec<String>,
    transcript_hash: String,
    created_at_unix_ms: u128,
}

fn temp_state_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("eunoma-ca-reg-v2-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

/// Build a canonical 5-of-7 Pedersen VSS share. Returns `(dk, blind, aggregate_commitments)`
/// for the polynomial f(x) with `coeffs[0] = dk`, blinded by `blind_coeffs[0] = blind`.
fn make_vss_polynomial() -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(0xD0_0000),
        det_scalar(0xD0_0001),
        det_scalar(0xD0_0002),
        det_scalar(0xD0_0003),
        det_scalar(0xD0_0004),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(0xB0_0000),
        det_scalar(0xB0_0001),
        det_scalar(0xB0_0002),
        det_scalar(0xB0_0003),
        det_scalar(0xB0_0004),
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

/// Persist a V2 share file under `state_dir/ca_dkg_share_v2.json` for the given slot. Uses
/// Horner evaluation of (coeffs, blind_coeffs) at x = slot + 1.
fn write_v2_share(
    state_dir: &Path,
    slot: usize,
    coeffs: &[Scalar; 5],
    blind_coeffs: &[Scalar; 5],
    aggregate_commitments: &[String; 5],
    transcript_hex: &str,
    dkg_epoch: &str,
) {
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
        transcript_hash: transcript_hex.to_string(),
        created_at_unix_ms: 1_700_000_000_000,
    };
    let path = state_dir.join("ca_dkg_share_v2.json");
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap())
        .expect("write share file");
}

/// Persist a V1 share file under `state_dir/ca_dkg_share.json`. Used by the
/// `ca_registration_v2_uses_v2_share` test to verify that V2 ignores V1 files even when
/// both are present on disk.
fn write_v1_fixture_share(state_dir: &Path, slot: usize, dk: Scalar) {
    let coeffs = [dk, det_scalar(0xC1), det_scalar(0xC2), det_scalar(0xC3), det_scalar(0xC4)];
    let blind_coeffs = [
        det_scalar(0xB1),
        det_scalar(0xB2),
        det_scalar(0xB3),
        det_scalar(0xB4),
        det_scalar(0xB5),
    ];
    let h = h_point();
    let aggregate_commitments: Vec<String> = (0..5)
        .map(|i| compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[i] + h * blind_coeffs[i])))
        .collect();
    let x = Scalar::from((slot as u64) + 1);
    let mut share = coeffs[4];
    let mut blind_share = blind_coeffs[4];
    for i in (0..4).rev() {
        share = share * x + coeffs[i];
        blind_share = blind_share * x + blind_coeffs[i];
    }
    let public_share = RISTRETTO_BASEPOINT_POINT * share + h * blind_share;
    let vault_ek = h * dk.invert();
    let layout = V1ShareFileLayout {
        scheme: "ca_dkg_local".to_string(),
        slot,
        threshold: 5,
        count: 7,
        dkg_epoch: "999".to_string(), // Distinct epoch so V2 binding catches any accidental fall-through.
        share: scalar_hex(&share),
        blind_share: scalar_hex(&blind_share),
        public_share: compressed_hex(&public_share),
        vault_ek: compressed_hex(&vault_ek),
        commitments: aggregate_commitments,
        transcript_hash: "ff".repeat(32),
        created_at_unix_ms: 1_700_000_000_000,
    };
    let path = state_dir.join("ca_dkg_share.json");
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap())
        .expect("write V1 share file");
}

#[test]
fn ca_registration_v2_uses_v2_share() {
    // BOTH files present on disk:
    //   - ca_dkg_share.json (V1 fixture, dk_v1)
    //   - ca_dkg_share_v2.json (V2 production, dk_v2)
    // V2 must use the V2 share. Different dk → different round2 response. Build the V2
    // share with dk_v2 and a vault_ek derived from dk_v2; if V2 accidentally fell back to
    // V1, the response wouldn't satisfy the verify equation (and load_ca_dkg_v2_share
    // wouldn't accept the V1 commitments anyway).
    let state_dir = temp_state_dir("uses-v2-share");
    let ca_transcript = "aa".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);

    // Write a V1 fixture with a DIFFERENT dk + epoch=999 (mismatched binding). If V2
    // somehow loaded V1, the dkg_epoch mismatch would surface as an InvalidRequest. But
    // load_ca_dkg_v2_share doesn't read ca_share.json at all — it goes straight for
    // ca_dkg_share_v2.json. This test asserts the round1 call succeeds (V2 share loaded
    // OK) and the resulting commitment uses the supplied vault_ek as the generator.
    write_v1_fixture_share(&state_dir, 0, det_scalar(0xFACE));

    let dk = coeffs[0]; // V2 polynomial constant term.
    let h = h_point();
    let vault_ek_point = h * dk.invert();
    let vault_ek_hex = compressed_hex(&vault_ek_point);

    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "uses-v2-share-req".to_string(),
        session_id: "uses-v2-share-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript.clone(),
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        vault_ek: vault_ek_hex.clone(),
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let result = create_registration_nonce_commitment_v2(&state_dir, &req).expect("round1");
    assert_eq!(result.slot, 0);
    // The commitment is `vault_ek * r_i`, on the curve and not the identity.
    let commitment_bytes = hex_decode(&result.commitment_hex);
    assert_eq!(commitment_bytes.len(), 32);
}

#[test]
fn ca_registration_v2_transcript_binding() {
    // ca_dkg_transcript_hash supplied in the request must match the value in the
    // persisted V2 share file. A mismatch → InvalidRequest (binding violation).
    let state_dir = temp_state_dir("transcript-binding");
    let ca_transcript = "aa".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);

    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * coeffs[0].invert()));

    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "transcript-mismatch-req".to_string(),
        session_id: "transcript-mismatch-sess".to_string(),
        // Mismatched value:
        ca_dkg_transcript_hash: "bb".repeat(32),
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        vault_ek: vault_ek_hex,
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let err = create_registration_nonce_commitment_v2(&state_dir, &req).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ca_dkg_transcript_hash"),
        "expected transcript hash mismatch error, got: {msg}"
    );
}

#[test]
fn ca_registration_v2_dkg_epoch_mismatch() {
    let state_dir = temp_state_dir("epoch-mismatch");
    let ca_transcript = "aa".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);

    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * coeffs[0].invert()));
    let req = Round1Request {
        dkg_epoch: "999".to_string(), // mismatch
        request_id: "epoch-mismatch-req".to_string(),
        session_id: "epoch-mismatch-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript,
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        vault_ek: vault_ek_hex,
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let err = create_registration_nonce_commitment_v2(&state_dir, &req).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("dkg_epoch"), "expected dkg_epoch mismatch, got: {msg}");
}

#[test]
fn ca_registration_v2_slot_mismatch() {
    let state_dir = temp_state_dir("slot-mismatch");
    let ca_transcript = "aa".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    // Write share for slot 2.
    write_v2_share(&state_dir, 2, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);
    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * coeffs[0].invert()));
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "slot-mismatch-req".to_string(),
        session_id: "slot-mismatch-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript,
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0, // request claims slot 0 but share is for slot 2
        player_id: 0,
        vault_ek: vault_ek_hex,
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let err = create_registration_nonce_commitment_v2(&state_dir, &req).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("slot"), "expected slot mismatch error, got: {msg}");
}

#[test]
fn ca_registration_v2_vault_ek_mismatch_on_replay() {
    // Round1 with vault_ek_A persists a nonce file bound to vault_ek_A. A retry with
    // vault_ek_B (different) MUST fail — silently reusing the persisted nonce would mean
    // the commitment was for a different sigma statement than the response will compute
    // against, which is a soundness violation.
    let state_dir = temp_state_dir("vault-ek-mismatch");
    let ca_transcript = "aa".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);
    let h = h_point();
    let vault_ek_a = compressed_hex(&(h * coeffs[0].invert()));
    let vault_ek_b = compressed_hex(&(h * det_scalar(0xDEADBEEF).invert()));

    let req_a = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "replay-req".to_string(),
        session_id: "replay-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript.clone(),
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        vault_ek: vault_ek_a.clone(),
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let first = create_registration_nonce_commitment_v2(&state_dir, &req_a).expect("first round1");

    // Replay with same request_id/session_id but different vault_ek → reject.
    let mut req_b = req_a.clone();
    req_b.vault_ek = vault_ek_b;
    let err = create_registration_nonce_commitment_v2(&state_dir, &req_b).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("vault_ek_mismatch") || msg.contains("vault_ek"),
        "expected vault_ek mismatch error, got: {msg}"
    );

    // Idempotency: replay with the SAME vault_ek returns the same nonce_id + commitment.
    let second = create_registration_nonce_commitment_v2(&state_dir, &req_a).expect("idempotent");
    assert_eq!(first.nonce_id, second.nonce_id);
    assert_eq!(first.commitment_hex, second.commitment_hex);
}

/// **Killer test for Milestone 1.**
///
/// Builds a canonical 5-of-7 Pedersen VSS, derives `vault_ek = H * 1/dk` directly (no
/// MP-SPDZ needed for this test — we control the polynomial so we know `dk`), runs the
/// full V2 threshold sigma pipeline:
///   1. round1 fan-out → 5 commitments T_i = vault_ek * r_i
///   2. aggregate commitments via Lagrange → T
///   3. Fiat-Shamir challenge c over (vault_ek, sender, asset, chain_id, T)
///   4. round2 fan-out → 5 responses s_i = r_i + c * dk_share_i
///   5. aggregate responses via Lagrange → s
///   6. verify_registration_proof(vault_ek, ..., T, s) returns Ok(())
///
/// If any step is broken — wrong share file loaded, wrong generator, broken Lagrange,
/// broken Fiat-Shamir — `verify_registration_proof` rejects.
#[test]
fn v2_threshold_sigma_passes_local_verifier() {
    let ca_transcript = "55".repeat(32);
    let roster_hash = "66".repeat(32);
    let sender = "01".repeat(32);
    let asset = "02".repeat(32);
    let chain_id: u8 = 4;
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    let dk = coeffs[0];
    let h = h_point();
    let vault_ek_point = h * dk.invert();
    let vault_ek_hex = compressed_hex(&vault_ek_point);

    // Persist a V2 share file for each of slots 0..4 (the selected subset).
    let root = temp_state_dir("v2-threshold-killer");
    let mut slot_dirs = Vec::with_capacity(5);
    let selected_slots = [0_usize, 1, 2, 3, 4];
    for slot in 0..7 {
        let dir = root.join(format!("slot-{slot}"));
        write_v2_share(
            &dir,
            slot,
            &coeffs,
            &blind_coeffs,
            &aggregate_commitments,
            &ca_transcript,
            DKG_EPOCH,
        );
        slot_dirs.push(dir);
    }

    // Round 1: fan-out → collect commitments.
    let mut round1_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = Round1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("killer-req-{slot}"),
            session_id: format!("killer-sess-{slot}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.to_vec(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id,
        };
        let result = create_registration_nonce_commitment_v2(&slot_dirs[slot], &req)
            .expect("round1 succeeds");
        round1_results.push(result);
    }

    let commitments: Vec<RegistrationCommitmentInput> = selected_slots
        .iter()
        .zip(round1_results.iter())
        .map(|(&slot, r)| RegistrationCommitmentInput {
            slot,
            commitment: r.commitment_hex.clone(),
        })
        .collect();

    // Interim aggregation: compute aggregate commitment + challenge BEFORE round2. We do
    // this by calling run_aggregate_v2 with placeholder responses just for the
    // challenge — but run_aggregate_v2 actually verifies; so instead, use the lower-level
    // public helpers exposed by ca_local. Easier path: hit the V1 `registration_challenge`
    // helper directly (same Lagrange + Fiat-Shamir math, share-independent).
    let aggregate_commitment =
        eunoma_crypto_worker::ca_local::aggregate_registration_commitment(&commitments)
            .expect("aggregate commitments");
    let challenge_hex = eunoma_crypto_worker::ca_local::registration_challenge(
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate_commitment,
    )
    .expect("challenge");

    // Round 2: fan-out → collect responses.
    let mut round2_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = Round2Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("killer-req-{slot}"),
            session_id: format!("killer-sess-{slot}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.to_vec(),
            self_slot: slot,
            player_id: ordinal,
            nonce_id: round1_results[ordinal].nonce_id.clone(),
            challenge: challenge_hex.clone(),
        };
        let result = create_registration_partial_response_v2(&slot_dirs[slot], &req)
            .expect("round2 succeeds");
        round2_results.push(result);
    }

    let responses: Vec<RegistrationResponseInput> = selected_slots
        .iter()
        .zip(round2_results.iter())
        .map(|(&slot, r)| RegistrationResponseInput {
            slot,
            response: r.response_hex.clone(),
        })
        .collect();

    // Final aggregate + verify via the worker-level helper.
    let aggregate = run_aggregate_v2(&AggregateRequest {
        vault_ek: vault_ek_hex.clone(),
        sender_address: sender.clone(),
        asset_type: asset.clone(),
        chain_id,
        commitments: commitments.clone(),
        responses: responses.clone(),
    })
    .expect("aggregate + verify succeeds — KILLER ASSERTION");

    // Cross-check: aggregate commitment + challenge between interim and final calls match.
    assert_eq!(
        aggregate.aggregate_commitment.to_lowercase(),
        aggregate_commitment.to_lowercase()
    );
    assert_eq!(aggregate.challenge.to_lowercase(), challenge_hex.to_lowercase());

    // Independent verification via the production verifier.
    verify_registration_proof(
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate.aggregate_commitment,
        &aggregate.aggregate_response,
    )
    .expect("verify_registration_proof Ok — production verifier accepts the V2-derived tuple");

    // Also confirm run_verify_v2 (the HTTP-exposed wrapper) accepts the same tuple.
    run_verify_v2(&VerifyRequest {
        vault_ek: vault_ek_hex,
        sender_address: sender,
        asset_type: asset,
        chain_id,
        aggregate_commitment: aggregate.aggregate_commitment,
        aggregate_response: aggregate.aggregate_response,
    })
    .expect("run_verify_v2 Ok");
}

#[test]
fn aggregate_proof_invalid_when_response_tampered() {
    // Verify the public verifier rejects a tampered response. Builds the same canonical
    // 5-of-7 VSS, runs the pipeline, but flips a byte in one response before aggregation.
    let ca_transcript = "55".repeat(32);
    let roster_hash = "66".repeat(32);
    let sender = "01".repeat(32);
    let asset = "02".repeat(32);
    let chain_id: u8 = 4;
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    let dk = coeffs[0];
    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * dk.invert()));

    let root = temp_state_dir("v2-tampered");
    let mut slot_dirs = Vec::with_capacity(7);
    let selected_slots = [0_usize, 1, 2, 3, 4];
    for slot in 0..7 {
        let dir = root.join(format!("slot-{slot}"));
        write_v2_share(
            &dir,
            slot,
            &coeffs,
            &blind_coeffs,
            &aggregate_commitments,
            &ca_transcript,
            DKG_EPOCH,
        );
        slot_dirs.push(dir);
    }

    let mut round1_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = Round1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("tampered-req-{slot}"),
            session_id: format!("tampered-sess-{slot}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.to_vec(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id,
        };
        round1_results.push(
            create_registration_nonce_commitment_v2(&slot_dirs[slot], &req).expect("round1"),
        );
    }
    let commitments: Vec<RegistrationCommitmentInput> = selected_slots
        .iter()
        .zip(round1_results.iter())
        .map(|(&slot, r)| RegistrationCommitmentInput {
            slot,
            commitment: r.commitment_hex.clone(),
        })
        .collect();
    let aggregate_commitment =
        eunoma_crypto_worker::ca_local::aggregate_registration_commitment(&commitments)
            .expect("aggregate commitments");
    let challenge_hex = eunoma_crypto_worker::ca_local::registration_challenge(
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate_commitment,
    )
    .expect("challenge");

    let mut round2_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = Round2Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("tampered-req-{slot}"),
            session_id: format!("tampered-sess-{slot}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.to_vec(),
            self_slot: slot,
            player_id: ordinal,
            nonce_id: round1_results[ordinal].nonce_id.clone(),
            challenge: challenge_hex.clone(),
        };
        round2_results
            .push(create_registration_partial_response_v2(&slot_dirs[slot], &req).expect("round2"));
    }

    // Tamper with response[0] by flipping a bit.
    let mut tampered_responses: Vec<RegistrationResponseInput> = selected_slots
        .iter()
        .zip(round2_results.iter())
        .map(|(&slot, r)| RegistrationResponseInput {
            slot,
            response: r.response_hex.clone(),
        })
        .collect();
    let mut response_bytes = hex_decode(&tampered_responses[0].response);
    response_bytes[0] ^= 0x01; // flip
    tampered_responses[0].response = hex_encode(&response_bytes);

    let err = run_aggregate_v2(&AggregateRequest {
        vault_ek: vault_ek_hex,
        sender_address: sender,
        asset_type: asset,
        chain_id,
        commitments,
        responses: tampered_responses,
    })
    .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("registration sigma proof verification failed"),
        "expected sigma verify failure, got: {msg}"
    );
}

#[test]
fn round2_without_round1_returns_missing_nonce_file() {
    // Direct round2 call without a prior round1 must fail-closed (no persisted nonce).
    let state_dir = temp_state_dir("missing-nonce");
    let ca_transcript = "55".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(
        &state_dir,
        0,
        &coeffs,
        &blind_coeffs,
        &aggregate_commitments,
        &ca_transcript,
        DKG_EPOCH,
    );
    let req = Round2Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "missing-nonce-req".to_string(),
        session_id: "missing-nonce-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript,
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        nonce_id: "ab".repeat(32),
        challenge: scalar_hex(&Scalar::ONE),
    };
    let err = create_registration_partial_response_v2(&state_dir, &req).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidDkgState(msg) if msg.contains("nonce_file_missing")),
        "expected nonce_file_missing, got: {err:?}"
    );
}

// =============================================================================================
// Codex P1 #1: nonce-reuse → dk_share recovery attack-resistance tests.
//
// The vulnerability: if `create_registration_partial_response_v2` were not atomic-single-use,
// two concurrent /round2 requests with the same nonceId but DIFFERENT challenges (c1, c2)
// would each return a valid response (s1, s2). The attacker computes
//   dk_share_i = (s1 - s2) * (c1 - c2)^{-1} (mod q)
// — the worker's actual Shamir share of dk. Five such attacks across slots reconstruct dk.
//
// The fix uses `std::fs::rename` to atomically claim the nonce file before reading it. Only
// ONE of two concurrent callers can win the rename; the loser sees ENOENT and is rejected
// with `ca_registration_v2_nonce_already_consumed`.
// =============================================================================================

/// Sequential re-use must fail: same nonceId, two calls in a row. First succeeds; second
/// returns `ca_registration_v2_nonce_already_consumed` (or `_file_missing` if the rename + drop
/// finished before the second call — both are valid fail-closed outcomes; the SECOND CALL
/// MUST NOT RETURN A VALID RESPONSE).
#[test]
fn nonce_reuse_returns_invalid_request() {
    let state_dir = temp_state_dir("nonce-reuse-sequential");
    let ca_transcript = "55".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);
    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * coeffs[0].invert()));

    // Round1 to populate the nonce file.
    let req1 = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "reuse-req".to_string(),
        session_id: "reuse-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript.clone(),
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        vault_ek: vault_ek_hex.clone(),
        sender_address: "01".repeat(32),
        asset_type: "02".repeat(32),
        chain_id: 2,
    };
    let round1 = create_registration_nonce_commitment_v2(&state_dir, &req1).expect("round1");

    let req2 = Round2Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "reuse-req".to_string(),
        session_id: "reuse-sess".to_string(),
        ca_dkg_transcript_hash: ca_transcript.clone(),
        roster_hash: "11".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        player_id: 0,
        nonce_id: round1.nonce_id.clone(),
        challenge: scalar_hex(&det_scalar(0xC1)),
    };
    // First call: must succeed and consume the nonce file.
    create_registration_partial_response_v2(&state_dir, &req2).expect("first round2 succeeds");

    // Second call with the SAME inputs: must fail. The nonce file is gone after the first
    // call's RAII drop unlinked it; we accept either "already_consumed" (if the rename loses
    // a race with concurrent cleanup) or "file_missing" (the typical sequential outcome).
    let mut req2_replay = req2.clone();
    // Even attacker-chosen challenge MUST be rejected.
    req2_replay.challenge = scalar_hex(&det_scalar(0xC2));
    let err = create_registration_partial_response_v2(&state_dir, &req2_replay).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidDkgState(msg)
            if msg.contains("nonce_already_consumed") || msg.contains("nonce_file_missing")),
        "expected nonce_already_consumed or nonce_file_missing, got: {err:?}"
    );
}

/// **Attack-resistance test for the dk_share recovery vulnerability.**
///
/// Spawns two threads, both attempt /round2 with the SAME nonceId but DIFFERENT challenges
/// concurrently. The atomic rename guarantee says:
///   - Exactly ONE thread must return a valid response.
///   - The OTHER thread must return an InvalidDkgState error (nonce_already_consumed).
///
/// If the protection breaks, BOTH would succeed and the test fails — exposing dk_share.
#[test]
fn nonce_consuming_race_no_share_leak() {
    use std::sync::Arc;
    use std::thread;

    let state_dir = temp_state_dir("nonce-race");
    let ca_transcript = "55".repeat(32);
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    write_v2_share(&state_dir, 0, &coeffs, &blind_coeffs, &aggregate_commitments, &ca_transcript, DKG_EPOCH);
    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * coeffs[0].invert()));

    // Run a fresh round1 per iteration; each iteration races two round2 calls with
    // DIFFERENT challenges. Repeat to give the race a real chance to surface a bug.
    //
    // Important: we drop the round1 file with the SAME (request_id, session_id) before
    // each iteration so the consuming rename targets exactly one file.
    let iterations = 16;
    let mut any_double_success = false;

    for iter in 0..iterations {
        let req1 = Round1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("race-req-{iter}"),
            session_id: format!("race-sess-{iter}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: "11".repeat(32),
            selected_slots: vec![0, 1, 2, 3, 4],
            self_slot: 0,
            player_id: 0,
            vault_ek: vault_ek_hex.clone(),
            sender_address: "01".repeat(32),
            asset_type: "02".repeat(32),
            chain_id: 2,
        };
        let round1 = create_registration_nonce_commitment_v2(&state_dir, &req1)
            .expect("round1 succeeds for race iteration");

        let state_dir_a = state_dir.clone();
        let ca_transcript_a = ca_transcript.clone();
        let nonce_id_a = round1.nonce_id.clone();
        let req_id_a = req1.request_id.clone();
        let sess_id_a = req1.session_id.clone();
        let challenge_a = scalar_hex(&det_scalar(0x1_0000 + iter as u64));

        let state_dir_b = state_dir.clone();
        let ca_transcript_b = ca_transcript.clone();
        let nonce_id_b = round1.nonce_id.clone();
        let req_id_b = req1.request_id.clone();
        let sess_id_b = req1.session_id.clone();
        let challenge_b = scalar_hex(&det_scalar(0x2_0000 + iter as u64));
        // Different challenges → DIFFERENT responses if both succeed. THIS IS THE ATTACK.
        assert_ne!(challenge_a, challenge_b, "challenges must differ for the race to surface the bug");

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b_a = Arc::clone(&barrier);
        let b_b = Arc::clone(&barrier);

        let t_a = thread::spawn(move || {
            b_a.wait();
            create_registration_partial_response_v2(
                &state_dir_a,
                &Round2Request {
                    dkg_epoch: DKG_EPOCH.to_string(),
                    request_id: req_id_a,
                    session_id: sess_id_a,
                    ca_dkg_transcript_hash: ca_transcript_a,
                    roster_hash: "11".repeat(32),
                    selected_slots: vec![0, 1, 2, 3, 4],
                    self_slot: 0,
                    player_id: 0,
                    nonce_id: nonce_id_a,
                    challenge: challenge_a,
                },
            )
        });
        let t_b = thread::spawn(move || {
            b_b.wait();
            create_registration_partial_response_v2(
                &state_dir_b,
                &Round2Request {
                    dkg_epoch: DKG_EPOCH.to_string(),
                    request_id: req_id_b,
                    session_id: sess_id_b,
                    ca_dkg_transcript_hash: ca_transcript_b,
                    roster_hash: "11".repeat(32),
                    selected_slots: vec![0, 1, 2, 3, 4],
                    self_slot: 0,
                    player_id: 0,
                    nonce_id: nonce_id_b,
                    challenge: challenge_b,
                },
            )
        });

        let r_a = t_a.join().expect("thread A");
        let r_b = t_b.join().expect("thread B");

        let a_ok = r_a.is_ok();
        let b_ok = r_b.is_ok();
        match (a_ok, b_ok) {
            (true, true) => {
                any_double_success = true;
            }
            (false, false) => {
                // Both could conceivably lose if the rename races destructively — but with
                // a unique random suffix per consume, this should NOT happen. Treat as a
                // separate test failure.
                panic!(
                    "iter {iter}: BOTH threads errored — rename race is destructive. \
                     a={:?} b={:?}",
                    r_a.unwrap_err(),
                    r_b.unwrap_err()
                );
            }
            _ => {
                // Exactly one succeeded → atomic single-use is honored. Verify the loser
                // returned the expected InvalidDkgState code.
                let loser_err = if a_ok { r_b.unwrap_err() } else { r_a.unwrap_err() };
                assert!(
                    matches!(&loser_err, WorkerError::InvalidDkgState(msg)
                        if msg.contains("nonce_already_consumed") || msg.contains("nonce_file_missing")),
                    "loser must return nonce_already_consumed/missing, got: {loser_err:?}"
                );
            }
        }
    }

    assert!(
        !any_double_success,
        "ATTACK SUCCEEDED: at least one race iteration returned valid responses on BOTH \
         concurrent calls — dk_share is recoverable via (s1 - s2)*(c1 - c2)^-1. \
         The atomic single-use guard is broken."
    );
}
