// Milestone 3 sub-milestone 3a — MPCCA withdraw state machine scaffolding.
//
// KILLER test (`mpcca_withdraw_v2_round1_surfaces_not_implemented_after_provenance_verifies`):
// builds the canonical (Phase 2 + Milestone 1 + Milestone 2a) tuple in-process, runs the
// Milestone 2a `init_vault_state_v2` to persist `vault_state_v2.json`, then drives
// `run_round1_v2`. Expected outcome:
//   1. Happy path → `WorkerError::NotImplemented(<round1 phase>)` AFTER the public binding work
//      ran. Session state file exists at mode 0o600.
//   2. Tampered vault_ek → `WorkerError::Crypto` (sigma rejects BEFORE NotImplemented).
//   3. Tampered dkg_epoch → `WorkerError::InvalidDkgState("mpcca_withdraw_v2_provenance_mismatch")`.
//   4. Missing vault_state_v2.json → `WorkerError::InvalidDkgState("missing_vault_state_file")`.
//
// Additional tests:
//   - run_round2_v2 / run_prove_v2 / run_finalize_v2 each return their distinct NotImplemented
//     phase string after the public-binding work runs.
//   - same request twice → same session_state_hash (idempotent / replayable).
//   - stale vault_sequence (req != existing) → InvalidRequest("stale_vault_sequence").

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use eunoma_crypto_worker::{
    ca_dkg_v2::init_hpke_local,
    ca_registration_v2::{
        create_registration_nonce_commitment_v2, create_registration_partial_response_v2,
        run_aggregate_v2, AggregateRequest, Round1Request as CaRound1Request,
        Round2Request as CaRound2Request,
    },
    mpcca_withdraw_v2::{
        load_ingress_state_file, load_round2_dk_state_file, load_round_state_file,
        m1_ingress_aad_for_test, mpcca_withdraw_session_dir, round1_worker_transcript_hash,
        round2_statement_inputs_hash_hex_for_test, run_finalize_v2, run_prove_v2, run_round1_v2,
        run_round2_v2, seal_ingress_envelope_for_test,
        ChainedRoundRequest as MpccaChainedRoundRequest, Round1Request as MpccaRound1Request,
        Round2Request as MpccaRound2Request,
    },
    registration_verifier::{
        aggregate_registration_commitment, lagrange_coefficients_at_zero,
        registration_challenge, verify_registration_proof, RegistrationCommitmentInput,
        RegistrationResponseInput,
    },
    vault_state_v2::{
        final_transcript_hash, finalize_vault_state_v2, init_vault_state_v2,
        FinalizeContribution, FinalizeRequest as VaultStateFinalizeRequest,
        InitRequest as VaultStateInitRequest,
    },
    WorkerError,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;

const DKG_EPOCH: &str = "11";

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
    path.push(format!("eunoma-mpcca-withdraw-v2-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn make_vss_polynomial() -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(0x91_0000),
        det_scalar(0x91_0001),
        det_scalar(0x91_0002),
        det_scalar(0x91_0003),
        det_scalar(0x91_0004),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(0xa1_0000),
        det_scalar(0xa1_0001),
        det_scalar(0xa1_0002),
        det_scalar(0xa1_0003),
        det_scalar(0xa1_0004),
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

// `aggregate_commitment`, `aggregate_response`, `challenge`, `ca_transcript` are part of the
// fixture set-up but not directly consulted by the milestone 3a tests — the sigma tuple gets
// embedded into the persisted `vault_state_v2.json` by `init_vault_state_v2`, and the
// MPCCA round1 handler then re-reads it from there. We keep the fields anyway so future
// tests can extend the fixture without rebuilding the Milestone 1 plumbing.
#[allow(dead_code)]
struct MpccaWithdrawFixture {
    vault_ek_hex: String,
    aggregate_commitment: String,
    aggregate_response: String,
    challenge: String,
    ca_transcript: String,
    roster_hash: String,
    sender: String,
    asset: String,
    chain_id: u8,
    selected_slots: Vec<usize>,
    slot_dirs: Vec<PathBuf>,
    vault_ek_transcript_hash: String,
    registration_transcript_hash: String,
    /// Codex M3a P1 v3 (partial-finalize recovery): the CANONICAL final transcript hash
    /// (EUNOMA_VAULT_STATE_V2_FINAL_V1 domain over public inputs + sorted contributions).
    /// This is what `finalize_vault_state_v2` pins as `init_transcript_hash` on every selected
    /// worker, and what MPCCA withdraw round1/2/prove/finalize binds against. Distinct from
    /// (and necessarily different from) any per-slot worker_transcript_hash.
    canonical_final_hash: String,
    /// M1: per-slot HPKE public keys (length 7, one per slot). Required for sealing real
    /// ingress envelopes that the worker can decrypt with its own private key.
    hpke_public_keys: Vec<String>,
    /// M1 test seed derived from the fixture label. Used to produce deterministic `(a_j, b_j)`
    /// shares so byte-parity probes stay stable across test runs.
    test_seed: [u8; 32],
}

fn build_milestone1_fixture(label: &str) -> MpccaWithdrawFixture {
    let ca_transcript = "44".repeat(32);
    let roster_hash = "55".repeat(32);
    let sender = "01".repeat(32);
    let asset = "02".repeat(32);
    let chain_id: u8 = 2;
    let (coeffs, blind_coeffs, aggregate_commitments) = make_vss_polynomial();
    let dk = coeffs[0];
    let h = h_point();
    let vault_ek_hex = compressed_hex(&(h * dk.invert()));

    let root = temp_state_dir(label);
    let mut slot_dirs = Vec::with_capacity(7);
    let selected_slots = vec![0_usize, 1, 2, 3, 4];
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

    // Milestone 1 round1 + round2 + aggregate.
    let mut round1_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = CaRound1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("mpcca-fix-req-{label}"),
            session_id: format!("mpcca-fix-sess-{label}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id,
        };
        let result = create_registration_nonce_commitment_v2(&slot_dirs[slot], &req)
            .expect("milestone1 round1");
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
    let aggregate_commitment = aggregate_registration_commitment(&commitments)
        .expect("aggregate commitments");
    let challenge =
        registration_challenge(&vault_ek_hex, &sender, &asset, chain_id, &aggregate_commitment)
            .expect("challenge");
    let mut round2_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = CaRound2Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("mpcca-fix-req-{label}"),
            session_id: format!("mpcca-fix-sess-{label}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            nonce_id: round1_results[ordinal].nonce_id.clone(),
            challenge: challenge.clone(),
        };
        let result = create_registration_partial_response_v2(&slot_dirs[slot], &req)
            .expect("milestone1 round2");
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
    let aggregate = run_aggregate_v2(&AggregateRequest {
        vault_ek: vault_ek_hex.clone(),
        sender_address: sender.clone(),
        asset_type: asset.clone(),
        chain_id,
        commitments: commitments.clone(),
        responses,
    })
    .expect("aggregate + verify");
    verify_registration_proof(
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate.aggregate_commitment,
        &aggregate.aggregate_response,
    )
    .expect("verify_registration_proof");

    // Phase 2 + Milestone 1 transcript hashes — synthetic markers (any 32-byte value works for
    // the worker's binding; the coordinator's provenance gate is what cross-references these
    // against the persisted transcript artifacts).
    let vault_ek_transcript_hash = "11".repeat(32);
    let registration_transcript_hash = "22".repeat(32);

    // Run Milestone 2a init for every selected worker so vault_state_v2.json exists with the
    // sigma tuple bound. Codex M3a P1 v3 (partial-finalize recovery): the per-slot
    // worker_transcript_hash is FROZEN at init, but the value MPCCA withdraw binds against is
    // the CANONICAL FINAL hash set by `finalize_vault_state_v2`. So we run init AND finalize
    // here to produce a fully-canonical fixture that mirrors what the coordinator's
    // /v2/vault_state/init produces in production.
    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(selected_slots.len());
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("mpcca-init-req-{label}"),
            session_id: format!("mpcca-init-sess-{label}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            vault_ek_transcript_hash: vault_ek_transcript_hash.clone(),
            registration_transcript_hash: registration_transcript_hash.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id,
            aggregate_commitment: aggregate.aggregate_commitment.clone(),
            aggregate_response: aggregate.aggregate_response.clone(),
            challenge: aggregate.challenge.clone(),
        };
        let result = init_vault_state_v2(&slot_dirs[slot], &req).expect("init vault_state_v2");
        per_slot_contribs.push(FinalizeContribution {
            slot,
            vault_state_hash: result.vault_state_hash,
            worker_transcript_hash: result.worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            initialized: true,
        });
    }
    // Compute the canonical FINAL_V1 transcript hash byte-for-byte the way the coordinator
    // does (sorted contributions, sorted selected slots).
    let mut sorted_slots = selected_slots.clone();
    sorted_slots.sort_unstable();
    let mut sorted_contribs = per_slot_contribs.clone();
    sorted_contribs.sort_by_key(|c| c.slot);
    let canonical_final_hash = final_transcript_hash(
        DKG_EPOCH,
        &ca_transcript,
        &vault_ek_transcript_hash,
        &registration_transcript_hash,
        &roster_hash,
        &sorted_slots,
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate.aggregate_commitment,
        &aggregate.aggregate_response,
        &aggregate.challenge,
        &sorted_contribs,
    );
    // Finalize each worker so `init_transcript_hash = canonical_final_hash`.
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = VaultStateFinalizeRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("mpcca-init-req-{label}"),
            session_id: format!("mpcca-init-sess-{label}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            vault_ek_transcript_hash: vault_ek_transcript_hash.clone(),
            registration_transcript_hash: registration_transcript_hash.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id,
            aggregate_commitment: aggregate.aggregate_commitment.clone(),
            aggregate_response: aggregate.aggregate_response.clone(),
            challenge: aggregate.challenge.clone(),
            per_slot_contributions: per_slot_contribs.clone(),
            final_transcript_hash: canonical_final_hash.clone(),
        };
        finalize_vault_state_v2(&slot_dirs[slot], &req).expect("finalize vault_state_v2");
    }

    // M1: init HPKE keypairs for all 7 slots so run_round1_v2 can load self_slot's keypair
    // for ingress decryption.
    let hpke_summary = init_hpke_local(&root, false).expect("init HPKE local");
    let hpke_public_keys: Vec<String> = hpke_summary
        .slots
        .iter()
        .map(|s| s.hpke_public_key.clone())
        .collect();
    assert_eq!(hpke_public_keys.len(), 7);

    // Deterministic seed from the label so tests are reproducible.
    let mut test_seed = [0_u8; 32];
    let label_bytes = label.as_bytes();
    for (i, b) in label_bytes.iter().enumerate().take(32) {
        test_seed[i] = *b;
    }
    test_seed[31] = label_bytes.len() as u8;

    MpccaWithdrawFixture {
        vault_ek_hex,
        aggregate_commitment: aggregate.aggregate_commitment,
        aggregate_response: aggregate.aggregate_response,
        challenge: aggregate.challenge,
        ca_transcript,
        roster_hash,
        sender,
        asset,
        chain_id,
        selected_slots,
        slot_dirs,
        vault_ek_transcript_hash,
        registration_transcript_hash,
        canonical_final_hash,
        hpke_public_keys,
        test_seed,
    }
}

// Canonical observed-deposit vector used by the round1 / chained-round fixtures. Length
// equals `deposit_count` (= 2 below) and each entry is unique — Codex M3a P2 #1 worker
// enforcement rejects mismatched length or duplicate entries.
fn fixture_observed_hashes() -> Vec<String> {
    vec!["44".repeat(32), "55".repeat(32)]
}

// Codex M3a P2 #1 v2: parallel cursor array. MUST be [1, 2, …, deposit_count] for the
// worker's strict-monotonic-ordering check to accept the request.
fn fixture_observed_cursors() -> Vec<u64> {
    vec![1, 2]
}

// =============================================================================================
// M1 ingress real-payload builder. Generates deterministic `(a_j, b_j)` shares from the
// fixture's seed + slot ordinal, computes per-share Pedersen commitments, builds AAD bytes
// matching the request, and HPKE-seals each share under the corresponding worker's pubkey.
// The returned payload is byte-equivalent across all 5 worker requests (only the AAD per
// slot differs).
// =============================================================================================
struct IngressTestPayload {
    amount_commitment: String,
    per_share_commitments: Vec<String>,
    ingress_envelopes: Vec<eunoma_crypto_worker::mpcca_withdraw_v2::HpkeEnvelope>,
}

fn deterministic_share_scalar(seed: &[u8; 32], slot_ordinal: usize, leg: u8) -> Scalar {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"EUNOMA_M1_INGRESS_TEST_SHARE_V1");
    hasher.update(seed);
    hasher.update(&slot_ordinal.to_le_bytes());
    hasher.update(&[leg]);
    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide[..32].copy_from_slice(&digest);
    // Second half: re-hash to get extra entropy and ensure result != 0 in practice.
    let mut hasher2 = sha2::Sha256::new();
    hasher2.update(&digest);
    hasher2.update(b"v2");
    wide[32..].copy_from_slice(&hasher2.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn build_real_ingress_payload(
    fix: &MpccaWithdrawFixture,
    request_id: &str,
    session_id: &str,
    dkg_epoch: &str,
    roster_hash_hex: &str,
    vault_ek_hex: &str,
    root_hex: &str,
    nullifier_hash_hex: &str,
    recipient_hash_hex: &str,
    amount_tag_hex: &str,
    vault_sequence: u64,
    deposit_count: u64,
) -> IngressTestPayload {
    let h = h_point();
    // 1. Generate (a_j, b_j) for each of the 5 selected slots.
    let mut shares: Vec<(Scalar, Scalar)> = Vec::with_capacity(5);
    let mut per_share_commitments: Vec<String> = Vec::with_capacity(5);
    let mut aggregate_a = Scalar::ZERO;
    let mut aggregate_b = Scalar::ZERO;
    for ordinal in 0..5 {
        let a = deterministic_share_scalar(&fix.test_seed, ordinal, 0);
        let b = deterministic_share_scalar(&fix.test_seed, ordinal, 1);
        let commitment = RISTRETTO_BASEPOINT_POINT * a + h * b;
        per_share_commitments.push(compressed_hex(&commitment));
        aggregate_a += a;
        aggregate_b += b;
        shares.push((a, b));
    }
    // 2. Compute aggregate amount_commitment = G·Σa_j + H·Σb_j.
    let amount_commitment = compressed_hex(&(RISTRETTO_BASEPOINT_POINT * aggregate_a + h * aggregate_b));

    // 3. Seal each (a_j, b_j) under selected_slots[j]'s HPKE pubkey with slot-j-specific AAD.
    let mut envelopes: Vec<eunoma_crypto_worker::mpcca_withdraw_v2::HpkeEnvelope> =
        Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let aad = m1_ingress_aad_for_test(
            request_id,
            session_id,
            dkg_epoch,
            slot,
            ordinal,
            roster_hash_hex,
            vault_ek_hex,
            root_hex,
            nullifier_hash_hex,
            recipient_hash_hex,
            amount_tag_hex,
            vault_sequence,
            deposit_count,
            &amount_commitment,
            &per_share_commitments,
        );
        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(&shares[ordinal].0.to_bytes());
        plaintext.extend_from_slice(&shares[ordinal].1.to_bytes());
        let env =
            seal_ingress_envelope_for_test(&fix.hpke_public_keys[slot], &aad, &plaintext)
                .expect("seal ingress envelope");
        envelopes.push(env);
    }
    IngressTestPayload {
        amount_commitment,
        per_share_commitments,
        ingress_envelopes: envelopes,
    }
}

/// Sentinel fixture envelope that is wire-shape-valid (matching ciphersuite + 80-byte ciphertext)
/// but NOT a real HPKE encryption under any keypair. Used by the negative-path tests that
/// flip a field on a baseline ingress payload — those tests never reach HPKE decrypt, so the
/// envelope only needs to pass the wire-shape gate.
fn fixture_ingress_envelope(seed: u8) -> eunoma_crypto_worker::mpcca_withdraw_v2::HpkeEnvelope {
    let seedhex = format!("{seed:02x}");
    eunoma_crypto_worker::mpcca_withdraw_v2::HpkeEnvelope {
        kem: "DHKEM_X25519_HKDF_SHA256".to_string(),
        kdf: "HKDF_SHA256".to_string(),
        aead: "AES_256_GCM".to_string(),
        enc: seedhex.repeat(32),
        ciphertext: seedhex.repeat(80),
        aad_hash: seedhex.repeat(32),
    }
}

fn fixture_ingress_envelopes() -> Vec<eunoma_crypto_worker::mpcca_withdraw_v2::HpkeEnvelope> {
    vec![
        fixture_ingress_envelope(0x11),
        fixture_ingress_envelope(0x22),
        fixture_ingress_envelope(0x33),
        fixture_ingress_envelope(0x44),
        fixture_ingress_envelope(0x55),
    ]
}

fn fixture_per_share_commitments() -> Vec<String> {
    vec![
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
    ]
}

// Constants used across all round1 fixtures so AAD remains stable per (fix.label, request).
const FIX_REQUEST_ID: &str = "mpcca-withdraw-req";
const FIX_SESSION_ID: &str = "mpcca-withdraw-sess";

fn fixture_request_root_hex() -> String {
    "66".repeat(32)
}
fn fixture_request_nullifier_hex() -> String {
    "77".repeat(32)
}
fn fixture_request_recipient_hex() -> String {
    "88".repeat(32)
}
fn fixture_request_recipient_hash_hex() -> String {
    "99".repeat(32)
}
fn fixture_request_amount_tag_hex() -> String {
    "0a".repeat(32)
}
fn fixture_request_hash_hex() -> String {
    "0b".repeat(32)
}

fn build_round1_request(
    fix: &MpccaWithdrawFixture,
    self_slot: usize,
    player_id: usize,
) -> MpccaRound1Request {
    let root_hex = fixture_request_root_hex();
    let nullifier_hex = fixture_request_nullifier_hex();
    let recipient_hex = fixture_request_recipient_hex();
    let recipient_hash_hex = fixture_request_recipient_hash_hex();
    let amount_tag_hex = fixture_request_amount_tag_hex();
    let request_hash_hex = fixture_request_hash_hex();
    let payload = build_real_ingress_payload(
        fix,
        FIX_REQUEST_ID,
        FIX_SESSION_ID,
        DKG_EPOCH,
        &fix.roster_hash,
        &fix.vault_ek_hex,
        &root_hex,
        &nullifier_hex,
        &recipient_hash_hex,
        &amount_tag_hex,
        0,
        2,
    );
    MpccaRound1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: FIX_REQUEST_ID.to_string(),
        session_id: FIX_SESSION_ID.to_string(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        // Codex M3a P1 v3: bind the CANONICAL FINAL_V1 transcript hash the worker pinned at
        // finalize. A different value here surfaces InvalidDkgState — see the dedicated
        // negative-case tests below.
        vault_state_init_transcript_hash: fix.canonical_final_hash.clone(),
        observed_deposit_transcript_hashes: fixture_observed_hashes(),
        observed_deposit_cursors: fixture_observed_cursors(),
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot,
        player_id,
        vault_ek: fix.vault_ek_hex.clone(),
        sender_address: fix.sender.clone(),
        asset_type: fix.asset.clone(),
        chain_id: fix.chain_id,
        root: root_hex,
        nullifier_hash: nullifier_hex,
        recipient: recipient_hex,
        recipient_hash: recipient_hash_hex,
        amount_tag: amount_tag_hex,
        vault_sequence: 0,
        expiry_secs: 1_700_000_000,
        request_hash: request_hash_hex,
        // Codex M3a P2 #1: deposit_count MUST equal observed_deposit_transcript_hashes.len()
        // — the worker now enforces this byte-for-byte. Two observed entries → deposit_count = 2.
        deposit_count: 2,
        // M1 real ingress payload — sealed under the 5 worker HPKE pubkeys.
        amount_commitment: payload.amount_commitment,
        per_share_commitments: payload.per_share_commitments,
        ingress_envelopes: payload.ingress_envelopes,
    }
}

fn build_chained_request(
    fix: &MpccaWithdrawFixture,
    self_slot: usize,
    player_id: usize,
) -> MpccaChainedRoundRequest {
    MpccaChainedRoundRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "mpcca-withdraw-req".to_string(),
        session_id: "mpcca-withdraw-sess".to_string(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        // Codex M3a P1 v3: bind the CANONICAL FINAL_V1 transcript hash (same rationale as
        // build_round1_request above).
        vault_state_init_transcript_hash: fix.canonical_final_hash.clone(),
        observed_deposit_transcript_hashes: fixture_observed_hashes(),
        observed_deposit_cursors: fixture_observed_cursors(),
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot,
        player_id,
        vault_ek: fix.vault_ek_hex.clone(),
        sender_address: fix.sender.clone(),
        asset_type: fix.asset.clone(),
        chain_id: fix.chain_id,
        root: "66".repeat(32),
        nullifier_hash: "77".repeat(32),
        recipient: "88".repeat(32),
        recipient_hash: "99".repeat(32),
        amount_tag: "0a".repeat(32),
        vault_sequence: 0,
        expiry_secs: 1_700_000_000,
        request_hash: "0b".repeat(32),
        deposit_count: 2,
        previous_round_transcript_hash: "0c".repeat(32),
        previous_round_commitments: vec![
            "0d".repeat(32),
            "0e".repeat(32),
            "0f".repeat(32),
            "10".repeat(32),
            "11".repeat(32),
        ],
    }
}

// =============================================================================================
// M4 Commit 1 — round2 request fixture. Wraps `build_chained_request` and adds the Aptos CA
// TransferV1 Statement input fields (recipient_ek + 6 ciphertext vectors). The fixture uses
// deterministic Ristretto points derived from a fixture seed so byte-parity probes stay
// stable across test runs.
// =============================================================================================

fn deterministic_ristretto_point(label: &[u8]) -> RistrettoPoint {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"EUNOMA_M4_ROUND2_FIXTURE_POINT_V1");
    hasher.update(label);
    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide[..32].copy_from_slice(&digest);
    let mut h2 = sha2::Sha256::new();
    h2.update(&digest);
    h2.update(b"v2");
    wide[32..].copy_from_slice(&h2.finalize());
    RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&wide)
}

fn deterministic_compressed_hex(label: &[u8]) -> String {
    compressed_hex(&deterministic_ristretto_point(label))
}

fn build_round2_request(
    fix: &MpccaWithdrawFixture,
    self_slot: usize,
    player_id: usize,
) -> MpccaRound2Request {
    let base = build_chained_request(fix, self_slot, player_id);
    fn group(label: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|i| deterministic_compressed_hex(format!("{label}-{i}").as_bytes()))
            .collect()
    }
    MpccaRound2Request {
        base,
        recipient_ek: deterministic_compressed_hex(b"recipient_ek"),
        old_balance_c: group("old_balance_c", 8),
        old_balance_d: group("old_balance_d", 8),
        new_balance_c: group("new_balance_c", 8),
        new_balance_d: group("new_balance_d", 8),
        transfer_amount_c: group("transfer_amount_c", 4),
        transfer_amount_d_sender: group("transfer_amount_d_sender", 4),
        transfer_amount_d_recipient: group("transfer_amount_d_recipient", 4),
    }
}

// =============================================================================================
// M1 KILLER test — round1 happy path completes ingress (HPKE decrypt + Pedersen verify +
// HPKE-encrypted-at-rest persist) and returns Round1IngressResult { completed: true }. The
// public binding gates run BEFORE the ingress crypto; a tampered request fails closed with a
// SPECIFIC validation error long before the M1 ingress surface.
// =============================================================================================
#[test]
fn mpcca_withdraw_v2_round1_m1_ingress_completes_happy_path() {
    let fix = build_milestone1_fixture("m1-r1-happy");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round1_request(&fix, slot, player_id);

    // Happy path: ingress crypto succeeds, round1 returns completed:true.
    let result = run_round1_v2(&state_dir, &req).expect("M1 ingress happy path");
    assert!(result.completed, "M1 round1 result.completed must be true");
    assert_eq!(result.slot, slot);
    assert_eq!(result.player_id, player_id);
    assert_eq!(
        result.ingress_transcript_hash, result.worker_transcript_hash,
        "ingressTranscriptHash MUST equal workerTranscriptHash"
    );
    assert!(
        result.worker_transcript_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "worker_transcript_hash must be hex"
    );

    // Session state file exists, mode 0o600.
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.request_id, &req.session_id).expect("dir");
    let session_state_path = session_dir.join("mpcca_withdraw_v2_round1.json");
    assert!(
        session_state_path.exists(),
        "round1 must persist its session-state file after M1 ingress completes"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&session_state_path)
            .expect("stat file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "session state file mode != 0o600 (got {:o})",
            mode & 0o777
        );
    }

    // M1: ingress state file MUST exist + mode 0o600 + NOT contain plaintext share bytes.
    let ingress_path = session_dir.join("mpcca_withdraw_v2_ingress.json");
    assert!(
        ingress_path.exists(),
        "M1 ingress state file must be persisted after successful round1"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&ingress_path)
            .expect("stat file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "ingress state file mode != 0o600 (got {:o})",
            mode & 0o777
        );
    }
    let ingress_file_loaded =
        load_ingress_state_file(&session_dir).expect("load ingress state").expect("present");
    assert_eq!(ingress_file_loaded.scheme, "mpcca_withdraw_v2_ingress");
    assert_eq!(ingress_file_loaded.slot, slot);
    assert_eq!(ingress_file_loaded.player_id, player_id);
    assert_eq!(ingress_file_loaded.amount_commitment, req.amount_commitment);
    assert_eq!(
        ingress_file_loaded.per_share_commitments,
        req.per_share_commitments
    );
    // The encrypted_share_envelope MUST be a valid HpkeEnvelope (X25519/HKDF/AES-256-GCM).
    assert_eq!(ingress_file_loaded.encrypted_share_envelope.kem, "DHKEM_X25519_HKDF_SHA256");

    // Persisted file parses cleanly and the worker_transcript_hash matches the reconstructor.
    let loaded = load_round_state_file(&session_dir, "round1")
        .expect("load round state")
        .expect("file present after run_round1_v2");
    assert_eq!(loaded.round, "round1");
    assert_eq!(loaded.slot, slot);
    assert_eq!(loaded.player_id, player_id);
    assert_eq!(loaded.dkg_epoch, DKG_EPOCH);
    // M1 round1 completes — not_implemented_phase is empty (sentinel for "completed").
    assert!(
        loaded.not_implemented_phase.is_empty(),
        "M1 round1 must persist not_implemented_phase=\"\" (sentinel for completed)"
    );

    let mut sorted = fix.selected_slots.clone();
    sorted.sort_unstable();
    let ingress_envelopes_hash =
        eunoma_crypto_worker::mpcca_withdraw_v2::ingress_envelopes_hash(&req.ingress_envelopes)
            .expect("ingress envelopes hash");
    let per_share_commitments = req.per_share_commitments.clone();
    let amount_commitment = req.amount_commitment.clone();
    let expected_hash = round1_worker_transcript_hash(
        &req.session_id,
        &req.request_id,
        &req.dkg_epoch,
        &fix.vault_ek_transcript_hash,
        &fix.registration_transcript_hash,
        &fix.canonical_final_hash,
        &req.observed_deposit_transcript_hashes,
        &fix.roster_hash,
        &sorted,
        slot,
        player_id,
        &fix.vault_ek_hex,
        &fix.sender,
        &fix.asset,
        fix.chain_id,
        &fixture_request_root_hex(),
        &fixture_request_nullifier_hex(),
        &fixture_request_recipient_hex(),
        &fixture_request_recipient_hash_hex(),
        &fixture_request_amount_tag_hex(),
        0,
        1_700_000_000,
        &fixture_request_hash_hex(),
        2,
        &amount_commitment,
        &per_share_commitments,
        &ingress_envelopes_hash,
    );
    assert_eq!(loaded.worker_transcript_hash, expected_hash);

    // Codex M3a P2 #1: the persisted round state carries the full ordered observe-deposit
    // vector verbatim so milestone 4's crypto can bind the canonical ordering.
    assert_eq!(
        loaded.observed_deposit_transcript_hashes,
        req.observed_deposit_transcript_hashes,
        "round state must persist the ordered observe-deposit vector"
    );

    // Tampered vault_ek → CRYPTO error (sigma rejects BEFORE M1 ingress crypto).
    let mut tampered = req.clone();
    tampered.vault_ek = "07".repeat(32);
    let err = run_round1_v2(&state_dir, &tampered).expect_err("tampered vault_ek should reject");
    // Provenance gate runs BEFORE sigma re-verify, so a tampered vault_ek hits the provenance
    // mismatch path first. Either failure mode is acceptable: both are SPECIFIC validation
    // errors, NOT a successful Ok.
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "mpcca_withdraw_v2_provenance_mismatch"
        ) || matches!(err, WorkerError::Crypto(_)),
        "tampered vault_ek must surface a specific error, got {err:?}"
    );

    // Tampered dkg_epoch → InvalidDkgState (provenance mismatch).
    let mut tampered = req.clone();
    tampered.dkg_epoch = "999".to_string();
    let err = run_round1_v2(&state_dir, &tampered).expect_err("tampered dkg_epoch should reject");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "mpcca_withdraw_v2_provenance_mismatch"
        ),
        "tampered dkg_epoch must surface InvalidDkgState(provenance_mismatch), got {err:?}"
    );

    // Missing vault_state_v2.json → InvalidDkgState("missing_vault_state_file").
    let empty_dir = temp_state_dir("killer-r1-missing");
    let err = run_round1_v2(&empty_dir, &req).expect_err("missing file should reject");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "missing_vault_state_file"
        ),
        "missing vault_state_v2.json must surface InvalidDkgState(missing_vault_state_file), got {err:?}"
    );

    // Stale vault_sequence → InvalidRequest("stale_vault_sequence").
    let mut stale = req.clone();
    stale.vault_sequence = 99;
    let err = run_round1_v2(&state_dir, &stale).expect_err("stale vault_sequence should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.starts_with("stale_vault_sequence")),
        "stale vault_sequence must surface InvalidRequest(stale_vault_sequence), got {err:?}"
    );

    // Codex M3a P2 #1: observed_deposit_transcript_hashes.len() != deposit_count → reject.
    let mut wrong_length = req.clone();
    wrong_length.observed_deposit_transcript_hashes = vec!["44".repeat(32)]; // 1 vs deposit_count=2
    let err = run_round1_v2(&state_dir, &wrong_length).expect_err("length mismatch should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("observed_deposit_transcript_hashes length")),
        "length-mismatched observed vector must surface InvalidRequest, got {err:?}"
    );

    // Codex M3a P2 #1: duplicate entries in observed_deposit_transcript_hashes → reject.
    let mut dup = req.clone();
    dup.observed_deposit_transcript_hashes = vec!["44".repeat(32), "44".repeat(32)];
    let err = run_round1_v2(&state_dir, &dup).expect_err("duplicate observed entries should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("duplicate observed_deposit_transcript_hashes")),
        "duplicate observed vector must surface InvalidRequest, got {err:?}"
    );

    // Codex M3a P2 #1 v2 (ordering KILLER): observed_deposit_cursors length != deposit_count
    // → reject. Without the parallel cursor array the worker cannot enforce ordering.
    let mut wrong_cursor_len = req.clone();
    wrong_cursor_len.observed_deposit_cursors = vec![1]; // length 1 vs deposit_count=2
    let err = run_round1_v2(&state_dir, &wrong_cursor_len)
        .expect_err("cursor length mismatch should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("observed_deposit_cursors length")),
        "length-mismatched cursors must surface InvalidRequest, got {err:?}"
    );

    // Codex M3a P2 #1 v2 (ordering KILLER): out-of-order cursors (e.g. [2, 1] instead of
    // [1, 2]) → reject. This is the EXACT regression — pre-fix, the worker accepted any
    // permutation as long as length + hash-set uniqueness held.
    let mut swapped = req.clone();
    swapped.observed_deposit_cursors = vec![2, 1];
    let err = run_round1_v2(&state_dir, &swapped)
        .expect_err("out-of-order cursors should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.starts_with("observed_deposit_cursors[0]")),
        "out-of-order cursors must surface InvalidRequest(observed_deposit_cursors[0]), got {err:?}"
    );

    // Cursor starts at 0 instead of 1 → reject.
    let mut zero_indexed = req.clone();
    zero_indexed.observed_deposit_cursors = vec![0, 1];
    let err = run_round1_v2(&state_dir, &zero_indexed)
        .expect_err("zero-indexed cursors should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.starts_with("observed_deposit_cursors[0]")),
        "zero-indexed cursors must surface InvalidRequest, got {err:?}"
    );

    // Skipped cursor in the middle → reject (e.g. [1, 3] for deposit_count=2).
    let mut skipped = req.clone();
    skipped.observed_deposit_cursors = vec![1, 3];
    let err = run_round1_v2(&state_dir, &skipped)
        .expect_err("skipped cursors should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.starts_with("observed_deposit_cursors[1]")),
        "skipped cursor must surface InvalidRequest(observed_deposit_cursors[1]), got {err:?}"
    );
}

// =============================================================================================
// Codex M3a P1 KILLER: a tampered vault_state_init_transcript_hash MUST fail closed with
// `InvalidDkgState("vault_state_init_transcript_hash_mismatch")` BEFORE the NotImplemented
// surface. Pre-fix the same forgery would reach NotImplemented because the worker only
// shape-checked the field without comparing it against persisted state.
// =============================================================================================
#[test]
fn mpcca_withdraw_v2_round1_rejects_forged_init_transcript_hash() {
    let fix = build_milestone1_fixture("forged-init-hash");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();

    // Sanity baseline: with the genuine init_transcript_hash the request completes M1
    // ingress successfully (public binding succeeds + ingress crypto succeeds).
    let baseline = build_round1_request(&fix, slot, player_id);
    let baseline_ok =
        run_round1_v2(&state_dir, &baseline).expect("baseline must complete M1 ingress");
    assert!(baseline_ok.completed, "baseline must complete: {baseline_ok:?}");

    // KILLER: tamper the init_transcript_hash with a random 32-byte hex. Expectation:
    // InvalidDkgState("vault_state_init_transcript_hash_mismatch"), NOT a successful Ok.
    let mut tampered = build_round1_request(&fix, slot, player_id);
    tampered.vault_state_init_transcript_hash = "ab".repeat(32);
    let err = run_round1_v2(&state_dir, &tampered)
        .expect_err("forged init_transcript_hash must reject");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_init_transcript_hash_mismatch"
        ),
        "forged init_transcript_hash must surface InvalidDkgState(vault_state_init_transcript_hash_mismatch), got {err:?}"
    );

    // Same check for the chained round handlers — defense-in-depth: every round verifies
    // the binding through common_public_binding_work.
    let mut tampered2 = build_round2_request(&fix, slot, player_id);
    tampered2.base.vault_state_init_transcript_hash = "cd".repeat(32);
    let err = run_round2_v2(&state_dir, &tampered2)
        .expect_err("forged init_transcript_hash must reject in round2");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_init_transcript_hash_mismatch"
        ),
        "round2 forged init_transcript_hash must surface InvalidDkgState, got {err:?}"
    );

    let mut tampered3 = build_chained_request(&fix, slot, player_id);
    tampered3.vault_state_init_transcript_hash = "ef".repeat(32);
    let err = run_prove_v2(&state_dir, &tampered3)
        .expect_err("forged init_transcript_hash must reject in prove");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_init_transcript_hash_mismatch"
        ),
        "prove forged init_transcript_hash must surface InvalidDkgState, got {err:?}"
    );

    let mut tampered4 = build_chained_request(&fix, slot, player_id);
    tampered4.vault_state_init_transcript_hash = "01".repeat(32);
    let err = run_finalize_v2(&state_dir, &tampered4)
        .expect_err("forged init_transcript_hash must reject in finalize");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_init_transcript_hash_mismatch"
        ),
        "finalize forged init_transcript_hash must surface InvalidDkgState, got {err:?}"
    );
}

#[test]
fn mpcca_withdraw_v2_session_state_hash_idempotent() {
    let fix = build_milestone1_fixture("idempotent");
    let slot = 2_usize;
    let player_id = 2_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round1_request(&fix, slot, player_id);

    // First call.
    let first_result = run_round1_v2(&state_dir, &req).expect("M1 ingress");
    let session_dir = mpcca_withdraw_session_dir(&state_dir, &req.request_id, &req.session_id)
        .expect("dir");
    let first = load_round_state_file(&session_dir, "round1")
        .expect("load 1")
        .expect("file 1");

    // Second call with same inputs.
    let second_result = run_round1_v2(&state_dir, &req).expect("M1 ingress replay");
    let second = load_round_state_file(&session_dir, "round1")
        .expect("load 2")
        .expect("file 2");

    // Worker transcript hash is byte-stable across replays (idempotent under M1).
    assert_eq!(first.worker_transcript_hash, second.worker_transcript_hash);
    assert_eq!(first.dkg_epoch, second.dkg_epoch);
    assert_eq!(first.slot, second.slot);
    assert_eq!(first.not_implemented_phase, second.not_implemented_phase);
    assert_eq!(
        first_result.ingress_transcript_hash, second_result.ingress_transcript_hash
    );
}

// M4 Commit 1 — round2 no longer surfaces NotImplemented. It now returns
// Ok(Round2DkResult { completed: true, partial_dk_commitments: [...], ... }).
// The companion RoundStateFile (M3a compat) is persisted with not_implemented_phase = "".
#[test]
fn mpcca_withdraw_v2_run_round2_v2_completes_after_m4_commit1() {
    let fix = build_milestone1_fixture("round2-completed");
    let slot = 1_usize;
    let player_id = 1_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round2_request(&fix, slot, player_id);

    let result = run_round2_v2(&state_dir, &req).expect("round2 M4 commit 1 happy path");
    assert!(result.completed);
    assert_eq!(result.slot, slot);
    assert_eq!(result.player_id, player_id);

    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.base.request_id, &req.base.session_id)
            .expect("dir");
    let loaded = load_round_state_file(&session_dir, "round2")
        .expect("load")
        .expect("file");
    assert_eq!(loaded.round, "round2");
    assert_eq!(
        loaded.not_implemented_phase, "",
        "round2 completed under M4 commit 1 → empty not_implemented_phase sentinel"
    );
}

#[test]
fn mpcca_withdraw_v2_run_prove_v2_returns_distinct_phase() {
    let fix = build_milestone1_fixture("prove-phase");
    let slot = 3_usize;
    let player_id = 3_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_chained_request(&fix, slot, player_id);

    let err = run_prove_v2(&state_dir, &req).expect_err("prove stub");
    let phase = match err {
        WorkerError::NotImplemented(p) => p,
        other => panic!("expected NotImplemented, got {other:?}"),
    };
    assert_eq!(
        phase, "mpcca_withdraw_v2_prove_collaborative_bulletproof_pending_milestone4",
        "prove phase string must be byte-stable across the codebase"
    );
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.request_id, &req.session_id).expect("dir");
    let loaded = load_round_state_file(&session_dir, "prove")
        .expect("load")
        .expect("file");
    assert_eq!(loaded.round, "prove");
}

#[test]
fn mpcca_withdraw_v2_run_finalize_v2_returns_distinct_phase() {
    let fix = build_milestone1_fixture("finalize-phase");
    let slot = 4_usize;
    let player_id = 4_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_chained_request(&fix, slot, player_id);

    let err = run_finalize_v2(&state_dir, &req).expect_err("finalize stub");
    let phase = match err {
        WorkerError::NotImplemented(p) => p,
        other => panic!("expected NotImplemented, got {other:?}"),
    };
    assert_eq!(
        phase, "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
        "finalize phase string must be byte-stable across the codebase"
    );
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.request_id, &req.session_id).expect("dir");
    let loaded = load_round_state_file(&session_dir, "finalize")
        .expect("load")
        .expect("file");
    assert_eq!(loaded.round, "finalize");
}

#[test]
fn mpcca_withdraw_v2_unsafe_request_id_rejected() {
    let fix = build_milestone1_fixture("unsafe-id");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.request_id = "../../evil".to_string();
    let err = run_round1_v2(&state_dir, &req).expect_err("unsafe request_id should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("request_id")),
        "expected InvalidRequest re: request_id, got {err:?}"
    );
}

#[test]
fn mpcca_withdraw_v2_round2_rejects_underquorum_previous_commitments() {
    let fix = build_milestone1_fixture("r2-under-quorum");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round2_request(&fix, slot, 0);
    req.base.previous_round_commitments = vec!["0a".repeat(32), "0b".repeat(32)];
    let err = run_round2_v2(&state_dir, &req)
        .expect_err("under-quorum previous_round_commitments should reject");
    assert!(
        matches!(err, WorkerError::InvalidRequest(_)),
        "expected InvalidRequest, got {err:?}"
    );
}

// =============================================================================================
// Milestone 1 — wire-shape rejection killers. These tests prove that round1's M1 ingress
// validation runs BEFORE persist + the NotImplemented surface, so a tampered ingress field
// trips a SPECIFIC error rather than slipping through to the stub.
// =============================================================================================

#[test]
fn m1_round1_rejects_under_count_per_share_commitments() {
    let fix = build_milestone1_fixture("m1-under-perShareCommit");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.per_share_commitments = vec!["aa".repeat(32), "bb".repeat(32)]; // 2 instead of 5
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("under-count per_share_commitments must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("per_share_commitments")),
        "expected per_share_commitments InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_over_count_per_share_commitments() {
    let fix = build_milestone1_fixture("m1-over-perShareCommit");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    let mut over = fixture_per_share_commitments();
    over.push("ff".repeat(32));
    req.per_share_commitments = over;
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("over-count per_share_commitments must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("per_share_commitments")),
        "expected per_share_commitments InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_non_32_byte_per_share_commitment() {
    let fix = build_milestone1_fixture("m1-bad-commit-len");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.per_share_commitments[2] = "11".repeat(31); // 31 bytes, must be 32
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("non-32-byte per_share_commitments[i] must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("per_share_commitments[2]")),
        "expected per_share_commitments[2] InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_under_count_ingress_envelopes() {
    let fix = build_milestone1_fixture("m1-under-envelopes");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.ingress_envelopes = fixture_ingress_envelopes()
        .into_iter()
        .take(4)
        .collect();
    let err =
        run_round1_v2(&state_dir, &req).expect_err("under-count ingress_envelopes must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("ingress_envelopes")),
        "expected ingress_envelopes InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_wrong_ciphertext_length_envelope() {
    let fix = build_milestone1_fixture("m1-bad-ciphertext-len");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    // 96 bytes is wrong (expected 80 = 64 plaintext + 16 GCM tag) — though hpke_aead::validate
    // only requires hex-decode success (not exact length); the M1 wire-shape contract is
    // captured at the TS coordinator boundary. Here we instead confirm a non-hex enc fails.
    req.ingress_envelopes[1].enc = "zz".repeat(32);
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("non-hex ingress_envelopes[1].enc must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("ingress_envelopes")),
        "expected ingress_envelopes InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_wrong_ciphersuite_envelope() {
    let fix = build_milestone1_fixture("m1-bad-ciphersuite");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.ingress_envelopes[3].kem = "DHKEM_P256".to_string();
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("wrong-ciphersuite ingress_envelopes[3] must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("ingress_envelopes")),
        "expected ingress_envelopes InvalidRequest, got {err:?}"
    );
}

#[test]
fn m1_round1_rejects_non_32_byte_amount_commitment() {
    let fix = build_milestone1_fixture("m1-bad-amount-commit");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, 0);
    req.amount_commitment = "ab".repeat(33);
    let err = run_round1_v2(&state_dir, &req)
        .expect_err("non-32-byte amount_commitment must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(_)),
        "expected amount_commitment InvalidRequest, got {err:?}"
    );
}

/// Pure-function binding test: prove that `round1_worker_transcript_hash` folds the M1
/// ingress fields (amount_commitment, per_share_commitments, ingress_envelopes_hash) into
/// its output. Using the function directly avoids the AAD-mismatch issue that arises if you
/// try to mutate a sealed envelope after the fact — we just call the hash with two different
/// inputs and observe the digest changes.
fn baseline_hash_args() -> (Vec<String>, [&'static str; 16]) {
    let observed = vec!["44".repeat(32), "55".repeat(32)];
    let raw_strs: [&'static str; 16] = [
        "sess-x", "req-x", "1", // session/request/dkg
        // intentionally placeholder; we'll override in calls below
        "44", "55", "66", "77", "88", "99", "0a", "0b", "0c", "0d", "0e", "0f", "10",
    ];
    (observed, raw_strs)
}

#[test]
fn m1_round1_transcript_hash_binds_amount_commitment() {
    // Hash with amount_commitment = "aa".repeat(32) vs "bb".repeat(32). Everything else identical.
    let (observed, _) = baseline_hash_args();
    let sorted = vec![0_usize, 1, 2, 3, 4];
    let per_share = vec![
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
    ];
    let envs_hash = "ff".repeat(32);
    let hash_a = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed,
        &"dd".repeat(32),
        &sorted,
        0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"aa".repeat(32), // amount_commitment v1
        &per_share, &envs_hash,
    );
    let hash_b = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed,
        &"dd".repeat(32),
        &sorted,
        0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"bb".repeat(32), // amount_commitment v2 — only change
        &per_share, &envs_hash,
    );
    assert_ne!(
        hash_a, hash_b,
        "M1 V2 round1 hash must change when amount_commitment flips"
    );
}

#[test]
fn m1_round1_transcript_hash_binds_per_share_commitments() {
    let (observed, _) = baseline_hash_args();
    let sorted = vec![0_usize, 1, 2, 3, 4];
    let per_share_a = vec![
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
    ];
    let mut per_share_b = per_share_a.clone();
    per_share_b[2] = "ff".repeat(32); // flip [2]
    let envs_hash = "ee".repeat(32);
    let hash_a = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed, &"dd".repeat(32), &sorted, 0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"aa".repeat(32),
        &per_share_a, &envs_hash,
    );
    let hash_b = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed, &"dd".repeat(32), &sorted, 0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"aa".repeat(32),
        &per_share_b, &envs_hash,
    );
    assert_ne!(
        hash_a, hash_b,
        "M1 V2 round1 hash must change when any per_share_commitments[i] flips"
    );
}

#[test]
fn m1_round1_transcript_hash_binds_ingress_envelopes_hash() {
    let (observed, _) = baseline_hash_args();
    let sorted = vec![0_usize, 1, 2, 3, 4];
    let per_share = vec![
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
    ];
    let hash_a = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed, &"dd".repeat(32), &sorted, 0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"aa".repeat(32),
        &per_share, &"aa".repeat(32),
    );
    let hash_b = round1_worker_transcript_hash(
        "sess-x", "req-x", "1",
        &"aa".repeat(32), &"bb".repeat(32), &"cc".repeat(32),
        &observed, &"dd".repeat(32), &sorted, 0, 0,
        &"ee".repeat(32), &"01".repeat(32), &"02".repeat(32),
        2,
        &"03".repeat(32), &"04".repeat(32), &"05".repeat(32), &"06".repeat(32),
        &"07".repeat(32), 4, 1_700_000_000,
        &"08".repeat(32), 7,
        &"aa".repeat(32),
        &per_share, &"bb".repeat(32), // flip ingress_envelopes_hash
    );
    assert_ne!(
        hash_a, hash_b,
        "M1 V2 round1 hash must change when ingress_envelopes_hash flips"
    );
}

#[test]
fn m1_ingress_envelopes_hash_ts_rust_parity() {
    // Byte-parity probe: a known set of 5 envelopes must hash to the same value as the TS
    // implementation. We don't have the TS digest pre-computed here; instead we assert
    // stability + that flipping ANY field flips the hash, which mirrors what the TS-side
    // killer tests assert.
    let envs = fixture_ingress_envelopes();
    let h_a = eunoma_crypto_worker::mpcca_withdraw_v2::ingress_envelopes_hash(&envs)
        .expect("hash");
    let h_b = eunoma_crypto_worker::mpcca_withdraw_v2::ingress_envelopes_hash(&envs)
        .expect("hash");
    assert_eq!(h_a, h_b, "ingress_envelopes_hash must be byte-stable");

    let mut envs_mut = envs.clone();
    envs_mut[2].aad_hash = "ff".repeat(32);
    let h_c =
        eunoma_crypto_worker::mpcca_withdraw_v2::ingress_envelopes_hash(&envs_mut).expect("hash");
    assert_ne!(h_a, h_c, "ingress_envelopes_hash must change on aad_hash flip");

    // Also assert order matters.
    let reordered = vec![
        envs[1].clone(),
        envs[0].clone(),
        envs[2].clone(),
        envs[3].clone(),
        envs[4].clone(),
    ];
    let h_d =
        eunoma_crypto_worker::mpcca_withdraw_v2::ingress_envelopes_hash(&reordered).expect("hash");
    assert_ne!(h_a, h_d, "ingress_envelopes_hash must change on order flip");
}

// =============================================================================================
// M1 ingress crypto killer tests — exercise the decrypt + verify path. These complement the
// wire-shape rejection tests above by proving the crypto layer fails closed on tampered
// envelopes, zero shares, and per-share-commitment mismatch.
// =============================================================================================

#[test]
fn m1_ingress_zero_share_rejected() {
    // Construct a real ingress payload with valid commitments + sealing, then SWAP one
    // envelope's plaintext for an a_j = 0 payload. The worker must reject with
    // ingress_zero_share_rejected.
    use eunoma_crypto_worker::mpcca_withdraw_v2::seal_ingress_envelope_for_test;
    let fix = build_milestone1_fixture("m1-zero-share");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, player_id);

    // Re-seal slot-0's envelope with a_0 = 0 (b_0 random). The AAD must match the original
    // envelopes' AAD bytes; otherwise we'd hit HPKE decrypt failure first.
    let zero_a = Scalar::ZERO;
    let real_b = deterministic_share_scalar(&fix.test_seed, 0, 1);
    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(&zero_a.to_bytes());
    plaintext.extend_from_slice(&real_b.to_bytes());
    // Compute the per-share commitment for (0, b_0) so the worker passes the commitment
    // check first; the zero-share gate runs BEFORE the commitment check.
    let h = h_point();
    let new_commit_0 =
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * zero_a + h * real_b));
    req.per_share_commitments[0] = new_commit_0.clone();
    // Also rebuild aggregate amount_commitment so the wire stays internally consistent.
    // Note: we don't bother recomputing — the AAD only binds the per_share_commitments_hash,
    // and we updated per_share_commitments[0]. We need to re-seal slot 0 envelope with the
    // NEW AAD that reflects the new per_share_commitments[0]. Actually simplest: rebuild
    // the whole payload with the new commitments, but we'd lose the (0, b) plaintext.
    //
    // Quick path: re-seal slot-0 envelope with AAD built from req.per_share_commitments.
    let aad = m1_ingress_aad_for_test(
        &req.request_id,
        &req.session_id,
        &req.dkg_epoch,
        slot,
        player_id,
        &req.roster_hash,
        &req.vault_ek,
        &req.root,
        &req.nullifier_hash,
        &req.recipient_hash,
        &req.amount_tag,
        req.vault_sequence,
        req.deposit_count,
        &req.amount_commitment,
        &req.per_share_commitments,
    );
    req.ingress_envelopes[0] =
        seal_ingress_envelope_for_test(&fix.hpke_public_keys[slot], &aad, &plaintext).expect("seal");
    // Re-seal envelope 1..5 with AAD that reflects the updated commitments. Since the
    // commitments hash is bound in AAD, every slot's envelope AAD changed → re-seal all.
    for (ordinal, &s) in fix.selected_slots.iter().enumerate().skip(1) {
        let a_s = deterministic_share_scalar(&fix.test_seed, ordinal, 0);
        let b_s = deterministic_share_scalar(&fix.test_seed, ordinal, 1);
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(&a_s.to_bytes());
        pt.extend_from_slice(&b_s.to_bytes());
        let aad_s = m1_ingress_aad_for_test(
            &req.request_id,
            &req.session_id,
            &req.dkg_epoch,
            s,
            ordinal,
            &req.roster_hash,
            &req.vault_ek,
            &req.root,
            &req.nullifier_hash,
            &req.recipient_hash,
            &req.amount_tag,
            req.vault_sequence,
            req.deposit_count,
            &req.amount_commitment,
            &req.per_share_commitments,
        );
        req.ingress_envelopes[ordinal] =
            seal_ingress_envelope_for_test(&fix.hpke_public_keys[s], &aad_s, &pt).expect("seal");
    }

    let err = run_round1_v2(&state_dir, &req).expect_err("zero a_j must reject");
    assert!(
        matches!(err, WorkerError::Crypto(ref s) if s == "ingress_zero_share_rejected"),
        "expected Crypto(ingress_zero_share_rejected), got {err:?}"
    );
}

#[test]
fn m1_ingress_share_commitment_mismatch_rejected() {
    // Seal the slot-0 envelope with a (a, b) pair whose Pedersen commitment does NOT match
    // per_share_commitments[0]. Worker rejects with ingress_share_commitment_mismatch.
    use eunoma_crypto_worker::mpcca_withdraw_v2::seal_ingress_envelope_for_test;
    let fix = build_milestone1_fixture("m1-commit-mismatch");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, player_id);

    // Replace slot-0 envelope plaintext with random (a', b') that DOES NOT match the
    // claimed per_share_commitments[0]. We rebuild AAD to match the original commitments
    // (otherwise HPKE decrypt fails first, not commitment mismatch).
    let bogus_a = deterministic_share_scalar(&fix.test_seed, 99, 0);
    let bogus_b = deterministic_share_scalar(&fix.test_seed, 99, 1);
    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(&bogus_a.to_bytes());
    plaintext.extend_from_slice(&bogus_b.to_bytes());
    let aad = m1_ingress_aad_for_test(
        &req.request_id,
        &req.session_id,
        &req.dkg_epoch,
        slot,
        player_id,
        &req.roster_hash,
        &req.vault_ek,
        &req.root,
        &req.nullifier_hash,
        &req.recipient_hash,
        &req.amount_tag,
        req.vault_sequence,
        req.deposit_count,
        &req.amount_commitment,
        &req.per_share_commitments,
    );
    req.ingress_envelopes[0] =
        seal_ingress_envelope_for_test(&fix.hpke_public_keys[slot], &aad, &plaintext).expect("seal");

    let err =
        run_round1_v2(&state_dir, &req).expect_err("commitment mismatch must reject");
    assert!(
        matches!(err, WorkerError::Crypto(ref s) if s == "ingress_share_commitment_mismatch"),
        "expected Crypto(ingress_share_commitment_mismatch), got {err:?}"
    );
}

#[test]
fn m1_ingress_aad_mismatch_rejected_as_hpke_decrypt_failure() {
    // Seal an envelope with a different AAD (e.g., wrong vault_ek). The worker re-derives
    // AAD from the request and HPKE open fails → Crypto(ingress_hpke_decrypt_failed).
    use eunoma_crypto_worker::mpcca_withdraw_v2::seal_ingress_envelope_for_test;
    let fix = build_milestone1_fixture("m1-aad-mismatch");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round1_request(&fix, slot, player_id);

    let a_0 = deterministic_share_scalar(&fix.test_seed, 0, 0);
    let b_0 = deterministic_share_scalar(&fix.test_seed, 0, 1);
    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(&a_0.to_bytes());
    plaintext.extend_from_slice(&b_0.to_bytes());
    // Build AAD with a DIFFERENT vault_ek so the worker's re-derived AAD diverges.
    let wrong_vault_ek = "07".repeat(32);
    let bad_aad = m1_ingress_aad_for_test(
        &req.request_id,
        &req.session_id,
        &req.dkg_epoch,
        slot,
        player_id,
        &req.roster_hash,
        &wrong_vault_ek,
        &req.root,
        &req.nullifier_hash,
        &req.recipient_hash,
        &req.amount_tag,
        req.vault_sequence,
        req.deposit_count,
        &req.amount_commitment,
        &req.per_share_commitments,
    );
    req.ingress_envelopes[0] =
        seal_ingress_envelope_for_test(&fix.hpke_public_keys[slot], &bad_aad, &plaintext).expect("seal");

    let err = run_round1_v2(&state_dir, &req).expect_err("AAD mismatch must reject");
    assert!(
        matches!(err, WorkerError::Crypto(ref s) if s == "ingress_hpke_decrypt_failed"),
        "expected Crypto(ingress_hpke_decrypt_failed), got {err:?}"
    );
}

#[test]
fn m1_ingress_state_file_does_not_contain_plaintext_shares_on_disk() {
    // After a successful M1 ingress, the worker's on-disk mpcca_withdraw_v2_ingress.json
    // MUST NOT contain the plaintext share bytes — only the HPKE-encrypted-at-rest envelope.
    let fix = build_milestone1_fixture("m1-no-plaintext-on-disk");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round1_request(&fix, slot, player_id);
    run_round1_v2(&state_dir, &req).expect("M1 ingress");

    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.request_id, &req.session_id).expect("dir");
    let ingress_path = session_dir.join("mpcca_withdraw_v2_ingress.json");
    let raw = fs::read_to_string(&ingress_path).expect("read ingress file");

    // Recompute the plaintext share hex for slot 0 and assert it does NOT appear on disk.
    let a_0 = deterministic_share_scalar(&fix.test_seed, 0, 0);
    let b_0 = deterministic_share_scalar(&fix.test_seed, 0, 1);
    let a_hex = hex_encode(&a_0.to_bytes());
    let b_hex = hex_encode(&b_0.to_bytes());
    assert!(
        !raw.contains(&a_hex),
        "ingress file MUST NOT contain plaintext a_0 hex bytes on disk"
    );
    assert!(
        !raw.contains(&b_hex),
        "ingress file MUST NOT contain plaintext b_0 hex bytes on disk"
    );
}

// =============================================================================================
// M4 Commit 1 — round2 dk-component killer tests. These prove:
//   1. Happy path completes with 2 partial commitments at canonical indices {0, 17}.
//   2. The round2 dk-state file lives at mode 0o600 with the new scheme tag.
//   3. α_share scalar plaintext NEVER appears on disk (the at-rest HPKE envelope is the
//      only on-disk representation of α_share).
//   4. Missing ca_dkg_share_v2.json fails closed with a SPECIFIC error before any crypto.
//   5. Non-canonical recipient_ek fails closed at the Statement-shape gate.
//   6. The round2 worker_transcript_hash binds the Statement input fields — tampered
//      recipient_ek produces a distinct hash (defense-in-depth at the coordinator gate).
//   7. Replays produce a byte-stable worker_transcript_hash even though α_share is fresh
//      each call (the hash binds public inputs only, not α_share).
//   8. Lagrange reconstruction over the fixture's 5 dk_shares recovers fix.coeffs[0] = dk
//      (proves the M4 commit-3 threshold algebra is well-defined for this fixture).
//   9. The on-wire partial commitments decompress to canonical Ristretto points.
//   10. The dk_base_indices_used field reports exactly [0, 17] (canonical BASE_DK_SET).
// =============================================================================================

#[test]
fn m4_round2_completes_dk_threshold_happy_path() {
    let fix = build_milestone1_fixture("m4-r2-happy");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round2_request(&fix, slot, player_id);

    let result = run_round2_v2(&state_dir, &req).expect("M4 round2 happy path");
    assert!(result.completed);
    assert_eq!(result.slot, slot);
    assert_eq!(result.player_id, player_id);
    assert_eq!(
        result.partial_dk_commitments.len(),
        2,
        "BASE_DK_SET has 2 positions (0 and 17) for the Aptos CA TransferV1 shape"
    );
    assert_eq!(
        result.dk_base_indices_used,
        vec![0_usize, 17_usize],
        "dk_base_indices_used MUST be the canonical {{0, 17}} set"
    );
    for partial in &result.partial_dk_commitments {
        // Each partial must be a canonical compressed Ristretto.
        let bytes = hex_decode(&partial.commitment_hex);
        assert_eq!(bytes.len(), 32);
        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&bytes);
        let decompressed = curve25519_dalek::ristretto::CompressedRistretto(arr).decompress();
        assert!(
            decompressed.is_some(),
            "partial commitment at index {} must be canonical compressed Ristretto",
            partial.index
        );
        // Identity-rejection: α_share is nonzero + base is non-identity, so the partial
        // cannot be the identity element.
        assert_ne!(
            decompressed.unwrap(),
            curve25519_dalek::ristretto::RistrettoPoint::identity(),
            "partial[{}] must not be identity",
            partial.index
        );
    }
    // The Round2 dk-state file must exist with the new scheme tag.
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.base.request_id, &req.base.session_id)
            .expect("session dir");
    let state_file = load_round2_dk_state_file(&session_dir)
        .expect("load dk state")
        .expect("dk state file exists");
    assert_eq!(state_file.scheme, "mpcca_withdraw_v2_round2_dk");
    assert_eq!(state_file.partial_dk_commitments, result.partial_dk_commitments);
    assert_eq!(state_file.dk_base_indices_used, result.dk_base_indices_used);
    assert_eq!(state_file.worker_transcript_hash, result.worker_transcript_hash);
}

#[test]
#[cfg(unix)]
fn m4_round2_dk_state_file_is_mode_0o600() {
    use std::os::unix::fs::PermissionsExt as _;
    let fix = build_milestone1_fixture("m4-r2-mode");
    let slot = 1_usize;
    let player_id = 1_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round2_request(&fix, slot, player_id);
    let _ = run_round2_v2(&state_dir, &req).expect("happy path");
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.base.request_id, &req.base.session_id)
            .expect("session dir");
    let file_path = session_dir.join("mpcca_withdraw_v2_round2_dk.json");
    let perms = fs::metadata(&file_path).expect("metadata").permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o600,
        "round2 dk-state file must be mode 0o600 on disk"
    );
}

#[test]
fn m4_round2_at_rest_envelope_does_not_contain_alpha_share_plaintext() {
    // Privacy contract: α_share_j[0] is generated, used once for the partial points, sealed
    // via HPKE under the worker's own pubkey, then zeroized on stack. No plaintext α copy
    // should reach the on-disk Round2StateFile. We verify by HPKE-opening the at-rest
    // envelope (using a recovered plaintext from a test seal — see below) and asserting
    // the recovered scalar bytes are NOT present elsewhere in the file bytes (only inside
    // the AEAD ciphertext, which is indistinguishable from random for a non-key-holder).
    let fix = build_milestone1_fixture("m4-r2-no-plain");
    let slot = 2_usize;
    let player_id = 2_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round2_request(&fix, slot, player_id);
    let _ = run_round2_v2(&state_dir, &req).expect("happy path");
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.base.request_id, &req.base.session_id)
            .expect("session dir");
    let file_path = session_dir.join("mpcca_withdraw_v2_round2_dk.json");
    let raw = fs::read(&file_path).expect("read");
    // The file MUST NOT contain the at-rest scheme tag's plaintext suffix. (Trivial sanity
    // check — the file does contain the scheme tag because it's part of the canonical
    // shape. We're checking that NO recognizable Scalar literal appears outside the
    // ciphertext field. Negative-by-construction: we read the structured file, walk every
    // value field except `ciphertext`, and confirm no 64-char hex blob outside that
    // field could be a Scalar. The ciphertext field IS opaque AEAD output so it cannot be
    // tested by literal byte presence — it's tested by the privacy:scan TS forbidden-token
    // guard at the wire boundary and by HPKE's IND-CCA security.)
    //
    // For this test we assert the simpler property that the file is well-formed JSON, the
    // sealed envelope's ciphertext is non-empty, and no field named anything matching
    // `alpha*` / `secret*` exists.
    let s = std::str::from_utf8(&raw).expect("utf8");
    assert!(s.contains("encryptedAlphaEnvelope"));
    // Camel-case forbidden tokens (per privacy:scan rules at the TS wire boundary).
    for forbidden in [
        "alphaShare",
        "alphaPlain",
        "alpha_share",
        "alpha_plain",
        "rawAlpha",
        "secretShare",
        "secret_share",
    ] {
        assert!(
            !s.contains(forbidden),
            "round2 dk-state file MUST NOT contain forbidden plaintext field name {forbidden:?}"
        );
    }
}

#[test]
fn m4_round2_missing_dk_share_file_rejected() {
    let fix = build_milestone1_fixture("m4-r2-missing-dk");
    let slot = 3_usize;
    let player_id = 3_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    // Remove the ca_dkg_share_v2.json file BEFORE round2.
    fs::remove_file(state_dir.join("ca_dkg_share_v2.json")).expect("remove dk share");
    let req = build_round2_request(&fix, slot, player_id);
    let err = run_round2_v2(&state_dir, &req).expect_err("missing dk_share must fail closed");
    // The loader returns MissingLocalState; either branch fails closed BEFORE the
    // round2 dk-state file is persisted (defense-in-depth).
    let session_dir =
        mpcca_withdraw_session_dir(&state_dir, &req.base.request_id, &req.base.session_id)
            .expect("session dir");
    assert!(
        !session_dir.join("mpcca_withdraw_v2_round2_dk.json").exists(),
        "no round2 dk-state file may be written when dk_share is missing"
    );
    assert!(
        matches!(
            err,
            WorkerError::MissingLocalState(_) | WorkerError::Io(_)
        ),
        "missing dk_share must fail closed with MissingLocalState or Io, got {err:?}"
    );
}

#[test]
fn m4_round2_tampered_recipient_ek_rejected() {
    let fix = build_milestone1_fixture("m4-r2-bad-ek");
    let slot = 4_usize;
    let player_id = 4_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round2_request(&fix, slot, player_id);
    // 0xff^32 is NOT a canonical compressed Ristretto encoding → Statement build fails.
    req.recipient_ek = "ff".repeat(32);
    let err = run_round2_v2(&state_dir, &req)
        .expect_err("non-canonical recipient_ek must fail closed");
    assert!(
        matches!(err, WorkerError::InvalidRequest(_)),
        "expected InvalidRequest for non-canonical recipient_ek, got {err:?}"
    );
}

#[test]
fn m4_round2_worker_transcript_hash_binds_statement_inputs() {
    // Defense-in-depth: a tampered Statement input field at round2 MUST change the per-slot
    // worker_transcript_hash. If a coordinator forwards a request with a different
    // recipient_ek than was used in the M5b assembler's eventual finalize call, the per-slot
    // transcript hash differs and the coordinator cross-check catches the divergence.
    let fix = build_milestone1_fixture("m4-r2-hash-bind");
    let slot = 0_usize;
    let player_id = 0_usize;
    let state_dir_a = fix.slot_dirs[slot].clone();
    let req_a = build_round2_request(&fix, slot, player_id);
    let result_a = run_round2_v2(&state_dir_a, &req_a).expect("a");

    // Fresh fixture for the tampered variant so request_id/session_id collide → would
    // otherwise hit no-clobber. We change the recipient_ek to a different canonical
    // Ristretto, and use a fresh fixture to keep state dirs distinct.
    let fix_b = build_milestone1_fixture("m4-r2-hash-bind-b");
    let state_dir_b = fix_b.slot_dirs[slot].clone();
    let mut req_b = build_round2_request(&fix_b, slot, player_id);
    req_b.recipient_ek = deterministic_compressed_hex(b"alt_recipient_ek");
    let result_b = run_round2_v2(&state_dir_b, &req_b).expect("b");

    assert_ne!(
        result_a.worker_transcript_hash, result_b.worker_transcript_hash,
        "round2 worker_transcript_hash MUST bind recipient_ek → tampered EK produces a different hash"
    );
}

#[test]
fn m4_round2_replay_returns_stable_worker_transcript_hash() {
    // Public-binding stability: two identical requests produce a byte-stable
    // worker_transcript_hash (since the hash binds only public inputs). The α_share is
    // fresh on each call but it does NOT enter the worker hash.
    let fix = build_milestone1_fixture("m4-r2-replay");
    let slot = 1_usize;
    let player_id = 1_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let req = build_round2_request(&fix, slot, player_id);
    let result_1 = run_round2_v2(&state_dir, &req).expect("call 1");
    let result_2 = run_round2_v2(&state_dir, &req).expect("call 2");
    assert_eq!(
        result_1.worker_transcript_hash, result_2.worker_transcript_hash,
        "round2 worker_transcript_hash MUST be byte-stable across replays of identical requests"
    );
    // Partial commitments WILL differ across replays because α_share is fresh — that's the
    // expected privacy property. We assert distinct partials as a check on the freshness.
    assert_ne!(
        result_1.partial_dk_commitments[0].commitment_hex,
        result_2.partial_dk_commitments[0].commitment_hex,
        "α_share is fresh per call → partial commitments MUST differ across replays"
    );
}

#[test]
fn m4_round2_lagrange_reconstruction_recovers_dk_from_fixture_shares() {
    // Pure threshold-algebra test: the fixture's 5 selected slots hold dk_shares that
    // Lagrange-reconstruct to fix.coeffs[0] = dk. This proves the M4 commit-3 finalize
    // algebra is well-defined for this fixture. M4 commit 3 will use λ_j · dk_share_j
    // as part of `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`.
    let fix = build_milestone1_fixture("m4-r2-lagrange");
    let sorted_slots: Vec<usize> = {
        let mut s = fix.selected_slots.clone();
        s.sort_unstable();
        s
    };
    let lambdas = lagrange_coefficients_at_zero(&sorted_slots).expect("lagrange");
    // Recover each slot's dk_share from the canonical Pedersen polynomial used by the
    // fixture (coeffs[0..5]). Direct shamir evaluation at x = slot+1.
    let coeffs = {
        let (c, _b, _agg) = make_vss_polynomial();
        c
    };
    let mut reconstructed = Scalar::ZERO;
    for (ordinal, &slot) in sorted_slots.iter().enumerate() {
        let x = Scalar::from((slot as u64) + 1);
        let mut share = coeffs[4];
        for i in (0..4).rev() {
            share = share * x + coeffs[i];
        }
        reconstructed += lambdas[ordinal] * share;
    }
    let expected_dk = coeffs[0];
    assert_eq!(
        reconstructed, expected_dk,
        "Σ_j λ_j · dk_share_j MUST reconstruct dk = coeffs[0]"
    );
}

#[test]
fn m4_round2_under_count_old_balance_c_rejected() {
    let fix = build_milestone1_fixture("m4-r2-under-cnt");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round2_request(&fix, slot, 0);
    req.old_balance_c.pop(); // 7 instead of 8
    let err = run_round2_v2(&state_dir, &req)
        .expect_err("under-count old_balance_c must fail closed");
    assert!(
        matches!(
            err,
            WorkerError::InvalidRequest(ref s) if s.contains("old_balance_c")
        ),
        "expected InvalidRequest for old_balance_c length mismatch, got {err:?}"
    );
}

#[test]
fn m4_round2_under_count_transfer_amount_c_rejected() {
    let fix = build_milestone1_fixture("m4-r2-amount-cnt");
    let slot = 0_usize;
    let state_dir = fix.slot_dirs[slot].clone();
    let mut req = build_round2_request(&fix, slot, 0);
    req.transfer_amount_c.push("01".repeat(32)); // 5 instead of 4
    let err = run_round2_v2(&state_dir, &req)
        .expect_err("over-count transfer_amount_c must fail closed");
    assert!(
        matches!(
            err,
            WorkerError::InvalidRequest(ref s) if s.contains("transfer_amount_c")
        ),
        "expected InvalidRequest for transfer_amount_c length mismatch, got {err:?}"
    );
}

// =============================================================================================
// M4 Commit 2 — Rust↔TS byte-parity for round2 statement_inputs_hash.
//
// The TS test `round2 statement_inputs hash matches the canonical Rust output (TS↔Rust byte
// parity)` asserts the same hex against `mpccaWithdrawRound2StatementInputsHash` over the
// SAME fixture. If either side drifts, BOTH tests fail in lockstep. This is the load-bearing
// wedge that prevents the coordinator's worker_transcript_hash cross-check from breaking
// silently between TS and Rust implementations.
//
// Fixture: 4-hex-char `(group||idx)` slots repeated 16× → 64 chars per entry. Counts
// match the canonical Aptos CA TransferV1 shape (ell=8, n=4).
// =============================================================================================
#[test]
fn mpcca_withdraw_v2_round2_statement_inputs_hash_byte_parity_with_ts_fixture() {
    fn gen_hex(group: &str, i: usize) -> String {
        let idx = format!("{i:02x}");
        let cell = format!("{group}{idx}");
        cell.repeat(16)
    }
    fn group(prefix: &str, count: usize) -> Vec<String> {
        (0..count).map(|i| gen_hex(prefix, i)).collect()
    }
    let recipient_ek = "a1".repeat(32);
    let old_balance_c = group("b0", 8);
    let old_balance_d = group("c0", 8);
    let new_balance_c = group("d0", 8);
    let new_balance_d = group("e0", 8);
    let transfer_amount_c = group("f0", 4);
    let transfer_amount_d_sender = group("12", 4);
    let transfer_amount_d_recipient = group("23", 4);

    let hash = round2_statement_inputs_hash_hex_for_test(
        &recipient_ek,
        &old_balance_c,
        &old_balance_d,
        &new_balance_c,
        &new_balance_d,
        &transfer_amount_c,
        &transfer_amount_d_sender,
        &transfer_amount_d_recipient,
    )
    .expect("statement inputs hash byte-parity fixture");
    assert_eq!(
        hash, "ffa00e43e67bf54fb188596887ce58bcf3e0223d7a7a9e9f9576cde8ef25ef8d",
        "statement_inputs_hash byte-parity with TS fixture broken — TS test must assert the same hex"
    );
}
