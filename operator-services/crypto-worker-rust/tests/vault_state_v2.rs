// Milestone 2 sub-milestone 2a: vault_state_v2 init tests.
//
// The killer test (`vault_state_v2_init_five_workers_idempotent`) builds the canonical
// (Phase 2 + Milestone 1) tuple in-process: 5-of-7 Pedersen VSS over a synthetic dk,
// derives vault_ek = H * 1/dk locally, runs the full ca_registration_v2 round1/round2/
// aggregate pipeline so we have a REAL (aggregateCommitment, aggregateResponse, challenge)
// tuple that passes the verifier — then fans `init_vault_state_v2` out across all 5
// selected workers and asserts:
//   1. Each worker writes a `state_dir/vault_state_v2.json` file at mode 0o600.
//   2. The file pins all required bindings (Phase 2, Milestone 1, dkg_epoch, sender, etc.).
//   3. A re-call with identical inputs is idempotent (initialized=false; same file bytes).
//   4. A re-call with ANY mutated binding is rejected
//      `vault_state_v2_already_initialized_with_different_inputs`.
//   5. The worker_transcript_hash is reproducible by the TS reconstructor (we test the Rust
//      side here; the TS side reconstructor lives in deop-protocol and is exercised by
//      the coordinator orchestrator test).
//   6. A tampered Milestone 1 sigma tuple (response byte flipped) fails closed BEFORE
//      writing the file. This is the load-bearing guard against a deop-node tricked into
//      proxying a forged tuple.

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::{
    // Codex M2a P1: V2 production code paths (and tests asserting V2 behaviour) MUST import
    // the public verifier surface from `registration_verifier`, NOT from `ca_local`.
    registration_verifier::{
        aggregate_registration_commitment, registration_challenge,
        verify_registration_proof, RegistrationCommitmentInput, RegistrationResponseInput,
    },
    ca_registration_v2::{
        create_registration_nonce_commitment_v2, create_registration_partial_response_v2,
        run_aggregate_v2, AggregateRequest, Round1Request, Round2Request,
    },
    vault_state_v2::{
        init_vault_state_v2, init_worker_transcript_hash, load_vault_state_v2, InitRequest,
        VaultStateFile,
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
    path.push(format!("eunoma-vault-state-v2-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn make_vss_polynomial() -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(0x71_0000),
        det_scalar(0x71_0001),
        det_scalar(0x71_0002),
        det_scalar(0x71_0003),
        det_scalar(0x71_0004),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(0x81_0000),
        det_scalar(0x81_0001),
        det_scalar(0x81_0002),
        det_scalar(0x81_0003),
        det_scalar(0x81_0004),
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

/// Build a real Milestone 1 sigma tuple in-process. Returns
/// (vault_ek_hex, aggregate_commitment, aggregate_response, challenge, ca_transcript,
///  selected_slots, slot_dirs, sender, asset, chain_id, roster_hash).
struct Milestone1Fixture {
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
}

fn build_milestone1_fixture(label: &str) -> Milestone1Fixture {
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

    // Run Milestone 1 round1 fan-out.
    let mut round1_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = Round1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("vault-state-fixture-req-{label}"),
            session_id: format!("vault-state-fixture-sess-{label}"),
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
        let req = Round2Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("vault-state-fixture-req-{label}"),
            session_id: format!("vault-state-fixture-sess-{label}"),
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
    // Sanity: production verifier accepts the tuple.
    verify_registration_proof(
        &vault_ek_hex,
        &sender,
        &asset,
        chain_id,
        &aggregate.aggregate_commitment,
        &aggregate.aggregate_response,
    )
    .expect("verify_registration_proof");

    Milestone1Fixture {
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
    }
}

fn build_init_request(
    fix: &Milestone1Fixture,
    self_slot: usize,
    player_id: usize,
) -> InitRequest {
    InitRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "vault-state-init-req".to_string(),
        session_id: "vault-state-init-sess".to_string(),
        ca_dkg_transcript_hash: fix.ca_transcript.clone(),
        vault_ek_transcript_hash: "aa".repeat(32),
        registration_transcript_hash: "bb".repeat(32),
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot,
        player_id,
        vault_ek: fix.vault_ek_hex.clone(),
        sender_address: fix.sender.clone(),
        asset_type: fix.asset.clone(),
        chain_id: fix.chain_id,
        aggregate_commitment: fix.aggregate_commitment.clone(),
        aggregate_response: fix.aggregate_response.clone(),
        challenge: fix.challenge.clone(),
    }
}

#[test]
fn vault_state_v2_init_five_workers_idempotent() {
    let fix = build_milestone1_fixture("killer-idempotent");
    let selected = fix.selected_slots.clone();

    // First pass: every worker initialises a fresh vault_state_v2.json.
    let mut first_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected.iter().enumerate() {
        let req = build_init_request(&fix, slot, ordinal);
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req)
            .expect("init_vault_state_v2 round 1");
        // KILLER ASSERTION: each worker reports initialized=true, vault_sequence=0, cursor=0.
        assert!(result.initialized, "slot {slot} should report initialized=true");
        assert_eq!(result.slot, slot);
        assert_eq!(result.player_id, ordinal);
        assert_eq!(result.vault_sequence, 0);
        assert_eq!(result.deposit_count_observed, 0);
        assert_eq!(result.vault_state_hash.len(), 64);
        assert_eq!(result.worker_transcript_hash.len(), 64);

        // KILLER ASSERTION: file present, mode 0o600.
        let file_path = fix.slot_dirs[slot].join("vault_state_v2.json");
        assert!(file_path.exists(), "slot {slot} did not write vault_state_v2.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&file_path).expect("stat file").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "slot {slot} file mode != 0o600 (got {:o})", mode & 0o777);
        }

        // KILLER ASSERTION: parsed file has every required binding.
        let loaded = load_vault_state_v2(&fix.slot_dirs[slot])
            .expect("load_vault_state_v2")
            .expect("file present after init");
        assert_eq!(loaded.scheme, "vault_state_v2");
        assert_eq!(loaded.slot, slot);
        assert_eq!(loaded.player_id, ordinal);
        assert_eq!(loaded.dkg_epoch, DKG_EPOCH);
        assert_eq!(loaded.vault_ek_hex.to_lowercase(), fix.vault_ek_hex.to_lowercase());
        assert_eq!(loaded.sender_address.to_lowercase(), fix.sender.to_lowercase());
        assert_eq!(loaded.asset_type.to_lowercase(), fix.asset.to_lowercase());
        assert_eq!(loaded.chain_id, fix.chain_id);
        assert_eq!(loaded.aggregate_commitment.to_lowercase(), fix.aggregate_commitment.to_lowercase());
        assert_eq!(loaded.aggregate_response.to_lowercase(), fix.aggregate_response.to_lowercase());
        assert_eq!(loaded.challenge.to_lowercase(), fix.challenge.to_lowercase());
        assert_eq!(loaded.vault_sequence, 0);
        assert_eq!(loaded.deposit_count_observed, 0);

        // KILLER ASSERTION: worker_transcript_hash is reproducible from public inputs.
        let mut sorted = selected.clone();
        sorted.sort_unstable();
        let expected_hash = init_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &fix.ca_transcript,
            &req.vault_ek_transcript_hash,
            &req.registration_transcript_hash,
            &fix.roster_hash,
            &sorted,
            slot,
            ordinal,
            &fix.vault_ek_hex,
            &fix.sender,
            &fix.asset,
            fix.chain_id,
            &fix.aggregate_commitment,
            &fix.aggregate_response,
            &fix.challenge,
            0,
            0,
        );
        assert_eq!(result.worker_transcript_hash, expected_hash);

        first_results.push(result);
    }

    // Second pass: identical inputs → idempotent replay. initialized=false, same hash.
    for (ordinal, &slot) in selected.iter().enumerate() {
        let req = build_init_request(&fix, slot, ordinal);
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req)
            .expect("init_vault_state_v2 idempotent replay");
        assert!(!result.initialized, "slot {slot} should report initialized=false on replay");
        assert_eq!(result.vault_state_hash, first_results[ordinal].vault_state_hash);
        assert_eq!(
            result.worker_transcript_hash,
            first_results[ordinal].worker_transcript_hash
        );
    }
}

#[test]
fn vault_state_v2_init_rejects_mutated_inputs() {
    // After a successful init, re-calling with ANY mutated binding must fail closed.
    let fix = build_milestone1_fixture("mutated-rejects");
    let slot = 2_usize;
    let ordinal = 2_usize;
    let req = build_init_request(&fix, slot, ordinal);
    init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("first init succeeds");

    // (a) mutated registration_transcript_hash → rejected
    let mut mutated = req.clone();
    mutated.registration_transcript_hash = "ff".repeat(32);
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &mutated)
        .expect_err("mutated registration_transcript_hash should be rejected");
    assert!(
        matches!(err, WorkerError::InvalidDkgState(ref s) if s == "vault_state_v2_already_initialized_with_different_inputs"),
        "expected vault_state_v2_already_initialized_with_different_inputs, got {err:?}"
    );

    // (b) mutated vault_ek_transcript_hash → rejected
    let mut mutated = req.clone();
    mutated.vault_ek_transcript_hash = "ee".repeat(32);
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &mutated)
        .expect_err("mutated vault_ek_transcript_hash should be rejected");
    if !matches!(err, WorkerError::InvalidDkgState(_)) {
        panic!("expected InvalidDkgState for mutated vault_ek_transcript_hash, got {err:?}");
    }

    // (c) mutated sender_address → rejected. NOTE: changing sender_address changes the
    // Fiat-Shamir challenge, so verify_registration_proof fails BEFORE the existing-file
    // check fires — we accept either `Crypto` (verify failure) or `InvalidDkgState`
    // (existing-file mismatch) as proof that the mutation was caught.
    let mut mutated = req.clone();
    mutated.sender_address = "07".repeat(32);
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &mutated)
        .expect_err("mutated sender_address should be rejected");
    if !matches!(err, WorkerError::InvalidDkgState(_) | WorkerError::Crypto(_)) {
        panic!("expected InvalidDkgState or Crypto for mutated sender_address, got {err:?}");
    }

    // (d) mutated chain_id → rejected (same reasoning as (c): challenge depends on chain_id).
    let mut mutated = req.clone();
    mutated.chain_id = (mutated.chain_id ^ 1) as u8;
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &mutated)
        .expect_err("mutated chain_id should be rejected");
    if !matches!(err, WorkerError::InvalidDkgState(_) | WorkerError::Crypto(_)) {
        panic!("expected InvalidDkgState or Crypto for mutated chain_id, got {err:?}");
    }

    // (e) mutated selected_slots → rejected. The slots affect downstream MPCCA Lagrange
    // weights; persisting under a different roster subset would silently break later rounds.
    // verify_registration_proof doesn't depend on selected_slots, so this hits the
    // existing-file branch and surfaces as InvalidDkgState.
    let mut mutated = req.clone();
    mutated.selected_slots = vec![1, 2, 3, 4, 5]; // shift by one — slot 2 still in subset
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &mutated)
        .expect_err("mutated selected_slots should be rejected");
    if !matches!(err, WorkerError::InvalidDkgState(_) | WorkerError::InvalidRequest(_)) {
        panic!("expected InvalidDkgState or InvalidRequest for mutated selected_slots, got {err:?}");
    }
}

#[test]
fn vault_state_v2_init_rejects_tampered_registration_tuple() {
    // The worker re-runs verify_registration_proof BEFORE writing. Flip a byte in
    // aggregate_response and confirm we fail closed with a Crypto error — NOT InvalidDkgState
    // (we have no file yet, so the "already_initialized" branch can't fire).
    let fix = build_milestone1_fixture("tampered-tuple");
    let slot = 0_usize;
    let mut req = build_init_request(&fix, slot, 0);
    // Tamper: flip the high bit of the first byte. The scalar may not stay canonical, in
    // which case `scalar_from_hex` rejects upstream. Both failure modes are fine for the
    // "tampered tuple is rejected" assertion.
    let mut bytes = hex_decode(&req.aggregate_response);
    bytes[0] ^= 0x01;
    req.aggregate_response = hex_encode(&bytes);

    let err = init_vault_state_v2(&fix.slot_dirs[slot], &req)
        .expect_err("tampered aggregate_response should be rejected");
    assert!(
        matches!(err, WorkerError::Crypto(_) | WorkerError::InvalidRequest(_)),
        "expected Crypto or InvalidRequest, got {err:?}"
    );

    // KILLER ASSERTION: NO vault_state_v2.json file was written.
    let file_path = fix.slot_dirs[slot].join("vault_state_v2.json");
    assert!(
        !file_path.exists(),
        "tampered tuple must not persist vault_state_v2.json — bug if file exists"
    );
}

#[test]
fn vault_state_v2_init_rejects_wrong_slot_share() {
    // Worker's local ca_dkg_share_v2.json says slot=3, but the request claims self_slot=2.
    // The worker MUST reject this before writing — the dk_share for slot 3 doesn't match
    // slot 2's expected share, so any later MPCCA round would compute the wrong response.
    let fix = build_milestone1_fixture("wrong-slot");
    // Try to init slot 2's state from slot 3's share dir → slot mismatch in the v2 share.
    let req = build_init_request(&fix, 2, 2);
    let result = init_vault_state_v2(&fix.slot_dirs[3], &req);
    assert!(result.is_err(), "wrong-slot-share init must fail");
    let err = result.err().unwrap();
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("slot")),
        "expected slot-mismatch InvalidRequest, got {err:?}"
    );

    // Sanity check: the file was not written.
    let file_path = fix.slot_dirs[3].join("vault_state_v2.json");
    assert!(!file_path.exists());
}

#[test]
fn vault_state_v2_init_rejects_stale_dkg_epoch() {
    // The local share has dkg_epoch=11, request claims dkg_epoch=12 → reject.
    let fix = build_milestone1_fixture("stale-epoch");
    let slot = 1_usize;
    let mut req = build_init_request(&fix, slot, 1);
    req.dkg_epoch = "12".to_string();
    let err = init_vault_state_v2(&fix.slot_dirs[slot], &req)
        .expect_err("stale dkg_epoch should be rejected");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s.contains("dkg_epoch")),
        "expected dkg_epoch InvalidRequest, got {err:?}"
    );
    let file_path = fix.slot_dirs[slot].join("vault_state_v2.json");
    assert!(!file_path.exists());
}

#[test]
fn vault_state_v2_init_rejects_mismatched_challenge() {
    // Codex M2a P2 #4: the worker recomputes the Fiat-Shamir challenge locally and
    // rejects any tuple whose `req.challenge` doesn't match. This guards against a
    // caller (inline coordinator mode, or a confused deop-node) supplying a valid
    // (commitment, response) tuple bound to one challenge but persisting a DIFFERENT
    // challenge into vault_state_v2.json.
    //
    // We construct a real, valid (vault_ek, sender, asset, chain_id, agg_commitment,
    // agg_response) tuple — i.e. `verify_registration_proof` accepts it — but flip a
    // byte in `req.challenge`. The worker must:
    //   1. Pass `verify_registration_proof` (the tuple is internally consistent), then
    //   2. Recompute the challenge and find it disagrees with `req.challenge`, then
    //   3. Reject `InvalidRequest("challenge_mismatch")` BEFORE writing the file.
    let fix = build_milestone1_fixture("challenge-mismatch");
    let slot = 4_usize;
    let mut req = build_init_request(&fix, slot, 4);
    // Tamper: flip the low byte of the challenge. The (commitment, response) tuple is
    // still mathematically valid against the canonical Fiat-Shamir challenge, but
    // `req.challenge` is now a different scalar.
    let mut bytes = hex_decode(&req.challenge);
    bytes[31] ^= 0x01;
    req.challenge = hex_encode(&bytes);

    let err = init_vault_state_v2(&fix.slot_dirs[slot], &req)
        .expect_err("mismatched challenge should be rejected");
    assert!(
        matches!(err, WorkerError::InvalidRequest(ref s) if s == "challenge_mismatch"),
        "expected InvalidRequest(\"challenge_mismatch\"), got {err:?}"
    );
    // KILLER ASSERTION: NO vault_state_v2.json file was written.
    let file_path = fix.slot_dirs[slot].join("vault_state_v2.json");
    assert!(
        !file_path.exists(),
        "challenge mismatch must not persist vault_state_v2.json"
    );
}
