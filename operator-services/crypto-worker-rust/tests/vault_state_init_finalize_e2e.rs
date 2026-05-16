// Milestone 3 sub-milestone 3a — END-TO-END integration test for the vault_state_v2 init
// finalize round + MPCCA withdraw round1 happy path. Closes the Codex M3a P1 regression.
//
// THE BUG this test pins:
//
//   Pre-fix, each worker persisted its OWN per-slot `worker_transcript_hash` as
//   `init_transcript_hash` in vault_state_v2.json. The coordinator's
//   /v2/withdraw/mpcca/start sent the FINAL aggregated init artifact transcriptHash
//   (EUNOMA_VAULT_STATE_V2_FINAL_V1 over all 5 contributions + public inputs) to every
//   worker in MPCCA round1. The two values were DIFFERENT by construction, so every
//   coordinator-orchestrated MPCCA withdraw failed closed with
//   `vault_state_init_transcript_hash_mismatch`.
//
//   The previous fix's unit test (mpcca_withdraw_v2_round1_rejects_forged_init_transcript_hash)
//   passed because the test fixture captured the worker's per-slot hash and used it in
//   the round1 body. But that path is NEVER taken by the coordinator. This integration test
//   exercises the FULL coordinator-orchestrated flow.
//
// HARNESS:
//
//   1. Build the canonical Milestone 1 fixture (5-of-7 VSS over a real scalar, REAL sigma
//      tuple via ca_registration_v2 round1/round2/aggregate, REAL Phase 2 vault_ek derived
//      from the same dk).
//   2. Run `init_vault_state_v2` against all 5 selected workers. Capture each per-slot
//      `worker_transcript_hash` + `vault_state_hash`.
//   3. SIMULATE THE COORDINATOR: build `perSlotContributions` and compute the final
//      transcript hash by calling the byte-stable Rust `final_transcript_hash` helper
//      (mirrors TS `vaultStateV2InitFinalTranscriptHash`). This is the value the
//      coordinator's MPCCA withdraw request body will carry.
//   4. Run `finalize_vault_state_v2` against each of the 5 workers with the canonical
//      final hash. Assert each worker pins the same value. Assert idempotent re-finalize.
//   5. KILLER: run `run_round1_v2` with `vault_state_init_transcript_hash = <canonical
//      final hash>`. MUST surface WorkerError::NotImplemented (the happy-path 501
//      equivalent), NOT InvalidDkgState("vault_state_init_transcript_hash_mismatch").
//      This is the exact path that was broken in production.
//   6. NEGATIVE CONTROL: BEFORE finalize, the same round1 request with the canonical final
//      hash MUST fail closed with `vault_state_init_transcript_hash_mismatch` — proving
//      the finalize round is load-bearing.
//
// This test does NOT spin up an HTTP server; it exercises the in-process Rust functions
// directly. The coordinator's HTTP layer is exercised by the TS coordinator tests; the
// Rust integration test ensures byte-stable agreement on the FINAL_V1 transcript across
// the worker / coordinator boundary, which is the load-bearing invariant.

use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::{
    ca_registration_v2::{
        create_registration_nonce_commitment_v2, create_registration_partial_response_v2,
        run_aggregate_v2, AggregateRequest, Round1Request as CaRound1Request,
        Round2Request as CaRound2Request,
    },
    mpcca_withdraw_v2::{
        run_round1_v2, Round1Request as MpccaRound1Request,
    },
    registration_verifier::{
        aggregate_registration_commitment, registration_challenge, verify_registration_proof,
        RegistrationCommitmentInput, RegistrationResponseInput,
    },
    vault_state_v2::{
        final_transcript_hash, finalize_vault_state_v2, init_vault_state_v2,
        load_vault_state_v2, FinalizeContribution, FinalizeRequest,
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
    path.push(format!("eunoma-init-finalize-e2e-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn make_vss_polynomial() -> ([Scalar; 5], [Scalar; 5], [String; 5]) {
    let coeffs: [Scalar; 5] = [
        det_scalar(0x10_0000),
        det_scalar(0x10_0001),
        det_scalar(0x10_0002),
        det_scalar(0x10_0003),
        det_scalar(0x10_0004),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(0x20_0000),
        det_scalar(0x20_0001),
        det_scalar(0x20_0002),
        det_scalar(0x20_0003),
        det_scalar(0x20_0004),
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
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap()).expect("write share file");
}

/// Test fixture wrapping the canonical (Phase 2 + Milestone 1) tuple. Each `slot_dirs[i]` has
/// `ca_dkg_share_v2.json` materialised; init_vault_state_v2 will read it during the init pass.
struct Fixture {
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
}

fn build_fixture(label: &str) -> Fixture {
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

    // Milestone 1 sigma — REAL, not a synthetic stub. The verifier runs the public
    // equation byte-for-byte; a placeholder tuple would be rejected by both
    // verify_registration_proof at init-time AND by the MPCCA round1 re-verify gate.
    let mut round1_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = CaRound1Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("init-fin-fix-req-{label}"),
            session_id: format!("init-fin-fix-sess-{label}"),
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
        let r = create_registration_nonce_commitment_v2(&slot_dirs[slot], &req)
            .expect("milestone1 round1");
        round1_results.push(r);
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
        aggregate_registration_commitment(&commitments).expect("aggregate commitments");
    let challenge =
        registration_challenge(&vault_ek_hex, &sender, &asset, chain_id, &aggregate_commitment)
            .expect("challenge");
    let mut round2_results = Vec::with_capacity(5);
    for (ordinal, &slot) in selected_slots.iter().enumerate() {
        let req = CaRound2Request {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("init-fin-fix-req-{label}"),
            session_id: format!("init-fin-fix-sess-{label}"),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            nonce_id: round1_results[ordinal].nonce_id.clone(),
            challenge: challenge.clone(),
        };
        let r = create_registration_partial_response_v2(&slot_dirs[slot], &req)
            .expect("milestone1 round2");
        round2_results.push(r);
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

    Fixture {
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
        vault_ek_transcript_hash: "11".repeat(32),
        registration_transcript_hash: "22".repeat(32),
    }
}

/// KILLER end-to-end test pinning the Codex M3a P1 regression. The previous fix's unit test
/// passed because the test fixture synthesised both sides of the binding from the per-slot
/// worker hash. Production, however, sends the FINAL aggregated transcript hash from the
/// coordinator's persisted init artifact — a value the worker only learns about during the
/// finalize round. Without finalize, every coordinator-orchestrated MPCCA withdraw fails
/// closed with vault_state_init_transcript_hash_mismatch. WITH finalize, the canonical hash
/// flows correctly across the boundary and round1 reaches the NotImplemented stub.
///
/// This test does NOT mock the coordinator; it computes the same FINAL_V1 digest the
/// coordinator would, then drives the worker functions in sequence:
///   init × 5  →  compute final hash  →  finalize × 5  →  MPCCA round1 (each slot)
///                                                       → expect WorkerError::NotImplemented
#[test]
fn vault_state_init_finalize_then_mpcca_round1_e2e_happy_path() {
    let fix = build_fixture("happy-path");

    // 1. INIT — fan out to all 5 selected slots, just like the coordinator does in its
    //    first phase. Each call writes vault_state_v2.json and returns the per-slot
    //    worker_transcript_hash.
    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "init-fin-e2e-req".to_string(),
            session_id: "init-fin-e2e-sess".to_string(),
            ca_dkg_transcript_hash: fix.ca_transcript.clone(),
            vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: fix.registration_transcript_hash.clone(),
            roster_hash: fix.roster_hash.clone(),
            selected_slots: fix.selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: fix.vault_ek_hex.clone(),
            sender_address: fix.sender.clone(),
            asset_type: fix.asset.clone(),
            chain_id: fix.chain_id,
            aggregate_commitment: fix.aggregate_commitment.clone(),
            aggregate_response: fix.aggregate_response.clone(),
            challenge: fix.challenge.clone(),
        };
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("init slot");
        assert!(result.initialized, "slot {slot} should report initialized=true");
        per_slot_contribs.push(FinalizeContribution {
            slot,
            vault_state_hash: result.vault_state_hash,
            worker_transcript_hash: result.worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            initialized: true,
        });
    }
    let mut sorted_slots = fix.selected_slots.clone();
    sorted_slots.sort_unstable();

    // 2. SIMULATE THE COORDINATOR: compute the FINAL transcript hash via the Rust helper
    //    that mirrors TS `vaultStateV2InitFinalTranscriptHash`. This is the canonical value
    //    every legitimate MPCCA withdraw round1 body will carry.
    let mut sorted_contribs = per_slot_contribs.clone();
    sorted_contribs.sort_by_key(|c| c.slot);
    let final_hash = final_transcript_hash(
        DKG_EPOCH,
        &fix.ca_transcript,
        &fix.vault_ek_transcript_hash,
        &fix.registration_transcript_hash,
        &fix.roster_hash,
        &sorted_slots,
        &fix.vault_ek_hex,
        &fix.sender,
        &fix.asset,
        fix.chain_id,
        &fix.aggregate_commitment,
        &fix.aggregate_response,
        &fix.challenge,
        &sorted_contribs,
    );
    assert_eq!(final_hash.len(), 64, "final transcript hash must be 32-byte hex");
    // Distinguishability KILLER: the final hash MUST differ from every per-slot worker
    // hash. Pre-fix, the worker compared the request body's value against the per-slot
    // value — which would always mismatch. This assertion is what makes this an
    // integration-level regression test rather than a unit test.
    for c in &per_slot_contribs {
        assert_ne!(
            final_hash.to_lowercase(),
            c.worker_transcript_hash.to_lowercase(),
            "final hash MUST differ from every per-slot hash (slot {})",
            c.slot
        );
    }

    // 3. NEGATIVE CONTROL: BEFORE finalize, MPCCA withdraw round1 with the canonical final
    //    hash MUST fail closed with `vault_state_init_transcript_hash_mismatch`. This is
    //    the EXACT path that broke production — the regression test that proves the
    //    finalize round is load-bearing, not optional.
    let round1_req_pre_finalize = MpccaRound1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "init-fin-e2e-withdraw-req".to_string(),
        session_id: "init-fin-e2e-withdraw-sess".to_string(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        vault_state_init_transcript_hash: final_hash.clone(),
        observed_deposit_transcript_hashes: vec![],
        // Codex M3a P2 #1 v2: empty observed list + depositCount=0 → empty cursors OK.
        observed_deposit_cursors: vec![],
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot: 0,
        player_id: 0,
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
        deposit_count: 0,
    };
    let pre_err = run_round1_v2(&fix.slot_dirs[0], &round1_req_pre_finalize)
        .expect_err("pre-finalize must fail closed (the regression baseline)");
    // Codex M3a P1 v3 (partial-finalize recovery): pre-finalize, the persisted
    // `init_transcript_hash` is None — the worker rejects with the distinct
    // `vault_state_v2_not_finalized` code (NOT `vault_state_init_transcript_hash_mismatch`).
    // This lets the coordinator distinguish "transient — run finalize" from "permanent —
    // investigate tamper". The original P1 regression manifested as either error; either
    // surfacing post-binding-work proves the finalize round is load-bearing.
    assert!(
        matches!(
            pre_err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_v2_not_finalized"
        ),
        "pre-finalize MUST surface InvalidDkgState(vault_state_v2_not_finalized) — the v3 \
         layout's distinct error code for the recoverable not-finalized-yet state; got {pre_err:?}"
    );

    // 4. FINALIZE: fan out the canonical hash to every slot. Each worker re-derives the
    //    same digest, asserts byte-equality, and updates its persisted
    //    init_transcript_hash to the canonical value. The mocked-coordinator finalize
    //    body is byte-identical with what coordinator/src/server.ts builds.
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = FinalizeRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "init-fin-e2e-req".to_string(),
            session_id: "init-fin-e2e-sess".to_string(),
            ca_dkg_transcript_hash: fix.ca_transcript.clone(),
            vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: fix.registration_transcript_hash.clone(),
            roster_hash: fix.roster_hash.clone(),
            selected_slots: fix.selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: fix.vault_ek_hex.clone(),
            sender_address: fix.sender.clone(),
            asset_type: fix.asset.clone(),
            chain_id: fix.chain_id,
            aggregate_commitment: fix.aggregate_commitment.clone(),
            aggregate_response: fix.aggregate_response.clone(),
            challenge: fix.challenge.clone(),
            per_slot_contributions: per_slot_contribs.clone(),
            final_transcript_hash: final_hash.clone(),
        };
        let res = finalize_vault_state_v2(&fix.slot_dirs[slot], &req)
            .expect("finalize must succeed for legitimate body");
        assert!(res.finalized, "slot {slot} should report finalized=true on first call");
        assert_eq!(
            res.init_transcript_hash.to_lowercase(),
            final_hash.to_lowercase(),
            "slot {slot}: persisted init_transcript_hash must equal canonical final hash"
        );

        // Persisted file pin: load + assert.
        let persisted = load_vault_state_v2(&fix.slot_dirs[slot])
            .expect("load")
            .expect("file present");
        assert_eq!(
            persisted.init_transcript_hash.as_deref().map(str::to_lowercase),
            Some(final_hash.to_lowercase()),
            "slot {slot}: vault_state_v2.json must persist canonical final hash"
        );

        // Idempotent re-finalize: same canonical hash → finalized=false, no rewrite.
        let res2 = finalize_vault_state_v2(&fix.slot_dirs[slot], &req)
            .expect("idempotent finalize must succeed");
        assert!(!res2.finalized, "slot {slot}: idempotent finalize must report finalized=false");
        assert_eq!(res.vault_state_hash, res2.vault_state_hash);
    }

    // 5. KILLER ASSERTION: post-finalize, MPCCA withdraw round1 with the canonical final
    //    hash MUST surface NotImplemented (the happy-path 501 equivalent). Exercise all
    //    5 selected slots — if any one fails closed, the regression isn't actually fixed.
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let mut req = round1_req_pre_finalize.clone();
        req.self_slot = slot;
        req.player_id = ordinal;
        let err = run_round1_v2(&fix.slot_dirs[slot], &req)
            .expect_err("happy-path MPCCA round1 reaches the NotImplemented stub");
        match err {
            WorkerError::NotImplemented(phase) => {
                assert_eq!(
                    phase, "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
                    "slot {slot}: round1 phase string must be byte-stable across the codebase"
                );
            }
            other => panic!(
                "slot {slot}: expected NotImplemented (post-finalize happy-path); the \
                 regression is NOT FIXED if this slot surfaces {other:?}"
            ),
        }
    }
}

/// Tampered final hash: the coordinator's claim doesn't match the locally-re-derived
/// digest. Worker MUST fail closed with vault_state_v2_finalize_hash_mismatch BEFORE
/// touching the persisted file.
#[test]
fn vault_state_init_finalize_rejects_tampered_final_hash() {
    let fix = build_fixture("tampered-final");

    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "tampered-init-req".to_string(),
            session_id: "tampered-init-sess".to_string(),
            ca_dkg_transcript_hash: fix.ca_transcript.clone(),
            vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: fix.registration_transcript_hash.clone(),
            roster_hash: fix.roster_hash.clone(),
            selected_slots: fix.selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: fix.vault_ek_hex.clone(),
            sender_address: fix.sender.clone(),
            asset_type: fix.asset.clone(),
            chain_id: fix.chain_id,
            aggregate_commitment: fix.aggregate_commitment.clone(),
            aggregate_response: fix.aggregate_response.clone(),
            challenge: fix.challenge.clone(),
        };
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("init");
        per_slot_contribs.push(FinalizeContribution {
            slot,
            vault_state_hash: result.vault_state_hash,
            worker_transcript_hash: result.worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            initialized: true,
        });
    }

    // Build a finalize body whose `final_transcript_hash` is a 32-byte hex that does NOT
    // equal the locally-re-derivable digest. Worker rejects before any disk mutation.
    let tampered_final = "de".repeat(32);
    let slot = 0;
    let req = FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "tampered-init-req".to_string(),
        session_id: "tampered-init-sess".to_string(),
        ca_dkg_transcript_hash: fix.ca_transcript.clone(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot: slot,
        player_id: 0,
        vault_ek: fix.vault_ek_hex.clone(),
        sender_address: fix.sender.clone(),
        asset_type: fix.asset.clone(),
        chain_id: fix.chain_id,
        aggregate_commitment: fix.aggregate_commitment.clone(),
        aggregate_response: fix.aggregate_response.clone(),
        challenge: fix.challenge.clone(),
        per_slot_contributions: per_slot_contribs.clone(),
        final_transcript_hash: tampered_final,
    };
    let err = finalize_vault_state_v2(&fix.slot_dirs[slot], &req)
        .expect_err("tampered final hash must reject");
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s) if s == "vault_state_v2_finalize_hash_mismatch"
        ),
        "tampered final hash must surface InvalidDkgState(vault_state_v2_finalize_hash_mismatch), \
         got {err:?}"
    );

    // Codex M3a P1 v3: after init (no finalize), `init_transcript_hash` is None and
    // `worker_transcript_hash` is the frozen per-slot init hash. A tampered finalize call
    // must leave both untouched.
    let persisted = load_vault_state_v2(&fix.slot_dirs[slot])
        .expect("load")
        .expect("file");
    assert_eq!(
        persisted.init_transcript_hash, None,
        "tampered finalize MUST NOT mutate init_transcript_hash (still None — never finalized)"
    );
    assert_eq!(
        persisted.worker_transcript_hash,
        per_slot_contribs[0].worker_transcript_hash,
        "tampered finalize MUST NOT mutate the frozen worker_transcript_hash"
    );
}

/// Tampered per-slot contributions: the coordinator's `perSlotContributions` doesn't
/// match the locally-re-derivable per-slot hash for `self_slot`. Worker MUST fail closed
/// with vault_state_v2_finalize_self_contribution_mismatch BEFORE writing.
#[test]
fn vault_state_init_finalize_rejects_tampered_self_contribution() {
    let fix = build_fixture("tampered-contrib");

    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "tampered-contrib-init-req".to_string(),
            session_id: "tampered-contrib-init-sess".to_string(),
            ca_dkg_transcript_hash: fix.ca_transcript.clone(),
            vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: fix.registration_transcript_hash.clone(),
            roster_hash: fix.roster_hash.clone(),
            selected_slots: fix.selected_slots.clone(),
            self_slot: slot,
            player_id: ordinal,
            vault_ek: fix.vault_ek_hex.clone(),
            sender_address: fix.sender.clone(),
            asset_type: fix.asset.clone(),
            chain_id: fix.chain_id,
            aggregate_commitment: fix.aggregate_commitment.clone(),
            aggregate_response: fix.aggregate_response.clone(),
            challenge: fix.challenge.clone(),
        };
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("init");
        per_slot_contribs.push(FinalizeContribution {
            slot,
            vault_state_hash: result.vault_state_hash,
            worker_transcript_hash: result.worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            initialized: true,
        });
    }

    // Tamper player 0's contribution (which is what self_slot=0 will re-derive).
    per_slot_contribs[0].worker_transcript_hash = "be".repeat(32);

    let mut sorted_slots = fix.selected_slots.clone();
    sorted_slots.sort_unstable();
    let mut sorted_contribs = per_slot_contribs.clone();
    sorted_contribs.sort_by_key(|c| c.slot);
    let tampered_final = final_transcript_hash(
        DKG_EPOCH,
        &fix.ca_transcript,
        &fix.vault_ek_transcript_hash,
        &fix.registration_transcript_hash,
        &fix.roster_hash,
        &sorted_slots,
        &fix.vault_ek_hex,
        &fix.sender,
        &fix.asset,
        fix.chain_id,
        &fix.aggregate_commitment,
        &fix.aggregate_response,
        &fix.challenge,
        &sorted_contribs,
    );

    let slot = 0;
    let req = FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "tampered-contrib-init-req".to_string(),
        session_id: "tampered-contrib-init-sess".to_string(),
        ca_dkg_transcript_hash: fix.ca_transcript.clone(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        roster_hash: fix.roster_hash.clone(),
        selected_slots: fix.selected_slots.clone(),
        self_slot: slot,
        player_id: 0,
        vault_ek: fix.vault_ek_hex.clone(),
        sender_address: fix.sender.clone(),
        asset_type: fix.asset.clone(),
        chain_id: fix.chain_id,
        aggregate_commitment: fix.aggregate_commitment.clone(),
        aggregate_response: fix.aggregate_response.clone(),
        challenge: fix.challenge.clone(),
        per_slot_contributions: per_slot_contribs.clone(),
        final_transcript_hash: tampered_final,
    };
    let err = finalize_vault_state_v2(&fix.slot_dirs[slot], &req)
        .expect_err("tampered self contribution must reject");
    // The tampered contribution causes the locally-re-derived self init hash to differ
    // from per_slot_contributions[player_id].worker_transcript_hash.
    assert!(
        matches!(
            err,
            WorkerError::InvalidDkgState(ref s)
                if s == "vault_state_v2_finalize_self_contribution_mismatch"
        ),
        "tampered self contribution must surface InvalidDkgState(self_contribution_mismatch), got {err:?}"
    );
}
