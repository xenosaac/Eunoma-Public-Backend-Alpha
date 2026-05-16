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
        run_round1_v2, HpkeEnvelope as MpccaHpkeEnvelope, Round1Request as MpccaRound1Request,
    },
    registration_verifier::{
        aggregate_registration_commitment, registration_challenge, verify_registration_proof,
        RegistrationCommitmentInput, RegistrationResponseInput,
    },
    vault_state_v2::{
        final_transcript_hash, finalize_vault_state_v2, init_vault_state_v2,
        load_vault_state_v2, observe_deposit_v2, FinalizeContribution, FinalizeRequest,
        InitRequest as VaultStateInitRequest, ObserveDepositRequest,
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
        // M1 ingress fields — wire shape only; this test runs the pre-finalize negative-control
        // path that rejects BEFORE the ingress validation runs (the vault_state_v2_not_finalized
        // error fires earlier in common_public_binding_work).
        amount_commitment: String::new(),
        per_share_commitments: vec![],
        ingress_envelopes: vec![],
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

    // M1 ingress envelopes/commitments — wire-shape valid so the post-finalize happy path
    // reaches the NotImplemented surface rather than failing at ingress validation.
    let m1_envelopes: Vec<MpccaHpkeEnvelope> = (0..5_u8)
        .map(|i| {
            let seed = format!("{i:02x}");
            MpccaHpkeEnvelope {
                kem: "DHKEM_X25519_HKDF_SHA256".to_string(),
                kdf: "HKDF_SHA256".to_string(),
                aead: "AES_256_GCM".to_string(),
                enc: seed.repeat(32),
                ciphertext: seed.repeat(80),
                aad_hash: seed.repeat(32),
            }
        })
        .collect();
    let m1_commitments: Vec<String> = (0..5_u8)
        .map(|i| format!("{i:02x}").repeat(32))
        .collect();

    // 5. KILLER ASSERTION: post-finalize, MPCCA withdraw round1 with the canonical final
    //    hash MUST surface NotImplemented (the happy-path 501 equivalent). Exercise all
    //    5 selected slots — if any one fails closed, the regression isn't actually fixed.
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let mut req = round1_req_pre_finalize.clone();
        req.self_slot = slot;
        req.player_id = ordinal;
        req.amount_commitment = "ac".repeat(32);
        req.per_share_commitments = m1_commitments.clone();
        req.ingress_envelopes = m1_envelopes.clone();
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
// =============================================================================================
// Codex M3a P1 v4 KILLER — partial-finalize recovery (rewritten to genuinely exercise replay).
//
// Scenario: coordinator runs init → collects 5 per-slot contributions → computes the
// canonical final_transcript_hash → fans out finalize. Network partitions mid-fan-out: 3 of 5
// workers (slots 0, 1, 2) acknowledge before the partition; slots 3, 4 don't. The
// coordinator's retry must converge by re-RUNNING init, re-BUILDING perSlotContributions from
// the REPLAYED responses, re-COMPUTING the final transcript hash, and re-fanning-out finalize.
// Already-finalized workers must accept the new final hash idempotently (= the original);
// not-yet-finalized workers finalize for the first time.
//
// Pre-v4 false-positive history:
//   The earlier version of this test SHARED `per_slot_contribs` between the original finalize
//   (PHASE 2) and the retry (PHASE 4). It claimed to test the recovery path but never
//   actually used the REPLAYED init responses to rebuild the contributions. The actual
//   coordinator does use the replayed responses (server.ts:2046 `vaultStateHash: r.vaultStateHash`)
//   — and pre-v4, finalized vs not-finalized slots returned DIFFERENT `vault_state_hash`
//   values (sha256 of mutated vs unmutated on-disk JSON), so the recomputed final hash
//   diverged from the original and already-finalized workers rejected the retry with
//   `vault_state_v2_finalize_already_pinned_with_different_value`. The pre-v4 test would
//   have passed even with the broken sha256-of-file-bytes definition, because it reused
//   the original (pre-partial-finalize) contribs.
//
//   This rewrite REPLACES the original `per_slot_contribs` with `per_slot_contribs_v2`
//   collected entirely from PHASE 3's replayed init responses and recomputes
//   `final_transcript_hash_v2` from those — exactly mirroring the production coordinator
//   path. If `vault_state_hash` is NOT stable across the init → finalize boundary,
//   `final_transcript_hash_v2 != final_transcript_hash` and PHASE 4's finalize retry fails
//   on slots 0/1/2 with `vault_state_v2_finalize_already_pinned_with_different_value`.
//
// v4 fix (lib.rs): `vault_state_hash` is now computed via `compute_vault_state_hash_canonical`
// over an IMMUTABLE field subset (excluding `init_transcript_hash`, `deposit_count_observed`,
// `vault_sequence`). Init replays therefore return the SAME `vault_state_hash` regardless of
// finalize state, so the recomputed final hash matches the original byte-for-byte.
// =============================================================================================
#[test]
fn vault_state_init_partial_finalize_recoverable() {
    let fix = build_fixture("partial-finalize");

    let mut sorted_slots = fix.selected_slots.clone();
    sorted_slots.sort_unstable();

    // Helper: build an init request for (slot, ordinal). Same body shape on every call so
    // replays hit the idempotent branch.
    let make_init_req = |slot: usize, ordinal: usize| VaultStateInitRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "partial-finalize-req".to_string(),
        session_id: "partial-finalize-sess".to_string(),
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

    // Helper: build the per-slot FinalizeContribution from an InitResult — the EXACT mapping
    // the coordinator does in server.ts:2046 (vaultStateHash: r.vaultStateHash).
    fn make_contrib(slot: usize, r: &eunoma_crypto_worker::vault_state_v2::InitResult)
        -> FinalizeContribution
    {
        FinalizeContribution {
            slot,
            vault_state_hash: r.vault_state_hash.clone(),
            worker_transcript_hash: r.worker_transcript_hash.clone(),
            vault_sequence: r.vault_sequence,
            deposit_count_observed: r.deposit_count_observed,
            initialized: r.initialized,
        }
    }

    // Helper: assemble the canonical FINAL_V1 transcript hash from a sorted contribs slice +
    // the fixture's public inputs.
    let compute_final_hash = |sorted_contribs: &[FinalizeContribution]| {
        final_transcript_hash(
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
            sorted_contribs,
        )
    };

    // PHASE 1: init all 5 selected workers. Capture original per-slot init responses + the
    // ORIGINAL `per_slot_contribs_v1` + `final_hash_v1` — these are what the coordinator
    // computes BEFORE the partition. We retain them as the canonical-value reference: the
    // post-replay PHASE 3 contributions MUST be byte-identical to these, and the post-replay
    // `final_hash_v2` MUST byte-equal `final_hash_v1` without any normalisation.
    //
    // Capture the raw init results too so PHASE 3 can byte-compare them as serde_json::Value
    // dictionaries (catching any field drift, including `initialized` and `createdAtUnixMs`
    // — though the latter is NOT in the contribution tuple).
    let mut init_responses_v1: Vec<eunoma_crypto_worker::vault_state_v2::InitResult> = Vec::with_capacity(5);
    let mut per_slot_contribs_v1: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = make_init_req(slot, ordinal);
        let result = init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("init");
        assert!(result.initialized, "slot {slot}: first init must report initialized=true");
        per_slot_contribs_v1.push(make_contrib(slot, &result));
        init_responses_v1.push(result);
    }
    let mut sorted_contribs_v1 = per_slot_contribs_v1.clone();
    sorted_contribs_v1.sort_by_key(|c| c.slot);
    let final_hash_v1 = compute_final_hash(&sorted_contribs_v1);

    // PHASE 2: SIMULATE the partial-finalize. Only slots 0, 1, 2 process the finalize body.
    // Slots 3 and 4 never see this round (coordinator partition mid-fan-out).
    let make_finalize_req_v1 = |slot: usize, ordinal: usize| FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "partial-finalize-req".to_string(),
        session_id: "partial-finalize-sess".to_string(),
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
        per_slot_contributions: per_slot_contribs_v1.clone(),
        final_transcript_hash: final_hash_v1.clone(),
    };
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate().take(3) {
        let res = finalize_vault_state_v2(
            &fix.slot_dirs[slot],
            &make_finalize_req_v1(slot, ordinal),
        )
        .expect("finalize must succeed for slot 0,1,2");
        assert!(res.finalized, "slot {slot}: first finalize must report finalized=true");
        assert_eq!(
            res.init_transcript_hash.to_lowercase(),
            final_hash_v1.to_lowercase()
        );
    }

    // Sanity check: slots 0, 1, 2 have init_transcript_hash = final_hash_v1; slots 3, 4
    // have None. This is the persistent state the coordinator wakes up to when it retries.
    for &slot in &fix.selected_slots[..3] {
        let persisted = load_vault_state_v2(&fix.slot_dirs[slot])
            .expect("load")
            .expect("file");
        assert_eq!(
            persisted.init_transcript_hash.as_deref().map(str::to_lowercase),
            Some(final_hash_v1.to_lowercase()),
            "slot {slot}: finalized, init_transcript_hash MUST equal final_hash_v1"
        );
    }
    for &slot in &fix.selected_slots[3..] {
        let persisted = load_vault_state_v2(&fix.slot_dirs[slot])
            .expect("load")
            .expect("file");
        assert_eq!(
            persisted.init_transcript_hash, None,
            "slot {slot}: NOT-finalized, init_transcript_hash MUST be None"
        );
    }

    // PHASE 3 (KILLER REPLAY): COORDINATOR RETRY. Re-run init on all 5 workers — the same
    // call the production coordinator makes in /v2/vault_state/init/start as the FIRST step
    // of its retry flow. Capture the REPLAYED init responses (NOT phase 1's values) and
    // build `per_slot_contribs_v2` from them DIRECTLY — NO normalisation. This is the
    // critical change from the pre-v5 test: we use the actual replay responses and the
    // coordinator binds `r.initialized` directly into the contribution (see server.ts:2050).
    //
    // The load-bearing assertion: `final_hash_v2 == final_hash_v1` byte-for-byte WITHOUT
    // any test-side normalisation of `initialized` or anything else. Pre-v5, the worker
    // returned `initialized=false` on replay, the contribution differed, and the
    // recomputed final hash diverged. v5 returns `initialized=true` on replay → byte-
    // identical contribution → byte-identical final hash → partial-finalize recovery works.
    //
    // If `vault_state_hash` were NOT canonical (pre-v4: sha256 of on-disk bytes), the replay
    // would return DIFFERENT `vault_state_hash` values for finalized vs not-finalized slots
    // and the same load-bearing assertion would surface that bug. So this single equality
    // check tests both the v4 canonical-hash fix AND the v5 initialized-monotonicity fix.
    let mut init_responses_v2: Vec<eunoma_crypto_worker::vault_state_v2::InitResult> = Vec::with_capacity(5);
    let mut per_slot_contribs_v2: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = make_init_req(slot, ordinal);
        let replay = init_vault_state_v2(&fix.slot_dirs[slot], &req).expect("init replay");
        assert!(
            replay.initialized,
            "slot {slot}: Codex M3a P1 v5 — `initialized` is now monotonic (once true, \
             stays true). Init replay on an existing vault MUST return initialized=true \
             — the file IS initialized. Pre-v5 returned false here, breaking partial-finalize \
             recovery."
        );
        per_slot_contribs_v2.push(make_contrib(slot, &replay));
        init_responses_v2.push(replay);
    }
    let mut sorted_contribs_v2 = per_slot_contribs_v2.clone();
    sorted_contribs_v2.sort_by_key(|c| c.slot);
    let final_hash_v2 = compute_final_hash(&sorted_contribs_v2);

    // Cross-checks: every contribution field is byte-stable across the replay boundary,
    // regardless of finalize state. If ANY of these fails, a mutable field leaked into the
    // contribution tuple bound into the final_transcript_hash.
    for (i, c) in per_slot_contribs_v2.iter().enumerate() {
        assert_eq!(
            c.worker_transcript_hash.to_lowercase(),
            per_slot_contribs_v1[i].worker_transcript_hash.to_lowercase(),
            "slot {}: replayed worker_transcript_hash MUST equal original (frozen at init)",
            c.slot,
        );
        assert_eq!(
            c.vault_state_hash.to_lowercase(),
            per_slot_contribs_v1[i].vault_state_hash.to_lowercase(),
            "slot {}: replayed vault_state_hash MUST equal original (v4 canonical-subset \
             hash — immutable across the init/finalize/observe lifecycle).",
            c.slot,
        );
        assert_eq!(
            c.vault_sequence, per_slot_contribs_v1[i].vault_sequence,
            "slot {}: vault_sequence stable across replay (no withdraw in this test)",
            c.slot,
        );
        assert_eq!(
            c.deposit_count_observed, per_slot_contribs_v1[i].deposit_count_observed,
            "slot {}: deposit_count_observed stable across replay (no observe in this test)",
            c.slot,
        );
        assert_eq!(
            c.initialized, per_slot_contribs_v1[i].initialized,
            "slot {}: Codex M3a P1 v5 — `initialized` is now monotonic. Replay MUST return \
             the same value as the first init (both true). Pre-v5 returned false here, \
             breaking partial-finalize recovery.",
            c.slot,
        );
    }

    // THE LOAD-BEARING ASSERTION (Codex M3a P1 v5 KILLER). NO normalisation. NO test-side
    // workarounds. The coordinator's `final_transcript_hash`, recomputed from the replayed
    // init responses BYTE-FOR-BYTE, MUST equal the original `final_transcript_hash`. This
    // is what makes partial-finalize recovery work: a coordinator that re-runs init →
    // re-computes the final hash → re-fans-out finalize gets the SAME canonical hash on
    // both rounds, so already-finalized workers accept the retry idempotently.
    //
    // If this fails: SOME field in `perSlotContributions` is mutable across init replay,
    // and partial-finalize recovery is broken. Audit every InitResponse field that flows
    // into the contribution tuple at server.ts:2041 — the bug is one of them.
    assert_eq!(
        final_hash_v2.to_lowercase(),
        final_hash_v1.to_lowercase(),
        "Codex M3a P1 v5 KILLER: `final_transcript_hash` recomputed from REPLAYED init \
         responses MUST byte-equal the original WITHOUT any test-side normalisation. If this \
         fails, a mutable field leaked into perSlotContributions and partial-finalize \
         recovery is broken — the coordinator's retry computes a different final hash and \
         already-finalized workers reject it as \
         vault_state_v2_finalize_already_pinned_with_different_value."
    );

    // Belt-and-braces: assert init response equality as serde_json::Value. This catches
    // ANY field drift between the first init and the replay — including fields that aren't
    // currently bound into the contribution but might be added later, AND including the
    // one field that legitimately differs (`createdAtUnixMs` is per-call). We exclude
    // `createdAtUnixMs` from this comparison BUT explicitly assert it remains OUT of
    // perSlotContributions (covered by the byte-equality above).
    for (i, _) in init_responses_v1.iter().enumerate() {
        let v1 = &init_responses_v1[i];
        let v2 = &init_responses_v2[i];
        assert_eq!(v1.slot, v2.slot, "slot drift");
        assert_eq!(v1.player_id, v2.player_id, "player_id drift");
        assert_eq!(v1.vault_state_path, v2.vault_state_path, "vault_state_path drift");
        assert_eq!(v1.vault_state_hash, v2.vault_state_hash, "vault_state_hash drift");
        assert_eq!(
            v1.worker_transcript_hash, v2.worker_transcript_hash,
            "worker_transcript_hash drift"
        );
        assert_eq!(v1.vault_sequence, v2.vault_sequence, "vault_sequence drift");
        assert_eq!(
            v1.deposit_count_observed, v2.deposit_count_observed,
            "deposit_count_observed drift"
        );
        assert_eq!(
            v1.initialized, v2.initialized,
            "initialized drift — Codex M3a P1 v5 makes this a vault-level monotonic flag"
        );
        assert_eq!(
            v1.created_at_unix_ms, v2.created_at_unix_ms,
            "created_at_unix_ms MUST equal the original (the worker reads it back from disk \
             on idempotent replay — NOT recomputed). It's also NOT a contribution field, so \
             even if it did drift it wouldn't break recovery; but byte-equality here is a \
             defense-in-depth signal."
        );
    }

    let final_hash = final_hash_v1.clone();

    // PHASE 4: COORDINATOR FINALIZE RETRY. The coordinator fans out finalize to all 5 slots
    // with `(final_transcript_hash = final_hash_v1, per_slot_contributions = per_slot_contribs_v2)`
    // — the canonical body it built DIRECTLY from the REPLAYED init responses (this test
    // path), with NO normalisation. Slots 0, 1, 2 must accept idempotently (finalized=false).
    // Slots 3, 4 must finalize for the first time (finalized=true). ALL 5 must accept — this
    // is the killer assertion that the v5 fix actually closes the recovery story.
    let make_finalize_req_v2 = |slot: usize, ordinal: usize| FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "partial-finalize-req".to_string(),
        session_id: "partial-finalize-sess".to_string(),
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
        per_slot_contributions: per_slot_contribs_v2.clone(),
        final_transcript_hash: final_hash.clone(),
    };
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let res = finalize_vault_state_v2(
            &fix.slot_dirs[slot],
            &make_finalize_req_v2(slot, ordinal),
        )
        .expect("finalize retry MUST succeed on every slot — false positive if this panics");
        let already_finalized = ordinal < 3;
        if already_finalized {
            assert!(
                !res.finalized,
                "slot {slot}: previously finalized → idempotent retry MUST report finalized=false"
            );
        } else {
            assert!(
                res.finalized,
                "slot {slot}: not previously finalized → retry MUST land for first time (finalized=true)"
            );
        }
        assert_eq!(
            res.init_transcript_hash.to_lowercase(),
            final_hash.to_lowercase(),
            "slot {slot}: all 5 slots MUST converge on the same canonical init_transcript_hash"
        );
    }

    // PHASE 5: KILLER — every worker now has init_transcript_hash = final_hash. MPCCA
    // round1 with that hash MUST reach NotImplemented (the happy-path 501 equivalent) on
    // every slot, proving the cluster has fully recovered from the partial-finalize state.
    // M1 ingress envelopes/commitments — wire-shape-valid so the test reaches the
    // NotImplemented surface in run_round1_v2 (rather than failing at the ingress
    // validation gate).
    let m1_envelopes: Vec<MpccaHpkeEnvelope> = (0..5_u8)
        .map(|i| {
            let seed = format!("{i:02x}");
            MpccaHpkeEnvelope {
                kem: "DHKEM_X25519_HKDF_SHA256".to_string(),
                kdf: "HKDF_SHA256".to_string(),
                aead: "AES_256_GCM".to_string(),
                enc: seed.repeat(32),
                ciphertext: seed.repeat(80),
                aad_hash: seed.repeat(32),
            }
        })
        .collect();
    let m1_commitments: Vec<String> = (0..5_u8)
        .map(|i| format!("{i:02x}").repeat(32))
        .collect();
    let round1_req_template = MpccaRound1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "partial-finalize-withdraw-req".to_string(),
        session_id: "partial-finalize-withdraw-sess".to_string(),
        vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
        registration_transcript_hash: fix.registration_transcript_hash.clone(),
        vault_state_init_transcript_hash: final_hash.clone(),
        observed_deposit_transcript_hashes: vec![],
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
        amount_commitment: "ac".repeat(32),
        per_share_commitments: m1_commitments,
        ingress_envelopes: m1_envelopes,
    };
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let mut req = round1_req_template.clone();
        req.self_slot = slot;
        req.player_id = ordinal;
        let err = run_round1_v2(&fix.slot_dirs[slot], &req)
            .expect_err("post-recovery MPCCA round1 reaches NotImplemented");
        match err {
            WorkerError::NotImplemented(phase) => assert_eq!(
                phase, "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4"
            ),
            other => panic!(
                "slot {slot}: expected NotImplemented post-recovery; partial-finalize recovery \
                 is NOT FIXED if this slot surfaces {other:?}"
            ),
        }
    }

    // PHASE 6 (Codex M3a P1 v5 audit): we've already asserted `final_hash_v2 == final_hash_v1`
    // up in PHASE 3 without any normalisation. That's the load-bearing fix. The remaining
    // belt-and-braces assertion is that the per-slot contribution tuple ONLY contains fields
    // that are stable across init replay. Audit (see also lib.rs ~5675, FinalizeContribution
    // struct definition):
    //   - slot                    : stable (the request input).
    //   - vault_state_hash        : stable (v4 canonical hash of immutable subset).
    //   - worker_transcript_hash  : stable (frozen at init; read back from disk on replay).
    //   - vault_sequence          : stable on init replay (mutated only by withdraw, not here).
    //   - deposit_count_observed  : stable on init replay (mutated only by observe-deposit).
    //   - initialized             : stable (v5: monotonic vault-level flag, true on both first
    //                               init and replay).
    // No mutable field remains in the contribution tuple. This is the FINAL audit boundary
    // for the partial-finalize recovery story.
}

// =============================================================================================
// Codex M3a P1 v5 KILLER — init replay on an already-initialized vault returns
// `initialized=true`.
//
// The micro-version of the partial-finalize recovery test, focused on the single load-bearing
// v5 invariant: `initialized` is a monotonic VAULT-level flag — true on first init, true on
// every subsequent replay. Pre-v5 this returned false on replay, which broke the partial-
// finalize recovery because the coordinator binds `r.initialized` directly into the per-slot
// contribution tuple bound into the final_transcript_hash. With every retry returning a
// different boolean, the coordinator's recomputed final hash would diverge from the original
// and already-finalized workers would reject the retry.
//
// This test also captures the response equality invariant: an init replay (excluding
// `created_at_unix_ms`, which is per-call) MUST return the same response as the first init.
// =============================================================================================
#[test]
fn init_replay_returns_initialized_true_for_already_initialized_vault() {
    let fix = build_fixture("init-replay-initialized-true");
    let slot = 0_usize;
    let ordinal = 0_usize;

    let init_req = VaultStateInitRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "v5-init-replay-req".to_string(),
        session_id: "v5-init-replay-sess".to_string(),
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

    // First init: materialises the file. Must return initialized=true.
    let first = init_vault_state_v2(&fix.slot_dirs[slot], &init_req).expect("first init");
    assert!(
        first.initialized,
        "first init must return initialized=true (the file was just created)"
    );

    // Replay: file already exists. v5 invariant: STILL returns initialized=true.
    let replay = init_vault_state_v2(&fix.slot_dirs[slot], &init_req).expect("init replay");
    assert!(
        replay.initialized,
        "Codex M3a P1 v5 KILLER: `initialized` is a monotonic VAULT-level flag. Once the \
         vault state file has been written, `initialized` stays true. Pre-v5 this returned \
         `false` on replay, which broke partial-finalize recovery — the coordinator binds \
         this value directly into perSlotContributions[i].initialized at server.ts:2050, \
         and a flipped flag makes the recomputed final_transcript_hash diverge from the \
         original."
    );

    // Every other field must be byte-equal across the replay boundary. We exclude
    // `created_at_unix_ms` from the comparison philosophy (the worker reads it back from
    // disk on replay, so it IS equal — but we still verify it explicitly). This catches
    // any future field drift in the InitResponse / InitResult shape.
    assert_eq!(first.slot, replay.slot, "slot drift");
    assert_eq!(first.player_id, replay.player_id, "player_id drift");
    assert_eq!(
        first.vault_state_path, replay.vault_state_path,
        "vault_state_path drift"
    );
    assert_eq!(
        first.vault_state_hash, replay.vault_state_hash,
        "vault_state_hash drift — v4 canonical hash MUST be stable across init replay"
    );
    assert_eq!(
        first.worker_transcript_hash, replay.worker_transcript_hash,
        "worker_transcript_hash drift — v3 frozen field MUST be stable across init replay"
    );
    assert_eq!(
        first.vault_sequence, replay.vault_sequence,
        "vault_sequence drift — must be read back from disk"
    );
    assert_eq!(
        first.deposit_count_observed, replay.deposit_count_observed,
        "deposit_count_observed drift — must be read back from disk"
    );
    assert_eq!(
        first.created_at_unix_ms, replay.created_at_unix_ms,
        "created_at_unix_ms drift — must be read back from disk on replay (NOT \
         recomputed). Even if it did drift, it is NOT part of the contribution tuple — \
         but byte-equality here is a defense-in-depth signal."
    );
    assert_eq!(
        first.initialized, replay.initialized,
        "initialized drift — v5 makes this a monotonic vault-level flag"
    );

    // Third replay (idempotency over many retries): same response.
    let replay2 = init_vault_state_v2(&fix.slot_dirs[slot], &init_req).expect("init replay 2");
    assert!(replay2.initialized);
    assert_eq!(first.vault_state_hash, replay2.vault_state_hash);
    assert_eq!(first.worker_transcript_hash, replay2.worker_transcript_hash);
}

// =============================================================================================
// Codex M3a P1 v3 KILLER — init replay returns frozen worker_transcript_hash after finalize.
//
// The micro-version of the partial-finalize recovery test, focused on the single load-
// bearing property: after init → finalize, an init replay must STILL return the per-slot
// worker_transcript_hash (NOT the canonical final hash). This is what makes the partial-
// finalize recovery path coordinator-retryable.
// =============================================================================================
#[test]
fn vault_state_init_replay_returns_frozen_worker_hash_after_finalize() {
    let fix = build_fixture("init-replay-frozen");
    let slot = 2_usize;
    let ordinal = 2_usize;

    // PHASE 1: fresh init on slot 2; capture the returned per-slot hash.
    let init_req = VaultStateInitRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "frozen-replay-req".to_string(),
        session_id: "frozen-replay-sess".to_string(),
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
    let first = init_vault_state_v2(&fix.slot_dirs[slot], &init_req).expect("first init");
    let frozen_per_slot_hash = first.worker_transcript_hash.clone();
    assert!(first.initialized);

    // PHASE 2: init the other 4 slots (we need 5 contributions to build the FINAL_V1 hash).
    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (other_ordinal, &other_slot) in fix.selected_slots.iter().enumerate() {
        if other_slot == slot {
            per_slot_contribs.push(FinalizeContribution {
                slot,
                vault_state_hash: first.vault_state_hash.clone(),
                worker_transcript_hash: frozen_per_slot_hash.clone(),
                vault_sequence: 0,
                deposit_count_observed: 0,
                initialized: true,
            });
            continue;
        }
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "frozen-replay-req".to_string(),
            session_id: "frozen-replay-sess".to_string(),
            ca_dkg_transcript_hash: fix.ca_transcript.clone(),
            vault_ek_transcript_hash: fix.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: fix.registration_transcript_hash.clone(),
            roster_hash: fix.roster_hash.clone(),
            selected_slots: fix.selected_slots.clone(),
            self_slot: other_slot,
            player_id: other_ordinal,
            vault_ek: fix.vault_ek_hex.clone(),
            sender_address: fix.sender.clone(),
            asset_type: fix.asset.clone(),
            chain_id: fix.chain_id,
            aggregate_commitment: fix.aggregate_commitment.clone(),
            aggregate_response: fix.aggregate_response.clone(),
            challenge: fix.challenge.clone(),
        };
        let r = init_vault_state_v2(&fix.slot_dirs[other_slot], &req).expect("init other slot");
        per_slot_contribs.push(FinalizeContribution {
            slot: other_slot,
            vault_state_hash: r.vault_state_hash,
            worker_transcript_hash: r.worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            initialized: true,
        });
    }
    per_slot_contribs.sort_by_key(|c| c.slot);

    let mut sorted_slots = fix.selected_slots.clone();
    sorted_slots.sort_unstable();
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
        &per_slot_contribs,
    );
    // The final hash MUST differ from the per-slot hash — otherwise this test would prove nothing.
    assert_ne!(final_hash.to_lowercase(), frozen_per_slot_hash.to_lowercase());

    // PHASE 3: finalize slot 2 with the canonical final hash. After this, the persisted
    // `init_transcript_hash = Some(final_hash)`.
    let finalize_req = FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "frozen-replay-req".to_string(),
        session_id: "frozen-replay-sess".to_string(),
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
    let f_res = finalize_vault_state_v2(&fix.slot_dirs[slot], &finalize_req).expect("finalize");
    assert!(f_res.finalized);
    assert_eq!(f_res.init_transcript_hash.to_lowercase(), final_hash.to_lowercase());

    // Sanity check persisted state: worker_transcript_hash = per-slot (frozen);
    // init_transcript_hash = final_hash.
    let persisted = load_vault_state_v2(&fix.slot_dirs[slot])
        .expect("load")
        .expect("file");
    assert_eq!(
        persisted.worker_transcript_hash.to_lowercase(),
        frozen_per_slot_hash.to_lowercase(),
        "frozen field MUST equal per-slot hash"
    );
    assert_eq!(
        persisted.init_transcript_hash.as_deref().map(str::to_lowercase),
        Some(final_hash.to_lowercase()),
        "post-finalize init_transcript_hash MUST equal final hash"
    );

    // PHASE 4 KILLER: init replay — MUST return the FROZEN per-slot hash, NOT the final hash.
    // Pre-v3 this returned final_hash, breaking the coordinator's per-slot recomputation gate.
    let replay = init_vault_state_v2(&fix.slot_dirs[slot], &init_req).expect("init replay");
    // Codex M3a P1 v5: `initialized` is now monotonic — true on first init AND on replay.
    assert!(
        replay.initialized,
        "v5: init replay on an already-initialized vault MUST return initialized=true"
    );
    assert_eq!(
        replay.worker_transcript_hash.to_lowercase(),
        frozen_per_slot_hash.to_lowercase(),
        "init replay MUST return the FROZEN per-slot worker_transcript_hash — NOT the canonical \
         final hash. This is the load-bearing invariant for partial-finalize recovery."
    );
    assert_ne!(
        replay.worker_transcript_hash.to_lowercase(),
        final_hash.to_lowercase(),
        "init replay MUST NOT return the final hash (distinguishability KILLER — the regression \
         this test pins is exactly the pre-v3 behaviour of returning final_hash here)"
    );
}

// =============================================================================================
// Codex M3a P2 KILLER — finalize replay after observe-deposit succeeds.
//
// observe_deposit_v2 bumps `deposit_count_observed` while preserving identity bindings. Pre-v3
// finalize re-computed the per-slot init hash from MUTABLE current state (using the bumped
// cursor), so a finalize replay AFTER even one observe-deposit would diverge from the original
// per-slot hash and fail closed with `vault_state_v2_finalize_self_contribution_mismatch`.
//
// v3 fix: finalize uses the FROZEN `worker_transcript_hash` from disk — no dependency on the
// cursor. Replay is idempotent across cursor bumps.
// =============================================================================================
#[test]
fn finalize_replay_after_observe_deposit_succeeds() {
    let fix = build_fixture("finalize-replay-obs");

    // PHASE 1: init all 5 + capture contributions + compute canonical final hash.
    let mut per_slot_contribs: Vec<FinalizeContribution> = Vec::with_capacity(5);
    for (ordinal, &slot) in fix.selected_slots.iter().enumerate() {
        let req = VaultStateInitRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: "fin-replay-obs-req".to_string(),
            session_id: "fin-replay-obs-sess".to_string(),
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
    let mut sorted_slots = fix.selected_slots.clone();
    sorted_slots.sort_unstable();
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

    let make_finalize_req = |slot: usize, ordinal: usize| FinalizeRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        request_id: "fin-replay-obs-req".to_string(),
        session_id: "fin-replay-obs-sess".to_string(),
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

    // PHASE 2: finalize slot 0.
    let slot = 0_usize;
    let ordinal = 0_usize;
    let res = finalize_vault_state_v2(&fix.slot_dirs[slot], &make_finalize_req(slot, ordinal))
        .expect("first finalize");
    assert!(res.finalized);

    // PHASE 3: observe-deposit twice — cursor goes 0 → 1 → 2. This is what would normally
    // happen between init/finalize and the next MPCCA withdraw (the observer polls the
    // chain event stream).
    for deposit_count in 1u64..=2 {
        let obs_req = ObserveDepositRequest {
            dkg_epoch: DKG_EPOCH.to_string(),
            request_id: format!("fin-replay-obs-obs-{deposit_count}"),
            session_id: format!("fin-replay-obs-obs-sess-{deposit_count}"),
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
            deposit_count,
            commitment: format!("{:02x}", deposit_count).repeat(32),
            amount_tag: format!("{:02x}", deposit_count + 1).repeat(32),
            ca_payload_hash: format!("{:02x}", deposit_count + 2).repeat(32),
            deposit_nonce: format!("{:02x}", deposit_count + 3).repeat(32),
            sequence_number: (deposit_count - 1).to_string(),
            tx_version: deposit_count.to_string(),
            event_guid: format!("evt-{deposit_count}"),
            previous_deposit_count_observed: deposit_count - 1,
            new_deposit_count_observed: deposit_count,
        };
        observe_deposit_v2(&fix.slot_dirs[slot], &obs_req).expect("observe_deposit_v2");
    }

    // Sanity check: cursor bumped to 2; FROZEN worker_transcript_hash and init_transcript_hash
    // both preserved.
    let post_obs = load_vault_state_v2(&fix.slot_dirs[slot])
        .expect("load")
        .expect("file");
    assert_eq!(post_obs.deposit_count_observed, 2);
    assert_eq!(
        post_obs.worker_transcript_hash.to_lowercase(),
        per_slot_contribs[ordinal].worker_transcript_hash.to_lowercase(),
        "observe-deposit MUST NOT mutate the FROZEN worker_transcript_hash"
    );
    assert_eq!(
        post_obs.init_transcript_hash.as_deref().map(str::to_lowercase),
        Some(final_hash.to_lowercase()),
        "observe-deposit MUST NOT mutate the canonical init_transcript_hash"
    );

    // PHASE 4 KILLER: finalize REPLAY with the SAME body. Pre-v3 this failed closed with
    // `vault_state_v2_finalize_self_contribution_mismatch` because finalize recomputed the
    // per-slot init hash using `existing.deposit_count_observed` (now 2 — different from the
    // 0 used at original init), and the recomputed value diverged from the supplied
    // contribution. v3 uses the FROZEN field from disk, so the replay is idempotent.
    let replay = finalize_vault_state_v2(&fix.slot_dirs[slot], &make_finalize_req(slot, ordinal))
        .expect("finalize replay after observe-deposit MUST succeed (v3 partial-finalize-recovery + P2 idempotency)");
    assert!(
        !replay.finalized,
        "finalize replay MUST be idempotent (finalized=false) — the body matched the persisted state"
    );
    assert_eq!(
        replay.init_transcript_hash.to_lowercase(),
        final_hash.to_lowercase(),
        "finalize replay MUST return the same canonical init_transcript_hash"
    );

    // Final state: cursor still 2, init_transcript_hash still pinned. Nothing mutated.
    let final_state = load_vault_state_v2(&fix.slot_dirs[slot])
        .expect("load")
        .expect("file");
    assert_eq!(final_state.deposit_count_observed, 2);
    assert_eq!(
        final_state.init_transcript_hash.as_deref().map(str::to_lowercase),
        Some(final_hash.to_lowercase())
    );
}
