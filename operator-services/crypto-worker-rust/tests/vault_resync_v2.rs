// M11 — tests for the worker `/v2/vault/resync` handler (`run_vault_resync_v2`).
//
// All chain access is injected via the `fetch_override` param, so these tests do
// NO HTTP and NO crypto. They exercise: trusted-config binding (package / vault /
// asset cross-checked against worker env, NOT the request), the pre/post-increment
// vault_sequence state machine, the full WithdrawEventV2 binding, the legacy-state
// guard (existing == expected_next but last_bound_tx_hash == None), the
// fail-closed paths, and the atomic 0o600 write.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use eunoma_crypto_worker::chain_fetch::TxWithdrawEventV2;
use eunoma_crypto_worker::vault_state_v2::{
    run_vault_resync_v2, VaultResyncError, VaultResyncRequest, VaultStateFile,
};

const PKG: &str = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";
const VAULT: &str = "0x554cd51d88770c83ac0000000000000000000000000000000000000000000001";
const ASSET: &str = "0xa";
const NODE: &str = "http://trusted-node.invalid"; // never hit (override supplied)
const TX: &str = "0x7e77b5c13d9677c639ff0e36b90c79f11a3d538871252f4374a1a4d59121a78c";
const ROOT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NULL: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const RECIP: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const REQH: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";

fn temp_state_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("eunoma-vault-resync-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("vault_state_v2.json")
}

/// Write a minimal-but-valid vault_state_v2.json with the given sequence + bound tx.
fn write_state(dir: &Path, seq: u64, last_bound: Option<&str>) {
    let f = VaultStateFile {
        scheme: "vault_state_v2".to_string(),
        slot: 0,
        player_id: 0,
        dkg_epoch: "1".to_string(),
        ca_dkg_transcript_hash: "00".repeat(32),
        vault_ek_transcript_hash: "00".repeat(32),
        registration_transcript_hash: "00".repeat(32),
        roster_hash: "00".repeat(32),
        selected_slots: vec![0, 1, 2, 3, 4],
        vault_ek_hex: "00".repeat(32),
        // sender_address INTENTIONALLY != VAULT — proves the handler binds vault via
        // trusted config, not via this provenance field (fix #3).
        sender_address: "ab".repeat(32),
        asset_type: "00".repeat(31) + "0a",
        chain_id: 2,
        aggregate_commitment: "00".repeat(32),
        aggregate_response: "00".repeat(32),
        challenge: "00".repeat(32),
        vault_sequence: seq,
        deposit_count_observed: 8,
        created_at_unix_ms: 1,
        worker_transcript_hash: "00".repeat(32),
        init_transcript_hash: Some("00".repeat(32)),
        last_bound_tx_hash: last_bound.map(|s| s.to_string()),
        last_resync_at: None,
    };
    fs::write(state_path(dir), serde_json::to_vec_pretty(&f).unwrap()).expect("write state");
    // Start at a non-0o600 mode so the post-resync 0o600 assertion is meaningful.
    fs::set_permissions(state_path(dir), fs::Permissions::from_mode(0o644)).unwrap();
}

fn read_seq(dir: &Path) -> u64 {
    let raw = fs::read(state_path(dir)).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["vault_sequence"].as_u64().unwrap()
}

/// A success event for the given pre-increment sequence, with the canonical binding.
fn ok_event(event_seq: u64) -> TxWithdrawEventV2 {
    TxWithdrawEventV2 {
        success: true,
        vm_status: "Executed successfully".to_string(),
        root: ROOT.to_string(),
        nullifier_hash: NULL.to_string(),
        recipient_hash: RECIP.to_string(),
        request_hash: REQH.to_string(),
        vault_sequence: event_seq,
    }
}

fn req(event_seq: u64) -> VaultResyncRequest {
    VaultResyncRequest {
        dkg_epoch: "1".to_string(),
        request_id: "m11-test".to_string(),
        tx_hash: TX.to_string(),
        bridge_package: PKG.to_string(),
        vault: VAULT.to_string(),
        asset_type: ASSET.to_string(),
        root: ROOT.to_string(),
        nullifier_hash: NULL.to_string(),
        recipient_hash: RECIP.to_string(),
        request_hash: REQH.to_string(),
        event_vault_sequence: event_seq,
        expected_next_sequence: event_seq + 1,
    }
}

async fn call(
    dir: &Path,
    r: &VaultResyncRequest,
    over: Option<Result<TxWithdrawEventV2, String>>,
) -> Result<eunoma_crypto_worker::vault_state_v2::VaultResyncResponse, VaultResyncError> {
    run_vault_resync_v2(dir, NODE, PKG, VAULT, ASSET, r, over).await
}

#[tokio::test]
async fn happy_path_advances_event_seq_1_to_chain_seq_2() {
    let dir = temp_state_dir("happy");
    write_state(&dir, 1, None);
    let resp = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect("resync ok");
    assert_eq!(resp.vault_sequence, 2);
    assert!(!resp.idempotent);
    assert!(!resp.legacy_backfill);
    assert_eq!(read_seq(&dir), 2);
}

#[tokio::test]
async fn idempotent_returns_same_sequence_when_tx_hash_matches() {
    let dir = temp_state_dir("idem");
    // Already advanced to 2, bound by TX. A replay with the same tx → idempotent.
    write_state(&dir, 2, Some(TX));
    let resp = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect("idempotent ok");
    assert_eq!(resp.vault_sequence, 2);
    assert!(resp.idempotent);
    assert!(!resp.legacy_backfill);
}

#[tokio::test]
async fn binding_conflict_when_same_sequence_different_tx() {
    let dir = temp_state_dir("conflict");
    write_state(&dir, 2, Some("0xdeadbeef")); // a DIFFERENT tx already bound seq 2
    let err = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect_err("must conflict");
    assert_eq!(err.code(), "binding_conflict");
    assert_eq!(err.status_u16(), 400);
}

#[tokio::test]
async fn legacy_backfill_verifies_tx_and_backfills_when_bound_tx_hash_none() {
    let dir = temp_state_dir("legacy-ok");
    // Already at 2 (somehow) but no recorded binding. The supplied tx must be the
    // one that advanced chain TO 2 → event_vault_sequence == 1.
    write_state(&dir, 2, None);
    let resp = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect("legacy backfill ok");
    assert_eq!(resp.vault_sequence, 2); // unchanged
    assert!(resp.legacy_backfill);
    assert!(resp.idempotent);
    // Re-reading must now show the backfilled binding (so a second call is a clean idempotent).
    let raw = fs::read(state_path(&dir)).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        v["last_bound_tx_hash"].as_str().unwrap(),
        TX.trim_start_matches("0x")
    );
}

#[tokio::test]
async fn legacy_backfill_fails_closed_when_tx_verification_fails() {
    let dir = temp_state_dir("legacy-fail");
    write_state(&dir, 2, None);
    // Supplied event has the WRONG root → legacy verification fails closed.
    let mut bad = ok_event(1);
    bad.root = "0x99".to_string();
    let err = call(&dir, &req(1), Some(Ok(bad)))
        .await
        .expect_err("must fail closed");
    assert_eq!(err.code(), "legacy_state_bound_tx_verification_failed");
    // State must be untouched (still no binding).
    let raw = fs::read(state_path(&dir)).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(v["last_bound_tx_hash"].is_null());
}

#[tokio::test]
async fn rejects_rollback_when_next_sequence_le_existing() {
    let dir = temp_state_dir("rollback");
    write_state(&dir, 5, Some("0xfeed"));
    // event_seq=1 → expected_next=2 < existing 5 → rollback.
    let err = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect_err("rollback");
    assert_eq!(err.code(), "rollback_rejected");
}

#[tokio::test]
async fn rejects_sequence_mismatch_when_existing_ne_event_vault_sequence() {
    let dir = temp_state_dir("seqmismatch");
    // existing 3, event_seq=1 → expected_next=2 > 3? no, 2<3 → that's rollback.
    // Use existing 1, event_seq=5 → expected_next=6 > 1 but step>1 → too_large.
    write_state(&dir, 1, None);
    let err = call(&dir, &req(5), Some(Ok(ok_event(5))))
        .await
        .expect_err("step too large");
    assert_eq!(err.code(), "sequence_step_too_large");
}

#[tokio::test]
async fn rejects_sequence_binding_invalid_when_expected_ne_event_seq_plus_one() {
    let dir = temp_state_dir("bindinvalid");
    write_state(&dir, 1, None);
    let mut r = req(1);
    r.expected_next_sequence = 3; // != event_vault_sequence(1) + 1
    let err = call(&dir, &r, Some(Ok(ok_event(1))))
        .await
        .expect_err("binding invalid");
    assert_eq!(err.code(), "sequence_binding_invalid");
}

#[tokio::test]
async fn rejects_wrong_package_against_trusted_config() {
    let dir = temp_state_dir("wrongpkg");
    write_state(&dir, 1, None);
    let mut r = req(1);
    r.bridge_package = "0xdeadbeef".to_string(); // != trusted PKG
    let err = call(&dir, &r, Some(Ok(ok_event(1))))
        .await
        .expect_err("wrong package");
    assert_eq!(err.code(), "wrong_package");
}

#[tokio::test]
async fn rejects_wrong_vault_against_trusted_config() {
    let dir = temp_state_dir("wrongvault");
    write_state(&dir, 1, None);
    let mut r = req(1);
    r.vault = "0xc0ffee".to_string(); // != trusted VAULT
    let err = call(&dir, &r, Some(Ok(ok_event(1))))
        .await
        .expect_err("wrong vault");
    assert_eq!(err.code(), "wrong_vault");
}

#[tokio::test]
async fn rejects_wrong_asset_against_trusted_config() {
    let dir = temp_state_dir("wrongasset");
    write_state(&dir, 1, None);
    let mut r = req(1);
    r.asset_type = "0xb".to_string(); // != trusted ASSET (0xa)
    let err = call(&dir, &r, Some(Ok(ok_event(1))))
        .await
        .expect_err("wrong asset");
    assert_eq!(err.code(), "wrong_asset");
}

#[tokio::test]
async fn fails_closed_worker_missing_bridge_config_when_env_empty() {
    let dir = temp_state_dir("nocfg");
    write_state(&dir, 1, None);
    // Empty trusted package → 503 fail-closed BEFORE any chain work.
    let err = run_vault_resync_v2(&dir, NODE, "", VAULT, ASSET, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect_err("missing config");
    assert_eq!(err.code(), "worker_missing_bridge_config");
    assert_eq!(err.status_u16(), 503);
}

#[tokio::test]
async fn vault_state_not_found_when_slot_uninitialized() {
    let dir = temp_state_dir("noinit"); // no vault_state_v2.json written
    let err = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect_err("not found");
    assert_eq!(err.code(), "vault_state_not_found");
    assert_eq!(err.status_u16(), 404);
}

#[tokio::test]
async fn rejects_binding_mismatch_per_field() {
    let cases: [(&str, fn(&mut TxWithdrawEventV2)); 4] = [
        ("root", |e| e.root = "0x99".into()),
        ("nullifier_hash", |e| e.nullifier_hash = "0x99".into()),
        ("recipient_hash", |e| e.recipient_hash = "0x99".into()),
        ("request_hash", |e| e.request_hash = "0x99".into()),
    ];
    for (field, mutate) in cases {
        let dir = temp_state_dir(&format!("mismatch-{field}"));
        write_state(&dir, 1, None);
        let mut ev = ok_event(1);
        mutate(&mut ev);
        let err = call(&dir, &req(1), Some(Ok(ev)))
            .await
            .expect_err("binding mismatch");
        assert_eq!(err.code(), format!("binding_mismatch:{field}"));
    }
}

#[tokio::test]
async fn rejects_event_sequence_mismatch() {
    let dir = temp_state_dir("evseq");
    write_state(&dir, 1, None);
    // Request claims event_seq=1, but the fetched event carries vault_sequence=7.
    let mut ev = ok_event(1);
    ev.vault_sequence = 7;
    let err = call(&dir, &req(1), Some(Ok(ev)))
        .await
        .expect_err("event seq mismatch");
    assert_eq!(err.code(), "event_sequence_mismatch");
}

#[tokio::test]
async fn rejects_tx_not_successful() {
    let dir = temp_state_dir("txfail");
    write_state(&dir, 1, None);
    let mut ev = ok_event(1);
    ev.success = false;
    let err = call(&dir, &req(1), Some(Ok(ev)))
        .await
        .expect_err("tx failed");
    assert_eq!(err.code(), "tx_not_successful");
}

#[tokio::test]
async fn rejects_tx_not_found_with_chain_fetch_failed() {
    let dir = temp_state_dir("nofetch");
    write_state(&dir, 1, None);
    // Inject a fetch error → 502 chain_fetch_failed.
    let err = call(&dir, &req(1), Some(Err("bad_status:404".to_string())))
        .await
        .expect_err("chain fetch failed");
    assert!(err.code().starts_with("chain_fetch_failed:"));
    assert_eq!(err.status_u16(), 502);
}

#[tokio::test]
async fn preserves_mode_0o600_after_update() {
    let dir = temp_state_dir("mode");
    write_state(&dir, 1, None); // written at 0o644
    call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect("resync ok");
    let mode = fs::metadata(state_path(&dir)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "resync write must enforce 0o600");
}

#[tokio::test]
async fn no_forbidden_plaintext_in_response_or_state_after_resync() {
    let dir = temp_state_dir("nopt");
    write_state(&dir, 1, None);
    let resp = call(&dir, &req(1), Some(Ok(ok_event(1))))
        .await
        .expect("resync ok");
    let resp_json = serde_json::to_string(&resp).unwrap();
    let state_json = String::from_utf8(fs::read(state_path(&dir)).unwrap()).unwrap();
    for forbidden in [
        "amount",
        "amountchunks",
        "balancechunks",
        "secret",
        "nullifierseed",
        "\"dk\"",
        "dk_share",
        "inverse",
        "blind",
        "commitmenthex",
        "leafindex",
        "vaultdk",
    ] {
        assert!(
            !resp_json.to_lowercase().contains(forbidden),
            "response leaked forbidden token {forbidden}"
        );
        assert!(
            !state_json.to_lowercase().contains(forbidden),
            "state leaked forbidden token {forbidden}"
        );
    }
}
