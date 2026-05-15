use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::{
    mpc_inverse_adapter::{
        AdapterError, InversionContext, MpcInverseAdapter, UnavailableMpcInverseAdapter,
    },
    vault_ek_derivation_v2::{
        final_transcript_hash, run_round1, run_verify, schnorr_pok, verify_schnorr_pok,
        worker_transcript_hash, ContributionInput, Round1Request, SchnorrProof, VerifyRequest,
    },
    WorkerError,
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DKG_EPOCH: &str = "3";

fn roster_hash_hex() -> String {
    "11".repeat(32)
}
fn ca_dkg_transcript_hex() -> String {
    "22".repeat(32)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareFileLayout {
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

fn slot_scalar(slot: usize) -> Scalar {
    Scalar::from((slot as u64) + 1)
}

// Build a synthetic ca_dkg_share_v2.json on disk that passes load_ca_dkg_v2_share's
// internal Pedersen-share verification. Uses the SAME H_RISTRETTO_HEX as ca_dkg_v2.
fn write_synthetic_share(state_dir: &Path, slot: usize) {
    fs::create_dir_all(state_dir).expect("create state_dir");
    let dk_share = det_scalar(0xD0D0_0000 + slot as u64);
    let blind_share = det_scalar(0xB1B1_0000 + slot as u64);

    let h_hex = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";
    let h_bytes = (0..h_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h_hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    let mut h_arr = [0u8; 32];
    h_arr.copy_from_slice(&h_bytes);
    let h = curve25519_dalek::ristretto::CompressedRistretto(h_arr)
        .decompress()
        .expect("valid H");

    let lhs = RISTRETTO_BASEPOINT_POINT * dk_share + h * blind_share;
    let x = slot_scalar(slot);

    let zero_commits = vec![RistrettoPoint::default(); 5];
    let mut commits = zero_commits;
    let mut power = Scalar::ONE;
    let mut accum = RistrettoPoint::default();
    for idx in 0..5 {
        if idx == 4 {
            let needed = lhs - accum;
            let x_pow_4 = x * x * x * x;
            let inv = x_pow_4.invert();
            commits[4] = needed * inv;
        } else {
            let coeff_scalar = det_scalar(0xCCCC_0000 + idx as u64);
            commits[idx] = RISTRETTO_BASEPOINT_POINT * coeff_scalar;
            accum += commits[idx] * power;
        }
        power *= x;
    }

    let aggregate_commitments: Vec<String> = commits
        .iter()
        .map(|p| compressed_hex(p))
        .collect();

    let layout = ShareFileLayout {
        scheme: "ca_dkg_v2".to_string(),
        slot,
        threshold: 5,
        count: 7,
        dkg_epoch: DKG_EPOCH.to_string(),
        dk_share: scalar_hex(&dk_share),
        blind_share: scalar_hex(&blind_share),
        valid_dealers: vec![0, 1, 2, 3, 4, 5, 6],
        aggregate_commitments,
        transcript_hash: ca_dkg_transcript_hex(),
        created_at_unix_ms: 1_700_000_000_000,
    };

    let path = state_dir.join("ca_dkg_share_v2.json");
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap()).expect("write share file");
}

// MockFixedScalarAdapter // NOT a real inverter; tests aggregation flow only
struct MockFixedScalarAdapter {
    scalar: Scalar,
}
impl MpcInverseAdapter for MockFixedScalarAdapter {
    fn compute_inverse_share(
        &self,
        _dk_share: &Scalar,
        _ctx: &InversionContext,
    ) -> Result<Scalar, AdapterError> {
        Ok(self.scalar)
    }
}

fn temp_state_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("eunoma-vault-ek-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn schnorr_pok_roundtrip_with_arbitrary_scalar() {
    let secret = det_scalar(42);
    let h_contribution = RISTRETTO_BASEPOINT_POINT * secret;
    let worker_hash = "ff".repeat(32);
    let proof = schnorr_pok(&secret, &h_contribution, &worker_hash);
    assert!(verify_schnorr_pok(&h_contribution, &proof, &worker_hash).expect("verify"));
}

#[test]
fn schnorr_pok_rejects_tampered_s() {
    let secret = det_scalar(7);
    let h_contribution = RISTRETTO_BASEPOINT_POINT * secret;
    let worker_hash = "ee".repeat(32);
    let mut proof = schnorr_pok(&secret, &h_contribution, &worker_hash);
    let mut bytes = (0..proof.s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&proof.s[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    bytes[0] ^= 0x01;
    proof.s = hex_encode(&bytes);
    assert!(!verify_schnorr_pok(&h_contribution, &proof, &worker_hash).expect("verify"));
}

#[test]
fn schnorr_pok_rejects_tampered_worker_hash() {
    let secret = det_scalar(13);
    let h_contribution = RISTRETTO_BASEPOINT_POINT * secret;
    let worker_hash = "dd".repeat(32);
    let proof = schnorr_pok(&secret, &h_contribution, &worker_hash);
    let other_hash = "cc".repeat(32);
    assert!(!verify_schnorr_pok(&h_contribution, &proof, &other_hash).expect("verify"));
}

#[test]
fn unavailable_adapter_returns_mp_spdz_unavailable() {
    let adapter = UnavailableMpcInverseAdapter;
    let ctx = InversionContext {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        roster_hash: roster_hash_hex(),
    };
    let result = adapter.compute_inverse_share(&Scalar::ONE, &ctx);
    assert_eq!(result, Err(AdapterError::McpSpdzNotAvailable));
}

#[test]
fn round1_with_unavailable_adapter_returns_not_implemented() {
    let state_dir = temp_state_dir("unavailable");
    write_synthetic_share(&state_dir, 0);
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
    };
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(matches!(&err, WorkerError::NotImplemented(msg) if *msg == "mpc_inverse_unavailable"));
}

/// Subprocess-level integration test: builds the binary, launches it on a free port with
/// CRYPTO_WORKER_STATE_DIR pointing at a synthetic share, POSTs /worker/v2/derive/vault_ek/round1,
/// asserts HTTP 503 + body { "error": "mpc_inverse_unavailable" }.
#[test]
fn http_round1_returns_503_with_default_adapter() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_status = std::process::Command::new(&cargo)
        .current_dir(manifest)
        .args(["build", "--bin", "eunoma-crypto-worker"])
        .status()
        .expect("cargo build");
    assert!(bin_status.success(), "cargo build failed");

    let exe = manifest
        .join("target")
        .join("debug")
        .join("eunoma-crypto-worker");
    assert!(exe.exists(), "binary not found at {}", exe.display());

    let state_dir = temp_state_dir("http-round1");
    write_synthetic_share(&state_dir, 0);

    // pick an ephemeral port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut child = std::process::Command::new(&exe)
        .env("CRYPTO_WORKER_HOST", "127.0.0.1")
        .env("CRYPTO_WORKER_PORT", port.to_string())
        .env("CRYPTO_WORKER_SLOT", "0")
        .env("CRYPTO_WORKER_STATE_DIR", state_dir.to_string_lossy().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn worker");

    // Wait up to 5 s for the listener to come up.
    let mut ready = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !ready {
        let _ = child.kill();
        panic!("worker did not bind on port {port}");
    }

    let body = serde_json::json!({
        "dkgEpoch": DKG_EPOCH,
        "caDkgTranscriptHash": ca_dkg_transcript_hex(),
        "rosterHash": roster_hash_hex(),
        "selectedSlots": [0, 1, 2, 3, 4],
        "selfSlot": 0,
    });
    let result = std::process::Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "-w",
            "\nHTTPSTATUS:%{http_code}",
            "-d",
            &serde_json::to_string(&body).unwrap(),
            &format!("http://127.0.0.1:{port}/worker/v2/derive/vault_ek/round1"),
        ])
        .output()
        .expect("curl");
    let _ = child.kill();
    let _ = child.wait();

    let stdout = String::from_utf8_lossy(&result.stdout).to_string();
    let (body_str, status_line) = stdout
        .rsplit_once("HTTPSTATUS:")
        .unwrap_or((stdout.as_str(), ""));
    let status: u16 = status_line.trim().parse().unwrap_or(0);
    assert_eq!(status, 503, "expected 503, got {status}; body={body_str}");
    let parsed: serde_json::Value = serde_json::from_str(body_str.trim()).expect("json body");
    assert_eq!(parsed["error"], "mpc_inverse_unavailable");
}

#[test]
fn round1_with_mock_adapter_succeeds_and_contribution_matches_basepoint_mul() {
    // MockFixedScalarAdapter // NOT a real inverter; tests aggregation flow only
    let state_dir = temp_state_dir("mock-round1");
    write_synthetic_share(&state_dir, 2);
    let inv_share = det_scalar(0xABCD);
    let adapter = MockFixedScalarAdapter { scalar: inv_share };
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 2,
    };
    let result = run_round1(&state_dir, &req, &adapter).expect("round1 succeeds");
    assert_eq!(result.slot, 2);
    let expected_point = RISTRETTO_BASEPOINT_POINT * inv_share;
    assert_eq!(result.h_contribution, compressed_hex(&expected_point));
    let expected_hash = worker_transcript_hash(
        DKG_EPOCH,
        &ca_dkg_transcript_hex(),
        &roster_hash_hex(),
        &[0, 1, 2, 3, 4],
        2,
        &result.h_contribution,
    );
    assert_eq!(result.worker_transcript_hash, expected_hash);
}

#[test]
fn verify_aggregates_five_contributions() {
    // MockFixedScalarAdapter // NOT a real inverter; tests aggregation flow only
    let fixed = det_scalar(0xFEED);
    let mut contributions = Vec::new();
    let mut expected_sum = RistrettoPoint::default();
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    for slot in &sorted_slots {
        let point = RISTRETTO_BASEPOINT_POINT * fixed;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash);
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
        });
        expected_sum += point;
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
    };
    let result = run_verify(&request).expect("verify succeeds");
    assert_eq!(result.vault_ek, compressed_hex(&expected_sum));
    // sanity: re-verify final hash matches recomputation
    let ordered: Vec<(usize, String, SchnorrProof)> = request
        .contributions
        .iter()
        .map(|c| (c.slot, c.h_contribution.clone(), c.schnorr_proof.clone()))
        .collect();
    let recomputed = final_transcript_hash(
        &request.dkg_epoch,
        &request.ca_dkg_transcript_hash,
        &request.roster_hash,
        &request.selected_slots,
        &result.vault_ek,
        &ordered,
    );
    assert_eq!(result.final_transcript_hash, recomputed);
}

#[test]
fn verify_rejects_under_quorum() {
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        contributions: (0..4)
            .map(|slot| ContributionInput {
                slot,
                h_contribution: "00".repeat(32),
                schnorr_proof: SchnorrProof {
                    r: "00".repeat(32),
                    s: "00".repeat(32),
                },
                worker_transcript_hash: "00".repeat(32),
            })
            .collect(),
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(err, WorkerError::InvalidRequest(msg) if msg.contains("contributions")));
}

#[test]
fn verify_rejects_duplicate_slot() {
    let fixed = det_scalar(0xBEEF);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    for _ in 0..5 {
        let point = RISTRETTO_BASEPOINT_POINT * fixed;
        let h_contribution_hex = compressed_hex(&point);
        // Force every contribution to claim slot 0
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            0,
            &h_contribution_hex,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash);
        contributions.push(ContributionInput {
            slot: 0,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(err, WorkerError::InvalidRequest(msg) if msg.contains("duplicate")));
}

#[test]
fn verify_rejects_worker_transcript_hash_mismatch() {
    let fixed = det_scalar(0xCAFE);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = RISTRETTO_BASEPOINT_POINT * fixed;
        let h_contribution_hex = compressed_hex(&point);
        // For slot index 2, use a different roster hash when generating the worker hash —
        // recompute inside verify will not match.
        let roster_for_hash = if idx == 2 {
            "ff".repeat(32)
        } else {
            roster_hash_hex()
        };
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_for_hash,
            &sorted_slots,
            *slot,
            &h_contribution_hex,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash);
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidRequest(msg) if msg.contains("worker_transcript_hash")),
        "expected worker_transcript_hash error, got {err:?}"
    );
}

#[test]
fn verify_rejects_invalid_schnorr_proof() {
    let fixed = det_scalar(0xDEAD);
    let bogus = det_scalar(0xBAAD);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = RISTRETTO_BASEPOINT_POINT * fixed;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
        );
        // For the third entry, prove knowledge of the WRONG secret (bogus): the schnorr will
        // fail verification.
        let secret = if idx == 2 { bogus } else { fixed };
        let proof = schnorr_pok(&secret, &point, &worker_hash);
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(&err, WorkerError::Crypto(msg) if msg.contains("schnorr")), "got {err:?}");
}

#[test]
fn round1_rejects_missing_share() {
    let state_dir = temp_state_dir("missing-share");
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
    };
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(matches!(err, WorkerError::MissingLocalState(_)));
}

#[test]
fn round1_rejects_bad_quorum() {
    let state_dir = temp_state_dir("bad-quorum");
    write_synthetic_share(&state_dir, 0);
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3],
        self_slot: 0,
    };
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(matches!(err, WorkerError::InvalidRequest(_)));
}

#[test]
fn worker_transcript_hash_is_deterministic_and_layout_documented() {
    // Locks down the canonical byte layout — keep in sync with the TS implementation.
    let dkg_epoch = "5";
    let ca = "aa".repeat(32);
    let roster = "bb".repeat(32);
    let slots = [0_usize, 2, 3, 4, 6];
    let slot = 3_usize;
    let h_hex = "cc".repeat(32);
    let observed = worker_transcript_hash(dkg_epoch, &ca, &roster, &slots, slot, &h_hex);
    let mut expected_input = Vec::new();
    expected_input.extend_from_slice(b"EUNOMA_VAULT_EK_DERIVATION_V1");
    expected_input.extend_from_slice(b"5");
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(ca.as_bytes());
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(roster.as_bytes());
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(b"0,2,3,4,6");
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(b"3");
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(h_hex.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&expected_input);
    let manual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(observed, manual);
}

#[test]
fn emit_worker_transcript_hash_parity_fixture() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    fs::create_dir_all(&fixture_dir).expect("fixture dir");
    let dkg_epoch = "7";
    let ca = "0a".repeat(32);
    let roster = "0b".repeat(32);
    let slots = [0_usize, 1, 2, 4, 5];
    let slot = 4_usize;
    let h_hex = "0c".repeat(32);
    let hash = worker_transcript_hash(dkg_epoch, &ca, &roster, &slots, slot, &h_hex);
    let value = serde_json::json!({
        "dkgEpoch": dkg_epoch,
        "caDkgTranscriptHash": ca,
        "rosterHash": roster,
        "sortedSelectedSlots": slots,
        "slot": slot,
        "hContribution": h_hex,
        "workerTranscriptHash": hash,
        "schnorrChallengeDomain": "EUNOMA_VAULT_EK_DERIVATION_SCHNORR_V1",
        "workerTranscriptDomain": "EUNOMA_VAULT_EK_DERIVATION_V1",
        "finalTranscriptDomain": "EUNOMA_VAULT_EK_DERIVATION_FINAL_V1",
    });
    fs::write(
        fixture_dir.join("vault_ek_derivation_parity.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .expect("write parity fixture");
}
