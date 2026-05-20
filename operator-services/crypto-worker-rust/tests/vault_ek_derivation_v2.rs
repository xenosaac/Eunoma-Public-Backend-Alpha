use std::{
    fs,
    path::{Path, PathBuf},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use eunoma_crypto_worker::{
    mpc_inverse_adapter::{
        mock_inversion_share_from_q, AdapterError, InversionContext, InversionShare,
        MpcInverseAdapter, UnavailableMpcInverseAdapter,
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

/// Twisted-ElGamal non-basepoint generator. Byte-identical to the crate-level
/// `pub(crate) const H_RISTRETTO_HEX` in lib.rs.
const H_RISTRETTO_HEX: &str =
    "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

fn h_point() -> RistrettoPoint {
    let bytes: Vec<u8> = (0..H_RISTRETTO_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&H_RISTRETTO_HEX[i..i + 2], 16).unwrap())
        .collect();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    curve25519_dalek::ristretto::CompressedRistretto(arr)
        .decompress()
        .expect("valid H")
}

/// Codex P1 #4: mock contributions use `mpc_open_m = 1` so that h_r_i = h * q_i trivially
/// passes the per-party check `h_q_i * m == h_r_i`. The hex bytes of Scalar::ONE in little-
/// endian = "0100...00".
fn mock_mpc_open_m_hex() -> String {
    scalar_hex(&Scalar::ONE)
}

/// Helper for tests that build ContributionInput manually with `h_contribution = h * q_i`
/// and `m = 1`. The h_r is identical to h_contribution under these mock semantics.
fn mock_h_r_for_q(q: &Scalar) -> String {
    compressed_hex(&(h_point() * q))
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
        _r_i: &Scalar,
        _ctx: &InversionContext,
    ) -> Result<InversionShare, AdapterError> {
        mock_inversion_share_from_q(self.scalar)
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

/// Phase 2 extension fields for `Round1Request`. The Mock adapters in this test file do not
/// consume them, but the new struct shape requires non-defaulted values, so tests use this
/// helper to keep the round1 construction concise. Real production callers always supply
/// fully-populated values via the coordinator's TS encoder.
fn phase2_round1_extras(
    selected_slots: &[usize],
    self_slot: usize,
) -> (usize, Vec<String>, Vec<String>) {
    let mut sorted = selected_slots.to_vec();
    sorted.sort_unstable();
    let player_id = sorted.iter().position(|s| *s == self_slot).unwrap_or(0);
    // Dummy peers + lagrange coefs — adapters in this file do not consume them.
    let peers: Vec<String> = sorted
        .iter()
        .map(|s| format!("127.0.0.1:{}", 14000 + s))
        .collect();
    let lagrange: Vec<String> = sorted.iter().map(|_| "00".repeat(32)).collect();
    (player_id, peers, lagrange)
}

/// Codex P1 #4 round0: write a fake round0.json under `state_dir/mpc-sessions/...` for
/// tests that need to drive `run_round1` directly without going through `run_round0`. The
/// (r_i, h_r_i) pair must be self-consistent (h_r_i = h * r_i). Returns h_r_i_hex for
/// later use in the test's allHRoundZero vector.
fn write_round0_file(
    state_dir: &Path,
    request_id: &str,
    session_id: &str,
    self_slot: usize,
    player_id: usize,
    selected_slots: &[usize],
    r_i: &Scalar,
) -> String {
    write_round0_file_with_roster(
        state_dir,
        request_id,
        session_id,
        self_slot,
        player_id,
        selected_slots,
        r_i,
        &roster_hash_hex(),
    )
}

/// Like `write_round0_file` but lets the caller specify the rosterHash recorded in the
/// file (so the killer test, which uses a non-default roster_hash, can write a file the
/// real `run_round1` won't reject).
fn write_round0_file_with_roster(
    state_dir: &Path,
    request_id: &str,
    session_id: &str,
    self_slot: usize,
    player_id: usize,
    selected_slots: &[usize],
    r_i: &Scalar,
    roster_hash: &str,
) -> String {
    let h_r_point = h_point() * r_i;
    let h_r_hex = compressed_hex(&h_r_point);
    let r_i_hex = scalar_hex(r_i);
    let mut sorted = selected_slots.to_vec();
    sorted.sort_unstable();
    let layout = serde_json::json!({
        "session_id": session_id,
        "request_id": request_id,
        "self_slot": self_slot,
        "player_id": player_id,
        "roster_hash": roster_hash,
        "selected_slots": sorted,
        "r_i_hex": r_i_hex,
        "h_r_i_hex": h_r_hex,
        "created_at_unix_ms": 1u128,
    });
    let dir = state_dir
        .join("mpc-sessions")
        .join(format!("{request_id}__{session_id}"));
    fs::create_dir_all(&dir).expect("create round0 dir");
    let path = dir.join("round0.json");
    fs::write(&path, serde_json::to_vec(&layout).unwrap()).expect("write round0 file");
    h_r_hex
}

#[test]
fn schnorr_pok_roundtrip_with_arbitrary_scalar() {
    let secret = det_scalar(42);
    let h_contribution = h_point() * secret;
    let worker_hash = "ff".repeat(32);
    let proof = schnorr_pok(&secret, &h_contribution, &worker_hash).expect("schnorr_pok");
    assert!(verify_schnorr_pok(&h_contribution, &proof, &worker_hash).expect("verify"));
}

#[test]
fn schnorr_pok_rejects_tampered_s() {
    let secret = det_scalar(7);
    let h_contribution = h_point() * secret;
    let worker_hash = "ee".repeat(32);
    let mut proof = schnorr_pok(&secret, &h_contribution, &worker_hash).expect("schnorr_pok");
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
    let h_contribution = h_point() * secret;
    let worker_hash = "dd".repeat(32);
    let proof = schnorr_pok(&secret, &h_contribution, &worker_hash).expect("schnorr_pok");
    let other_hash = "cc".repeat(32);
    assert!(!verify_schnorr_pok(&h_contribution, &proof, &other_hash).expect("verify"));
}

#[test]
fn unavailable_adapter_returns_mp_spdz_unavailable() {
    let adapter = UnavailableMpcInverseAdapter;
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 0);
    let ctx = InversionContext {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        roster_hash: roster_hash_hex(),
        request_id: "req".to_string(),
        session_id: "sess".to_string(),
        work_dir: PathBuf::from("/tmp"),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients_hex: lagrange,
    };
    let result = adapter.compute_inverse_share(&Scalar::ONE, &Scalar::ONE, &ctx);
    assert!(matches!(result, Err(AdapterError::McpSpdzNotAvailable)));
}

#[test]
fn round1_with_unavailable_adapter_returns_not_implemented() {
    let state_dir = temp_state_dir("unavailable");
    write_synthetic_share(&state_dir, 0);
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 0);
    // Codex P1 #4 round0: round1 now requires a persisted round0 file. Write one so the
    // adapter call is reached (the unavailable adapter still returns 503 — that's what
    // this test asserts).
    let r_i = det_scalar(0x6e1);
    let h_r = write_round0_file(
        &state_dir,
        "req-unavail",
        "sess-unavail",
        0,
        player_id,
        &[0, 1, 2, 3, 4],
        &r_i,
    );
    let mut all_h = vec![h_r.clone(); 5];
    all_h[player_id] = h_r;
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-unavail".to_string(),
        session_id: "sess-unavail".to_string(),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients: lagrange,
        all_h_round_zero: all_h,
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
    // Codex P1 #4 round0: write a valid round0 file so round1 reaches the adapter (which
    // is UnavailableMpcInverseAdapter for this test) and returns 503.
    let r_i = det_scalar(0x4747);
    let h_r_hex = write_round0_file(
        &state_dir,
        "http-test-req",
        "http-test-sess",
        0,
        0,
        &[0, 1, 2, 3, 4],
        &r_i,
    );

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

    // Codex P1 #4 round0: build allHRoundZero with the locally-persisted h_r_i at this
    // party's ordinal (player_id == self_slot == 0 for the lowest5 selection). Other
    // entries can be any 32-byte hex; round1's adapter-call gate fires before any per-
    // party check against other ordinals.
    let mut all_h: Vec<String> = vec![h_r_hex.clone(); 5];
    all_h[0] = h_r_hex;
    let body = serde_json::json!({
        "dkgEpoch": DKG_EPOCH,
        "caDkgTranscriptHash": ca_dkg_transcript_hex(),
        "rosterHash": roster_hash_hex(),
        "selectedSlots": [0, 1, 2, 3, 4],
        "selfSlot": 0,
        "requestId": "http-test-req",
        "sessionId": "http-test-sess",
        "playerId": 0,
        "peerAddresses": vec![
            "127.0.0.1:14000".to_string(),
            "127.0.0.1:14001".to_string(),
            "127.0.0.1:14002".to_string(),
            "127.0.0.1:14003".to_string(),
            "127.0.0.1:14004".to_string(),
        ],
        "lagrangeCoefficients": vec!["00".repeat(32); 5],
        "allHRoundZero": all_h,
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
fn round1_with_mock_adapter_succeeds_and_contribution_matches_h_mul() {
    // MockFixedScalarAdapter // NOT a real inverter; tests aggregation flow only
    let state_dir = temp_state_dir("mock-round1");
    write_synthetic_share(&state_dir, 2);
    let inv_share = det_scalar(0xABCD);
    let adapter = MockFixedScalarAdapter { scalar: inv_share };
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 2);
    // Codex P1 #4 round0: mock adapter returns h_r_i = h * q_i (with m=1). For run_round1
    // to pass the "adapter h_r matches persisted h_r" check, the persisted r_i in the
    // round0 file must satisfy h * r_i == h * q_i, i.e. r_i = q_i. Persist r_i = q_i.
    let r_i = inv_share;
    let h_r = write_round0_file(
        &state_dir,
        "req-mock",
        "sess-mock",
        2,
        player_id,
        &[0, 1, 2, 3, 4],
        &r_i,
    );
    // All 5 entries in allHRoundZero must be h * q_i for this mock — same value at each
    // ordinal because the mock returns the same fixed q.
    let all_h = vec![h_r.clone(); 5];
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 2,
        request_id: "req-mock".to_string(),
        session_id: "sess-mock".to_string(),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients: lagrange,
        all_h_round_zero: all_h.clone(),
    };
    let result = run_round1(&state_dir, &req, &adapter).expect("round1 succeeds");
    assert_eq!(result.slot, 2);
    let expected_point = h_point() * inv_share;
    assert_eq!(result.h_contribution, compressed_hex(&expected_point));
    // Codex P1 #4: mock adapter uses m=1; result must echo that.
    assert_eq!(result.mpc_open_m, mock_mpc_open_m_hex());
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    let expected_hash = worker_transcript_hash(
        DKG_EPOCH,
        &ca_dkg_transcript_hex(),
        &roster_hash_hex(),
        &[0, 1, 2, 3, 4],
        2,
        &result.h_contribution,
        &h_r,
        &result.mpc_open_m,
        &r0_hash,
    );
    assert_eq!(result.worker_transcript_hash, expected_hash);
}

#[test]
fn verify_aggregates_five_contributions() {
    // MockFixedScalarAdapter // NOT a real inverter; tests aggregation flow only.
    // After the H-generator fix: each contribution = h * fixed, sum = h * (5 * fixed).
    let fixed = det_scalar(0xFEED);
    let mut contributions = Vec::new();
    let mut expected_sum = RistrettoPoint::default();
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let h_r_hex = mock_h_r_for_q(&fixed);
    // Codex P1 #4 round0: allHRoundZero is supplied at verify time. With m=1 and q=fixed,
    // each party's h_r_i = h * fixed.
    let all_h: Vec<String> = vec![h_r_hex.clone(); 5];
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for slot in &sorted_slots {
        let point = h * fixed;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
        expected_sum += point;
    }
    // Independent reference: H * (5 * fixed) — catches a regression where the sum is
    // computed via G instead of H.
    let five = Scalar::from(5_u64);
    let independent_expected = h * (five * fixed);
    assert_eq!(expected_sum, independent_expected);
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h.clone(),
    };
    let result = run_verify(&request).expect("verify succeeds");
    assert_eq!(result.vault_ek, compressed_hex(&expected_sum));
    // sanity: re-verify final hash matches recomputation
    let ordered: Vec<(usize, String, SchnorrProof, String)> = request
        .contributions
        .iter()
        .map(|c| (
            c.slot,
            c.h_contribution.clone(),
            c.schnorr_proof.clone(),
            c.mpc_open_m.clone(),
        ))
        .collect();
    let recomputed = final_transcript_hash(
        &request.dkg_epoch,
        &request.ca_dkg_transcript_hash,
        &request.roster_hash,
        &request.selected_slots,
        &result.vault_ek,
        &ordered,
        &all_h,
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
                mpc_open_m: "00".repeat(32),
            })
            .collect(),
        all_h_round_zero: vec!["00".repeat(32); 5],
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(err, WorkerError::InvalidRequest(msg) if msg.contains("contributions")));
}

#[test]
fn verify_rejects_duplicate_slot() {
    let fixed = det_scalar(0xBEEF);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let h_r_hex = mock_h_r_for_q(&fixed);
    let all_h = vec![h_r_hex.clone(); 5];
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for _ in 0..5 {
        let point = h * fixed;
        let h_contribution_hex = compressed_hex(&point);
        // Force every contribution to claim slot 0
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            0,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: 0,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(err, WorkerError::InvalidRequest(msg) if msg.contains("duplicate")));
}

#[test]
fn verify_rejects_worker_transcript_hash_mismatch() {
    let fixed = det_scalar(0xCAFE);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let h_r_hex = mock_h_r_for_q(&fixed);
    let all_h = vec![h_r_hex.clone(); 5];
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = h * fixed;
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
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&fixed, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
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
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let h_r_hex = mock_h_r_for_q(&fixed);
    let all_h = vec![h_r_hex.clone(); 5];
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = h * fixed;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        // For the third entry, prove knowledge of the WRONG secret (bogus): the schnorr will
        // fail verification.
        let secret = if idx == 2 { bogus } else { fixed };
        let proof = schnorr_pok(&secret, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(matches!(&err, WorkerError::Crypto(msg) if msg.contains("schnorr")), "got {err:?}");
}

#[test]
fn round1_rejects_missing_share() {
    let state_dir = temp_state_dir("missing-share");
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 0);
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-missing-share".to_string(),
        session_id: "sess-missing-share".to_string(),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients: lagrange,
        all_h_round_zero: vec!["00".repeat(32); 5],
    };
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(matches!(err, WorkerError::MissingLocalState(_)));
}

#[test]
fn round1_rejects_bad_quorum() {
    let state_dir = temp_state_dir("bad-quorum");
    write_synthetic_share(&state_dir, 0);
    // For an under-quorum selected_slots, the helper would return mismatching shape — call
    // through with a 4-entry placeholder anyway since validate_selected_slots fires first.
    let peers: Vec<String> = (0..4).map(|i| format!("127.0.0.1:{}", 14000 + i)).collect();
    let lagrange: Vec<String> = (0..4).map(|_| "00".repeat(32)).collect();
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3],
        self_slot: 0,
        request_id: "req-bad-quorum".to_string(),
        session_id: "sess-bad-quorum".to_string(),
        peer_addresses: peers,
        player_id: 0,
        lagrange_coefficients: lagrange,
        all_h_round_zero: vec!["00".repeat(32); 4],
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
    let h_r_hex = "dd".repeat(32);
    let m_hex = "ee".repeat(32);
    let r0_commit = "ff".repeat(32);
    let observed = worker_transcript_hash(
        dkg_epoch, &ca, &roster, &slots, slot, &h_hex, &h_r_hex, &m_hex, &r0_commit,
    );
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
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(h_r_hex.as_bytes());
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(m_hex.as_bytes());
    expected_input.extend_from_slice(b":");
    expected_input.extend_from_slice(r0_commit.as_bytes());
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
    let h_r_hex = "0d".repeat(32);
    let m_hex = "0e".repeat(32);
    // Codex P1 #4 round0: parity fixture includes round0_commit_hash so the TS
    // implementation can mirror the same 9-arg layout.
    let all_h_round_zero = vec![
        "1a".repeat(32),
        "1b".repeat(32),
        "1c".repeat(32),
        "1d".repeat(32),
        "1e".repeat(32),
    ];
    let r0_commit_hash =
        eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h_round_zero);
    let hash = worker_transcript_hash(
        dkg_epoch, &ca, &roster, &slots, slot, &h_hex, &h_r_hex, &m_hex, &r0_commit_hash,
    );
    let value = serde_json::json!({
        "dkgEpoch": dkg_epoch,
        "caDkgTranscriptHash": ca,
        "rosterHash": roster,
        "sortedSelectedSlots": slots,
        "slot": slot,
        "hContribution": h_hex,
        "hR": h_r_hex,
        "mpcOpenM": m_hex,
        "allHRoundZero": all_h_round_zero,
        "round0CommitHash": r0_commit_hash,
        "workerTranscriptHash": hash,
        "schnorrChallengeDomain": "EUNOMA_VAULT_EK_DERIVATION_SCHNORR_V1",
        "workerTranscriptDomain": "EUNOMA_VAULT_EK_DERIVATION_V1",
        "finalTranscriptDomain": "EUNOMA_VAULT_EK_DERIVATION_FINAL_V1",
        "round0HashDomain": "EUNOMA_VAULT_EK_DERIVATION_ROUND0_V1",
    });
    fs::write(
        fixture_dir.join("vault_ek_derivation_parity.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .expect("write parity fixture");
}

/// Emits a JSON fixture with Lagrange coefficients at x=0 for several Shamir sets. The TS
/// helper `lagrangeCoefficientsAtZero` must produce byte-identical hex outputs for the same
/// inputs (validated by `deop-protocol/tests/vault_ek_derivation.test.ts`).
#[test]
fn emit_lagrange_parity_fixture() {
    use curve25519_dalek::scalar::Scalar;
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    fs::create_dir_all(&fixture_dir).expect("fixture dir");

    fn lagrange(slots: &[usize]) -> Vec<String> {
        // Same algorithm as MpcSpdzInverseAdapter::compute_lagrange_coefficient_at_zero,
        // expressed in Scalar arithmetic.
        let mut out = Vec::with_capacity(slots.len());
        for i in 0..slots.len() {
            let x_i = Scalar::from((slots[i] as u64) + 1);
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for (j, slot) in slots.iter().enumerate() {
                if j == i {
                    continue;
                }
                let x_j = Scalar::from((*slot as u64) + 1);
                num *= -x_j;
                den *= x_i - x_j;
            }
            let lambda = num * den.invert();
            out.push(scalar_hex(&lambda));
        }
        out
    }

    let cases = vec![
        ("lowest5", vec![0usize, 1, 2, 3, 4]),
        ("alt5", vec![0usize, 2, 3, 4, 6]),
        ("hi5", vec![2usize, 3, 4, 5, 6]),
    ];
    let mut payload = serde_json::Map::new();
    for (label, slots) in &cases {
        let coefs = lagrange(slots);
        payload.insert(
            label.to_string(),
            serde_json::json!({
                "sortedSelectedSlots": slots,
                "lagrangeCoefficients": coefs,
            }),
        );
    }
    fs::write(
        fixture_dir.join("vault_ek_lagrange_parity.json"),
        serde_json::to_vec_pretty(&serde_json::Value::Object(payload)).unwrap(),
    )
    .expect("write lagrange fixture");
}

// === Regression tests added for the H-generator correction ===

/// Build a 7-slot Pedersen VSS using coefficients `(coeffs, blind_coeffs)` of degree 4
/// (i.e. threshold 5). For each slot s in 0..7, evaluate the polynomial at x=s+1
/// and write a `ca_dkg_share_v2.json` that `load_ca_dkg_v2_share` will accept.
fn write_vss_share_for_slot(
    state_dir: &Path,
    slot: usize,
    coeffs: &[Scalar; 5],
    blind_coeffs: &[Scalar; 5],
    aggregate_commitments_hex: &[String; 5],
    transcript_hex: &str,
    dkg_epoch: &str,
) {
    fs::create_dir_all(state_dir).expect("create state_dir");
    let x = Scalar::from((slot as u64) + 1);
    // Horner evaluation
    let mut dk_share = coeffs[4];
    let mut blind_share = blind_coeffs[4];
    for i in (0..4).rev() {
        dk_share = dk_share * x + coeffs[i];
        blind_share = blind_share * x + blind_coeffs[i];
    }
    let layout = ShareFileLayout {
        scheme: "ca_dkg_v2".to_string(),
        slot,
        threshold: 5,
        count: 7,
        dkg_epoch: dkg_epoch.to_string(),
        dk_share: scalar_hex(&dk_share),
        blind_share: scalar_hex(&blind_share),
        valid_dealers: vec![0, 1, 2, 3, 4, 5, 6],
        aggregate_commitments: aggregate_commitments_hex.to_vec(),
        transcript_hash: transcript_hex.to_string(),
        created_at_unix_ms: 1_700_000_000_000,
    };
    let path = state_dir.join("ca_dkg_share_v2.json");
    fs::write(&path, serde_json::to_vec_pretty(&layout).unwrap()).expect("write share file");
}

/// MockAdditiveInverseAdapter
/// NOT a real inverter; precomputed additive shares of 1/dk; tests aggregation reaches
/// h*dk^-1, not the inversion math. Phase 2 replaces with MP-SPDZ.
struct MockAdditiveInverseAdapter {
    by_slot: std::collections::BTreeMap<usize, Scalar>,
}
impl MpcInverseAdapter for MockAdditiveInverseAdapter {
    fn compute_inverse_share(
        &self,
        _dk_share: &Scalar,
        _r_i: &Scalar,
        ctx: &InversionContext,
    ) -> Result<InversionShare, AdapterError> {
        let q = self
            .by_slot
            .get(&ctx.self_slot)
            .copied()
            .ok_or_else(|| AdapterError::Internal(format!("no mock share for slot {}", ctx.self_slot)))?;
        mock_inversion_share_from_q(q)
    }
}

/// The killer test: derive vault_ek through the full Phase 1 module with a mock additive
/// inverse adapter that aggregates to `dk^-1`. Then build a real registration sigma proof
/// under `dk` and assert `ca_local::verify_registration_proof(...)` returns Ok(()).
///
/// If the generator inside the module ever drifts from H back to G, this test catches it:
/// step (1) `result.vault_ek == compressed_hex(h * dk.invert())` will fail, and step (2)
/// `verify_registration_proof(...)` will fail with "registration sigma proof verification
/// failed".
#[test]
fn vault_ek_passes_registration_sigma() {
    let dkg_epoch = "11";
    let ca_dkg_transcript = "33".repeat(32);
    let roster_hash = "44".repeat(32);

    // 1. Polynomial coefficients (degree 4 ⇒ threshold 5). dk = coeffs[0].
    let coeffs: [Scalar; 5] = [
        det_scalar(0xC0_0000),
        det_scalar(0xC0_0001),
        det_scalar(0xC0_0002),
        det_scalar(0xC0_0003),
        det_scalar(0xC0_0004),
    ];
    let blind_coeffs: [Scalar; 5] = [
        det_scalar(0xB0_0000),
        det_scalar(0xB0_0001),
        det_scalar(0xB0_0002),
        det_scalar(0xB0_0003),
        det_scalar(0xB0_0004),
    ];
    let dk = coeffs[0];

    // 2. Pedersen aggregate commitments: C_i = G*coeffs[i] + H*blind_coeffs[i].
    let h = h_point();
    let aggregate_commitments: [String; 5] = [
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[0] + h * blind_coeffs[0])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[1] + h * blind_coeffs[1])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[2] + h * blind_coeffs[2])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[3] + h * blind_coeffs[3])),
        compressed_hex(&(RISTRETTO_BASEPOINT_POINT * coeffs[4] + h * blind_coeffs[4])),
    ];

    // 3. Write a share file for each of the 7 slots.
    let root = temp_state_dir("vault-ek-reg-sigma");
    let mut slot_dirs = Vec::with_capacity(7);
    for slot in 0..7 {
        let dir = root.join(format!("slot-{slot}"));
        write_vss_share_for_slot(
            &dir,
            slot,
            &coeffs,
            &blind_coeffs,
            &aggregate_commitments,
            &ca_dkg_transcript,
            dkg_epoch,
        );
        slot_dirs.push(dir);
    }

    // 4. Selected subset: lowest 5 slots [0..4].
    let selected = [0_usize, 1, 2, 3, 4];

    // 5. Precompute additive shares summing to dk.invert().
    let target_inv = dk.invert();
    let mut additive_shares = [Scalar::ZERO; 5];
    let mut accum = Scalar::ZERO;
    for i in 0..4 {
        additive_shares[i] = det_scalar(0xADD0_0000 + i as u64);
        accum += additive_shares[i];
    }
    additive_shares[4] = target_inv - accum;
    let sanity: Scalar = additive_shares.iter().copied().sum();
    assert_eq!(sanity, target_inv, "additive shares must sum to 1/dk");

    let mut by_slot = std::collections::BTreeMap::new();
    for (idx, slot) in selected.iter().enumerate() {
        by_slot.insert(*slot, additive_shares[idx]);
    }
    let adapter = MockAdditiveInverseAdapter { by_slot };

    // 6. Codex P1 #4 round0: pre-write round0 files for each slot. The mock adapter
    // returns h_r_i = h * q_i (with m=1), so the persisted r_i in each party's round0
    // file must equal q_i for the post-MPC `adapter h_r matches persisted h_r` check
    // to pass. Build allHRoundZero from the same q values.
    let mut all_h_round_zero: Vec<String> = Vec::with_capacity(5);
    for (ordinal, slot) in selected.iter().enumerate() {
        let q = additive_shares[ordinal];
        let h_r_hex = write_round0_file_with_roster(
            &slot_dirs[*slot],
            &format!("req-reg-sigma-{slot}"),
            &format!("sess-reg-sigma-{slot}"),
            *slot,
            ordinal,
            &selected,
            &q,
            &roster_hash,
        );
        all_h_round_zero.push(h_r_hex);
    }

    // 7. Run round1 for each of the 5 selected slots. The MockAdditiveInverseAdapter ignores
    // the Phase 2 fields; pass placeholder peer/lagrange values so the Round1Request shape is
    // satisfied. Production lagrange-validation lives in MpcSpdzInverseAdapter (not the mock),
    // so the validation logic does not gate this test.
    let mut contributions: Vec<ContributionInput> = Vec::with_capacity(5);
    for (ordinal, slot) in selected.iter().enumerate() {
        let (_player_id, peers, lagrange) = phase2_round1_extras(&selected, *slot);
        let req = Round1Request {
            dkg_epoch: dkg_epoch.to_string(),
            ca_dkg_transcript_hash: ca_dkg_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: selected.to_vec(),
            self_slot: *slot,
            request_id: format!("req-reg-sigma-{slot}"),
            session_id: format!("sess-reg-sigma-{slot}"),
            peer_addresses: peers,
            player_id: ordinal,
            lagrange_coefficients: lagrange,
            all_h_round_zero: all_h_round_zero.clone(),
        };
        let res = run_round1(&slot_dirs[*slot], &req, &adapter).expect("round1 succeeds");
        contributions.push(ContributionInput {
            slot: res.slot,
            h_contribution: res.h_contribution,
            schnorr_proof: res.schnorr_proof,
            worker_transcript_hash: res.worker_transcript_hash,
            mpc_open_m: res.mpc_open_m,
        });
    }

    // 8. Run verify.
    let verify_req = VerifyRequest {
        dkg_epoch: dkg_epoch.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript.clone(),
        roster_hash: roster_hash.clone(),
        selected_slots: selected.to_vec(),
        contributions,
        all_h_round_zero,
    };
    let verify_res = run_verify(&verify_req).expect("verify succeeds");

    // 8. The vault_ek must equal H * dk^-1 (NOT G * dk^-1).
    let expected_vault_ek = compressed_hex(&(h * target_inv));
    assert_eq!(
        verify_res.vault_ek, expected_vault_ek,
        "vault_ek must equal H * dk^-1; if this fails, the generator drifted back to G"
    );

    // 9. KILLER ASSERTION: build a registration sigma proof under dk and run it through
    // the production registration verifier. Sigma: prover knows dk such that
    // vault_ek = h * dk^-1  ⇔  h = vault_ek * dk. Treat vault_ek as the generator and
    // dk as the discrete log: commitment T = vault_ek * r, challenge c, response s = r +
    // c * dk. Verifier checks vault_ek * s == T + h * c — exactly the equation at
    // lib.rs:1293-1294, and the production prover at lib.rs:1099 also commits as
    // `vault_ek * nonce`.
    let vault_ek_point =
        curve25519_dalek::ristretto::CompressedRistretto::from_slice(
            &(0..verify_res.vault_ek.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&verify_res.vault_ek[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>(),
        )
        .expect("vault_ek compressed slice")
        .decompress()
        .expect("vault_ek decompresses");
    let mut rng = ChaCha20Rng::seed_from_u64(0x7E57_BEEF);
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let nonce = Scalar::from_bytes_mod_order_wide(&buf);
    let commitment = vault_ek_point * nonce;
    let commitment_hex = compressed_hex(&commitment);

    let sender_address_hex = "01".repeat(32);
    let asset_type_hex = "02".repeat(32);
    let chain_id: u8 = 4;

    let challenge = eunoma_crypto_worker::ca_local::registration_challenge_scalar(
        &verify_res.vault_ek,
        &sender_address_hex,
        &asset_type_hex,
        chain_id,
        &commitment_hex,
    )
    .expect("registration challenge");

    let response = nonce + challenge * dk;
    let response_hex = scalar_hex(&response);

    eunoma_crypto_worker::ca_local::verify_registration_proof(
        &verify_res.vault_ek,
        &sender_address_hex,
        &asset_type_hex,
        chain_id,
        &commitment_hex,
        &response_hex,
    )
    .expect("verify_registration_proof must return Ok(()) — this is the killer assertion");
}

#[test]
fn verify_rejects_non_canonical_schnorr_s() {
    // Codex P2 #9: Schnorr `s` MUST decode canonically — Scalar::from_canonical_bytes
    // returns None for bytes >= q, so silently mod-reducing (the old behavior) would accept
    // a non-canonical s that has a different effective value than what the signer published.
    let fixed = det_scalar(0x5C5C);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let mut contributions = Vec::new();
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let h_r_hex = mock_h_r_for_q(&fixed);
    let all_h = vec![h_r_hex.clone(); 5];
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = h * fixed;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let mut proof = schnorr_pok(&fixed, &point, &worker_hash).expect("schnorr_pok");
        if idx == 2 {
            // Replace `s` with all-0xFF — well above q in little-endian.
            proof.s = "ff".repeat(32);
        }
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidRequest(msg) if msg.contains("not canonical"))
            || matches!(&err, WorkerError::Crypto(msg) if msg.contains("schnorr")),
        "expected non-canonical scalar rejection, got {err:?}"
    );
}

// === Codex P1 #4 tests: bind h_q_i to (h_r_i, mpc_open_m) ===

#[test]
fn verify_rejects_malicious_h_contribution_unbacked_by_h_r() {
    // Codex P1 #4 round0: with allHRoundZero coming from the coordinator-broadcast round0
    // vector, a malicious worker can't supply a different h_r_i in its contribution. But
    // it can still publish a malicious h_q_i that doesn't satisfy `h_q_i * m == h_r_i`
    // where h_r_i is the entry from allHRoundZero at this party's ordinal. Verifier MUST
    // catch that.
    let honest_q = det_scalar(0xDADA);
    let evil_x = det_scalar(0xEEEE);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let h = h_point();
    let m_hex = mock_mpc_open_m_hex();
    let all_h: Vec<String> = sorted_slots
        .iter()
        .map(|_| compressed_hex(&(h * honest_q)))
        .collect();
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    let mut contributions = Vec::new();
    for (idx, slot) in sorted_slots.iter().enumerate() {
        // For slot 2, publish a malicious h_q_i = h * evil_x that does NOT satisfy
        // h_q_i * 1 == allHRoundZero[2]. The Schnorr POK is still valid (evil_x is known).
        let secret = if idx == 2 { evil_x } else { honest_q };
        let point = h * secret;
        let h_contribution_hex = compressed_hex(&point);
        // h_r in the transcript hash comes from allHRoundZero[ordinal] — verifier
        // recomputes the same hash using the same source.
        let h_r_hex = all_h[idx].clone();
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&secret, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::Crypto(msg) if msg.contains("h_q_i * m != allHRoundZero")),
        "expected h_q_i * m mismatch against round0 commitment, got {err:?}"
    );
}

#[test]
fn verify_rejects_disagreeing_mpc_open_m() {
    // Codex P1 #4: all 5 workers MUST report the same MPC-opened m. The MAC-check in MASCOT
    // guarantees they will in production; the verifier still asserts as defense in depth.
    let honest_q = det_scalar(0xC0DE);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let h = h_point();
    let m_honest_hex = mock_mpc_open_m_hex(); // = Scalar::ONE
    let m_evil = Scalar::from(2_u64);
    let m_evil_hex = scalar_hex(&m_evil);
    // Build allHRoundZero so each party's h_r_i corresponds to the per-party (m, q) pair
    // that this test crafts. For idx == 2: h_r_i = h * (m_evil * honest_q); else h_r_i =
    // h * honest_q (with m=1).
    let all_h: Vec<String> = sorted_slots
        .iter()
        .enumerate()
        .map(|(idx, _)| {
            if idx == 2 {
                compressed_hex(&(h * (m_evil * honest_q)))
            } else {
                mock_h_r_for_q(&honest_q)
            }
        })
        .collect();
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    let mut contributions = Vec::new();
    for (idx, slot) in sorted_slots.iter().enumerate() {
        let point = h * honest_q;
        let h_contribution_hex = compressed_hex(&point);
        let m_hex = if idx == 2 { m_evil_hex.clone() } else { m_honest_hex.clone() };
        let h_r_hex = all_h[idx].clone();
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&honest_q, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex,
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidRequest(msg) if msg.contains("mpc_open_m disagreement")),
        "expected mpc_open_m disagreement, got {err:?}"
    );
}

#[test]
fn verify_rejects_zero_mpc_open_m() {
    // Codex P1 #4: m=0 is never legitimate (would imply dk*R == 0 mod q). Reject.
    let honest_q = det_scalar(0x0707);
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let h = h_point();
    let m_hex = "00".repeat(32); // m = 0
    let mut contributions = Vec::new();
    // With m=0: h_q_i * 0 = identity. allHRoundZero entries must each be identity too.
    let h_r_hex_identity =
        compressed_hex(&curve25519_dalek::ristretto::RistrettoPoint::default());
    let all_h: Vec<String> = (0..5).map(|_| h_r_hex_identity.clone()).collect();
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    for slot in &sorted_slots {
        let point = h * honest_q;
        let h_contribution_hex = compressed_hex(&point);
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex_identity,
            &m_hex,
            &r0_hash,
        );
        let proof = schnorr_pok(&honest_q, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidRequest(msg) if msg.contains("mpc_open_m is zero")),
        "expected zero m rejection, got {err:?}"
    );
}

// === Codex P1 #4 round0 tests: post-m bias attack & round0 file management ===

/// The Phase 2 attack codex P1 #4 was originally about. Without the round0 commitment,
/// a malicious worker waits for the MPC to open `m`, picks any scalar `y`, publishes
/// `h_r_i' = H*y` and `h_q_i' = H*(y*m_inv)`, and produces a Schnorr POK on `y*m_inv`.
/// Per-party `h_q_i' * m == h_r_i'` is trivially satisfied. Aggregate
/// `vault_ek * m == sum(h_r_i)` passes too. The registration sigma accepts a malicious
/// `vault_ek`.
///
/// With the round0 fix, h_r_i is committed BEFORE the MPC reveals m, and the verifier
/// uses `allHRoundZero[i]` (the committed value) rather than a round1-supplied one. A
/// malicious worker can no longer pick (h_q', h_r') as a matched pair after seeing m —
/// they're forced to pick h_r FIRST.
///
/// This test simulates the adversary: it builds the round0 commitment honestly (so the
/// commit-reveal binding looks legitimate), then in round1's contribution publishes a
/// malicious h_q_i' that doesn't actually equal `r_i * m^-1`. The verifier MUST reject
/// because `h_q_i' * m != allHRoundZero[i]`.
#[test]
fn post_m_bias_attack_rejected() {
    let honest_r_i = det_scalar(0x1230_0001);
    let m = Scalar::from(7_u64); // any non-trivial m
    let sorted_slots = vec![0_usize, 1, 2, 3, 4];
    let h = h_point();

    // Honest h_r_i commitments published in round0.
    let all_h: Vec<String> = sorted_slots
        .iter()
        .map(|_| compressed_hex(&(h * honest_r_i)))
        .collect();
    let r0_hash = eunoma_crypto_worker::vault_ek_derivation_v2::round0_commit_hash(&all_h);
    let m_hex = scalar_hex(&m);

    let mut contributions = Vec::new();
    for (idx, slot) in sorted_slots.iter().enumerate() {
        // Honest contribution = h * (r_i * m_inv).
        let m_inv = m.invert();
        let honest_q_i = honest_r_i * m_inv;
        let honest_h_q = h * honest_q_i;
        // Malicious slot 2: publish an arbitrary h_q' that doesn't match the round0
        // commitment. Use y = some unrelated scalar.
        let evil = det_scalar(0xBADBAD);
        let point = if idx == 2 { h * evil } else { honest_h_q };
        let h_contribution_hex = compressed_hex(&point);
        let h_r_hex = all_h[idx].clone();
        let worker_hash = worker_transcript_hash(
            DKG_EPOCH,
            &ca_dkg_transcript_hex(),
            &roster_hash_hex(),
            &sorted_slots,
            *slot,
            &h_contribution_hex,
            &h_r_hex,
            &m_hex,
            &r0_hash,
        );
        // Adversary's Schnorr proof is over `evil` (its known secret); this is valid POK
        // for h_q' BUT h_q' * m != allHRoundZero[2].
        let secret = if idx == 2 { evil } else { honest_q_i };
        let proof = schnorr_pok(&secret, &point, &worker_hash).expect("schnorr_pok");
        contributions.push(ContributionInput {
            slot: *slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash: worker_hash,
            mpc_open_m: m_hex.clone(),
        });
    }
    let request = VerifyRequest {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: sorted_slots,
        contributions,
        all_h_round_zero: all_h,
    };
    let err = run_verify(&request).unwrap_err();
    assert!(
        matches!(&err, WorkerError::Crypto(msg) if msg.contains("h_q_i * m != allHRoundZero")),
        "expected post-m bias attack to be rejected via round0 binding, got {err:?}"
    );
}

/// Variant of the post-m bias attack: malicious worker tries to swap the WHOLE round0
/// commitment vector — supplying a different `allHRoundZero` than what the coordinator
/// broadcast. round1 catches this when the persisted h_r_i in this party's round0 file
/// doesn't match `allHRoundZero[playerId]`. The check fires before MPC runs.
#[test]
fn round0_commitment_mismatch_rejected_in_round1() {
    let state_dir = temp_state_dir("round0-commit-mismatch");
    write_synthetic_share(&state_dir, 0);
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 0);
    // Persist round0 with a fixed r_i.
    let r_i = det_scalar(0xC0FFEE);
    let persisted_h_r = write_round0_file(
        &state_dir,
        "req-collide",
        "sess-collide",
        0,
        player_id,
        &[0, 1, 2, 3, 4],
        &r_i,
    );
    // But the coordinator broadcasts a DIFFERENT h_r_i for player 0.
    let evil_h_r = compressed_hex(&(h_point() * det_scalar(0xDEADBEEF)));
    assert_ne!(evil_h_r, persisted_h_r);
    let mut all_h = vec![persisted_h_r.clone(); 5];
    all_h[player_id] = evil_h_r;
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-collide".to_string(),
        session_id: "sess-collide".to_string(),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients: lagrange,
        all_h_round_zero: all_h,
    };
    // Even with the UnavailableMpcInverseAdapter the round0 mismatch check fires first.
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(
        matches!(&err, WorkerError::Crypto(msg) if msg.contains("round0_commitment_mismatch")),
        "expected round0_commitment_mismatch, got {err:?}"
    );
}

/// round1 without a persisted round0 file MUST be rejected before MPC. This catches the
/// case where round1 is invoked directly (e.g., a buggy coordinator that skipped round0).
#[test]
fn missing_round0_file_rejected_in_round1() {
    let state_dir = temp_state_dir("round0-missing");
    write_synthetic_share(&state_dir, 0);
    let (player_id, peers, lagrange) = phase2_round1_extras(&[0, 1, 2, 3, 4], 0);
    let req = Round1Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-no-r0".to_string(),
        session_id: "sess-no-r0".to_string(),
        peer_addresses: peers,
        player_id,
        lagrange_coefficients: lagrange,
        all_h_round_zero: vec!["00".repeat(32); 5],
    };
    let err = run_round1(&state_dir, &req, &UnavailableMpcInverseAdapter).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidDkgState(msg) if msg.contains("round0_file_missing")),
        "expected round0_file_missing, got {err:?}"
    );
}

/// run_round0 is idempotent for matching (request_id, session_id) — returns the same
/// committed h_r_i. Defense in depth against a coordinator retry that would otherwise
/// regenerate r_i and break the commit.
#[test]
fn round0_idempotent_same_request() {
    use eunoma_crypto_worker::vault_ek_derivation_v2::{run_round0, Round0Request};
    let state_dir = temp_state_dir("round0-idempotent");
    write_synthetic_share(&state_dir, 0);
    let req = Round0Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-idem".to_string(),
        session_id: "sess-idem".to_string(),
        peer_addresses: (0..5)
            .map(|i| format!("127.0.0.1:{}", 14000 + i))
            .collect(),
        player_id: 0,
        lagrange_coefficients: (0..5)
            .map(|i| scalar_hex(&compute_lagrange_for_test(i, &[0, 1, 2, 3, 4])))
            .collect(),
    };
    let first = run_round0(&state_dir, &req).expect("first round0");
    let second = run_round0(&state_dir, &req).expect("second round0 must succeed");
    // h_r_i and worker_round0_hash must be identical (same r_i underneath).
    assert_eq!(first.h_r, second.h_r);
    assert_eq!(first.worker_round0_hash, second.worker_round0_hash);
}

/// run_round0 with a session-id collision (same path, different sessionId) is rejected.
/// Mirrors what would happen if two requests with different sessionIds hit the same file
/// — should never happen in practice but defense in depth.
#[test]
fn round0_session_collision_rejected() {
    use eunoma_crypto_worker::vault_ek_derivation_v2::{run_round0, Round0Request};
    let state_dir = temp_state_dir("round0-collide");
    write_synthetic_share(&state_dir, 0);
    // Stage 1: legit round0 for (req-A, sess-A).
    let lagrange_hex: Vec<String> = (0..5)
        .map(|i| scalar_hex(&compute_lagrange_for_test(i, &[0, 1, 2, 3, 4])))
        .collect();
    let peers: Vec<String> = (0..5).map(|i| format!("127.0.0.1:{}", 14000 + i)).collect();
    let first = Round0Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-A".to_string(),
        session_id: "sess-A".to_string(),
        peer_addresses: peers.clone(),
        player_id: 0,
        lagrange_coefficients: lagrange_hex.clone(),
    };
    run_round0(&state_dir, &first).expect("first round0");
    // Stage 2: manually corrupt the file's sessionId to simulate a path collision
    // (two distinct request_id/session_id values pointing at the same on-disk shape).
    // The session_dir layout namespaces by request_id__session_id, so this only matters
    // if the file was opened wrong. We test the resulting `round0_session_collision`
    // path by hand-crafting a file under req-B/sess-B that claims to be req-A/sess-A.
    let bad_dir = state_dir
        .join("mpc-sessions")
        .join("req-B__sess-B");
    fs::create_dir_all(&bad_dir).unwrap();
    let bad_layout = serde_json::json!({
        "session_id": "sess-A",      // mismatch — file claims A but request says B
        "request_id": "req-A",
        "self_slot": 0,
        "player_id": 0,
        "roster_hash": roster_hash_hex(),
        "selected_slots": [0, 1, 2, 3, 4],
        "r_i_hex": scalar_hex(&det_scalar(0x999)),
        "h_r_i_hex": compressed_hex(&(h_point() * det_scalar(0x999))),
        "created_at_unix_ms": 1u128,
    });
    fs::write(
        bad_dir.join("round0.json"),
        serde_json::to_vec(&bad_layout).unwrap(),
    )
    .unwrap();
    let collide = Round0Request {
        dkg_epoch: DKG_EPOCH.to_string(),
        ca_dkg_transcript_hash: ca_dkg_transcript_hex(),
        roster_hash: roster_hash_hex(),
        selected_slots: vec![0, 1, 2, 3, 4],
        self_slot: 0,
        request_id: "req-B".to_string(),
        session_id: "sess-B".to_string(),
        peer_addresses: peers,
        player_id: 0,
        lagrange_coefficients: lagrange_hex,
    };
    let err = run_round0(&state_dir, &collide).unwrap_err();
    assert!(
        matches!(&err, WorkerError::InvalidDkgState(msg) if msg.contains("round0_session_collision")),
        "expected round0_session_collision, got {err:?}"
    );
}

/// Helper to compute a Lagrange coefficient for tests that need to populate
/// `lagrange_coefficients` with valid values (run_round0 doesn't actually consume them,
/// but validates length/shape).
fn compute_lagrange_for_test(player_id: usize, sorted_slots: &[usize]) -> Scalar {
    let x_i = Scalar::from((sorted_slots[player_id] as u64) + 1);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for (j, slot) in sorted_slots.iter().enumerate() {
        if j == player_id {
            continue;
        }
        let x_j = Scalar::from((*slot as u64) + 1);
        num *= -x_j;
        den *= x_i - x_j;
    }
    num * den.invert()
}

/// If a malicious or buggy implementation builds a Schnorr proof against G instead of H,
/// `verify_schnorr_pok` (which now uses H) must reject it.
#[test]
fn wrong_generator_proof_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let secret = Scalar::from_bytes_mod_order_wide(&buf);

    let h = h_point();
    let g = RISTRETTO_BASEPOINT_POINT;
    let h_contribution = h * secret;

    // Manually build a Schnorr proof using G as the generator.
    let mut buf2 = [0u8; 64];
    rng.fill_bytes(&mut buf2);
    let r = Scalar::from_bytes_mod_order_wide(&buf2);
    let r_point = g * r; // wrong-generator commitment

    let worker_hash = "ab".repeat(32);

    // Replicate vault_ek_derivation_v2::schnorr_challenge — domain + worker_hash bytes +
    // r_point compressed + h_contribution compressed, Sha512 wide reduction.
    let challenge = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_VAULT_EK_DERIVATION_SCHNORR_V1");
        bytes.extend_from_slice(worker_hash.to_lowercase().as_bytes());
        bytes.extend_from_slice(r_point.compress().as_bytes());
        bytes.extend_from_slice(h_contribution.compress().as_bytes());
        let digest = sha2::Sha512::digest(&bytes);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(digest.as_slice());
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    let s = r + challenge * secret;

    let proof = SchnorrProof {
        r: compressed_hex(&r_point),
        s: hex_encode(s.to_bytes().as_slice()),
    };

    // The verifier checks h * s == r_point + h_contribution * c. We have
    // h * s = h * r + c * h * secret = h * r + c * h_contribution. The submitted r_point
    // is g * r, not h * r, so the LHS-RHS check fails.
    let ok = verify_schnorr_pok(&h_contribution, &proof, &worker_hash).expect("verify");
    assert!(
        !ok,
        "verify_schnorr_pok must reject a Schnorr proof whose commitment uses G instead of H"
    );
}
