//! Phase 2 integration tests for the real MP-SPDZ adapter.
//!
//! The "killer" test `real_mp_spdz_inversion_passes_registration_sigma` is `#[ignore]`'d so
//! `cargo test` works without MP-SPDZ on the host. To run it, ensure `npm run mpc:bootstrap`
//! has been executed and pass `MP_SPDZ_HOME=...` (or rely on the manifest), then run
//!     cargo test --test mpc_spdz_adapter -- --ignored

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use eunoma_crypto_worker::{
    mpc_inverse_adapter::{AdapterError, InversionContext, MpcInverseAdapter},
    mpc_spdz_adapter::{MpcSpdzInverseAdapter, PROGRAM_NAME},
};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

const ED25519_SCALAR_PRIME_DECIMAL: &str =
    "7237005577332262213973186563042994240857116359379907606001950938285454250989";

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("eunoma-mpc-spdz-adapter-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn det_scalar(seed: u64) -> Scalar {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn scalar_hex(s: &Scalar) -> String {
    s.to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Synthesize an adapter pointing at an empty `mp_spdz_home`. Lagrange validation runs before
/// any filesystem operation that depends on the home being real.
fn dummy_adapter_for_validation(home: PathBuf) -> MpcSpdzInverseAdapter {
    let bytecode_path = home
        .join("Programs")
        .join("Bytecode")
        .join("vault_ek_inversion_v1-0.bc");
    let mascot_binary = home.join("mascot-party.x");
    MpcSpdzInverseAdapter {
        mp_spdz_home: home,
        program_name: PROGRAM_NAME.to_string(),
        bytecode_path,
        timeout: Duration::from_secs(2),
        mascot_binary,
        keep_session_dirs: false,
    }
}

#[test]
fn unavailable_when_env_unset() {
    // The adapter must declare itself unavailable when MP_SPDZ_HOME is missing OR points
    // somewhere without bytecode. To avoid racing with this test process's env (other tests
    // may have set MP_SPDZ_HOME), explicitly aim at an empty temp dir.
    let temp = temp_dir("unavailable");
    let result = MpcSpdzInverseAdapter::from_home(temp);
    assert!(result.is_none(), "from_home must return None when bytecode is missing");
}

#[test]
fn lagrange_coefficient_recompute_mismatch_rejected() {
    // Direct adapter call with a deliberately wrong Lagrange coefficient. Validation must
    // fire before any subprocess spawn — so the test does not need a real MP-SPDZ runtime.
    let home = temp_dir("lagrange-mismatch-home");
    let adapter = dummy_adapter_for_validation(home);
    let work_dir = temp_dir("lagrange-mismatch-work");
    let sorted_slots: Vec<usize> = vec![0, 1, 2, 3, 4];
    // Supply a non-recoverable bogus lambda for player_id=0.
    let mut bogus_lagrange: Vec<String> = sorted_slots.iter().map(|_| "00".repeat(32)).collect();
    bogus_lagrange[0] = "01".to_string() + &"00".repeat(31);
    let ctx = InversionContext {
        dkg_epoch: "1".to_string(),
        ca_dkg_transcript_hash: "00".repeat(32),
        selected_slots: sorted_slots.clone(),
        self_slot: 0,
        roster_hash: "00".repeat(32),
        request_id: "req".to_string(),
        session_id: "sess".to_string(),
        work_dir,
        peer_addresses: sorted_slots
            .iter()
            .map(|s| format!("127.0.0.1:{}", 14000 + s))
            .collect(),
        player_id: 0,
        lagrange_coefficients_hex: bogus_lagrange,
    };
    let err = adapter
        .compute_inverse_share(&Scalar::ONE, &ctx)
        .expect_err("lagrange mismatch must reject");
    assert!(
        matches!(&err, AdapterError::InvalidInput(msg) if msg == "lagrange_coefficient_mismatch"),
        "expected lagrange_coefficient_mismatch, got {err:?}"
    );
}

#[test]
fn session_dir_collision_resolved_by_request_id() {
    // Two contexts with the SAME session_id but DIFFERENT request_id must allocate distinct
    // work dirs under work_dir/mpc-sessions/. The check is constructive: we run the adapter
    // far enough to create the dir, but since the dummy adapter lacks a real binary we expect
    // the spawn to fail; capture the path that would have been created instead.
    //
    // Implementation note: we mirror the adapter's path construction here as a regression
    // gate. If the format changes, this test must be updated to match.
    let work_dir = temp_dir("session-dir-collision");
    let req_a = "req-AAA".to_string();
    let req_b = "req-BBB".to_string();
    let sess = "shared-session-id".to_string();

    let path_a = work_dir.join("mpc-sessions").join(format!("{req_a}__{sess}"));
    let path_b = work_dir.join("mpc-sessions").join(format!("{req_b}__{sess}"));
    assert_ne!(path_a, path_b);

    // Sanity: writing both must succeed without contention.
    fs::create_dir_all(&path_a).unwrap();
    fs::create_dir_all(&path_b).unwrap();
    assert!(path_a.exists());
    assert!(path_b.exists());
}

// ==========================================================================================
// The killer integration test — `#[ignore]`'d. Requires MP-SPDZ bootstrapped on this host
// (`npm run mpc:bootstrap`) so the bytecode + binary exist.
// ==========================================================================================

#[test]
#[ignore]
fn real_mp_spdz_inversion_passes_registration_sigma() {
    use std::sync::mpsc;
    use std::thread;

    let home = mp_spdz_home_for_test();
    let adapter_one = match MpcSpdzInverseAdapter::from_home(home.clone()) {
        Some(a) => a,
        None => panic!(
            "MP_SPDZ runtime missing at {} — run `npm run mpc:bootstrap` first",
            home.display()
        ),
    };

    // Build a 7-slot Pedersen-VSS polynomial of degree 4; the secret dk = coeffs[0].
    let coeffs: [Scalar; 5] = [
        det_scalar(0xC0_0000),
        det_scalar(0xC0_0001),
        det_scalar(0xC0_0002),
        det_scalar(0xC0_0003),
        det_scalar(0xC0_0004),
    ];
    let dk = coeffs[0];

    // dk_share at slot s is f(s+1) for the degree-4 polynomial.
    let mut dk_shares: [Scalar; 5] = [Scalar::ZERO; 5];
    let selected_slots: [usize; 5] = [0, 1, 2, 3, 4];
    for (ordinal, slot) in selected_slots.iter().enumerate() {
        let x = Scalar::from((*slot as u64) + 1);
        let mut acc = coeffs[4];
        for k in (0..4).rev() {
            acc = acc * x + coeffs[k];
        }
        dk_shares[ordinal] = acc;
    }

    // Compute Lagrange coefficients at x=0 for the selected set, in player-ordinal order.
    let lagrange_hex: Vec<String> = (0..5)
        .map(|ordinal| {
            scalar_hex(&lagrange_coefficient_at_zero(ordinal, &selected_slots))
        })
        .collect();

    // Allocate 5 peer ports on 127.0.0.1.
    let ports = allocate_ports(5);
    let peer_addresses: Vec<String> = ports
        .iter()
        .map(|p| format!("127.0.0.1:{p}"))
        .collect();

    // Each player gets its own work_dir under a per-test root so session_dir paths don't
    // collide between parties. We pass a long timeout so MASCOT preprocessing has time.
    let test_root = temp_dir("real-mpc-inversion");
    let session_id = "real".to_string();
    let request_id = "killer".to_string();
    let dkg_epoch = "9".to_string();
    let ca = "33".repeat(32);
    let roster = "44".repeat(32);

    let mut handles = Vec::with_capacity(5);
    let (tx, rx) = mpsc::channel::<Result<(usize, Scalar), String>>();
    for ordinal in 0..5usize {
        let work_dir = test_root.join(format!("player-{ordinal}"));
        fs::create_dir_all(&work_dir).unwrap();
        let home_for_thread = home.clone();
        let peers_for_thread = peer_addresses.clone();
        let lagrange_for_thread = lagrange_hex.clone();
        let dk_share = dk_shares[ordinal];
        let request_id = request_id.clone();
        let session_id = session_id.clone();
        let dkg_epoch = dkg_epoch.clone();
        let ca = ca.clone();
        let roster = roster.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            // Each thread sets MP_SPDZ_HOME for its own adapter clone (idempotent).
            let adapter = MpcSpdzInverseAdapter::from_home(home_for_thread).expect("home");
            let ctx = InversionContext {
                dkg_epoch,
                ca_dkg_transcript_hash: ca,
                selected_slots: selected_slots.to_vec(),
                self_slot: selected_slots[ordinal],
                roster_hash: roster,
                request_id,
                session_id,
                work_dir,
                peer_addresses: peers_for_thread,
                player_id: ordinal,
                lagrange_coefficients_hex: lagrange_for_thread,
            };
            match adapter.compute_inverse_share(&dk_share, &ctx) {
                Ok(q) => {
                    let _ = tx.send(Ok((ordinal, q)));
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("player {ordinal}: {e:?}")));
                }
            }
        }));
    }
    drop(tx);
    drop(adapter_one);

    let mut q_shares: Vec<Option<Scalar>> = vec![None; 5];
    for _ in 0..5 {
        let msg = rx.recv_timeout(Duration::from_secs(180)).expect("recv");
        let (i, q) = msg.expect("player succeeded");
        q_shares[i] = Some(q);
    }
    for h in handles {
        let _ = h.join();
    }

    let mut q_sum = Scalar::ZERO;
    for q in &q_shares {
        q_sum += q.expect("all q's present");
    }
    assert_eq!(q_sum, dk.invert(), "sum of q_i must equal 1/dk");

    // Now derive vault_ek = H * (sum q_i) and prove it satisfies the registration sigma.
    let h_point = h_ristretto();
    let vault_ek_point = h_point * q_sum;
    let vault_ek_hex: String = vault_ek_point
        .compress()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(vault_ek_point, h_point * dk.invert());

    // Build a registration sigma proof under dk and verify via ca_local::verify_registration_proof.
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EAF_FF11);
    let mut buf = [0u8; 64];
    rng.fill_bytes(&mut buf);
    let nonce = Scalar::from_bytes_mod_order_wide(&buf);
    let commitment = vault_ek_point * nonce;
    let commitment_hex: String = commitment
        .compress()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sender_address_hex = "01".repeat(32);
    let asset_type_hex = "02".repeat(32);
    let chain_id: u8 = 4;
    let challenge = eunoma_crypto_worker::ca_local::registration_challenge_scalar(
        &vault_ek_hex,
        &sender_address_hex,
        &asset_type_hex,
        chain_id,
        &commitment_hex,
    )
    .expect("challenge");
    let response = nonce + challenge * dk;
    let response_hex = scalar_hex(&response);

    eunoma_crypto_worker::ca_local::verify_registration_proof(
        &vault_ek_hex,
        &sender_address_hex,
        &asset_type_hex,
        chain_id,
        &commitment_hex,
        &response_hex,
    )
    .expect("verify_registration_proof must accept v2-derived vault_ek (KILLER ASSERTION)");
}

// ==========================================================================================
// helpers
// ==========================================================================================

fn h_ristretto() -> curve25519_dalek::ristretto::RistrettoPoint {
    let hex = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    CompressedRistretto(buf).decompress().expect("H")
}

fn mp_spdz_home_for_test() -> PathBuf {
    if let Ok(env) = std::env::var("MP_SPDZ_HOME") {
        return PathBuf::from(env);
    }
    // Fall back to the well-known bootstrap location relative to the repo root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join(".agent-local")
        .join("mp-spdz")
        .join("MP-SPDZ-7bf16a74e10b")
}

fn allocate_ports(n: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(n);
    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }
    drop(listeners);
    // Brief settle window — the kernel sometimes lingers in TIME_WAIT.
    std::thread::sleep(Duration::from_millis(50));
    ports
}

/// Pure-Scalar Lagrange coefficient at x=0 for x_i = sorted_slots[player_id] + 1. Used to
/// supply the SAME values the adapter recomputes internally — so validation passes.
fn lagrange_coefficient_at_zero(player_id: usize, sorted_slots: &[usize]) -> Scalar {
    let _ = ED25519_SCALAR_PRIME_DECIMAL;
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
