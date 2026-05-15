//! MP-SPDZ-backed implementation of `MpcInverseAdapter` for Phase 2 of DKG A.
//!
//! Each worker invocation spawns one `mascot-party.x` subprocess and feeds it three inputs:
//!   - `dk_share_i`  (this party's Shamir share of `dk`)
//!   - `r_i`         (a freshly random scalar drawn by this party for this session)
//! plus the public Lagrange coefficients λ_0..λ_4 (shared across all parties via a
//! Programs/Public-Input file). The program (vault_ek_inversion_v1.mpc) computes
//! `m = (Σ λ_i * dk_share_i) * (Σ r_i)` under MASCOT MAC-checking and opens `m`. Each party
//! then locally computes `q_i = r_i * m^{-1}`, and aggregation of `H * q_i` across the five
//! parties produces `vault_ek = H / dk` without any party ever seeing `dk` or `dk^{-1}`.
//!
//! See plan §"Adapter implementation outline" and §"Risks" for the full security model.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::h_ristretto;
use crate::mpc_inverse_adapter::{
    AdapterError, InversionContext, InversionShare, MpcInverseAdapter,
};
use crate::DEOPERATOR_THRESHOLD;

/// Filename produced by `npm run mpc:bootstrap` (matches scripts/_lib/mpc_spdz_constants.mjs).
pub const PROGRAM_NAME: &str = "vault_ek_inversion_v1";
const BYTECODE_FILE: &str = "vault_ek_inversion_v1-0.bc";

const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Real per-party MP-SPDZ runner. Fails closed (returns `McpSpdzNotAvailable`) when the
/// runtime isn't bootstrapped on this host.
pub struct MpcSpdzInverseAdapter {
    pub mp_spdz_home: PathBuf,
    pub program_name: String,
    pub bytecode_path: PathBuf,
    pub timeout: Duration,
    pub mascot_binary: PathBuf,
    pub keep_session_dirs: bool,
}

impl MpcSpdzInverseAdapter {
    /// Build from `MP_SPDZ_HOME`. Returns `None` if the env var is missing OR the bytecode
    /// hasn't been compiled (caller falls back to `UnavailableMpcInverseAdapter`).
    pub fn from_env() -> Option<Self> {
        let home = std::env::var("MP_SPDZ_HOME").ok().map(PathBuf::from)?;
        Self::from_home(home)
    }

    pub fn from_home(mp_spdz_home: PathBuf) -> Option<Self> {
        let bytecode_path = mp_spdz_home.join("Programs").join("Bytecode").join(BYTECODE_FILE);
        if !bytecode_path.exists() {
            return None;
        }
        let mascot_binary = mp_spdz_home.join("mascot-party.x");
        if !mascot_binary.exists() {
            return None;
        }
        let timeout_secs = std::env::var("EUNOMA_MPC_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        let keep_session_dirs = std::env::var("EUNOMA_MPC_KEEP_SESSION_DIRS")
            .map(|v| v == "1")
            .unwrap_or(false);
        Some(Self {
            mp_spdz_home,
            program_name: PROGRAM_NAME.to_string(),
            bytecode_path,
            timeout: Duration::from_secs(timeout_secs),
            mascot_binary,
            keep_session_dirs,
        })
    }
}

impl MpcInverseAdapter for MpcSpdzInverseAdapter {
    fn compute_inverse_share(
        &self,
        dk_share: &Scalar,
        ctx: &InversionContext,
    ) -> Result<InversionShare, AdapterError> {
        // Defense in depth: validate the context shape.
        if ctx.selected_slots.len() != DEOPERATOR_THRESHOLD {
            return Err(AdapterError::InvalidInput(format!(
                "selected_slots must have {DEOPERATOR_THRESHOLD} entries"
            )));
        }
        if ctx.peer_addresses.len() != DEOPERATOR_THRESHOLD {
            return Err(AdapterError::InvalidInput(format!(
                "peer_addresses must have {DEOPERATOR_THRESHOLD} entries"
            )));
        }
        if ctx.lagrange_coefficients_hex.len() != DEOPERATOR_THRESHOLD {
            return Err(AdapterError::InvalidInput(format!(
                "lagrange_coefficients must have {DEOPERATOR_THRESHOLD} entries"
            )));
        }
        if ctx.player_id >= DEOPERATOR_THRESHOLD {
            return Err(AdapterError::InvalidInput(format!(
                "player_id {} out of range 0..{}",
                ctx.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        if ctx.request_id.is_empty() || !is_safe_id(&ctx.request_id) {
            return Err(AdapterError::InvalidInput(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if ctx.session_id.is_empty() || !is_safe_id(&ctx.session_id) {
            return Err(AdapterError::InvalidInput(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }

        // Defense in depth: recompute ALL N λ values locally from sorted_slots (which is
        // already cross-checked against rosterHash and selected_slots binding upstream). Reject
        // if any supplied value differs from the locally-recomputed one. The MPC public input
        // file is written from the LOCAL values regardless — so even if the comparison logic
        // has a bug, MASCOT never opens a value driven by attacker-supplied coefficients.
        //
        // Also verify the player's own slot/ordinal binding: sorted_slots[player_id] must
        // equal self_slot. Otherwise a malicious coordinator could give us an `selected_slots`
        // permutation where our ordinal corresponds to someone else's lambda.
        let mut sorted_slots = ctx.selected_slots.clone();
        sorted_slots.sort_unstable();
        if sorted_slots[ctx.player_id] != ctx.self_slot {
            return Err(AdapterError::InvalidInput(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                ctx.player_id, sorted_slots[ctx.player_id], ctx.self_slot
            )));
        }
        let mut local_lambdas: Vec<Scalar> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for ordinal in 0..DEOPERATOR_THRESHOLD {
            let lambda = compute_lagrange_coefficient_at_zero(ordinal, &sorted_slots)?;
            let supplied = scalar_from_hex(&ctx.lagrange_coefficients_hex[ordinal])?;
            if supplied != lambda {
                return Err(AdapterError::InvalidInput(
                    "lagrange_coefficient_mismatch".to_string(),
                ));
            }
            local_lambdas.push(lambda);
        }

        // Codex P1 #3: only the identity selection (sorted_slots == 0..N-1) keeps the
        // MASCOT cert CN binding intact (CN is "P<slot>" but MASCOT expects "P<ordinal>").
        // Fail closed for any non-identity selection unless the operator opts in.
        let identity_selection = sorted_slots
            .iter()
            .enumerate()
            .all(|(ordinal, slot)| ordinal == *slot);
        if !identity_selection {
            let allow_shifted = std::env::var("EUNOMA_MPC_ALLOW_SHIFTED_SELECTION")
                .map(|v| v == "1")
                .unwrap_or(false);
            if !allow_shifted {
                return Err(AdapterError::InvalidInput(format!(
                    "selected_slots {sorted_slots:?} != 0..{DEOPERATOR_THRESHOLD}; MASCOT cert CN \
                     binding (P<slot>) does not match the player ordinal. Phase 2 supports only \
                     the canonical lowest-N selection in single-host local-cluster mode. Set \
                     EUNOMA_MPC_ALLOW_SHIFTED_SELECTION=1 only if you have provisioned per-ordinal \
                     certs out-of-band."
                )));
            }
        }
        // Check own private key and peer cert presence BEFORE any filesystem allocation —
        // failing closed early gives a better error than a deep TLS handshake failure later.
        let host_player_data_check = self.mp_spdz_home.join("Player-Data");
        let own_key = host_player_data_check.join(format!("P{}.key", ctx.self_slot));
        if !own_key.exists() {
            return Err(AdapterError::Internal(format!(
                "missing own private key {} — run `npm run mpc:bootstrap`",
                own_key.display()
            )));
        }
        for slot in &sorted_slots {
            let pem = host_player_data_check.join(format!("P{slot}.pem"));
            if !pem.exists() {
                return Err(AdapterError::Internal(format!(
                    "missing peer cert {} (slot {slot}); single-host local-cluster setup \
                     requires all 5 peer certs on this host. Run `npm run mpc:bootstrap`.",
                    pem.display()
                )));
            }
        }

        // Allocate session directory. Combining request_id and session_id namespaces the
        // workspace so that two concurrent calls — even sharing a session_id — get distinct
        // dirs. Mode 0o700.
        let session_dir = ctx
            .work_dir
            .join("mpc-sessions")
            .join(format!("{}__{}", ctx.request_id, ctx.session_id));
        if session_dir.exists() {
            // Idempotency: a stale run may have left files behind. Wipe before re-using.
            let _ = fs::remove_dir_all(&session_dir);
        }
        fs::create_dir_all(&session_dir)
            .map_err(|e| AdapterError::Internal(format!("create session_dir: {e}")))?;
        set_dir_mode_700(&session_dir)?;

        let player_data_dir = session_dir.join("Player-Data");
        fs::create_dir_all(&player_data_dir)
            .map_err(|e| AdapterError::Internal(format!("create Player-Data: {e}")))?;
        set_dir_mode_700(&player_data_dir)?;

        // Write Programs/Public-Input/<program> with the 5 λ values in player-ordinal order.
        // CRITICAL: feed MP-SPDZ the LOCALLY-RECOMPUTED lambdas, not the coordinator-supplied
        // ones. The comparison loop above is defense-in-depth; this is the actual gate.
        let public_input_dir = session_dir.join("Programs").join("Public-Input");
        fs::create_dir_all(&public_input_dir)
            .map_err(|e| AdapterError::Internal(format!("create Public-Input: {e}")))?;
        let mut public_input = String::new();
        for lambda in &local_lambdas {
            public_input.push_str(&scalar_to_decimal(lambda));
            public_input.push('\n');
        }
        fs::write(public_input_dir.join(&self.program_name), public_input.as_bytes())
            .map_err(|e| AdapterError::Internal(format!("write Public-Input: {e}")))?;
        let self_lambda_decimal = scalar_to_decimal(&local_lambdas[ctx.player_id]);

        // Symlink the compiled bytecode + schedule + compiled-VAR file into the session dir so
        // mascot-party.x finds them under cwd = session_dir.
        let host_programs = self.mp_spdz_home.join("Programs");
        link_programs(&host_programs, &session_dir.join("Programs"), &self.program_name)?;

        // Codex P1 #3: we used to copy every peer's PRIVATE key into our session dir, which
        // means a compromised worker would have peer parties' private keys locally. Fix:
        //   - Only symlink our OWN private key (P{ordinal}.key ← P{self_slot}.key).
        //   - Symlink each peer's PUBLIC cert (P{ordinal}.pem ← P{peer_slot}.pem).
        // The shifted-selection guard + cert/key existence checks ran at the top of the
        // function; here we just wire up the session dir.
        let host_player_data = self.mp_spdz_home.join("Player-Data");
        // OWN private key.
        symlink_or_copy(
            &host_player_data.join(format!("P{}.key", ctx.self_slot)),
            &player_data_dir.join(format!("P{}.key", ctx.player_id)),
        )?;
        // Peer PUBLIC certs (no private keys).
        for (ordinal, slot) in sorted_slots.iter().enumerate() {
            symlink_or_copy(
                &host_player_data.join(format!("P{slot}.pem")),
                &player_data_dir.join(format!("P{ordinal}.pem")),
            )?;
        }
        // c_rehash creates SSL_DIR/<hash>.0 -> P<i>.pem links so OpenSSL's verify path can
        // find the trust anchors. The host already has these, but in our session-local dir we
        // need fresh hashes pointing at our newly-renamed files. Computing the hash without
        // shelling out to OpenSSL is feasible (it's the X509 subject hash) but error-prone;
        // simplest portable approach is to invoke `c_rehash` if it's on PATH, else fall back
        // to OpenSSL's add_verify_path which also scans for .pem files in the dir directly
        // (true for ssl_sockets.h's add_verify_path).
        let _ = run_c_rehash(&player_data_dir);

        // Generate a fresh per-session r_i. Never logged, never leaves this process.
        let mut r_i = random_scalar();

        // Write our two per-party sint inputs: dk_share, r_i. (lambda_i is read as
        // public_input, handled by the Public-Input file above.)
        let input_path = player_data_dir.join(format!("Input-P{}-0", ctx.player_id));
        let mut input_text = String::new();
        let dk_decimal = scalar_to_decimal(dk_share);
        let r_decimal = scalar_to_decimal(&r_i);
        input_text.push_str(&dk_decimal);
        input_text.push('\n');
        input_text.push_str(&r_decimal);
        input_text.push('\n');
        write_secret_file(&input_path, &input_text)?;
        // Codex P2 #6: RAII guard. From this point forward, if any `?` returns early or
        // any panic unwinds the stack, Drop will scrub the input file with zeros and
        // remove it. The guard is disarmed only after the explicit `zeroize_file_inplace`
        // on the happy paths below (success and known-error paths). This closes the
        // residual leak where a `spawn` or stdio-setup failure left dk_share + r_i on
        // disk in plaintext.
        let mut input_guard = SecretFileGuard::new(input_path.clone());

        // Spawn mascot-party.x. Per `--help`:
        //   -p <player>          (this player's ordinal)
        //   -N <nparties>        (number of players)
        //   -ip <ip_filename>    (one host:port per line in ordinal order)
        //   -P <prime>           (Ed25519 scalar prime)
        //   -IF Player-Data/Input  (input file prefix; we use the default and write to Player-Data/Input-P<i>-0)
        // cwd = session_dir so all relative paths resolve under it.
        let hosts_path = session_dir.join("HOSTS");
        let mut hosts_content = String::new();
        for peer in &ctx.peer_addresses {
            hosts_content.push_str(peer);
            hosts_content.push('\n');
        }
        fs::write(&hosts_path, hosts_content.as_bytes())
            .map_err(|e| AdapterError::Internal(format!("write HOSTS: {e}")))?;

        let log_stdout = session_dir.join("stdout.log");
        let log_stderr = session_dir.join("stderr.log");
        let mut command = Command::new(&self.mascot_binary);
        command
            .current_dir(&session_dir)
            .arg("-p")
            .arg(ctx.player_id.to_string())
            .arg("-N")
            .arg(DEOPERATOR_THRESHOLD.to_string())
            .arg("-ip")
            .arg("HOSTS")
            .arg("-P")
            .arg(ED25519_SCALAR_PRIME_DECIMAL)
            // Per `mascot-party.x --help`: `-OF` "default is to output to stdout for party 0
            // (silent otherwise)". We need EVERY party to emit `EUNOMA_VAULT_EK_M` on its own
            // stdout so each adapter instance can parse it locally. `.` requests stdout for
            // all parties.
            .arg("-OF")
            .arg(".")
            .arg(&self.program_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PLAYERS", DEOPERATOR_THRESHOLD.to_string());
        // Propagate MP-SPDZ runtime library paths set up by mpc:bootstrap on macOS/Linux so
        // libSPDZ.so + brew-installed libsodium/openssl/boost/gmp are found at runtime.
        let lib_path = child_library_path(&self.mp_spdz_home);
        let merged = match std::env::var("DYLD_LIBRARY_PATH").ok() {
            Some(existing) if !existing.is_empty() => format!("{lib_path}:{existing}"),
            _ => lib_path.clone(),
        };
        command.env("DYLD_LIBRARY_PATH", &merged);
        let merged_ld = match std::env::var("LD_LIBRARY_PATH").ok() {
            Some(existing) if !existing.is_empty() => format!("{lib_path}:{existing}"),
            _ => lib_path,
        };
        command.env("LD_LIBRARY_PATH", merged_ld);
        forward_runtime_env(&mut command);

        let mut child = command
            .spawn()
            .map_err(|e| AdapterError::Internal(format!("spawn mascot-party.x: {e}")))?;

        // Capture stdout/stderr in background threads (Linux pipe buffers can deadlock if not
        // drained). Each thread sends its accumulated buffer through a oneshot mpsc.
        let mut child_stdout = child.stdout.take().ok_or_else(|| {
            AdapterError::Internal("mascot-party.x has no stdout pipe".to_string())
        })?;
        let mut child_stderr = child.stderr.take().ok_or_else(|| {
            AdapterError::Internal("mascot-party.x has no stderr pipe".to_string())
        })?;
        let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>();
        let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();
        let stdout_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_stdout.read_to_end(&mut buf);
            let _ = stdout_tx.send(buf);
        });
        let stderr_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_stderr.read_to_end(&mut buf);
            let _ = stderr_tx.send(buf);
        });

        // Watchdog: timed wait with `try_wait` polling. On timeout, kill the child.
        let started = std::time::Instant::now();
        let poll = Duration::from_millis(50);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if started.elapsed() > self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        // Drain logs for diagnostics.
                        let so = stdout_rx.recv_timeout(Duration::from_millis(500)).unwrap_or_default();
                        let se = stderr_rx.recv_timeout(Duration::from_millis(500)).unwrap_or_default();
                        let _ = fs::write(&log_stdout, &so);
                        let _ = fs::write(&log_stderr, &se);
                        let _ = stdout_handle.join();
                        let _ = stderr_handle.join();
                        // Codex P2 #6: zero plaintext input file even on timeout. The guard
                        // would also run via Drop, but doing it eagerly preserves the
                        // legible error path; disarm after to avoid double-scrub.
                        let _ = zeroize_file_inplace(&input_path);
                        input_guard.disarm();
                        cleanup_or_keep(&session_dir, self.keep_session_dirs);
                        r_i.zeroize();
                        return Err(AdapterError::Internal(format!(
                            "mascot-party.x timeout after {}s",
                            self.timeout.as_secs()
                        )));
                    }
                    thread::sleep(poll);
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    // Codex P2 #6: zero plaintext input file even on try_wait error.
                    let _ = zeroize_file_inplace(&input_path);
                    input_guard.disarm();
                    cleanup_or_keep(&session_dir, self.keep_session_dirs);
                    r_i.zeroize();
                    return Err(AdapterError::Internal(format!("try_wait: {e}")));
                }
            }
        };

        // Collect logs.
        let stdout_bytes = stdout_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        let stderr_bytes = stderr_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        let _ = stdout_handle.join();
        let _ = stderr_handle.join();
        let _ = fs::write(&log_stdout, &stdout_bytes);
        let _ = fs::write(&log_stderr, &stderr_bytes);

        // Codex P2 #6: overwrite the plaintext input file (containing dk_share + r_i in
        // decimal) with zeros IMMEDIATELY after the subprocess exits, regardless of whether
        // we keep the session dir. This prevents operators who set
        // EUNOMA_MPC_KEEP_SESSION_DIRS=1 for debugging from accidentally preserving plaintext
        // secrets on disk. Disarm the RAII guard so Drop is a no-op.
        let _ = zeroize_file_inplace(&input_path);
        input_guard.disarm();

        if !status.success() {
            let trail = String::from_utf8_lossy(&stderr_bytes);
            let excerpt = trail.lines().rev().take(5).collect::<Vec<_>>();
            excerpt.iter().rev().for_each(|_| ());
            let last_lines = trail.lines().rev().take(5).collect::<Vec<_>>().join(" | ");
            cleanup_or_keep(&session_dir, self.keep_session_dirs);
            r_i.zeroize();
            return Err(AdapterError::Internal(format!(
                "mascot-party.x exited {} — stderr tail: {}",
                status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                last_lines
            )));
        }

        // Parse `EUNOMA_VAULT_EK_M=<decimal>` line out of stdout.
        let stdout_text = String::from_utf8_lossy(&stdout_bytes);
        let m_decimal = match find_open_m(&stdout_text) {
            Some(s) => s,
            None => {
                cleanup_or_keep(&session_dir, self.keep_session_dirs);
                r_i.zeroize();
                return Err(AdapterError::Internal(
                    "mascot stdout missing EUNOMA_VAULT_EK_M= line".to_string(),
                ));
            }
        };
        let m = scalar_from_decimal(&m_decimal)?;
        // Discard zero `m` (only possible if dk * r ≡ 0 mod Q; either dk == 0 — corrupt — or
        // r == 0 — should not happen with OsRng). Defense in depth.
        if m == Scalar::ZERO {
            cleanup_or_keep(&session_dir, self.keep_session_dirs);
            r_i.zeroize();
            return Err(AdapterError::Internal(
                "opened m is zero — refusing to invert".to_string(),
            ));
        }
        let m_inv = m.invert();
        let q_i = r_i * m_inv;

        // Compute h * r_i for the public artifact (codex P1 #4). The verifier checks
        // h_q_i * m == h_r_i, which binds q_i to the MPC-opened m and prevents a malicious
        // worker from publishing an arbitrary point. We use the same H_RISTRETTO that the
        // round1 + verify code paths use to make h_q_i. After this scalar-mult, r_i is no
        // longer needed and is zeroized.
        let h = h_ristretto().map_err(|e| AdapterError::Internal(format!("h_ristretto: {e:?}")))?;
        let h_r_i = h * r_i;

        // Hide the unused-by-name placeholder.
        let _self_lambda_unused = self_lambda_decimal;

        // Wipe sensitive material. q_i is still secret — caller is responsible for zeroizing
        // it after producing h_q_i + Schnorr proof.
        r_i.zeroize();

        cleanup_or_keep(&session_dir, self.keep_session_dirs);
        Ok(InversionShare {
            q_i,
            h_r_i,
            mpc_open_m: m,
        })
    }
}

// =================== helpers ===================

/// Ed25519 scalar prime Q in decimal — keep in sync with scripts/_lib/mpc_spdz_constants.mjs
/// and the curve25519-dalek constant. Compile-time string.
const ED25519_SCALAR_PRIME_DECIMAL: &str =
    "7237005577332262213973186563042994240857116359379907606001950938285454250989";

fn ed25519_scalar_prime_biguint() -> BigUint {
    BigUint::parse_decimal(ED25519_SCALAR_PRIME_DECIMAL).expect("Q decimal is valid")
}

/// Returns true iff `s` is non-empty and contains only `[A-Za-z0-9._-]`.
fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
        })
}

/// Codex P2 #6: RAII scrubber for plaintext on-disk secrets.
///
/// Wraps a path written via `write_secret_file` (containing dk_share + r_i in decimal). The
/// guard is "armed" by default; if it is dropped while still armed, Drop overwrites the file
/// with zeros and removes it. Call `disarm` only after an explicit zeroize + truncate has
/// already run on a known-safe code path, so the guard becomes a no-op.
///
/// This closes the residual leak codex P2 #6 (PARTIALLY_CLOSED): previously the explicit
/// zeroize ran on the happy path, the timeout path, and the `try_wait` error path — but a
/// `?` return from any of:
///   - `child.stdout.take()` / `child.stderr.take()` (after spawn, before wait loop)
///   - any other `?` that surfaces after `write_secret_file` but before `zeroize_file_inplace`
/// left the plaintext file on disk. With the guard armed at write time and disarmed only on
/// known-safe paths, every early return — including panics — now scrubs.
pub(crate) struct SecretFileGuard {
    path: PathBuf,
    armed: bool,
}

impl SecretFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort scrub + remove. Errors are swallowed because Drop cannot panic, and the
        // guard is already a defense-in-depth layer over the explicit zeroize calls.
        let _ = zeroize_file_inplace(&self.path);
        let _ = fs::remove_file(&self.path);
    }
}

fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let s = Scalar::from_bytes_mod_order_wide(&bytes);
    bytes.zeroize();
    s
}

fn scalar_from_hex(hex: &str) -> Result<Scalar, AdapterError> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if raw.len() != 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AdapterError::InvalidInput(
            "lagrange coefficient must be 32-byte hex".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|e| AdapterError::InvalidInput(format!("hex parse: {e}")))?;
    }
    Ok(Scalar::from_bytes_mod_order(bytes))
}

fn scalar_from_decimal(s: &str) -> Result<Scalar, AdapterError> {
    // The MASCOT opener may print values in centered representation `(-Q/2, Q/2]` rather than
    // canonical `[0, Q)`. We handle the optional leading sign, parse the absolute value with
    // BigUint, then reduce mod Q (subtracting from Q for negatives).
    let trimmed = s.trim();
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    let abs = BigUint::parse_decimal(body)
        .ok_or_else(|| AdapterError::Internal(format!("EUNOMA_VAULT_EK_M not decimal: {s:?}")))?;
    let q = ed25519_scalar_prime_biguint();
    let reduced_abs = abs.modulo(&q);
    let reduced = if negative {
        if reduced_abs.is_zero() {
            reduced_abs
        } else {
            q.sub(&reduced_abs)
        }
    } else {
        reduced_abs
    };
    let mut le = reduced.to_bytes_le();
    if le.len() > 32 {
        return Err(AdapterError::Internal("opened m too large after reduction".to_string()));
    }
    while le.len() < 32 {
        le.push(0);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&le);
    Ok(Scalar::from_bytes_mod_order(buf))
}

fn scalar_to_decimal(s: &Scalar) -> String {
    // Scalar::to_bytes() is little-endian.
    let le = s.to_bytes();
    let n = BigUint::from_bytes_le(&le);
    n.to_decimal()
}

fn find_open_m(stdout: &str) -> Option<String> {
    // MASCOT prints the opened value as a (possibly negative, centered-representation)
    // decimal scalar. Accept an optional leading `-` followed by ASCII digits.
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("EUNOMA_VAULT_EK_M=") {
            let value = rest.trim();
            if value.is_empty() {
                continue;
            }
            let (sign_prefix, digits) = value
                .strip_prefix('-')
                .map(|d| ("-", d))
                .unwrap_or(("", value));
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                return Some(format!("{sign_prefix}{digits}"));
            }
        }
    }
    None
}

/// Codex P2 #6: overwrite a file's contents with zero bytes of the same length, then
/// truncate. Used to scrub the plaintext MPC input file (dk_share + r_i decimal) after the
/// subprocess exits — guarantees no plaintext secret survives on disk even if the operator
/// kept the session dir for debugging.
fn zeroize_file_inplace(path: &Path) -> Result<(), std::io::Error> {
    use std::fs::OpenOptions;
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };
    let len = metadata.len() as usize;
    let zeros = vec![0u8; len];
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)?;
    file.write_all(&zeros)?;
    file.sync_all()?;
    // Now truncate (defensive: in case the file grew, we still wrote `len` bytes of zeros).
    let _ = OpenOptions::new().write(true).truncate(true).open(path);
    Ok(())
}

fn write_secret_file(path: &Path, contents: &str) -> Result<(), AdapterError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| AdapterError::Internal(format!("open {}: {e}", path.display())))?;
    file.write_all(contents.as_bytes())
        .map_err(|e| AdapterError::Internal(format!("write {}: {e}", path.display())))?;
    Ok(())
}

fn set_dir_mode_700(path: &Path) -> Result<(), AdapterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perm)
            .map_err(|e| AdapterError::Internal(format!("chmod 700 {}: {e}", path.display())))?;
    }
    let _ = path;
    Ok(())
}

fn symlink_or_copy(src: &Path, dst: &Path) -> Result<(), AdapterError> {
    if !src.exists() {
        return Err(AdapterError::Internal(format!(
            "missing source {}",
            src.display()
        )));
    }
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        return symlink(src, dst)
            .map_err(|e| AdapterError::Internal(format!("symlink {} -> {}: {e}", dst.display(), src.display())));
    }
    #[cfg(not(unix))]
    {
        fs::copy(src, dst)
            .map_err(|e| AdapterError::Internal(format!("copy {}: {e}", src.display())))?;
        Ok(())
    }
}

fn link_programs(
    host_programs: &Path,
    session_programs: &Path,
    program_name: &str,
) -> Result<(), AdapterError> {
    let dest_source = session_programs.join("Source");
    let dest_bytecode = session_programs.join("Bytecode");
    let dest_schedule = session_programs.join("Schedules");
    fs::create_dir_all(&dest_source)
        .map_err(|e| AdapterError::Internal(format!("mkdir Programs/Source: {e}")))?;
    fs::create_dir_all(&dest_bytecode)
        .map_err(|e| AdapterError::Internal(format!("mkdir Programs/Bytecode: {e}")))?;
    fs::create_dir_all(&dest_schedule)
        .map_err(|e| AdapterError::Internal(format!("mkdir Programs/Schedules: {e}")))?;
    // Source — for diagnostics
    symlink_or_copy(
        &host_programs.join("Source").join(format!("{program_name}.mpc")),
        &dest_source.join(format!("{program_name}.mpc")),
    )?;
    // Schedule
    symlink_or_copy(
        &host_programs.join("Schedules").join(format!("{program_name}.sch")),
        &dest_schedule.join(format!("{program_name}.sch")),
    )?;
    // Bytecode — link every .bc that starts with our program name (the compiler may emit
    // <program>-0.bc, <program>-1.bc, ...).
    let bc_dir = host_programs.join("Bytecode");
    let entries = fs::read_dir(&bc_dir)
        .map_err(|e| AdapterError::Internal(format!("read_dir {}: {e}", bc_dir.display())))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(&format!("{program_name}-")) && name_str.ends_with(".bc") {
            symlink_or_copy(&entry.path(), &dest_bytecode.join(&*name_str))?;
        }
    }
    Ok(())
}

fn run_c_rehash(player_data: &Path) -> Result<(), ()> {
    // Best-effort. If c_rehash isn't on PATH, OpenSSL's add_verify_path will still scan the
    // dir directly per Networking/ssl_sockets.h.
    let status = Command::new("c_rehash")
        .arg(player_data)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| ())?;
    if status.success() { Ok(()) } else { Err(()) }
}

fn cleanup_or_keep(session_dir: &Path, keep: bool) {
    if keep {
        return;
    }
    let _ = fs::remove_dir_all(session_dir);
}

fn forward_runtime_env(_command: &mut Command) {
    // The mascot-party.x binary links `libSPDZ.so` (MP-SPDZ's internal shared lib) by name,
    // expecting it to live in MP_SPDZ_HOME at runtime. The dyld/ld search list won't include
    // that directory by default. The DYLD_LIBRARY_PATH/LD_LIBRARY_PATH setup happens inline
    // at the call site so the merged value is computed once per call. This hook exists for
    // future per-platform additions (PATH, PYTHONHOME, etc.).
}

fn child_library_path(home: &Path) -> String {
    let mut entries: Vec<String> = Vec::new();
    entries.push(home.to_string_lossy().to_string());
    for prefix in [
        "/opt/homebrew/opt/libsodium/lib",
        "/opt/homebrew/opt/openssl@3/lib",
        "/opt/homebrew/opt/openssl/lib",
        "/opt/homebrew/opt/boost@1.85/lib",
        "/opt/homebrew/opt/boost/lib",
        "/opt/homebrew/opt/gmp/lib",
        "/usr/local/lib",
    ] {
        if std::path::Path::new(prefix).exists() {
            entries.push(prefix.to_string());
        }
    }
    entries.join(":")
}

/// Computes λ_i(0) for the Shamir set { x_j = sorted_slots[j] + 1 }. Pure modular arithmetic
/// over Q. Used to defend against a malicious coordinator submitting forged λ values.
fn compute_lagrange_coefficient_at_zero(
    player_id: usize,
    sorted_slots: &[usize],
) -> Result<Scalar, AdapterError> {
    if player_id >= sorted_slots.len() {
        return Err(AdapterError::InvalidInput(
            "player_id beyond selected_slots".to_string(),
        ));
    }
    let q = ed25519_scalar_prime_biguint();
    let x_i = BigUint::from_u64((sorted_slots[player_id] as u64) + 1);
    let mut num = BigUint::from_u64(1);
    let mut den = BigUint::from_u64(1);
    for (j, slot) in sorted_slots.iter().enumerate() {
        if j == player_id {
            continue;
        }
        let x_j = BigUint::from_u64((*slot as u64) + 1);
        // num *= (-x_j)  mod Q
        let neg_x_j = q.sub_mod(&x_j, &q);
        num = num.mul_mod(&neg_x_j, &q);
        // den *= (x_i - x_j)  mod Q
        let diff = x_i.sub_mod(&x_j, &q);
        den = den.mul_mod(&diff, &q);
    }
    let den_inv = den.pow_mod(&q.sub_mod(&BigUint::from_u64(2), &q), &q);
    let lambda = num.mul_mod(&den_inv, &q);
    let mut le = lambda.to_bytes_le();
    while le.len() < 32 {
        le.push(0);
    }
    if le.len() > 32 {
        return Err(AdapterError::Internal(
            "Lagrange coefficient exceeds 32 bytes after reduction".to_string(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&le);
    Ok(Scalar::from_bytes_mod_order(buf))
}

// =================== tiny BigUint to avoid a new dep ===================
//
// curve25519-dalek 4.x doesn't expose modular bignum arithmetic externally. We need it for
// the Lagrange recompute and for decimal <-> Scalar conversion. Pulling in num-bigint would
// bloat the crate. This little struct uses base-2^32 limbs and supports the operations we
// need over a bounded prime (Q ~ 253 bits ⇒ 8 limbs).

#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint {
    /// Little-endian u32 limbs.
    limbs: Vec<u32>,
}

impl BigUint {
    fn from_u64(v: u64) -> Self {
        let lo = (v & 0xFFFF_FFFF) as u32;
        let hi = (v >> 32) as u32;
        let mut limbs = vec![lo, hi];
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity((bytes.len() + 3) / 4);
        let mut iter = bytes.chunks(4);
        while let Some(chunk) = iter.next() {
            let mut limb = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                limb |= (*b as u32) << (i * 8);
            }
            limbs.push(limb);
        }
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn to_bytes_le(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for limb in &self.limbs {
            out.push((*limb & 0xFF) as u8);
            out.push(((*limb >> 8) & 0xFF) as u8);
            out.push(((*limb >> 16) & 0xFF) as u8);
            out.push(((*limb >> 24) & 0xFF) as u8);
        }
        while out.len() > 1 && *out.last().unwrap() == 0 {
            out.pop();
        }
        out
    }
    fn to_decimal(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let mut digits = Vec::new();
        let mut n = self.clone();
        let ten = BigUint::from_u64(10);
        while !n.is_zero() {
            let (q, r) = n.div_mod_small(10);
            digits.push(b'0' + r as u8);
            n = q;
        }
        digits.reverse();
        // Suppress unused warning
        let _ = ten;
        String::from_utf8(digits).unwrap()
    }
    fn parse_decimal(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut n = BigUint::from_u64(0);
        let ten = BigUint::from_u64(10);
        for ch in s.chars() {
            if !ch.is_ascii_digit() {
                return None;
            }
            let d = (ch as u32) - ('0' as u32);
            n = n.mul_small(10);
            n = n.add(&BigUint::from_u64(d as u64));
        }
        let _ = ten;
        Some(n)
    }
    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|l| *l == 0)
    }
    fn normalize(limbs: &mut Vec<u32>) {
        while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
            limbs.pop();
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
    }
    fn cmp(a: &Self, b: &Self) -> std::cmp::Ordering {
        if a.limbs.len() != b.limbs.len() {
            return a.limbs.len().cmp(&b.limbs.len());
        }
        for i in (0..a.limbs.len()).rev() {
            if a.limbs[i] != b.limbs[i] {
                return a.limbs[i].cmp(&b.limbs[i]);
            }
        }
        std::cmp::Ordering::Equal
    }
    fn add(&self, b: &Self) -> Self {
        let n = std::cmp::max(self.limbs.len(), b.limbs.len());
        let mut limbs = Vec::with_capacity(n + 1);
        let mut carry: u64 = 0;
        for i in 0..n {
            let a = *self.limbs.get(i).unwrap_or(&0) as u64;
            let c = *b.limbs.get(i).unwrap_or(&0) as u64;
            let sum = a + c + carry;
            limbs.push((sum & 0xFFFF_FFFF) as u32);
            carry = sum >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn sub(&self, b: &Self) -> Self {
        // Caller guarantees self >= b.
        let n = self.limbs.len();
        let mut limbs = Vec::with_capacity(n);
        let mut borrow: i64 = 0;
        for i in 0..n {
            let a = self.limbs[i] as i64;
            let c = *b.limbs.get(i).unwrap_or(&0) as i64;
            let diff = a - c - borrow;
            if diff < 0 {
                limbs.push((diff + (1 << 32)) as u32);
                borrow = 1;
            } else {
                limbs.push(diff as u32);
                borrow = 0;
            }
        }
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn mul_small(&self, m: u32) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry: u64 = 0;
        for limb in &self.limbs {
            let prod = (*limb as u64) * (m as u64) + carry;
            limbs.push((prod & 0xFFFF_FFFF) as u32);
            carry = prod >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn div_mod_small(&self, d: u32) -> (Self, u32) {
        let mut limbs = vec![0u32; self.limbs.len()];
        let mut rem: u64 = 0;
        for i in (0..self.limbs.len()).rev() {
            let acc = (rem << 32) | (self.limbs[i] as u64);
            limbs[i] = (acc / (d as u64)) as u32;
            rem = acc % (d as u64);
        }
        Self::normalize(&mut limbs);
        (BigUint { limbs }, rem as u32)
    }
    fn sub_mod(&self, b: &Self, m: &Self) -> Self {
        // (self - b) mod m, accepting self < b.
        if Self::cmp(self, b).is_ge() {
            let d = self.sub(b);
            if Self::cmp(&d, m).is_ge() {
                d.modulo(m)
            } else {
                d
            }
        } else {
            // (m - (b - self) mod m)
            let diff = b.sub(self);
            let r = diff.modulo(m);
            if r.is_zero() {
                r
            } else {
                m.sub(&r)
            }
        }
    }
    fn mul_mod(&self, b: &Self, m: &Self) -> Self {
        let mut acc = BigUint::from_u64(0);
        // Schoolbook multiply then mod (operands < 2^256 so result < 2^512; folding mod m at
        // each limb keeps memory bounded).
        for (i, limb) in b.limbs.iter().enumerate() {
            if *limb == 0 {
                continue;
            }
            let shifted = self.shl_limbs(i);
            let partial = shifted.mul_small(*limb);
            acc = acc.add(&partial);
        }
        acc.modulo(m)
    }
    fn shl_limbs(&self, n: usize) -> Self {
        let mut limbs = vec![0u32; n];
        limbs.extend_from_slice(&self.limbs);
        Self::normalize(&mut limbs);
        BigUint { limbs }
    }
    fn modulo(&self, m: &Self) -> Self {
        // Slow but correct: subtract shifted m until the result is < m.
        let mut r = self.clone();
        while Self::cmp(&r, m).is_ge() {
            let bits_r = r.bit_len();
            let bits_m = m.bit_len();
            let shift = bits_r.saturating_sub(bits_m);
            let mut shifted = m.clone();
            // Multiply m by 2^shift (using mul_small in chunks).
            let mut remaining = shift;
            while remaining > 0 {
                let chunk = std::cmp::min(remaining, 31);
                shifted = shifted.mul_small(1u32 << chunk);
                remaining -= chunk;
            }
            if Self::cmp(&r, &shifted).is_ge() {
                r = r.sub(&shifted);
            } else {
                // Back off by one bit if we overshot.
                let half = shifted.div_mod_small(2).0;
                if Self::cmp(&r, &half).is_ge() {
                    r = r.sub(&half);
                } else {
                    // shouldn't happen; safety net to avoid infinite loop
                    break;
                }
            }
        }
        r
    }
    fn pow_mod(&self, exp: &Self, m: &Self) -> Self {
        let mut result = BigUint::from_u64(1);
        let mut base = self.modulo(m);
        let mut e = exp.clone();
        let zero = BigUint::from_u64(0);
        let two = BigUint::from_u64(2);
        while Self::cmp(&e, &zero).is_gt() {
            let (q, r) = e.div_mod_small(2);
            if r == 1 {
                result = result.mul_mod(&base, m);
            }
            base = base.mul_mod(&base, m);
            e = q;
            let _ = two;
        }
        result
    }
    fn bit_len(&self) -> usize {
        let mut bits = self.limbs.len() * 32;
        for &limb in self.limbs.iter().rev() {
            if limb == 0 {
                bits -= 32;
            } else {
                bits -= (limb.leading_zeros()) as usize;
                break;
            }
        }
        bits
    }
}

#[cfg(test)]
mod inner_tests {
    use super::*;

    #[test]
    fn biguint_roundtrip_decimal() {
        let cases = ["0", "1", "12345", ED25519_SCALAR_PRIME_DECIMAL];
        for s in cases {
            let n = BigUint::parse_decimal(s).expect("parse");
            assert_eq!(n.to_decimal(), s);
        }
    }

    #[test]
    fn lagrange_lowest5_sums_to_value_at_zero() {
        // For S = [0,1,2,3,4], λ_i values reconstruct f(0) for any degree-4 polynomial.
        let slots = [0usize, 1, 2, 3, 4];
        let mut lambdas: Vec<Scalar> = Vec::new();
        for i in 0..5 {
            lambdas.push(compute_lagrange_coefficient_at_zero(i, &slots).unwrap());
        }
        // f(x) = 7 + 3x + 9x^2 + 11x^3 + 5x^4 mod Q. Reconstruct f(0) = 7.
        let f0 = Scalar::from(7u64);
        let coeffs: [Scalar; 5] = [
            Scalar::from(7u64),
            Scalar::from(3u64),
            Scalar::from(9u64),
            Scalar::from(11u64),
            Scalar::from(5u64),
        ];
        let mut acc = Scalar::ZERO;
        for (i, slot) in slots.iter().enumerate() {
            let x = Scalar::from((slot + 1) as u64);
            // Horner
            let mut fx = coeffs[4];
            for k in (0..4).rev() {
                fx = fx * x + coeffs[k];
            }
            acc += lambdas[i] * fx;
        }
        assert_eq!(acc, f0);
    }

    #[test]
    fn find_open_m_picks_first_valid_line() {
        let stdout = "Compiler messages\nEUNOMA_VAULT_EK_M=42\nTrailing\n";
        assert_eq!(find_open_m(stdout).as_deref(), Some("42"));
    }

    #[test]
    fn find_open_m_missing_returns_none() {
        let stdout = "no marker here\n";
        assert!(find_open_m(stdout).is_none());
    }

    #[test]
    fn secret_file_guard_scrubs_on_drop_when_armed() {
        // Codex P2 #6 RAII: an armed guard going out of scope must zero + remove the file.
        let dir = std::env::temp_dir().join(format!(
            "eunoma-guard-armed-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Input-P0-0");
        let plaintext = b"123456789\n123456789\n";
        fs::write(&path, plaintext).unwrap();
        assert_eq!(fs::read(&path).unwrap(), plaintext);
        {
            let _guard = SecretFileGuard::new(path.clone());
            // guard is armed; drop will scrub
        }
        // After drop, the file must be gone.
        assert!(!path.exists(), "armed guard must remove file on drop");
    }

    #[test]
    fn secret_file_guard_disarmed_leaves_file() {
        // Codex P2 #6: a disarmed guard MUST be a no-op so the explicit zeroize on the
        // happy/known-error paths doesn't double-scrub or remove something it shouldn't.
        let dir = std::env::temp_dir().join(format!(
            "eunoma-guard-disarmed-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Input-P0-0");
        let plaintext = b"abc\n";
        fs::write(&path, plaintext).unwrap();
        {
            let mut guard = SecretFileGuard::new(path.clone());
            guard.disarm();
        }
        // File must still exist (the caller already explicitly handled scrubbing).
        assert!(path.exists(), "disarmed guard must not delete file");
        // Clean up.
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn secret_file_guard_panic_safety_scrubs_anyway() {
        // Codex P2 #6: if a panic unwinds the stack between `write_secret_file` and the
        // explicit zeroize, Drop still scrubs. Use catch_unwind to capture the unwinding
        // safely inside the test.
        let dir = std::env::temp_dir().join(format!(
            "eunoma-guard-panic-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Input-P0-0");
        let plaintext = b"42\n";
        fs::write(&path, plaintext).unwrap();
        let path_clone = path.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = SecretFileGuard::new(path_clone);
            panic!("simulated mid-flow failure");
        }));
        assert!(result.is_err(), "test scenario must panic");
        assert!(!path.exists(), "Drop must scrub even when panic unwinds");
    }

}
