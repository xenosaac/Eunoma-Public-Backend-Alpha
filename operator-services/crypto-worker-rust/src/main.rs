use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use eunoma_crypto_worker::ca_dkg_v2::{init_hpke_local, run_round as run_ca_dkg_v2_round, CaDkgV2RoundRequest};
use eunoma_crypto_worker::ca_local::{
    aggregate_registration_commitment, aggregate_registration_proof, ca_state_summary,
    create_registration_nonce_commitment, create_registration_partial_response,
    init_ca_dkg_local, load_ca_share, registration_challenge, RegistrationCommitmentInput,
    RegistrationResponseInput,
};
use eunoma_crypto_worker::frost_dkg_v2::{
    run_round as run_frost_dkg_v2_round, FrostDkgV2Roster, FrostDkgV2RoundRequest,
    FrostRound1Broadcast, FrostRound2Envelope,
};
use eunoma_crypto_worker::local_state::{
    aggregate_frost_signature, create_frost_nonce_commitment, create_frost_partial_signature,
    default_state_dir, init_frost_local, state_summary, FrostCommitmentInput,
    FrostSignatureShareInput,
};
use eunoma_crypto_worker::mpc_inverse_adapter::{MpcInverseAdapter, UnavailableMpcInverseAdapter};
use eunoma_crypto_worker::mpc_spdz_adapter::MpcSpdzInverseAdapter;
use eunoma_crypto_worker::vault_ek_derivation_v2::{
    run_round0 as run_vault_ek_round0, run_round1 as run_vault_ek_round1,
    run_verify as run_vault_ek_verify, Round0Request, Round1Request, VerifyRequest,
};
use eunoma_crypto_worker::ca_registration_v2::{
    aggregate_commitments_v2, challenge_v2, create_registration_nonce_commitment_v2,
    create_registration_partial_response_v2, run_aggregate_v2 as run_ca_registration_v2_aggregate,
    run_verify_v2 as run_ca_registration_v2_verify, AggregateRequest as CaRegistrationV2AggregateRequest,
    Round1Request as CaRegistrationV2Round1Request,
    Round2Request as CaRegistrationV2Round2Request, VerifyRequest as CaRegistrationV2VerifyRequest,
};
use eunoma_crypto_worker::vault_state_v2::{
    finalize_vault_state_v2 as run_vault_state_v2_finalize,
    init_vault_state_v2 as run_vault_state_v2_init,
    observe_deposit_v2 as run_vault_state_v2_observe_deposit,
    FinalizeRequest as VaultStateV2FinalizeRequest,
    InitRequest as VaultStateV2InitRequest,
    ObserveDepositRequest as VaultStateV2ObserveDepositRequest,
};
use eunoma_crypto_worker::mpcca_withdraw_v2::{
    last_persisted_round_state as mpcca_last_persisted_round_state,
    mpcca_withdraw_session_dir,
    run_finalize_v2 as run_mpcca_withdraw_finalize_v2,
    run_prove_v2 as run_mpcca_withdraw_prove_v2,
    run_round1_v2 as run_mpcca_withdraw_round1_v2,
    run_round2_v2 as run_mpcca_withdraw_round2_v2,
    ChainedRoundRequest as MpccaWithdrawChainedRoundRequest,
    Round1Request as MpccaWithdrawRound1Request,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone)]
struct AppState {
    slot: usize,
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "init-frost-local") {
        args.remove(0);
        run_init_frost_local(args);
        return;
    }
    if args.first().is_some_and(|arg| arg == "init-ca-local") {
        args.remove(0);
        run_init_ca_local(args);
        return;
    }
    if args.first().is_some_and(|arg| arg == "init-ca-dkg-v2-hpke-local") {
        args.remove(0);
        run_init_ca_dkg_v2_hpke_local(args);
        return;
    }

    let host = std::env::var("CRYPTO_WORKER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("CRYPTO_WORKER_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(4400);
    let slot = std::env::var("CRYPTO_WORKER_SLOT")
        .or_else(|_| std::env::var("DEOPERATOR_SLOT"))
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);
    let state_dir = std::env::var("CRYPTO_WORKER_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_state_dir(slot).expect("valid CRYPTO_WORKER_SLOT"));
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .expect("valid CRYPTO_WORKER_HOST/CRYPTO_WORKER_PORT");
    assert_loopback(&addr);
    let app_state = AppState { slot, state_dir };

    let app = Router::new()
        .route("/worker/v2/health", get(health))
        .route("/worker/v2/local/state", get(local_state))
        .route("/worker/v2/session-share", post(fail_closed))
        .route("/worker/v2/dkg/ca/start", post(ca_dkg_start))
        .route("/worker/v2/dkg/frost/start", post(frost_dkg_start))
        .route(
            "/worker/v2/dkg/:protocol/:round",
            post(dkg_round),
        )
        // Codex M3a P3: the legacy generic MPCCA route was removed. Its only crypto path
        // was `load_ca_share(&state.state_dir)` which crosses the `ca_local` trusted-party
        // surface — a violation of the V2 invariant that production code must not import
        // from ca_local. The new MPCCA withdraw lives at
        // `/worker/v2/mpcca/withdraw/{round1,round2,prove,finalize}` (registered below)
        // and never touches ca_local.
        .route(
            "/worker/v2/ca/registration/nonce-commit",
            post(ca_registration_nonce_commit),
        )
        .route(
            "/worker/v2/ca/registration/challenge",
            post(ca_registration_challenge),
        )
        .route(
            "/worker/v2/ca/registration/partial",
            post(ca_registration_partial),
        )
        .route(
            "/worker/v2/ca/registration/aggregate",
            post(ca_registration_aggregate),
        )
        .route("/worker/v2/deposit/bind", post(fail_closed))
        .route("/worker/v2/withdraw/ca-payload", post(fail_closed))
        .route("/worker/v2/attestation/partial", post(fail_closed))
        .route(
            "/worker/v2/frost/sign/nonce-commit",
            post(frost_nonce_commit),
        )
        .route("/worker/v2/frost/sign/partial", post(frost_partial_sign))
        .route("/worker/v2/frost/sign/aggregate", post(frost_aggregate))
        .route("/worker/v2/derive/vault_ek/round0", post(vault_ek_round0))
        .route("/worker/v2/derive/vault_ek/round1", post(vault_ek_round1))
        .route("/worker/v2/derive/vault_ek/verify", post(vault_ek_verify))
        .route(
            "/worker/v2/derive/ca_registration/round1",
            post(ca_registration_v2_round1),
        )
        .route(
            "/worker/v2/derive/ca_registration/round2",
            post(ca_registration_v2_round2),
        )
        // Codex P1 #2: interim aggregation endpoint — returns aggregateCommitment +
        // challenge ONLY (no responses required). Coordinator needs the challenge BEFORE
        // round2; the share-independent /aggregate endpoint also runs verify, which
        // requires responses, so it can't be used here. Replaces the V1
        // `/worker/v2/ca/registration/challenge` route the coordinator was calling — that
        // route is not in the deop-node allowlist so production V2 stalled at round2.
        .route(
            "/worker/v2/derive/ca_registration/challenge",
            post(ca_registration_v2_challenge),
        )
        .route(
            "/worker/v2/derive/ca_registration/verify",
            post(ca_registration_v2_verify),
        )
        .route(
            "/worker/v2/derive/ca_registration/aggregate",
            post(ca_registration_v2_aggregate),
        )
        // Milestone 2a — per-worker vault-state share initialisation. Bound to (Phase 2
        // vault_ek, Milestone 1 sigma tuple, CA DKG V2 share metadata). No secret material on
        // the wire; the worker re-verifies the Milestone 1 public equation before persisting.
        .route(
            "/worker/v2/vault_state/init",
            post(vault_state_v2_init),
        )
        // Codex M3a P1 (regression fix): vault_state_v2 init finalize. Coordinator fans this
        // round out AFTER collecting all 5 per-slot init contributions + computing the FINAL
        // transcript hash. Each worker re-derives the final hash locally, asserts byte-
        // equality with the coordinator's claim, then UPDATES its persisted
        // `vault_state_v2.json` to pin `init_transcript_hash = finalTranscriptHash`. This is
        // the ONLY value MPCCA withdraw rounds will accept downstream — without this round,
        // the coordinator's request body's `vaultStateInitTranscriptHash` (= the final hash)
        // would NEVER match a worker's persisted per-slot init hash, and every legitimate
        // withdraw would fail closed with `vault_state_init_transcript_hash_mismatch`.
        .route(
            "/worker/v2/vault_state/init/finalize",
            post(vault_state_v2_init_finalize),
        )
        // Milestone 2b — confirmed-deposit observer. Strict cursor monotonicity over the
        // worker's persisted deposit_count_observed counter. No secret material on the wire.
        .route(
            "/worker/v2/vault_state/observe_deposit",
            post(vault_state_v2_observe_deposit),
        )
        // Milestone 3a — MPCCA withdraw state machine scaffolding. Each per-round handler does
        // the FULL public binding work (id safety, hex normalisation, provenance gate against
        // vault_state_v2.json, vault_sequence gate, Milestone 1 sigma re-verify) BEFORE
        // returning NotImplemented with a per-round phase string. Milestone 4 fills the crypto
        // in without re-touching the public binding.
        .route(
            "/worker/v2/mpcca/withdraw/round1",
            post(mpcca_withdraw_round1),
        )
        .route(
            "/worker/v2/mpcca/withdraw/round2",
            post(mpcca_withdraw_round2),
        )
        .route(
            "/worker/v2/mpcca/withdraw/prove",
            post(mpcca_withdraw_prove),
        )
        .route(
            "/worker/v2/mpcca/withdraw/finalize",
            post(mpcca_withdraw_finalize),
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind crypto worker");
    println!("eunoma crypto worker slot {slot} listening on {addr}");
    axum::serve(listener, app)
        .await
        .expect("serve crypto worker");
}

fn run_init_frost_local(args: Vec<String>) {
    let mut state_root = PathBuf::from(".agent-local/eunoma-v2");
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state-root" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--state-root requires a path");
                    std::process::exit(2);
                };
                state_root = PathBuf::from(raw);
            }
            "--force" => force = true,
            other => {
                eprintln!("unknown init-frost-local arg: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    match init_frost_local(&state_root, force)
        .and_then(|summary| serde_json::to_string_pretty(&summary).map_err(|err| {
            eunoma_crypto_worker::WorkerError::Serde(err.to_string())
        }))
    {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("init-frost-local failed: {err:?}");
            std::process::exit(1);
        }
    }
}

fn run_init_ca_local(args: Vec<String>) {
    let mut state_root = PathBuf::from(".agent-local/eunoma-v2");
    let mut dkg_epoch = "1".to_string();
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state-root" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--state-root requires a path");
                    std::process::exit(2);
                };
                state_root = PathBuf::from(raw);
            }
            "--dkg-epoch" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--dkg-epoch requires a value");
                    std::process::exit(2);
                };
                dkg_epoch = raw.clone();
            }
            "--force" => force = true,
            other => {
                eprintln!("unknown init-ca-local arg: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    match init_ca_dkg_local(&state_root, &dkg_epoch, force)
        .and_then(|summary| serde_json::to_string_pretty(&summary).map_err(|err| {
            eunoma_crypto_worker::WorkerError::Serde(err.to_string())
        }))
    {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("init-ca-local failed: {err:?}");
            std::process::exit(1);
        }
    }
}

fn run_init_ca_dkg_v2_hpke_local(args: Vec<String>) {
    let mut state_root = PathBuf::from(".agent-local/eunoma-v2");
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state-root" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--state-root requires a path");
                    std::process::exit(2);
                };
                state_root = PathBuf::from(raw);
            }
            "--force" => force = true,
            other => {
                eprintln!("unknown init-ca-dkg-v2-hpke-local arg: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    match init_hpke_local(&state_root, force)
        .and_then(|summary| serde_json::to_string_pretty(&summary).map_err(|err| {
            eunoma_crypto_worker::WorkerError::Serde(err.to_string())
        }))
    {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("init-ca-dkg-v2-hpke-local failed: {err:?}");
            std::process::exit(1);
        }
    }
}

fn assert_loopback(addr: &SocketAddr) {
    if !addr.ip().is_loopback() {
        panic!("crypto worker must bind to a loopback address for local MVP");
    }
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "eunoma-crypto-worker",
        "threshold": eunoma_crypto_worker::DEOPERATOR_THRESHOLD,
        "count": eunoma_crypto_worker::DEOPERATOR_COUNT,
        "cryptoStatus": "local_frost_and_ca_dkg_enabled_mpcca_round1_round2_only"
    }))
}

async fn local_state(State(state): State<AppState>) -> impl IntoResponse {
    match state_summary(state.slot, &state.state_dir) {
        Ok(summary) => {
            let ca = ca_state_summary(state.slot, &state.state_dir).ok();
            (StatusCode::OK, Json(json!({
                "slot": summary.slot,
                "state_dir": summary.state_dir,
                "has_frost_key_package": summary.has_frost_key_package,
                "has_frost_public_package": summary.has_frost_public_package,
                "frost_key_package_hash": summary.frost_key_package_hash,
                "frost_public_package_hash": summary.frost_public_package_hash,
                "pending_frost_nonces": summary.pending_frost_nonces,
                "has_ca_dkg_share": ca.as_ref().is_some_and(|item| item.has_ca_dkg_share),
                "ca_dkg_share_hash": ca.as_ref().and_then(|item| item.ca_dkg_share_hash.clone()),
                "ca_dkg_transcript_hash": ca.as_ref().and_then(|item| item.ca_dkg_transcript_hash.clone()),
                "vault_ek": ca.as_ref().and_then(|item| item.vault_ek.clone()),
                "pending_registration_nonces": ca.as_ref().map(|item| item.pending_registration_nonces).unwrap_or(0),
            })))
        }
        Err(err) => worker_error_response(err),
    }
}

async fn fail_closed(Json(_body): Json<Value>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "message": "This worker endpoint is gated until its audited implementation lands"
        })),
    )
}

#[derive(Debug, Deserialize)]
struct CaDkgStartRequest {
    #[serde(rename = "operatorSetVersion")]
    operator_set_version: String,
    #[serde(rename = "dkgEpoch")]
    dkg_epoch: String,
    #[serde(rename = "rosterHash")]
    roster_hash: String,
}

async fn ca_dkg_start(
    State(state): State<AppState>,
    Json(body): Json<CaDkgStartRequest>,
) -> impl IntoResponse {
    match load_ca_share(&state.state_dir) {
        Ok(share) => {
            if share.dkg_epoch != body.dkg_epoch {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "message": "dkgEpoch does not match local CA DKG share"
                    })),
                );
            }
            let transcript_hash = hash_hex(&[
                b"EUNOMA_CA_DKG_START_V1".as_slice(),
                body.operator_set_version.as_bytes(),
                body.dkg_epoch.as_bytes(),
                body.roster_hash.as_bytes(),
                share.transcript_hash.as_bytes(),
            ]);
            (
                StatusCode::OK,
                Json(json!({
                    "dkgEpoch": share.dkg_epoch,
                    "vaultEkShare": share.public_share,
                    "vaultEk": share.vault_ek,
                    "transcriptHash": transcript_hash,
                    "caDkgTranscriptHash": share.transcript_hash
                })),
            )
        }
        Err(err) => worker_error_response(err),
    }
}

#[derive(Debug, Deserialize)]
struct FrostDkgStartRequest {
    #[serde(rename = "operatorSetVersion")]
    operator_set_version: String,
    #[serde(rename = "dkgEpoch")]
    dkg_epoch: String,
    #[serde(rename = "frostDkgV2RosterHash", default)]
    frost_dkg_v2_roster_hash: Option<String>,
}

async fn frost_dkg_start(
    State(state): State<AppState>,
    Json(body): Json<FrostDkgStartRequest>,
) -> impl IntoResponse {
    let manifest_path = state.state_dir.join("frost_state_manifest.json");
    let bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            let kind = err.kind();
            let mapped = if kind == std::io::ErrorKind::NotFound {
                eunoma_crypto_worker::WorkerError::MissingLocalState(manifest_path.display().to_string())
            } else {
                eunoma_crypto_worker::WorkerError::Io(err.to_string())
            };
            return worker_error_response(mapped);
        }
    };
    let manifest: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(err) => return worker_error_response(eunoma_crypto_worker::WorkerError::Serde(err.to_string())),
    };
    let group_public_key = manifest
        .get("groupPublicKey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let frost_verifying_share = manifest
        .get("frostVerifyingShare")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let dkg_epoch = manifest
        .get("dkgEpoch")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| body.dkg_epoch.clone());
    let roster_hash = body
        .frost_dkg_v2_roster_hash
        .clone()
        .unwrap_or_else(|| "".to_string());
    let transcript_hash = hash_hex(&[
        b"EUNOMA_FROST_DKG_START_V1".as_slice(),
        body.operator_set_version.as_bytes(),
        dkg_epoch.as_bytes(),
        roster_hash.as_bytes(),
        group_public_key.as_bytes(),
    ]);
    (
        StatusCode::OK,
        Json(json!({
            "dkgEpoch": dkg_epoch,
            "frostVerifyingShare": frost_verifying_share,
            "groupPublicKey": group_public_key,
            "transcriptHash": transcript_hash,
        })),
    )
}

#[derive(Debug, Deserialize)]
struct FrostNonceCommitRequest {
    #[serde(rename = "requestId")]
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct FrostPartialSignRequest {
    #[serde(rename = "nonceId")]
    nonce_id: String,
    #[serde(rename = "messageBytes")]
    message_bytes: String,
    commitments: Vec<FrostCommitmentInput>,
}

#[derive(Debug, Deserialize)]
struct FrostAggregateRequest {
    #[serde(rename = "messageBytes")]
    message_bytes: String,
    commitments: Vec<FrostCommitmentInput>,
    #[serde(rename = "signatureShares")]
    signature_shares: Vec<FrostSignatureShareInput>,
}

async fn frost_nonce_commit(
    State(state): State<AppState>,
    Json(body): Json<FrostNonceCommitRequest>,
) -> impl IntoResponse {
    match create_frost_nonce_commitment(&state.state_dir, &body.request_id) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn frost_partial_sign(
    State(state): State<AppState>,
    Json(body): Json<FrostPartialSignRequest>,
) -> impl IntoResponse {
    match create_frost_partial_signature(
        &state.state_dir,
        &body.nonce_id,
        &body.message_bytes,
        body.commitments,
    ) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn frost_aggregate(
    State(state): State<AppState>,
    Json(body): Json<FrostAggregateRequest>,
) -> impl IntoResponse {
    match aggregate_frost_signature(
        &state.state_dir,
        &body.message_bytes,
        body.commitments,
        body.signature_shares,
    ) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

#[derive(Debug, Deserialize)]
struct DkgRoundBody {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "operatorSetVersion")]
    operator_set_version: String,
    #[serde(rename = "dkgEpoch")]
    dkg_epoch: String,
    #[serde(rename = "rosterHash", default)]
    roster_hash: Option<String>,
    slot: usize,
    threshold: usize,
    #[serde(rename = "participantSlots")]
    participant_slots: Vec<usize>,
    #[serde(rename = "transcriptHash")]
    transcript_hash: Option<String>,
    #[serde(rename = "caDkgScheme")]
    ca_dkg_scheme: Option<String>,
    #[serde(rename = "caDkgV2Roster")]
    ca_dkg_v2_roster: Option<eunoma_crypto_worker::ca_dkg_v2::CaDkgV2Roster>,
    #[serde(default, rename = "dealerBroadcasts")]
    dealer_broadcasts: Vec<eunoma_crypto_worker::ca_dkg_v2::DealerBroadcast>,
    #[serde(default, rename = "encryptedShares")]
    encrypted_shares: Vec<eunoma_crypto_worker::ca_dkg_v2::EncryptedDkgShare>,
    #[serde(rename = "frostDkgV2Roster")]
    frost_dkg_v2_roster: Option<FrostDkgV2Roster>,
    #[serde(rename = "frostDkgV2RosterHash")]
    frost_dkg_v2_roster_hash: Option<String>,
    #[serde(default, rename = "frostRound1Broadcasts")]
    frost_round1_broadcasts: Vec<FrostRound1Broadcast>,
    #[serde(default, rename = "frostRound2Envelopes")]
    frost_round2_envelopes: Vec<FrostRound2Envelope>,
    complaint: Option<Value>,
}

async fn dkg_round(
    State(state): State<AppState>,
    Path((protocol, round)): Path<(String, String)>,
    Json(body): Json<DkgRoundBody>,
) -> impl IntoResponse {
    if protocol != "ca" && protocol != "frost" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "not_implemented",
                "protocol": protocol,
                "round": round,
                "message": "unsupported DKG protocol"
            })),
        );
    }
    if body.slot != state.slot {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "message": "slot mismatch" })),
        );
    }
    if body.threshold != eunoma_crypto_worker::DEOPERATOR_THRESHOLD
        || body.participant_slots.len() != eunoma_crypto_worker::DEOPERATOR_COUNT
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bad_threshold" })),
        );
    }
    if protocol == "frost" {
        let roster_hash = body.frost_dkg_v2_roster_hash.unwrap_or_default();
        let request = FrostDkgV2RoundRequest {
            request_id: body.request_id,
            session_id: body.session_id,
            round: round.clone(),
            operator_set_version: body.operator_set_version,
            dkg_epoch: body.dkg_epoch,
            frost_dkg_v2_roster_hash: roster_hash,
            threshold: body.threshold,
            participant_slots: body.participant_slots,
            slot: body.slot,
            frost_dkg_v2_roster: body.frost_dkg_v2_roster,
            frost_round1_broadcasts: body.frost_round1_broadcasts,
            frost_round2_envelopes: body.frost_round2_envelopes,
            transcript_hash: body.transcript_hash,
            complaint: body.complaint,
        };
        return match run_frost_dkg_v2_round(&state.state_dir, request) {
            Ok(result) => (StatusCode::ACCEPTED, Json(json!(result))),
            Err(err) => worker_error_response(err),
        };
    }
    let roster_hash = body.roster_hash.clone().unwrap_or_default();
    if body.ca_dkg_scheme.as_deref() == Some("ca_dkg_v2")
        || body.ca_dkg_v2_roster.is_some()
        || !body.dealer_broadcasts.is_empty()
    {
        let request = CaDkgV2RoundRequest {
            request_id: body.request_id,
            session_id: body.session_id,
            round: round.clone(),
            operator_set_version: body.operator_set_version,
            dkg_epoch: body.dkg_epoch,
            roster_hash,
            threshold: body.threshold,
            participant_slots: body.participant_slots,
            slot: body.slot,
            ca_dkg_v2_roster: body.ca_dkg_v2_roster,
            dealer_broadcasts: body.dealer_broadcasts,
            encrypted_shares: body.encrypted_shares,
            transcript_hash: body.transcript_hash,
        };
        return match run_ca_dkg_v2_round(&state.state_dir, request) {
            Ok(result) => (StatusCode::ACCEPTED, Json(json!(result))),
            Err(err) => worker_error_response(err),
        };
    }
    match load_ca_share(&state.state_dir) {
        Ok(share) => {
            if share.dkg_epoch != body.dkg_epoch {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "message": "dkgEpoch does not match local CA DKG share"
                    })),
                );
            }
            let transcript_hash = body.transcript_hash.unwrap_or_else(|| share.transcript_hash.clone());
            let artifact_hash = hash_hex(&[
                b"EUNOMA_CA_DKG_ROUND_ARTIFACT_V1".as_slice(),
                body.request_id.as_bytes(),
                body.session_id.as_bytes(),
                body.operator_set_version.as_bytes(),
                body.dkg_epoch.as_bytes(),
                protocol.as_bytes(),
                round.as_bytes(),
                transcript_hash.as_bytes(),
                share.public_share.as_bytes(),
            ]);
            let abort_evidence_hash = body.complaint.as_ref().map(|complaint| {
                hash_hex(&[
                    b"EUNOMA_CA_DKG_COMPLAINT_V1".as_slice(),
                    serde_json::to_string(complaint).unwrap_or_default().as_bytes(),
                ])
            });
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "requestId": body.request_id,
                    "sessionId": body.session_id,
                    "protocol": protocol,
                    "round": round,
                    "operatorSetVersion": body.operator_set_version,
                    "dkgEpoch": body.dkg_epoch,
                    "slot": state.slot,
                    "accepted": true,
                    "transcriptHash": transcript_hash,
                    "artifactHash": artifact_hash,
                    "publicShare": share.public_share,
                    "groupPublicKey": share.vault_ek,
                    "abortEvidenceHash": abort_evidence_hash
                })),
            )
        }
        Err(err) => worker_error_response(err),
    }
}

#[derive(Debug, Deserialize)]
struct CaRegistrationNonceRequest {
    #[serde(rename = "requestId")]
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct CaRegistrationChallengeRequest {
    #[serde(rename = "vaultEk")]
    vault_ek: String,
    #[serde(rename = "senderAddress")]
    sender_address: String,
    #[serde(rename = "assetType")]
    asset_type: String,
    #[serde(rename = "chainId")]
    chain_id: u8,
    commitments: Vec<RegistrationCommitmentInput>,
}

#[derive(Debug, Deserialize)]
struct CaRegistrationPartialRequest {
    #[serde(rename = "nonceId")]
    nonce_id: String,
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct CaRegistrationAggregateRequest {
    #[serde(rename = "vaultEk")]
    vault_ek: String,
    #[serde(rename = "senderAddress")]
    sender_address: String,
    #[serde(rename = "assetType")]
    asset_type: String,
    #[serde(rename = "chainId")]
    chain_id: u8,
    commitments: Vec<RegistrationCommitmentInput>,
    responses: Vec<RegistrationResponseInput>,
}

async fn ca_registration_nonce_commit(
    State(state): State<AppState>,
    Json(body): Json<CaRegistrationNonceRequest>,
) -> impl IntoResponse {
    match create_registration_nonce_commitment(&state.state_dir, &body.request_id) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_challenge(
    Json(body): Json<CaRegistrationChallengeRequest>,
) -> impl IntoResponse {
    match aggregate_registration_commitment(&body.commitments).and_then(|commitment| {
        registration_challenge(
            &body.vault_ek,
            &body.sender_address,
            &body.asset_type,
            body.chain_id,
            &commitment,
        )
        .map(|challenge| (commitment, challenge))
    }) {
        Ok((aggregate_commitment, challenge)) => (
            StatusCode::OK,
            Json(json!({
                "aggregateCommitment": aggregate_commitment,
                "challenge": challenge
            })),
        ),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_partial(
    State(state): State<AppState>,
    Json(body): Json<CaRegistrationPartialRequest>,
) -> impl IntoResponse {
    match create_registration_partial_response(&state.state_dir, &body.nonce_id, &body.challenge) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_aggregate(
    Json(body): Json<CaRegistrationAggregateRequest>,
) -> impl IntoResponse {
    match aggregate_registration_proof(
        &body.vault_ek,
        &body.sender_address,
        &body.asset_type,
        body.chain_id,
        body.commitments,
        body.responses,
    ) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn vault_ek_round0(
    State(state): State<AppState>,
    Json(body): Json<Round0Request>,
) -> (StatusCode, Json<Value>) {
    // Codex P1 #4 round0: pre-MPC commit endpoint. No adapter dispatch — round0 is pure
    // local state (validate roster/slot/lambda, draw r_i, write 0o600 file). The 503
    // path doesn't apply here.
    match run_vault_ek_round0(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn vault_ek_round1(
    State(state): State<AppState>,
    Json(body): Json<Round1Request>,
) -> (StatusCode, Json<Value>) {
    // Runtime adapter selection: when MP-SPDZ is bootstrapped (MP_SPDZ_HOME set and the
    // vault_ek_inversion_v1 bytecode is on disk), use the real MASCOT adapter. Otherwise fail
    // closed to the 503 path so callers know to bootstrap the runtime.
    let adapter: Box<dyn MpcInverseAdapter> = match MpcSpdzInverseAdapter::from_env() {
        Some(real) => Box::new(real),
        None => Box::new(UnavailableMpcInverseAdapter),
    };
    match run_vault_ek_round1(&state.state_dir, &body, &*adapter) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => vault_ek_error_response(err),
    }
}

async fn vault_ek_verify(Json(body): Json<VerifyRequest>) -> (StatusCode, Json<Value>) {
    match run_vault_ek_verify(&body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => vault_ek_error_response(err),
    }
}

// Milestone 1 V2 threshold CA registration sigma. Loads ca_dkg_share_v2.json (NOT
// ca_share.json — V2 has no centralized vault_ek), accepts vault_ek from request body.
async fn ca_registration_v2_round1(
    State(state): State<AppState>,
    Json(body): Json<CaRegistrationV2Round1Request>,
) -> (StatusCode, Json<Value>) {
    match create_registration_nonce_commitment_v2(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_v2_round2(
    State(state): State<AppState>,
    Json(body): Json<CaRegistrationV2Round2Request>,
) -> (StatusCode, Json<Value>) {
    match create_registration_partial_response_v2(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

// Codex P1 #2: V2 interim aggregator. Same wire shape as the V1 challenge endpoint, same
// math (share-independent public compute). Lives under /worker/v2/derive/ca_registration/*
// so the deop-node's existing V2 allowlist forwards it correctly. The coordinator hits
// this on the verifier slot AFTER round1 to derive (aggregateCommitment, challenge), then
// fans out round2 with the challenge.
async fn ca_registration_v2_challenge(
    Json(body): Json<CaRegistrationChallengeRequest>,
) -> impl IntoResponse {
    match aggregate_commitments_v2(&body.commitments).and_then(|commitment| {
        challenge_v2(
            &body.vault_ek,
            &body.sender_address,
            &body.asset_type,
            body.chain_id,
            &commitment,
        )
        .map(|challenge| (commitment, challenge))
    }) {
        Ok((aggregate_commitment, challenge)) => (
            StatusCode::OK,
            Json(json!({
                "aggregateCommitment": aggregate_commitment,
                "challenge": challenge
            })),
        ),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_v2_verify(
    Json(body): Json<CaRegistrationV2VerifyRequest>,
) -> (StatusCode, Json<Value>) {
    match run_ca_registration_v2_verify(&body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

async fn ca_registration_v2_aggregate(
    Json(body): Json<CaRegistrationV2AggregateRequest>,
) -> (StatusCode, Json<Value>) {
    match run_ca_registration_v2_aggregate(&body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

// Milestone 2a — `/worker/v2/vault_state/init`. The Phase 2 + Milestone 1 transcripts have
// already been cross-checked by the coordinator before this call lands; the worker re-verifies
// the Milestone 1 public equation here against its supplied `vault_ek` so a deop-node tricked
// into proxying a bogus tuple still fails closed on the worker side.
async fn vault_state_v2_init(
    State(state): State<AppState>,
    Json(body): Json<VaultStateV2InitRequest>,
) -> (StatusCode, Json<Value>) {
    match run_vault_state_v2_init(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

// Codex M3a P1 (regression fix) — `/worker/v2/vault_state/init/finalize`. Runs AFTER the
// init fan-out. The coordinator passes the aggregated FINAL transcript hash plus the 5
// per-slot init contributions. Worker re-derives the hash, asserts byte-equality, then
// UPDATES `init_transcript_hash` in the persisted `vault_state_v2.json` to the canonical
// final hash so subsequent MPCCA withdraw rounds cross-check against the SAME value the
// coordinator already pinned in its persisted init artifact.
async fn vault_state_v2_init_finalize(
    State(state): State<AppState>,
    Json(body): Json<VaultStateV2FinalizeRequest>,
) -> (StatusCode, Json<Value>) {
    match run_vault_state_v2_finalize(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

// Milestone 2b — `/worker/v2/vault_state/observe_deposit`. Bumps the per-worker
// `deposit_count_observed` cursor strictly upward after the coordinator has already cross-
// referenced the supplied (Phase 2, Milestone 1) provenance against the request body. The
// worker re-runs the provenance gate against its persisted `vault_state_v2.json` and enforces
// strict cursor monotonicity (req.deposit_count > existing.deposit_count_observed). A re-call
// at the same cursor is rejected `stale_deposit_count`; this is the load-bearing security
// check that prevents an already-observed deposit from being replayed.
async fn vault_state_v2_observe_deposit(
    State(state): State<AppState>,
    Json(body): Json<VaultStateV2ObserveDepositRequest>,
) -> (StatusCode, Json<Value>) {
    match run_vault_state_v2_observe_deposit(&state.state_dir, &body) {
        Ok(result) => (StatusCode::OK, Json(json!(result))),
        Err(err) => worker_error_response(err),
    }
}

// Milestone 3a — `/worker/v2/mpcca/withdraw/{round1,round2,prove,finalize}`. Each handler
// invokes the corresponding library function. The library function ALWAYS does the full
// public-binding work BEFORE returning `Err(WorkerError::NotImplemented(<phase>))`. We surface
// the public binding outputs (sessionStatePath, sessionStateHash, workerTranscriptHash)
// alongside the 501 so the coordinator can persist its round-N partial transcript even though
// the crypto is pending.
//
// The KILLER design: a request that fails the provenance gate, the vault_sequence gate, or the
// sigma re-verify gets a SPECIFIC validation error (InvalidDkgState / InvalidRequest / Crypto)
// — NOT NotImplemented. Milestone 4 fills the crypto in; the public binding errors stay
// load-bearing.
async fn mpcca_withdraw_round1(
    State(state): State<AppState>,
    Json(body): Json<MpccaWithdrawRound1Request>,
) -> (StatusCode, Json<Value>) {
    let request_id = body.request_id.clone();
    let session_id = body.session_id.clone();
    let self_slot = body.self_slot;
    let player_id = body.player_id;
    match run_mpcca_withdraw_round1_v2(&state.state_dir, &body) {
        Ok(_result) => {
            // Should never happen under milestone 3a — the stub ALWAYS returns NotImplemented.
            // If milestone 4 lands the crypto and forgets to update this surface, we want a
            // load-bearing assert here.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "mpcca_withdraw_v2_stub_unexpectedly_returned_ok",
                    "message": "milestone 3a stub returned Ok; this is a wire-shape regression"
                })),
            )
        }
        Err(eunoma_crypto_worker::WorkerError::NotImplemented(phase)) => {
            mpcca_not_implemented_response(
                &state.state_dir,
                &request_id,
                &session_id,
                self_slot,
                player_id,
                "round1",
                phase,
            )
        }
        Err(err) => worker_error_response(err),
    }
}

async fn mpcca_withdraw_round2(
    State(state): State<AppState>,
    Json(body): Json<MpccaWithdrawChainedRoundRequest>,
) -> (StatusCode, Json<Value>) {
    let request_id = body.request_id.clone();
    let session_id = body.session_id.clone();
    let self_slot = body.self_slot;
    let player_id = body.player_id;
    match run_mpcca_withdraw_round2_v2(&state.state_dir, &body) {
        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "mpcca_withdraw_v2_stub_unexpectedly_returned_ok",
                "message": "milestone 3a stub returned Ok; this is a wire-shape regression"
            })),
        ),
        Err(eunoma_crypto_worker::WorkerError::NotImplemented(phase)) => {
            mpcca_not_implemented_response(
                &state.state_dir,
                &request_id,
                &session_id,
                self_slot,
                player_id,
                "round2",
                phase,
            )
        }
        Err(err) => worker_error_response(err),
    }
}

async fn mpcca_withdraw_prove(
    State(state): State<AppState>,
    Json(body): Json<MpccaWithdrawChainedRoundRequest>,
) -> (StatusCode, Json<Value>) {
    let request_id = body.request_id.clone();
    let session_id = body.session_id.clone();
    let self_slot = body.self_slot;
    let player_id = body.player_id;
    match run_mpcca_withdraw_prove_v2(&state.state_dir, &body) {
        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "mpcca_withdraw_v2_stub_unexpectedly_returned_ok",
                "message": "milestone 3a stub returned Ok; this is a wire-shape regression"
            })),
        ),
        Err(eunoma_crypto_worker::WorkerError::NotImplemented(phase)) => {
            mpcca_not_implemented_response(
                &state.state_dir,
                &request_id,
                &session_id,
                self_slot,
                player_id,
                "prove",
                phase,
            )
        }
        Err(err) => worker_error_response(err),
    }
}

async fn mpcca_withdraw_finalize(
    State(state): State<AppState>,
    Json(body): Json<MpccaWithdrawChainedRoundRequest>,
) -> (StatusCode, Json<Value>) {
    let request_id = body.request_id.clone();
    let session_id = body.session_id.clone();
    let self_slot = body.self_slot;
    let player_id = body.player_id;
    match run_mpcca_withdraw_finalize_v2(&state.state_dir, &body) {
        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "mpcca_withdraw_v2_stub_unexpectedly_returned_ok",
                "message": "milestone 3a stub returned Ok; this is a wire-shape regression"
            })),
        ),
        Err(eunoma_crypto_worker::WorkerError::NotImplemented(phase)) => {
            mpcca_not_implemented_response(
                &state.state_dir,
                &request_id,
                &session_id,
                self_slot,
                player_id,
                "finalize",
                phase,
            )
        }
        Err(err) => worker_error_response(err),
    }
}

/// Surfaces the 501 response shape: HTTP 501 + body carrying the public binding outputs
/// (sessionStatePath, sessionStateHash, workerTranscriptHash) read back from the file the
/// library function persisted before returning NotImplemented. The coordinator parses this
/// shape and asserts the per-slot transcript hashes agree.
fn mpcca_not_implemented_response(
    state_dir: &std::path::Path,
    request_id: &str,
    session_id: &str,
    self_slot: usize,
    player_id: usize,
    round_name: &str,
    phase: &'static str,
) -> (StatusCode, Json<Value>) {
    // Compute the per-session dir + read back the persisted round state file. The library
    // function already validated id safety, so mpcca_withdraw_session_dir should succeed here.
    let session_dir = match mpcca_withdraw_session_dir(state_dir, request_id, session_id) {
        Ok(dir) => dir,
        Err(err) => return worker_error_response(err),
    };
    let (session_state_path, session_state_hash) =
        match mpcca_last_persisted_round_state(&session_dir, round_name) {
            Ok(pair) => pair,
            Err(err) => return worker_error_response(err),
        };
    // Read the persisted file to lift its worker_transcript_hash field.
    let raw = match std::fs::read(&session_state_path) {
        Ok(raw) => raw,
        Err(err) => {
            return worker_error_response(eunoma_crypto_worker::WorkerError::Crypto(
                format!("read mpcca round state {}: {err}", session_state_path.display()),
            ));
        }
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(err) => {
            return worker_error_response(eunoma_crypto_worker::WorkerError::Crypto(format!(
                "parse mpcca round state: {err}"
            )));
        }
    };
    let worker_transcript_hash = parsed
        .get("worker_transcript_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "slot": self_slot,
            "playerId": player_id,
            "sessionStatePath": session_state_path.display().to_string(),
            "sessionStateHash": session_state_hash,
            "workerTranscriptHash": worker_transcript_hash,
            "observedAtUnixMs": observed_at_unix_ms,
            "completed": false,
            "notImplementedPhase": phase,
        })),
    )
}

fn vault_ek_error_response(
    err: eunoma_crypto_worker::WorkerError,
) -> (StatusCode, Json<Value>) {
    if let eunoma_crypto_worker::WorkerError::NotImplemented(msg) = &err {
        if *msg == "mpc_inverse_unavailable" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "mpc_inverse_unavailable" })),
            );
        }
    }
    worker_error_response(err)
}

fn worker_error_response(
    err: eunoma_crypto_worker::WorkerError,
) -> (StatusCode, Json<Value>) {
    let (status, code) = match err {
        eunoma_crypto_worker::WorkerError::BadThreshold { .. } => {
            (StatusCode::BAD_REQUEST, "bad_threshold")
        }
        eunoma_crypto_worker::WorkerError::UnderQuorum { .. } => {
            (StatusCode::BAD_REQUEST, "under_quorum")
        }
        eunoma_crypto_worker::WorkerError::ForbiddenPlaintextField(_) => {
            (StatusCode::BAD_REQUEST, "forbidden_plaintext_field")
        }
        eunoma_crypto_worker::WorkerError::MissingLocalState(_) => {
            (StatusCode::PRECONDITION_FAILED, "missing_local_state")
        }
        eunoma_crypto_worker::WorkerError::InvalidRequest(_) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        eunoma_crypto_worker::WorkerError::Io(_)
        | eunoma_crypto_worker::WorkerError::Serde(_)
        | eunoma_crypto_worker::WorkerError::Crypto(_) => {
            (StatusCode::BAD_REQUEST, "worker_error")
        }
        eunoma_crypto_worker::WorkerError::NotImplemented(_) => {
            (StatusCode::NOT_IMPLEMENTED, "not_implemented")
        }
        eunoma_crypto_worker::WorkerError::InvalidDkgState(_) => {
            (StatusCode::CONFLICT, "invalid_dkg_state")
        }
        eunoma_crypto_worker::WorkerError::Complaint(_) => (StatusCode::CONFLICT, "complaint"),
        eunoma_crypto_worker::WorkerError::InvalidPathSegment(_) => {
            (StatusCode::BAD_REQUEST, "invalid_path_segment")
        }
    };
    (
        status,
        Json(json!({
            "error": code,
            "message": format!("{err:?}")
        })),
    )
}

fn hash_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
