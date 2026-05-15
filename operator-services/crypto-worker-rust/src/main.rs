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
use eunoma_crypto_worker::local_state::{
    aggregate_frost_signature, create_frost_nonce_commitment, create_frost_partial_signature,
    default_state_dir, init_frost_local, state_summary, FrostCommitmentInput,
    FrostSignatureShareInput,
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
        .route("/worker/v2/dkg/frost/start", post(fail_closed))
        .route(
            "/worker/v2/dkg/:protocol/:round",
            post(dkg_round),
        )
        .route(
            "/worker/v2/mpcca/:protocol/:round",
            post(mpcca_round),
        )
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
    #[serde(rename = "rosterHash")]
    roster_hash: String,
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
    complaint: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct MpccaRoundBody {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "sessionId")]
    session_id: String,
    slot: usize,
    #[serde(rename = "quorumSlots")]
    quorum_slots: Option<Vec<usize>>,
    #[serde(rename = "vaultSequence")]
    vault_sequence: String,
    #[serde(rename = "transcriptHash")]
    transcript_hash: String,
    #[serde(rename = "publicInputsHash")]
    public_inputs_hash: String,
}

async fn dkg_round(
    State(state): State<AppState>,
    Path((protocol, round)): Path<(String, String)>,
    Json(body): Json<DkgRoundBody>,
) -> impl IntoResponse {
    if protocol != "ca" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "not_implemented",
                "protocol": protocol,
                "round": round,
                "message": "FROST DKG transport is wired through local FROST initialization; online FROST DKG rounds are not enabled"
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
            roster_hash: body.roster_hash,
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

async fn mpcca_round(
    State(state): State<AppState>,
    Path((protocol, round)): Path<(String, String)>,
    Json(body): Json<MpccaRoundBody>,
) -> impl IntoResponse {
    if protocol != "withdraw" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "message": "invalid MPCCA protocol" })),
        );
    }
    if body.slot != state.slot {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "message": "slot mismatch" })),
        );
    }
    if round == "prove" || round == "finalize" {
        let Some(quorum_slots) = body.quorum_slots.as_deref() else {
            return worker_error_response(eunoma_crypto_worker::WorkerError::InvalidRequest(
                "quorumSlots is required for MPCCA prove/finalize".to_string(),
            ));
        };
        if let Err(err) = eunoma_crypto_worker::assert_quorum_slots5(quorum_slots) {
            return worker_error_response(err);
        }
        return worker_error_response(eunoma_crypto_worker::WorkerError::NotImplemented(
            "collaborative Aptos CA transfer sigma and Bulletproof payload generation are required for MPCCA prove/finalize",
        ));
    }
    match load_ca_share(&state.state_dir) {
        Ok(share) => {
            let artifact_hash = hash_hex(&[
                b"EUNOMA_MPCCA_WITHDRAW_ROUND_ARTIFACT_V1".as_slice(),
                body.request_id.as_bytes(),
                body.session_id.as_bytes(),
                body.vault_sequence.as_bytes(),
                protocol.as_bytes(),
                round.as_bytes(),
                body.transcript_hash.as_bytes(),
                body.public_inputs_hash.as_bytes(),
                share.transcript_hash.as_bytes(),
                share.public_share.as_bytes(),
            ]);
            let ca_payload_hash_share = hash_hex(&[
                b"EUNOMA_MPCCA_CA_PAYLOAD_HASH_SHARE_V1".as_slice(),
                artifact_hash.as_bytes(),
            ]);
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "requestId": body.request_id,
                    "sessionId": body.session_id,
                    "protocol": protocol,
                    "round": round,
                    "slot": state.slot,
                    "accepted": true,
                    "transcriptHash": body.transcript_hash,
                    "artifactHash": artifact_hash,
                    "caPayloadHashShare": ca_payload_hash_share
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
