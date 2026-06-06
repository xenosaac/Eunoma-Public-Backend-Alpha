//! Normalize ceremony — worker partial endpoint.
//!
//! `POST /worker/v2/normalize/sigma/s0_partial` — each worker in the active
//! 5-of-7 quorum decrypts its HPKE-sealed additive alpha share and computes
//! its own partial share
//!
//!   `partial_i = α_share_i + e · λ_i · dk_share_i   (mod q)`
//!
//! over the Ed25519 scalar field. The coordinator collects 5 partials and
//! Lagrange-aggregates them at x=0 to obtain
//!
//!   `s[0]_threshold = Σ_i partial_i = α[0] + e · dk_REAL`
//!
//! (because Σ_i λ_i = 1). The output `s[0]_threshold` is the σ-position-0
//! response component that the σ-prover for the Aptos CA WithdrawalV1
//! (`normalize_raw`) entry would have computed if `dk_REAL` were available
//! in plaintext — but no party (worker, coordinator, user) ever holds
//! `dk_REAL`.
//!
//! ## Mirror of `balance_decrypt.rs`
//!
//! The shape, validation, error variants, and `AppStateFor*` trait pattern
//! are copied 1:1 from `balance_decrypt.rs` so the route plugs into the
//! existing worker `main.rs` wiring. Key differences:
//!
//!   * No chain re-fetch. The normalize ceremony's HPKE-sealed alpha share +
//!     public e are caller-supplied, not chain-bound points; there's no
//!     defense-in-depth D-byte-equality check to perform. (The (vault, asset)
//!     binding is still enforced — same M10-l iter-6 P1-13 closure as
//!     balance_decrypt.)
//!   * No transcript signature. The coordinator's Lagrange aggregation +
//!     the closed-form verifier check (`partial == α[0] + e · dk_share` for
//!     a known α[0]/e) makes per-worker SHA-256 attestation redundant: if a
//!     worker forges its partial, the aggregated `s[0]_threshold` will
//!     fail σ-position-0 chain-side verification with `E_INVALID_SIGMA_RESP`.
//!     This matches the existing transfer-finalize convention (no
//!     per-worker signature on the `s_share_j` scalar — see
//!     `mpcca_withdraw_v2::run_finalize_v2` at `lib.rs:9604`).
//!
//! ## Zeroize discipline
//!
//! `dk_share` is decoded from the share file and held in a single `Scalar`
//! on the stack. We zeroize it on EVERY return path. The `CaDkgV2ShareFile`
//! returned by `load_ca_dkg_v2_share` already implements `Drop` that
//! zeroizes its hex `dk_share` string when the struct goes out of scope.
//!
//! ## Privacy note
//!
//! `α[0]` is never supplied in plaintext to the coordinator or workers. The
//! caller splits it into additive shares and HPKE-seals exactly one share to
//! each selected worker using `EUNOMA_NORMALIZE_ALPHA_SHARE_V1`.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use zeroize::Zeroize;

use crate::ca_dkg_v2::{load_ca_dkg_v2_share, load_hpke_keypair_for_slot};
pub use crate::hpke_aead::HpkeEnvelope;
use crate::{hpke_aead, DEOPERATOR_THRESHOLD};

pub const NORMALIZE_ALPHA_SHARE_INFO: &[u8] = b"EUNOMA_NORMALIZE_ALPHA_SHARE_V1";

/// Required JSON request body. All fields are mandatory; no defaults.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizeSigmaPartialRequest {
    /// CA DKG V2 epoch — must equal the share file's `dkg_epoch`.
    pub dkg_epoch: String,
    /// Aptos vault address (hex). Used solely for the (vault, asset) trust
    /// binding — no chain re-fetch.
    pub vault_address: String,
    /// Confidential-asset type tag. Same trust-binding role as
    /// `vault_address`.
    pub asset_type: String,
    /// Slot the requester believes this worker holds. Must equal the share
    /// file's slot.
    pub slot: usize,
    /// CA DKG V2 roster hash chosen by the coordinator. Bound into the HPKE AAD.
    pub roster_hash: String,
    /// Strictly ascending selected quorum slots. Used locally to compute λ_i.
    pub selected_slots: Vec<usize>,
    /// `e` — Fiat-Shamir challenge scalar, 32-byte LE hex (curve25519-dalek
    /// canonical encoding).
    pub fiat_shamir_challenge_hex: String,
    /// HPKE envelope sealing this worker's additive alpha share.
    pub alpha_share_hpke: HpkeEnvelope,
    /// Caller-supplied request correlation id.
    pub request_id: String,
}

/// Successful response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizeSigmaPartialResponse {
    /// Echo of the worker's slot index (post-cross-check).
    pub slot: usize,
    /// `partial_i = alpha_share_i + e · lambda_i · dk_share_i` (mod q) — 32-byte LE hex.
    pub partial_s0_hex: String,
}

/// Errors mirror `BalanceDecryptError` in shape + HTTP-status mapping.
#[derive(Debug)]
pub enum NormalizeSigmaPartialError {
    /// Caller-supplied input failed validation before any share access.
    BadRequest(String),
    /// Worker has no CA DKG V2 share file at the expected path, OR the
    /// file's epoch/slot doesn't match the request.
    MissingShare(String),
    /// Anything else (share decode, scalar decode).
    Internal(String),
}

impl NormalizeSigmaPartialError {
    fn http_status(&self) -> StatusCode {
        match self {
            NormalizeSigmaPartialError::BadRequest(_) => StatusCode::BAD_REQUEST,
            NormalizeSigmaPartialError::MissingShare(_) => StatusCode::NOT_FOUND,
            NormalizeSigmaPartialError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> String {
        match self {
            NormalizeSigmaPartialError::BadRequest(reason) => {
                format!("bad_request:{reason}")
            }
            NormalizeSigmaPartialError::MissingShare(reason) => {
                format!("missing_share:{reason}")
            }
            NormalizeSigmaPartialError::Internal(reason) => format!("internal:{reason}"),
        }
    }
}

impl std::fmt::Display for NormalizeSigmaPartialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code())
    }
}

impl std::error::Error for NormalizeSigmaPartialError {}

/// Decode a 64-hex string into 32 raw bytes. Tolerates a `0x` prefix.
fn hex_to_32(hex: &str) -> Result<[u8; 32], NormalizeSigmaPartialError> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if raw.len() != 64 {
        return Err(NormalizeSigmaPartialError::BadRequest(format!(
            "hex must be 64 chars, got {}",
            raw.len()
        )));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "non-hex character".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|e| NormalizeSigmaPartialError::BadRequest(format!("hex decode: {e}")))?;
    }
    Ok(bytes)
}

/// Decode a 32-byte scalar from the worker's share file format
/// (`Scalar::to_bytes` LE, may be canonical or reduced — same semantics as
/// balance_decrypt's `scalar_from_share_hex`).
fn scalar_from_share_hex(hex: &str) -> Result<Scalar, NormalizeSigmaPartialError> {
    let bytes = hex_to_32(hex).map_err(|e| {
        NormalizeSigmaPartialError::Internal(format!("share dk_share hex invalid: {e}"))
    })?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

/// Decode a CANONICAL scalar (e/α[0] supplied by caller — must be canonical
/// for unambiguous round-trip with the coordinator's bigint arithmetic).
fn canonical_scalar_from_hex(
    hex: &str,
    field_name: &str,
) -> Result<Scalar, NormalizeSigmaPartialError> {
    let bytes = hex_to_32(hex).map_err(|e| {
        NormalizeSigmaPartialError::BadRequest(format!("{field_name} hex invalid: {e}"))
    })?;
    let opt = Scalar::from_canonical_bytes(bytes);
    if opt.is_none().into() {
        return Err(NormalizeSigmaPartialError::BadRequest(format!(
            "{field_name} is not a canonical Ed25519 scalar"
        )));
    }
    Ok(opt.unwrap())
}

fn normalize_hex_no_prefix(
    raw: &str,
    field_name: &str,
) -> Result<String, NormalizeSigmaPartialError> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if stripped.is_empty()
        || stripped.len() % 2 != 0
        || !stripped.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(NormalizeSigmaPartialError::BadRequest(format!(
            "{field_name} must be even-length hex"
        )));
    }
    Ok(stripped.to_ascii_lowercase())
}

fn normalize_selected_slots(
    slots: &[usize],
    self_slot: usize,
) -> Result<(), NormalizeSigmaPartialError> {
    if slots.len() != DEOPERATOR_THRESHOLD {
        return Err(NormalizeSigmaPartialError::BadRequest(format!(
            "selectedSlots must contain {DEOPERATOR_THRESHOLD} slots"
        )));
    }
    let mut saw_self = false;
    for (idx, slot) in slots.iter().enumerate() {
        if *slot >= crate::DEOPERATOR_COUNT {
            return Err(NormalizeSigmaPartialError::BadRequest(format!(
                "selectedSlots[{idx}] out of range"
            )));
        }
        if idx > 0 && slots[idx - 1] >= *slot {
            return Err(NormalizeSigmaPartialError::BadRequest(
                "selectedSlots must be strictly ascending".to_string(),
            ));
        }
        if *slot == self_slot {
            saw_self = true;
        }
    }
    if !saw_self {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "selectedSlots does not include request slot".to_string(),
        ));
    }
    Ok(())
}

fn lagrange_at_zero_for_slot(
    selected_slots: &[usize],
    self_slot: usize,
) -> Result<Scalar, NormalizeSigmaPartialError> {
    normalize_selected_slots(selected_slots, self_slot)?;
    let x_i = Scalar::from((self_slot as u64) + 1);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for slot in selected_slots {
        if *slot == self_slot {
            continue;
        }
        let x_j = Scalar::from((*slot as u64) + 1);
        num *= -x_j;
        den *= x_i - x_j;
    }
    if den == Scalar::ZERO {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "lagrange_denominator_zero".to_string(),
        ));
    }
    Ok(num * den.invert())
}

pub fn normalize_alpha_share_aad(
    request_id: &str,
    dkg_epoch: &str,
    roster_hash: &str,
    vault_address: &str,
    asset_type: &str,
    fiat_shamir_challenge_hex: &str,
    selected_slots: &[usize],
    slot: usize,
) -> Result<Vec<u8>, NormalizeSigmaPartialError> {
    normalize_selected_slots(selected_slots, slot)?;
    let roster = normalize_hex_no_prefix(roster_hash, "rosterHash")?;
    let challenge = normalize_hex_no_prefix(fiat_shamir_challenge_hex, "fiatShamirChallengeHex")?;
    if roster.len() != 64 {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "rosterHash must be 32-byte hex".to_string(),
        ));
    }
    if challenge.len() != 64 {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "fiatShamirChallengeHex must be 32-byte hex".to_string(),
        ));
    }
    Ok(format!(
        "domain={}|request={}|dkg={}|roster={}|vault={}|asset={}|challenge={}|slots={}|slot={}",
        std::str::from_utf8(NORMALIZE_ALPHA_SHARE_INFO)
            .unwrap_or("EUNOMA_NORMALIZE_ALPHA_SHARE_V1"),
        request_id,
        dkg_epoch,
        roster,
        vault_address
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase(),
        asset_type
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase(),
        challenge,
        selected_slots
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(","),
        slot,
    )
    .into_bytes())
}

pub fn seal_normalize_alpha_share_for_test(
    recipient_public_key_hex: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> crate::WorkerResult<HpkeEnvelope> {
    hpke_aead::seal(
        recipient_public_key_hex,
        NORMALIZE_ALPHA_SHARE_INFO,
        aad,
        plaintext,
    )
}

/// Encode a Scalar as 32-byte LE lowercase hex (no `0x` prefix).
fn scalar_to_hex(s: &Scalar) -> String {
    s.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Core handler — pure async function. Loads the worker's dk_share for the
/// given (epoch, slot), opens this worker's HPKE-sealed `alpha_share`, parses `e` as
/// a canonical Ed25519 scalar, computes
/// `partial = alpha_share_i + e · lambda_i · dk_share_i`, zeroizes the secret scalars,
/// and returns the partial as 32-byte LE hex.
///
/// `state_dir` is the worker's per-slot state directory (e.g.
/// `.agent-local/eunoma-v2/slot-3`). It MUST already contain a valid
/// `ca_dkg_share_v2.json` for the requested epoch.
pub async fn handle(
    state_dir: &Path,
    trusted_bridge_vault_address: &str,
    trusted_bridge_asset_type: &str,
    req: NormalizeSigmaPartialRequest,
) -> Result<NormalizeSigmaPartialResponse, NormalizeSigmaPartialError> {
    // 1. Cheap input validation.
    if req.dkg_epoch.is_empty() {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "dkgEpoch is empty".to_string(),
        ));
    }
    if req.vault_address.is_empty() {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "vaultAddress is empty".to_string(),
        ));
    }
    if req.asset_type.is_empty() {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "assetType is empty".to_string(),
        ));
    }
    if req.request_id.is_empty() {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "requestId is empty".to_string(),
        ));
    }

    // 2. Bridge (vault, asset) trust-binding (same M10-l iter-6 P1-13 closure
    //    as balance_decrypt.rs:362).
    if trusted_bridge_vault_address.is_empty() || trusted_bridge_asset_type.is_empty() {
        return Err(NormalizeSigmaPartialError::Internal(
            "worker_missing_bridge_vault_or_asset_config".to_string(),
        ));
    }
    let normalize_aptos_addr = |raw: &str| -> Option<String> {
        let stripped = raw.trim_start_matches("0x").trim_start_matches("0X");
        if stripped.is_empty() || stripped.len() > 64 {
            return None;
        }
        if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(format!("{:0>64}", stripped.to_ascii_lowercase()))
    };
    let cfg_vault_norm = normalize_aptos_addr(trusted_bridge_vault_address);
    let req_vault_norm = normalize_aptos_addr(&req.vault_address);
    if cfg_vault_norm.is_none() || req_vault_norm.is_none() || cfg_vault_norm != req_vault_norm {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "vault_address_does_not_match_configured_bridge_vault".to_string(),
        ));
    }
    let cfg_asset_norm = normalize_aptos_addr(trusted_bridge_asset_type);
    let req_asset_norm = normalize_aptos_addr(&req.asset_type);
    let asset_matches = match (cfg_asset_norm.as_ref(), req_asset_norm.as_ref()) {
        (Some(cfg), Some(reqv)) => cfg == reqv,
        _ => {
            let strip = |s: &str| -> String {
                s.trim_start_matches("0x")
                    .trim_start_matches("0X")
                    .to_ascii_lowercase()
            };
            strip(trusted_bridge_asset_type) == strip(&req.asset_type)
        }
    };
    if !asset_matches {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "asset_type_does_not_match_configured_bridge_asset".to_string(),
        ));
    }

    // 3. Load the CA DKG V2 share. The loader returns a `CaDkgV2ShareFile`
    //    whose `dk_share` hex string is zeroized on drop (lib.rs:2047).
    let share = load_ca_dkg_v2_share(state_dir).map_err(|err| match err {
        crate::WorkerError::MissingLocalState(path) => {
            NormalizeSigmaPartialError::MissingShare(format!("file_not_found:{path}"))
        }
        other => NormalizeSigmaPartialError::MissingShare(format!("load_failed:{other:?}")),
    })?;

    // 4. Cross-check the request against the share file BEFORE decoding the
    //    secret scalar (mirror balance_decrypt.rs:431).
    if share.dkg_epoch != req.dkg_epoch {
        return Err(NormalizeSigmaPartialError::MissingShare(format!(
            "dkg_epoch_mismatch:share={}:request={}",
            share.dkg_epoch, req.dkg_epoch
        )));
    }
    if share.slot != req.slot {
        return Err(NormalizeSigmaPartialError::BadRequest(format!(
            "slot_mismatch:share={}:request={}",
            share.slot, req.slot
        )));
    }

    // 5. Parse caller-supplied public scalar and selected slot set BEFORE touching dk_share so we can
    //    fail closed without secret material entering our stack frame.
    normalize_selected_slots(&req.selected_slots, req.slot)?;
    let lambda_j = lagrange_at_zero_for_slot(&req.selected_slots, req.slot)?;
    if lambda_j == Scalar::ZERO {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "lagrange_coefficient_zero".to_string(),
        ));
    }
    let e_scalar =
        canonical_scalar_from_hex(&req.fiat_shamir_challenge_hex, "fiatShamirChallengeHex")?;
    if e_scalar == Scalar::ZERO {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "fiatShamirChallenge_zero_rejected".to_string(),
        ));
    }
    hpke_aead::validate(&req.alpha_share_hpke).map_err(|err| {
        NormalizeSigmaPartialError::BadRequest(format!("alphaShareHpke invalid: {err:?}"))
    })?;
    let keypair = load_hpke_keypair_for_slot(state_dir, req.slot).map_err(|err| match err {
        crate::WorkerError::MissingLocalState(path) => {
            NormalizeSigmaPartialError::MissingShare(format!("hpke_keypair_file_not_found:{path}"))
        }
        other => {
            NormalizeSigmaPartialError::MissingShare(format!("hpke_keypair_load_failed:{other:?}"))
        }
    })?;
    let aad = normalize_alpha_share_aad(
        &req.request_id,
        &req.dkg_epoch,
        &req.roster_hash,
        &req.vault_address,
        &req.asset_type,
        &req.fiat_shamir_challenge_hex,
        &req.selected_slots,
        req.slot,
    )?;
    if req.alpha_share_hpke.aad_hash != hpke_aead::sha256_hex(&aad) {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "alphaShareHpke aadHash mismatch".to_string(),
        ));
    }
    let mut alpha_plaintext = hpke_aead::open(
        &keypair.private_key,
        NORMALIZE_ALPHA_SHARE_INFO,
        &aad,
        &req.alpha_share_hpke,
    )
    .map_err(|_| {
        NormalizeSigmaPartialError::BadRequest("alpha_share_hpke_open_failed".to_string())
    })?;
    if alpha_plaintext.len() != 32 {
        alpha_plaintext.zeroize();
        return Err(NormalizeSigmaPartialError::BadRequest(
            "alpha_share_plaintext_wrong_length".to_string(),
        ));
    }
    let mut alpha_bytes = [0_u8; 32];
    alpha_bytes.copy_from_slice(&alpha_plaintext);
    alpha_plaintext.zeroize();
    let alpha_opt = Scalar::from_canonical_bytes(alpha_bytes);
    alpha_bytes.zeroize();
    if alpha_opt.is_none().into() {
        return Err(NormalizeSigmaPartialError::BadRequest(
            "alpha_share_non_canonical".to_string(),
        ));
    }
    let mut alpha_share = alpha_opt.unwrap();

    // 6. Decode dk_share. FIRST point at which secret material enters our
    //    stack frame as a `Scalar`. Zeroize on every return path until
    //    step 8.
    let mut dk_share = scalar_from_share_hex(&share.dk_share)?;
    if dk_share == Scalar::ZERO {
        dk_share.zeroize();
        return Err(NormalizeSigmaPartialError::Internal(
            "dk_share_zero_rejected".to_string(),
        ));
    }

    // 7. Compute partial = α_share_i + e · λ_i · dk_share_i   (mod q).
    let partial = alpha_share + e_scalar * (lambda_j * dk_share);

    // 8. Zeroize secrets IMMEDIATELY after the last use. `partial` is a
    //    public output (the worker's threshold partial share).
    alpha_share.zeroize();
    dk_share.zeroize();

    // 9. Encode and return.
    let partial_s0_hex = scalar_to_hex(&partial);

    Ok(NormalizeSigmaPartialResponse {
        slot: share.slot,
        partial_s0_hex,
    })
}

/// Axum HTTP adapter. Adapts the typed handler to a Json/Json route. Errors
/// are surfaced as `{ "error": "<code>", "message": "<display>" }` with the
/// status code derived from the error variant.
///
/// Generic over any `AppState`-like value that exposes a `state_dir` +
/// bridge config via `AppStateForNormalizeSigmaPartial`. The worker `main.rs`
/// implements this trait on the same `AppState` it uses for balance_decrypt.
pub async fn handle_http<S: AppStateForNormalizeSigmaPartial + Send + Sync>(
    State(state): State<S>,
    Json(req): Json<NormalizeSigmaPartialRequest>,
) -> impl IntoResponse {
    let state_dir = state.state_dir().to_path_buf();
    let trusted_vault = state.bridge_vault_address().to_string();
    let trusted_asset = state.bridge_asset_type().to_string();
    match handle(&state_dir, &trusted_vault, &trusted_asset, req).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))).into_response(),
        Err(err) => {
            let status = err.http_status();
            let body = json!({
                "error": err.code(),
                "message": err.to_string(),
            });
            (status, Json(body)).into_response()
        }
    }
}

/// Read-only view of the worker's per-slot state directory + trusted (vault,
/// asset) bridge binding. Implemented by `main.rs`'s `AppState`.
pub trait AppStateForNormalizeSigmaPartial: Clone + 'static {
    fn state_dir(&self) -> &Path;
    fn bridge_vault_address(&self) -> &str;
    fn bridge_asset_type(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_32_validates_length() {
        assert!(hex_to_32(&"ab".repeat(32)).is_ok());
        assert!(hex_to_32("dead").is_err());
        assert!(hex_to_32(&"gg".repeat(32)).is_err());
    }

    #[test]
    fn error_codes_are_stable_strings() {
        let cases = [
            (
                NormalizeSigmaPartialError::BadRequest("x".into()),
                "bad_request:x",
                StatusCode::BAD_REQUEST,
            ),
            (
                NormalizeSigmaPartialError::MissingShare("y".into()),
                "missing_share:y",
                StatusCode::NOT_FOUND,
            ),
            (
                NormalizeSigmaPartialError::Internal("z".into()),
                "internal:z",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected_code, expected_status) in cases {
            assert_eq!(err.code(), expected_code);
            assert_eq!(err.http_status(), expected_status);
        }
    }

    #[test]
    fn scalar_round_trip() {
        // Encode → decode round-trip preserves the value.
        let s = Scalar::from(0xdeadbeefu64);
        let hex = scalar_to_hex(&s);
        let bytes = hex_to_32(&hex).unwrap();
        let s2 = Scalar::from_canonical_bytes(bytes).unwrap();
        assert_eq!(s, s2);
    }
}
