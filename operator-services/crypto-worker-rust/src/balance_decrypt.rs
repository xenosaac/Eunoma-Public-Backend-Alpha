//! M10-b: worker partial-decryption endpoint.
//!
//! `POST /v2/balance/decrypt_partial` — each worker in the active 5-of-7 quorum
//! computes its own partial share `dk_share_i · oldBalanceD[k]` per chunk and
//! returns the resulting Vec<RistrettoPoint>. The orchestrator collects 5
//! partials, Lagrange-aggregates → `real_dk · oldBalanceD[k]`, subtracts from
//! `oldBalanceC[k]` → BSGS-decodes → integer chunk. No party (worker,
//! coordinator, orchestrator) ever reconstructs `real_dk`.
//!
//! ## Defense-in-depth
//!
//! The worker MUST re-fetch `oldBalanceD[]` from the Aptos chain via
//! `0x1::confidential_asset::get_available_balance` and reject the request if
//! ANY chunk's compressed encoding differs from what the requester supplied.
//! This guards against a chosen-D attack: an attacker who could pick arbitrary
//! `D` points could probe the worker's `dk_share` by observing the output
//! pattern across many requests.
//!
//! M10-l (codex P1): the chain re-fetch URL is sourced from the worker's
//! own `APTOS_NODE_URL` env var via `AppState.aptos_node_url()` — never the
//! request body. A request-controlled URL turns the worker into an oracle:
//! attacker hosts `/v1/view` that returns chosen `D'` matching the request's
//! `oldBalanceDHex`, byte-equality check passes, worker returns
//! `dk_share · D'`. Threshold-aggregate 5 such partials and you recover
//! `real_dk · D'` for attacker-chosen D' — full vault decryption.
//!
//! ## Zeroize discipline
//!
//! `dk_share` is decoded from the share file and held in a single `Scalar` on
//! the stack. We zeroize it on EVERY return path — success, chain-fetch
//! failure, D-mismatch, signing failure. The `CaDkgV2ShareFile` returned by
//! `load_ca_dkg_v2_share` already implements `Drop` that zeroizes its hex
//! `dk_share` string when the struct goes out of scope.
//!
//! ## Attestation
//!
//! The response carries a `signature` field. Per the existing FROST/round1/
//! round2 convention, this is a SHA-256 *transcript hash* over canonical bytes
//! binding (request_id, dkg_epoch, vault, asset, slot, partials[*]). The plan's
//! pseudocode names this "ed25519 signature" but the worker has no per-slot
//! Ed25519 attestation key in its persistent state — the FROST signing share
//! is the only secret key, and it would compromise the FROST threshold scheme
//! to use it directly here. The orchestrator re-derives the SAME canonical
//! bytes and compares hashes. This is documented as the M10-b "transcript
//! signature" deviation.
//!
//! ### M10-l known limitation (codex iter-2 P1, deferred)
//!
//! A SHA-256 of public fields is NOT a per-slot signature. Anyone with
//! response-path access (a MITM between coordinator and worker, a compromised
//! deop-node passthrough, or any actor that can intercept the HTTP response)
//! can forge an arbitrary `partialHex` and recompute the matching
//! `signature` — the coordinator's verification only detects accidental
//! tampering, not malicious response forgery. Closing this requires either:
//!   (a) a per-slot signing key bound to the roster's `transcriptPublicKey`
//!       (workers don't currently carry the matching private key — adding it
//!       is a new DKG-like state initialization, out of M10-l "no new crypto
//!       scope" per the milestone contract); OR
//!   (b) a verifiable partial-decryption NIZK (e.g. Chaum-Pedersen proof of
//!       `dk_share · D = partial` for known `D`), which is new crypto scope.
//!
//! Threat-model impact: this is **DoS-only**, not a privacy or key-material
//! compromise. Even with a forged partial, the threshold aggregation yields
//! a wrong `real_dk · D`, which produces a wrong `newBalanceChunks` witness,
//! which the chain σ-position-17 verifier rejects (`E_INVALID_TRANSFER_PROOF`).
//! The vault's confidential balance and the workers' `dk_share` material stay
//! protected by the existing 5-of-7 threshold + chain-D byte-equality check.
//! Tracked for a future hardening milestone (M11+).

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroize;

use crate::ca_dkg_v2::load_ca_dkg_v2_share;
use crate::chain_fetch::fetch_old_balance_d_from_chain;

/// Domain-separation label for the M10-b transcript hash. Bumped if the
/// canonical payload format changes; orchestrator must mirror.
pub const M10B_TRANSCRIPT_DOMAIN: &str = "EUNOMA_M10B_BALANCE_DECRYPT_PARTIAL_V1";

/// Required JSON request body. All fields are mandatory; no defaults. The
/// `slot` field is the requester's view of which worker this request targets —
/// the worker cross-checks against the share file's slot and rejects on
/// mismatch.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceDecryptPartialRequest {
    /// CA DKG V2 epoch — must equal the share file's `dkg_epoch`.
    pub dkg_epoch: String,
    /// Aptos vault address (hex). Used for the `/v1/view` lookup. Treated as an
    /// opaque string; we trust the chain re-fetch to surface bad addresses.
    pub vault_address: String,
    /// Confidential-asset type tag (e.g. `0x1::aptos_coin::AptosCoin`). Treated
    /// as opaque.
    pub asset_type: String,
    /// Requester's view of `oldBalanceD[]` — one 64-hex (32-byte compressed
    /// Ristretto) per chunk. Length MUST match the chain's view-call response
    /// length and every byte MUST match.
    pub old_balance_d_hex: Vec<String>,
    /// Caller-supplied request correlation id. Bound into the transcript.
    pub request_id: String,
    /// Slot the requester believes this worker holds. Must equal the share
    /// file's slot.
    pub slot: usize,
}

/// Successful response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceDecryptPartialResponse {
    /// Echo of the worker's slot index (post-cross-check).
    pub slot: usize,
    /// `partial[k] = dk_share_i · D[k]` for each chunk, compressed Ristretto
    /// in 64-hex.
    pub partial_hex: Vec<String>,
    /// SHA-256 transcript hash over canonical bytes (see module docs). 64-hex.
    pub signature: String,
    /// Transcript domain label (echoed so the orchestrator's re-derivation
    /// can't be fooled by a worker emitting a stale domain).
    pub transcript_domain: String,
}

/// Errors are surfaced as short, stable, lower-snake-case strings. The HTTP
/// adapter maps them to 400 / 404 / 502 / 500 per the variant.
#[derive(Debug)]
pub enum BalanceDecryptError {
    /// Caller-supplied input failed validation before any share access.
    BadRequest(String),
    /// Worker has no CA DKG V2 share file at the expected path, OR the file's
    /// epoch/slot doesn't match the request.
    MissingShare(String),
    /// Chain re-fetch failed (network, timeout, bad status, bad JSON, parse
    /// error). Includes the prefixed reason from `chain_fetch.rs`.
    ChainFetch(String),
    /// Request's `oldBalanceD[k]` disagrees with the chain at chunk `k`. This
    /// is the load-bearing defense-in-depth check.
    DMismatch { chunk: usize },
    /// `oldBalanceD.len()` does not match the chain's ell.
    EllMismatch { request: usize, chain: usize },
    /// Anything else (share decode, scalar decode, transcript hashing). Logged
    /// but surfaced as a 500 to the caller.
    Internal(String),
}

impl BalanceDecryptError {
    fn http_status(&self) -> StatusCode {
        match self {
            BalanceDecryptError::BadRequest(_) => StatusCode::BAD_REQUEST,
            BalanceDecryptError::MissingShare(_) => StatusCode::NOT_FOUND,
            BalanceDecryptError::ChainFetch(_) => StatusCode::BAD_GATEWAY,
            BalanceDecryptError::DMismatch { .. } => StatusCode::BAD_REQUEST,
            BalanceDecryptError::EllMismatch { .. } => StatusCode::BAD_REQUEST,
            BalanceDecryptError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Short, stable error code for the HTTP body's `error` field.
    fn code(&self) -> String {
        match self {
            BalanceDecryptError::BadRequest(reason) => format!("bad_request:{reason}"),
            BalanceDecryptError::MissingShare(reason) => format!("missing_share:{reason}"),
            BalanceDecryptError::ChainFetch(reason) => format!("chain_fetch:{reason}"),
            BalanceDecryptError::DMismatch { chunk } => format!("d_mismatch_at_chunk_{chunk}"),
            BalanceDecryptError::EllMismatch { request, chain } => {
                format!("ell_mismatch:request={request}:chain={chain}")
            }
            BalanceDecryptError::Internal(reason) => format!("internal:{reason}"),
        }
    }
}

impl std::fmt::Display for BalanceDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code())
    }
}

impl std::error::Error for BalanceDecryptError {}

/// Decode a 64-hex string into 32 raw bytes. Tolerates a `0x` prefix.
fn hex_to_32(hex: &str) -> Result<[u8; 32], BalanceDecryptError> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if raw.len() != 64 {
        return Err(BalanceDecryptError::BadRequest(format!(
            "hex must be 64 chars, got {}",
            raw.len()
        )));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BalanceDecryptError::BadRequest(
            "non-hex character".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|e| BalanceDecryptError::BadRequest(format!("hex decode: {e}")))?;
    }
    Ok(bytes)
}

/// Decode a 32-byte scalar (canonical or non-canonical). The CA DKG V2 share
/// loader stores `dk_share` as a 32-byte little-endian hex; `Scalar::
/// from_bytes_mod_order` accepts any 32 bytes and reduces, which matches the
/// loader's existing semantics (see `lib.rs:2147`).
fn scalar_from_share_hex(hex: &str) -> Result<Scalar, BalanceDecryptError> {
    let bytes = hex_to_32(hex)
        .map_err(|e| BalanceDecryptError::Internal(format!("share dk_share hex invalid: {e}")))?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

/// Canonical byte serialization for the M10-b transcript hash.
///
/// Layout (no embedded length-prefix collisions — every field is followed by a
/// single ASCII colon byte 0x3a; field bytes themselves carry no colons because
/// they're either hex strings, decimal integers, or ASCII strings without
/// colons):
///
/// ```text
/// M10B_TRANSCRIPT_DOMAIN | ':' |
/// dkg_epoch              | ':' |
/// vault_address          | ':' |
/// asset_type             | ':' |
/// slot (decimal)         | ':' |
/// request_id             | ':' |
/// ell (decimal)          | ':' |
/// partial_hex[0]         | ':' |
/// partial_hex[1]         | ':' |
/// …                      | ':' |
/// partial_hex[ell-1]
/// ```
///
/// SHA-256 of the resulting bytes is the `signature` value. The orchestrator
/// re-derives the same bytes from its known inputs and the worker's returned
/// partials, recomputes SHA-256, and compares hex-strings byte-for-byte.
///
/// `ell` is encoded explicitly even though `partial_hex.len()` would suffice,
/// because a coordinator that buffers responses MUST be able to detect a
/// length-tampered partial array without trusting the array boundary.
pub fn canonical_transcript_bytes(
    dkg_epoch: &str,
    vault_address: &str,
    asset_type: &str,
    slot: usize,
    request_id: &str,
    partial_hex: &[String],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        M10B_TRANSCRIPT_DOMAIN.len()
            + dkg_epoch.len()
            + vault_address.len()
            + asset_type.len()
            + request_id.len()
            + partial_hex.iter().map(|s| s.len() + 1).sum::<usize>()
            + 64,
    );
    out.extend_from_slice(M10B_TRANSCRIPT_DOMAIN.as_bytes());
    out.push(b':');
    out.extend_from_slice(dkg_epoch.as_bytes());
    out.push(b':');
    out.extend_from_slice(vault_address.as_bytes());
    out.push(b':');
    out.extend_from_slice(asset_type.as_bytes());
    out.push(b':');
    out.extend_from_slice(slot.to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(request_id.as_bytes());
    out.push(b':');
    out.extend_from_slice(partial_hex.len().to_string().as_bytes());
    for (idx, partial) in partial_hex.iter().enumerate() {
        out.push(b':');
        out.extend_from_slice(partial.as_bytes());
        let _ = idx;
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encode a compressed Ristretto point as 64-hex (lowercase, no `0x` prefix).
fn compressed_hex(point: &RistrettoPoint) -> String {
    point
        .compress()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Core handler — pure async function. Loads the share, re-fetches chain D,
/// validates equality byte-for-byte, computes `dk_share · D[k]` for each
/// chunk, zeroizes the share scalar, and returns the partials + transcript
/// hash.
///
/// `state_dir` is the worker's per-slot state directory (e.g.
/// `.agent-local/eunoma-v2/slot-3`). It MUST already contain a valid
/// `ca_dkg_share_v2.json` for the requested epoch.
///
/// `chain_d_override` is an optional injection point for tests: when `Some`,
/// the chain re-fetch is skipped and the supplied vector is used as the
/// authoritative chain D. Production callers always pass `None`.
pub async fn handle(
    state_dir: &Path,
    trusted_aptos_node_url: &str,
    trusted_bridge_vault_address: &str,
    trusted_bridge_asset_type: &str,
    req: BalanceDecryptPartialRequest,
    chain_d_override: Option<Vec<RistrettoPoint>>,
) -> Result<BalanceDecryptPartialResponse, BalanceDecryptError> {
    // 1. Cheap input validation BEFORE touching any secret material.
    if req.dkg_epoch.is_empty() {
        return Err(BalanceDecryptError::BadRequest(
            "dkgEpoch is empty".to_string(),
        ));
    }
    if req.vault_address.is_empty() {
        return Err(BalanceDecryptError::BadRequest(
            "vaultAddress is empty".to_string(),
        ));
    }
    if req.asset_type.is_empty() {
        return Err(BalanceDecryptError::BadRequest(
            "assetType is empty".to_string(),
        ));
    }
    if req.request_id.is_empty() {
        return Err(BalanceDecryptError::BadRequest(
            "requestId is empty".to_string(),
        ));
    }
    // M10-l (codex P1): the chain URL is config-trusted (from AppState ←
    // APTOS_NODE_URL env at worker startup). A request-controlled URL
    // becomes a chosen-D oracle for `dk_share · D'` (attacker points the
    // worker at `/v1/view` they control, returning D' that matches the
    // request's `oldBalanceDHex`; worker then signs `dk_share · D'`).
    // Threshold-aggregate 5 such partials and you recover `real_dk · D'`
    // for attacker-chosen D' — full vault decryption.
    if trusted_aptos_node_url.is_empty() && chain_d_override.is_none() {
        return Err(BalanceDecryptError::Internal(
            "worker_missing_aptos_node_url_config".to_string(),
        ));
    }
    // M10-l (codex iter-6 P1-13): bind to the trusted (vault, asset) pair.
    // Even with `aptos_node_url` config-trusted, a caller could otherwise
    // ask `dk_share · D` for any other confidential balance the same CA DKG
    // signs over (e.g. a different vault on the same chain). Reject early —
    // before reading the share file.
    if trusted_bridge_vault_address.is_empty() || trusted_bridge_asset_type.is_empty() {
        return Err(BalanceDecryptError::Internal(
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
        let lower = stripped.to_ascii_lowercase();
        // Left-pad with zeros to 64 hex chars (32-byte canonical).
        Some(format!("{:0>64}", lower))
    };
    let cfg_vault_norm = normalize_aptos_addr(trusted_bridge_vault_address);
    let req_vault_norm = normalize_aptos_addr(&req.vault_address);
    if cfg_vault_norm.is_none() || req_vault_norm.is_none() || cfg_vault_norm != req_vault_norm {
        return Err(BalanceDecryptError::BadRequest(
            "vault_address_does_not_match_configured_bridge_vault".to_string(),
        ));
    }
    // Asset types may be address-shaped OR Move struct-tag shaped. Try
    // address normalization first; if both sides fail, fall back to a
    // strict case-insensitive string compare with leading-`0x` stripped.
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
        return Err(BalanceDecryptError::BadRequest(
            "asset_type_does_not_match_configured_bridge_asset".to_string(),
        ));
    }
    if req.old_balance_d_hex.is_empty() {
        return Err(BalanceDecryptError::BadRequest(
            "oldBalanceDHex is empty".to_string(),
        ));
    }

    // 2. Load the CA DKG V2 share. The loader returns a `CaDkgV2ShareFile`
    //    whose `dk_share` hex string is zeroized on drop via the existing
    //    `Drop` impl at `lib.rs:2047`.
    let share = load_ca_dkg_v2_share(state_dir).map_err(|err| match err {
        crate::WorkerError::MissingLocalState(path) => {
            BalanceDecryptError::MissingShare(format!("file_not_found:{path}"))
        }
        other => BalanceDecryptError::MissingShare(format!("load_failed:{other:?}")),
    })?;

    // 3. Cross-check the request against the share file's bindings BEFORE
    //    decoding the secret scalar. A wrong epoch / slot should fail closed
    //    without touching dk_share.
    if share.dkg_epoch != req.dkg_epoch {
        return Err(BalanceDecryptError::MissingShare(format!(
            "dkg_epoch_mismatch:share={}:request={}",
            share.dkg_epoch, req.dkg_epoch
        )));
    }
    if share.slot != req.slot {
        return Err(BalanceDecryptError::BadRequest(format!(
            "slot_mismatch:share={}:request={}",
            share.slot, req.slot
        )));
    }

    // 4. Decode dk_share. This is the FIRST point at which secret material
    //    enters our stack frame as a `Scalar`. We MUST zeroize on every
    //    subsequent return path until step 7.
    let mut dk_share = scalar_from_share_hex(&share.dk_share)?;

    // 5. Re-fetch oldBalanceD from chain using the worker's TRUSTED URL
    //    (M10-l codex P1: never the request-supplied URL — see top of handler).
    //    Failure → zeroize dk_share, surface ChainFetch error.
    let chain_d = match chain_d_override {
        Some(v) => v,
        None => match fetch_old_balance_d_from_chain(
            &req.vault_address,
            &req.asset_type,
            trusted_aptos_node_url,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                dk_share.zeroize();
                return Err(BalanceDecryptError::ChainFetch(e));
            }
        },
    };

    // 6. Length check.
    if chain_d.len() != req.old_balance_d_hex.len() {
        dk_share.zeroize();
        return Err(BalanceDecryptError::EllMismatch {
            request: req.old_balance_d_hex.len(),
            chain: chain_d.len(),
        });
    }

    // 7. Defense-in-depth: byte-for-byte equality check between request's
    //    oldBalanceD[k] and the chain's view-call result. This is what stops
    //    an attacker from feeding a forged D to extract chosen-D oracle
    //    information about dk_share.
    for (k, req_hex) in req.old_balance_d_hex.iter().enumerate() {
        let req_bytes = match hex_to_32(req_hex) {
            Ok(b) => b,
            Err(e) => {
                dk_share.zeroize();
                return Err(e);
            }
        };
        let req_point = match CompressedRistretto(req_bytes).decompress() {
            Some(p) => p,
            None => {
                dk_share.zeroize();
                return Err(BalanceDecryptError::BadRequest(format!(
                    "non-canonical D at chunk {k}"
                )));
            }
        };
        if req_point.compress() != chain_d[k].compress() {
            dk_share.zeroize();
            return Err(BalanceDecryptError::DMismatch { chunk: k });
        }
    }

    // 8. Compute partial[k] = dk_share · D[k] for each chunk. Each
    //    multiplication is a scalar-by-point op on Ristretto; the result is
    //    indistinguishable from random without knowing dk_share, so the worker
    //    never leaks anything beyond what's strictly necessary for the
    //    Lagrange-aggregation step the orchestrator performs.
    let mut partials = Vec::with_capacity(chain_d.len());
    for d in chain_d.iter() {
        partials.push(d * dk_share);
    }

    // 9. Zeroize dk_share IMMEDIATELY after the last use. No further reference
    //    to it past this line. The `CaDkgV2ShareFile` Drop impl will also
    //    zeroize the underlying hex String when `share` goes out of scope at
    //    the end of the function, but we don't depend on that for the scalar
    //    copy we made.
    dk_share.zeroize();

    // 10. Encode partials and compute the attestation transcript hash.
    let partial_hex: Vec<String> = partials.iter().map(compressed_hex).collect();

    let transcript = canonical_transcript_bytes(
        &req.dkg_epoch,
        &req.vault_address,
        &req.asset_type,
        req.slot,
        &req.request_id,
        &partial_hex,
    );
    let signature = sha256_hex(&transcript);

    Ok(BalanceDecryptPartialResponse {
        slot: share.slot,
        partial_hex,
        signature,
        transcript_domain: M10B_TRANSCRIPT_DOMAIN.to_string(),
    })
}

/// Axum HTTP adapter. Adapts the typed handler to a Json/Json route. Errors
/// are surfaced as `{ "error": "<code>", "message": "<display>" }` with the
/// status code derived from the error variant.
///
/// The adapter is generic over any `AppState`-like value that exposes a
/// `state_dir: PathBuf` field via the trait below, so `main.rs`'s `AppState`
/// can use it without modification beyond implementing the trait. We keep the
/// trait in this module to avoid forcing an import cycle.
pub async fn handle_http<S: AppStateForBalanceDecrypt + Send + Sync>(
    State(state): State<S>,
    Json(req): Json<BalanceDecryptPartialRequest>,
) -> impl IntoResponse {
    let state_dir = state.state_dir().to_path_buf();
    let trusted_url = state.aptos_node_url().to_string();
    let trusted_vault = state.bridge_vault_address().to_string();
    let trusted_asset = state.bridge_asset_type().to_string();
    match handle(
        &state_dir,
        &trusted_url,
        &trusted_vault,
        &trusted_asset,
        req,
        None,
    )
    .await
    {
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

/// Read-only view of the worker's per-slot state directory, the trusted
/// chain URL, and the trusted (vault, asset) bridge binding. Implemented by
/// `main.rs`'s `AppState`.
///
/// `aptos_node_url`, `bridge_vault_address`, and `bridge_asset_type` are all
/// sourced from the worker's env at startup (`APTOS_NODE_URL`,
/// `BRIDGE_VAULT_ADDRESS`, `BRIDGE_ASSET_TYPE`). The balance-decrypt handler
/// rejects any request whose `vault_address` / `asset_type` don't match the
/// configured trusted pair — without this gate, a caller with a valid bearer
/// could ask the threshold-decrypt to operate on any confidential balance
/// under the same CA DKG (M10-l codex iter-6 P1-13).
pub trait AppStateForBalanceDecrypt: Clone + 'static {
    fn state_dir(&self) -> &Path;
    fn aptos_node_url(&self) -> &str;
    fn bridge_vault_address(&self) -> &str;
    fn bridge_asset_type(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};

    #[test]
    fn canonical_bytes_are_deterministic_and_length_bound() {
        let p_hex: Vec<String> = (0u64..3)
            .map(|i| {
                let p = RISTRETTO_BASEPOINT_POINT * Scalar::from(100 + i);
                compressed_hex(&p)
            })
            .collect();
        let a =
            canonical_transcript_bytes("epoch-1", "0xvault", "0x1::asset::T", 3, "req-1", &p_hex);
        let b =
            canonical_transcript_bytes("epoch-1", "0xvault", "0x1::asset::T", 3, "req-1", &p_hex);
        assert_eq!(a, b);

        // Tampering with ell MUST change the transcript.
        let mut shorter = p_hex.clone();
        shorter.pop();
        let c =
            canonical_transcript_bytes("epoch-1", "0xvault", "0x1::asset::T", 3, "req-1", &shorter);
        assert_ne!(a, c);

        // Tampering with slot MUST change the transcript.
        let d =
            canonical_transcript_bytes("epoch-1", "0xvault", "0x1::asset::T", 4, "req-1", &p_hex);
        assert_ne!(a, d);
    }

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
                BalanceDecryptError::BadRequest("x".into()),
                "bad_request:x",
                StatusCode::BAD_REQUEST,
            ),
            (
                BalanceDecryptError::MissingShare("y".into()),
                "missing_share:y",
                StatusCode::NOT_FOUND,
            ),
            (
                BalanceDecryptError::DMismatch { chunk: 3 },
                "d_mismatch_at_chunk_3",
                StatusCode::BAD_REQUEST,
            ),
            (
                BalanceDecryptError::EllMismatch {
                    request: 8,
                    chain: 4,
                },
                "ell_mismatch:request=8:chain=4",
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (err, expected_code, expected_status) in cases {
            assert_eq!(err.code(), expected_code);
            assert_eq!(err.http_status(), expected_status);
        }
    }
}
