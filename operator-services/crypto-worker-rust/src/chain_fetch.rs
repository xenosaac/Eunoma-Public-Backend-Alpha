//! M10-b: chain-side defense-in-depth helper.
//!
//! The worker's `/v2/balance/decrypt_partial` endpoint MUST re-fetch
//! `oldBalanceD[]` from the Aptos chain via the `0x1::confidential_asset::
//! get_available_balance` view function before computing `dk_share · D` partial
//! shares. This guards against an attacker submitting a forged `D` point to
//! extract a chosen-D oracle output about the worker's secret `dk_share`.
//!
//! This module exposes two pieces:
//!   * `fetch_old_balance_d_from_chain(...)` — the production implementation
//!     using `reqwest`. POSTs to `/v1/view` and parses the returned `D` array.
//!   * `parse_view_response_d(...)` — the pure parsing function. Decoupled from
//!     the HTTP transport so tests can inject canned JSON without spinning up a
//!     local Aptos node.
//!
//! The fetch is intentionally minimal: no retries, no caching, no rate limiting.
//! Failures bubble up so the handler can fail closed with a precise reason.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde_json::{json, Value};
use std::time::Duration;

/// Default timeout for the Aptos `/v1/view` call. Tight on purpose — the worker
/// is responding to a coordinator HTTP request that itself has a deadline, and
/// a slow chain RPC should fail fast so the orchestrator can route around it
/// rather than block the whole quorum.
pub const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 8;

/// Decode a 64-hex-character string into a `RistrettoPoint`. Returns `Err` if
/// the string is not exactly 64 ASCII hex characters or if the bytes don't
/// decode to a canonical Ristretto element.
fn ristretto_from_hex(hex: &str) -> Result<RistrettoPoint, String> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    if raw.len() != 64 {
        return Err(format!(
            "ristretto hex must be 64 chars, got {}",
            raw.len()
        ));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("ristretto hex contains non-hex chars".to_string());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex decode: {e}"))?;
    }
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| "non-canonical compressed Ristretto point".to_string())
}

/// Parse the JSON response from `/v1/view` for `get_available_balance`. Aptos
/// returns the view result as a top-level JSON array; for confidential-asset
/// `get_available_balance(...)` the array contains a single object with `P` and
/// `R` (or equivalently `chunks`) — the `R` array is the chunked `D` points
/// (one per chunk, compressed Ristretto in 0x-prefixed hex).
///
/// Tolerant of two shapes that the Aptos node has emitted historically:
///   1. `[ { "P": [...], "R": [...] } ]`
///   2. `[ { "chunks": [ { "left": "...", "right": "..." }, ... ] } ]`
///
/// We attempt #1 first (the documented shape), fall back to #2, and return a
/// precise error if neither matches.
pub fn parse_view_response_d(value: &Value) -> Result<Vec<RistrettoPoint>, String> {
    let arr = value
        .as_array()
        .ok_or_else(|| "view response is not a JSON array".to_string())?;
    let first = arr
        .first()
        .ok_or_else(|| "view response array is empty".to_string())?;

    if let Some(r) = first.get("R").and_then(|v| v.as_array()) {
        return parse_hex_array(r);
    }

    if let Some(chunks) = first.get("chunks").and_then(|v| v.as_array()) {
        let mut out = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let right = chunk
                .get("right")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "chunk.right missing or not a string".to_string())?;
            out.push(ristretto_from_hex(right)?);
        }
        return Ok(out);
    }

    Err("view response missing 'R' array and 'chunks' fallback".to_string())
}

fn parse_hex_array(arr: &[Value]) -> Result<Vec<RistrettoPoint>, String> {
    let mut out = Vec::with_capacity(arr.len());
    for (idx, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("R[{idx}] is not a string"))?;
        out.push(ristretto_from_hex(s)?);
    }
    Ok(out)
}

/// Build the JSON body for the `0x1::confidential_asset::get_available_balance`
/// view request. Public so tests can assert the request shape without driving a
/// real HTTP call.
pub fn build_view_request_body(vault: &str, asset: &str) -> Value {
    json!({
        "function": "0x1::confidential_asset::get_available_balance",
        "type_arguments": [],
        "arguments": [vault, asset],
    })
}

/// Production helper: POST to `<aptos_node_url>/v1/view` and return the parsed
/// `D` points.
///
/// Errors are mapped to short, lower-snake-case prefixes so the handler can
/// surface them in HTTP error bodies without leaking internals: `network:`,
/// `timeout:`, `bad_status:`, `bad_json:`, `parse:`.
pub async fn fetch_old_balance_d_from_chain(
    vault: &str,
    asset: &str,
    aptos_node_url: &str,
) -> Result<Vec<RistrettoPoint>, String> {
    let url = format!("{}/v1/view", aptos_node_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("network:client_build:{e}"))?;
    let body = build_view_request_body(vault, asset);
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                format!("timeout:{e}")
            } else {
                format!("network:{e}")
            }
        })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("bad_status:{}", status.as_u16()));
    }
    let value: Value = resp
        .json()
        .await
        .map_err(|e| format!("bad_json:{e}"))?;
    parse_view_response_d(&value).map_err(|e| format!("parse:{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar,
    };

    fn compressed_hex(point: &RistrettoPoint) -> String {
        point
            .compress()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn parses_r_array_shape() {
        let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::from(42u64);
        let p2 = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let val = json!([{
            "P": ["00".repeat(32), "00".repeat(32)],
            "R": [compressed_hex(&p1), compressed_hex(&p2)],
        }]);
        let parsed = parse_view_response_d(&val).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].compress(), p1.compress());
        assert_eq!(parsed[1].compress(), p2.compress());
    }

    #[test]
    fn parses_chunks_right_shape() {
        let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::from(11u64);
        let val = json!([{
            "chunks": [
                { "left": "00".repeat(32), "right": compressed_hex(&p1) }
            ]
        }]);
        let parsed = parse_view_response_d(&val).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].compress(), p1.compress());
    }

    #[test]
    fn rejects_empty_array() {
        let val = json!([]);
        assert!(parse_view_response_d(&val).is_err());
    }

    #[test]
    fn rejects_non_array_root() {
        let val = json!({ "R": [] });
        assert!(parse_view_response_d(&val).is_err());
    }

    #[test]
    fn rejects_missing_r_and_chunks() {
        let val = json!([{ "P": [] }]);
        assert!(parse_view_response_d(&val).is_err());
    }

    #[test]
    fn rejects_bad_hex_length() {
        let val = json!([{ "R": ["dead"] }]);
        assert!(parse_view_response_d(&val).is_err());
    }

    #[test]
    fn build_view_request_body_shape() {
        let body = build_view_request_body("0xabc", "0xdef");
        assert_eq!(
            body["function"],
            "0x1::confidential_asset::get_available_balance"
        );
        assert_eq!(body["arguments"][0], "0xabc");
        assert_eq!(body["arguments"][1], "0xdef");
    }
}
