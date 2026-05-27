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
/// Tolerant of three shapes that the Aptos node has emitted historically:
///   1. `[ { "P": [...], "R": [...] } ]` where each array entry is either a
///      bare hex string OR an object `{ "data": "0x..." }` (the latter is
///      what the live testnet `/v1/view` actually returns).
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
        // Accept either bare string OR { "data": "0x..." } shape (what Aptos
        // /v1/view actually emits for compressed Ristretto entries).
        let hex_str = if let Some(s) = v.as_str() {
            s
        } else if let Some(data) = v.get("data").and_then(|d| d.as_str()) {
            data
        } else {
            return Err(format!(
                "R[{idx}] is neither string nor {{data:string}}"
            ));
        };
        out.push(ristretto_from_hex(hex_str)?);
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

// ── M11: vault-state resync chain helper ──────────────────────────────────
//
// The worker's `/v2/vault/resync` endpoint re-fetches a withdraw transaction by
// hash and verifies the emitted `WithdrawEventV2` before advancing its persisted
// `vault_sequence`. Like the balance-decrypt re-fetch above, the tx hash is the
// only caller-supplied input; the node URL and the expected bridge package come
// from the worker's trusted env config, never the request body. This closes the
// same chosen-package / chosen-target class as M10-l's chosen-D closure.

/// Subset of the Aptos user-transaction `/v1/transactions/by_hash/{hash}`
/// response that the resync handler needs. `vault_sequence` arrives as a JSON
/// string (Aptos serializes `u64` as a string) and is parsed to `u64` here. The
/// `root` / `nullifier_hash` / `recipient_hash` / `request_hash` fields are the
/// `vector<u8>` event fields, returned as `0x`-prefixed hex strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxWithdrawEventV2 {
    pub success: bool,
    pub vm_status: String,
    pub root: String,
    pub nullifier_hash: String,
    pub recipient_hash: String,
    pub request_hash: String,
    pub vault_sequence: u64,
}

/// Normalize an Aptos account address to 64-hex lowercase (no `0x`), left-padded
/// with zeros. Used to compare the event-type address segment against the
/// trusted package regardless of leading-zero / `0x` / casing differences.
fn norm_addr(addr: &str) -> Result<String, String> {
    let raw = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .unwrap_or(addr);
    if raw.is_empty() || raw.len() > 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid address: {addr}"));
    }
    Ok(format!("{:0>64}", raw.to_lowercase()))
}

/// Pure parser: given a tx JSON value and the TRUSTED bridge package address,
/// locate the `<package>::eunoma_bridge::WithdrawEventV2`/`WithdrawEventV3` module event and
/// extract its binding fields + the tx success flag / vm_status. Decoupled from
/// HTTP so tests inject canned JSON. The event type's address segment is matched
/// against the trusted package only — a tx whose withdraw event was emitted by a
/// different package address is treated as "not found".
pub fn parse_tx_withdraw_event_v2(
    value: &Value,
    bridge_package: &str,
) -> Result<TxWithdrawEventV2, String> {
    let want_addr = norm_addr(bridge_package).map_err(|e| format!("bad_package:{e}"))?;
    let success = value
        .get("success")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "tx missing success flag".to_string())?;
    let vm_status = value
        .get("vm_status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let events = value
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tx missing events array".to_string())?;

    for ev in events {
        let ty = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
        // Aptos module-event type: "0x<addr>::eunoma_bridge::WithdrawEventV2"
        // or the privacy-hardened "WithdrawEventV3" shape.
        let mut segs = ty.splitn(2, "::");
        let addr_seg = segs.next().unwrap_or("");
        let rest = segs.next().unwrap_or("");
        if rest != "eunoma_bridge::WithdrawEventV2" && rest != "eunoma_bridge::WithdrawEventV3" {
            continue;
        }
        let addr_norm = match norm_addr(addr_seg) {
            Ok(a) => a,
            Err(_) => continue,
        };
        if addr_norm != want_addr {
            // Withdraw event emitted by a non-trusted package — ignore.
            continue;
        }
        let data = ev
            .get("data")
            .ok_or_else(|| "withdraw event missing data".to_string())?;
        let get_hex = |k: &str| -> Result<String, String> {
            data.get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("withdraw event data.{k} missing or not a string"))
        };
        let vault_sequence = {
            let v = data
                .get("vault_sequence")
                .ok_or_else(|| "withdraw event data.vault_sequence missing".to_string())?;
            if let Some(s) = v.as_str() {
                s.parse::<u64>()
                    .map_err(|e| format!("vault_sequence parse: {e}"))?
            } else if let Some(n) = v.as_u64() {
                n
            } else {
                return Err("vault_sequence neither string nor u64".to_string());
            }
        };
        return Ok(TxWithdrawEventV2 {
            success,
            vm_status,
            root: get_hex("root")?,
            nullifier_hash: get_hex("nullifier_hash")?,
            recipient_hash: get_hex("recipient_hash")?,
            request_hash: get_hex("request_hash")?,
            vault_sequence,
        });
    }
    Err("withdraw event not found for trusted package".to_string())
}

/// Production helper: GET `<aptos_node_url>/v1/transactions/by_hash/<tx_hash>`
/// and return the parsed JSON value. Same error-prefix convention as
/// `fetch_old_balance_d_from_chain`: `network:` / `timeout:` / `bad_status:` /
/// `bad_json:`. The caller passes `aptos_node_url` WITHOUT a trailing `/v1`
/// (this fn appends `/v1/...`), matching the balance-decrypt convention.
pub async fn fetch_tx_by_hash(aptos_node_url: &str, tx_hash: &str) -> Result<Value, String> {
    let url = format!(
        "{}/v1/transactions/by_hash/{}",
        aptos_node_url.trim_end_matches('/'),
        tx_hash
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("network:client_build:{e}"))?;
    let resp = client.get(&url).send().await.map_err(|e| {
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
    resp.json::<Value>().await.map_err(|e| format!("bad_json:{e}"))
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

    /// M10-b-fix: live Aptos `/v1/view` emits each Ristretto entry as an
    /// object `{ "data": "0x..." }` rather than a bare hex string. The
    /// parser must accept this shape across both `P` and `R` arrays.
    #[test]
    fn parse_view_response_d_accepts_object_with_data_field() {
        let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::from(123u64);
        let p2 = RISTRETTO_BASEPOINT_POINT * Scalar::from(456u64);
        let val = json!([{
            "P": [
                { "data": format!("0x{}", "00".repeat(32)) },
                { "data": format!("0x{}", "00".repeat(32)) }
            ],
            "R": [
                { "data": format!("0x{}", compressed_hex(&p1)) },
                { "data": format!("0x{}", compressed_hex(&p2)) }
            ]
        }]);
        let parsed = parse_view_response_d(&val).expect("object-shape parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].compress(), p1.compress());
        assert_eq!(parsed[1].compress(), p2.compress());
    }

    /// Regression: the original bare-string shape must continue to parse.
    #[test]
    fn parse_view_response_d_still_accepts_bare_strings() {
        let p1 = RISTRETTO_BASEPOINT_POINT * Scalar::from(99u64);
        let val = json!([{
            "P": ["00".repeat(32)],
            "R": [compressed_hex(&p1)],
        }]);
        let parsed = parse_view_response_d(&val).expect("bare-string parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].compress(), p1.compress());
    }

    /// `{ "data": <non-string> }` must surface a precise error (not a panic).
    #[test]
    fn parse_view_response_d_rejects_non_string_data() {
        let val = json!([{
            "P": [],
            "R": [{ "data": 42 }],
        }]);
        let err = parse_view_response_d(&val)
            .expect_err("non-string data must be rejected");
        assert!(
            err.contains("neither string nor {data:string}"),
            "expected precise parse error, got {err}"
        );
    }

    // ── M11: parse_tx_withdraw_event_v2 ───────────────────────────────────

    const PKG: &str = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";

    fn withdraw_tx_with_event(pkg: &str, seq: serde_json::Value, success: bool, event_name: &str) -> Value {
        json!({
            "success": success,
            "vm_status": if success { "Executed successfully" } else { "ABORTED" },
            "events": [
                { "type": "0x1::coin::WithdrawEvent", "data": { "amount": "5" } },
                {
                    "type": format!("{pkg}::eunoma_bridge::{event_name}"),
                    "data": {
                        "root": "0xaa",
                        "nullifier_hash": "0xbb",
                        "recipient": "0x554cd51d",
                        "recipient_hash": "0xcc",
                        "amount_tag": "0xdd",
                        "ca_payload_hash": "0xee",
                        "request_hash": "0xff",
                        "vault_sequence": seq
                    }
                }
            ]
        })
    }

    fn withdraw_tx(pkg: &str, seq: serde_json::Value, success: bool) -> Value {
        withdraw_tx_with_event(pkg, seq, success, "WithdrawEventV2")
    }

    #[test]
    fn parse_tx_withdraw_event_v2_extracts_binding_and_parses_string_sequence() {
        let tx = withdraw_tx(PKG, json!("1"), true);
        let ev = parse_tx_withdraw_event_v2(&tx, PKG).expect("parse");
        assert!(ev.success);
        assert_eq!(ev.root, "0xaa");
        assert_eq!(ev.nullifier_hash, "0xbb");
        assert_eq!(ev.recipient_hash, "0xcc");
        assert_eq!(ev.request_hash, "0xff");
        assert_eq!(ev.vault_sequence, 1);
    }

    #[test]
    fn parse_tx_withdraw_event_v2_accepts_numeric_sequence() {
        let tx = withdraw_tx(PKG, json!(2u64), true);
        let ev = parse_tx_withdraw_event_v2(&tx, PKG).expect("parse");
        assert_eq!(ev.vault_sequence, 2);
    }

    #[test]
    fn parse_tx_withdraw_event_v2_accepts_event_v3() {
        let tx = withdraw_tx_with_event(PKG, json!("3"), true, "WithdrawEventV3");
        let ev = parse_tx_withdraw_event_v2(&tx, PKG).expect("parse");
        assert_eq!(ev.vault_sequence, 3);
    }

    #[test]
    fn parse_tx_withdraw_event_v2_surfaces_failed_tx() {
        let tx = withdraw_tx(PKG, json!("1"), false);
        let ev = parse_tx_withdraw_event_v2(&tx, PKG).expect("parse");
        assert!(!ev.success);
    }

    #[test]
    fn parse_tx_withdraw_event_v2_ignores_event_from_wrong_package() {
        let other = "0xdeadbeef";
        let tx = withdraw_tx(other, json!("1"), true);
        // Searching with the trusted PKG must NOT match the other package's event.
        assert!(parse_tx_withdraw_event_v2(&tx, PKG).is_err());
        // But searching with the actual emitting package finds it.
        assert!(parse_tx_withdraw_event_v2(&tx, other).is_ok());
    }

    #[test]
    fn parse_tx_withdraw_event_v2_address_normalization_matches() {
        // Event emitted with a 0X-prefixed, mixed-case, leading-zero address must
        // still match a trusted package given in a different but equivalent form.
        let emitted = "0X0a08850B1Ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";
        let trusted = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";
        // Note: emitted has an extra leading 0 byte (0a..) vs trusted (a0..) — these
        // are DIFFERENT addresses, so this must NOT match. Use it as a negative.
        let tx = withdraw_tx(emitted, json!("1"), true);
        assert!(parse_tx_withdraw_event_v2(&tx, trusted).is_err());
        // Same address, only 0x/casing differs → matches.
        let tx2 = withdraw_tx("0XA08850B1CA22CC5AA3A3A3FB1179CF3F1F169312CEA8038FF1B1E3B4ACE79EC1", json!("1"), true);
        assert!(parse_tx_withdraw_event_v2(&tx2, trusted).is_ok());
    }

    #[test]
    fn parse_tx_withdraw_event_v2_missing_event_errs() {
        let tx = json!({ "success": true, "vm_status": "Executed successfully", "events": [
            { "type": "0x1::coin::WithdrawEvent", "data": { "amount": "5" } }
        ]});
        assert!(parse_tx_withdraw_event_v2(&tx, PKG).is_err());
    }

    #[test]
    fn parse_tx_withdraw_event_v2_missing_success_errs() {
        let tx = json!({ "vm_status": "x", "events": [] });
        assert!(parse_tx_withdraw_event_v2(&tx, PKG).is_err());
    }
}
