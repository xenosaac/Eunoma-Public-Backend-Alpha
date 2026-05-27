// Thin CLI wrapper exposing `eunoma_crypto_worker::mpcca_withdraw_v2::seal_ingress_envelope_for_test`
// so the TS user-side withdraw orchestrator can construct cryptographically-valid M1 ingress
// envelopes (DHKEM-X25519-HKDF-SHA256 + HKDF-SHA256 + AES-256-GCM with HPKE_INFO_INGRESS) under
// the SAME crypto used by the workers' run_round1_v2 ingress-open path.
//
// Usage:
//
//   echo '{"recipientPubKeyHex":"0x..32 bytes..","aadHex":"0x..","plaintextHex":"0x.."}' \
//     | ./hpke_seal_ingress
//
// Stdout (success): {"kem":"DHKEM_X25519_HKDF_SHA256","kdf":"HKDF_SHA256","aead":"AES_256_GCM",
//                    "enc":"<hex>","ciphertext":"<hex>","aadHash":"<hex>"}
//   This matches the HpkeEnvelope serde camelCase shape the workers + coordinator expect.
//
// Stdout (failure): {"error":"<message>"} + exit code 1.

use std::io::Read;

use eunoma_crypto_worker::mpcca_withdraw_v2::seal_ingress_envelope_for_test;
use eunoma_crypto_worker::normalize_sigma_partial::{
    seal_normalize_alpha_share_for_test, NORMALIZE_ALPHA_SHARE_INFO,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    recipient_pub_key_hex: String,
    aad_hex: String,
    plaintext_hex: String,
    info_string: Option<String>,
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

fn decode_hex(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let hex_str = strip_0x(s);
    if hex_str.len() % 2 != 0 {
        return Err(format!("{label}: odd hex length"));
    }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte_hex = &hex_str[i..i + 2];
        let byte = u8::from_str_radix(byte_hex, 16)
            .map_err(|e| format!("{label}: invalid hex byte at {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn main() {
    let mut buf = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
        eprintln!("{{\"error\":\"stdin read failed: {e}\"}}");
        std::process::exit(1);
    }
    let req: Request = match serde_json::from_str(buf.trim()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{{\"error\":\"invalid JSON: {e}\"}}");
            std::process::exit(2);
        }
    };

    // Recipient pub-key is passed as hex to seal_ingress_envelope_for_test (which strips 0x).
    let pub_key_hex = strip_0x(&req.recipient_pub_key_hex).to_string();
    let aad = match decode_hex(&req.aad_hex, "aadHex") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{{\"error\":\"{e}\"}}");
            std::process::exit(2);
        }
    };
    let plaintext = match decode_hex(&req.plaintext_hex, "plaintextHex") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{{\"error\":\"{e}\"}}");
            std::process::exit(2);
        }
    };

    let seal_result = match req.info_string.as_deref() {
        None => seal_ingress_envelope_for_test(&pub_key_hex, &aad, &plaintext),
        Some("EUNOMA_M1_AMOUNT_INGRESS_V1") => {
            seal_ingress_envelope_for_test(&pub_key_hex, &aad, &plaintext)
        }
        Some(info) if info.as_bytes() == NORMALIZE_ALPHA_SHARE_INFO => {
            seal_normalize_alpha_share_for_test(&pub_key_hex, &aad, &plaintext)
        }
        Some(other) => {
            eprintln!("{{\"error\":\"unsupported infoString: {other}\"}}");
            std::process::exit(2);
        }
    };

    match seal_result {
        Ok(env) => {
            // env serializes as camelCase via the derive on HpkeEnvelope.
            match serde_json::to_string(&env) {
                Ok(s) => {
                    println!("{s}");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{{\"error\":\"serialize: {e}\"}}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("{{\"error\":\"seal: {e:?}\"}}");
            std::process::exit(1);
        }
    }
}
