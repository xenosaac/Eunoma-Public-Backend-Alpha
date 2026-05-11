// Build canonical attestation messages from request bodies. Centralized so
// main + partner operators sign over byte-identical bytes.

import {
  bcsEncodeDepositAttestationMessage,
} from "./bcs.js";
import {
  CAPayloadForHashStruct,
  CAPayloadJson,
  DepositAttestationMessageStruct,
  DOMAIN_DEPOSIT_OK_V1,
} from "./types.js";
import { hexToBytes } from "./hex.js";

export function caPayloadFromJson(p: CAPayloadJson): CAPayloadForHashStruct {
  return {
    asset_type: hexToBytes(p.asset_type),
    vault_addr: hexToBytes(p.vault_addr),
    new_balance_p: p.new_balance_p.map(hexToBytes),
    new_balance_r: p.new_balance_r.map(hexToBytes),
    new_balance_r_eff_aud: p.new_balance_r_eff_aud.map(hexToBytes),
    amount_p: p.amount_p.map(hexToBytes),
    amount_r_sender: p.amount_r_sender.map(hexToBytes),
    amount_r_recip: p.amount_r_recip.map(hexToBytes),
    amount_r_eff_aud: p.amount_r_eff_aud.map(hexToBytes),
    ek_volun_auds: p.ek_volun_auds.map(hexToBytes),
    amount_r_volun_auds: p.amount_r_volun_auds.map((middle) =>
      middle.map(hexToBytes),
    ),
    zkrp_new_balance: hexToBytes(p.zkrp_new_balance),
    zkrp_amount: hexToBytes(p.zkrp_amount),
    sigma_proto_comm: p.sigma_proto_comm.map(hexToBytes),
    sigma_proto_resp: p.sigma_proto_resp.map(hexToBytes),
    memo: hexToBytes(p.memo),
  };
}

export interface BuildAttestationArgs {
  chain_id: number;
  pool_id: bigint; // u64
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: Uint8Array; // 32 bytes
  asset_type: Uint8Array; // 32 bytes
  commitment: Uint8Array;
  amount_tag: Uint8Array;
  ca_payload_hash: Uint8Array;
  deposit_nonce: Uint8Array;
  expiry_secs: bigint;
}

/// Build a DepositAttestationMessage struct + the canonical BCS bytes the
/// operator signs over. Mirror of Move's attestation-build path.
export function buildDepositAttestationMessage(
  args: BuildAttestationArgs,
): {
  msg: DepositAttestationMessageStruct;
  msg_bytes: Uint8Array;
} {
  // Move encodes pool_id as `vector<u8>` (8-byte u64 LE — see Gate 4a circuit
  // wiring at confidential_bridge.move:1078-1085 `pool_id_to_fr_bytes` which
  // returns a 32-byte LE Fr; but the attestation-message field type is
  // `vector<u8>` and the Gate 2 / Gate 4b convention stores the raw 8-byte
  // representation). For Gate 4c we mirror exactly what Move's attestation
  // builder does — see `confidential_bridge.move:806-823 build_deposit_attestation`.
  // That builder accepts pool_id as a `vector<u8>` parameter from the caller.
  // Convention: u64 LE 8 bytes.
  const pool_id = new Uint8Array(8);
  let v = args.pool_id;
  for (let i = 0; i < 8; i++) {
    pool_id[i] = Number(v & 0xffn);
    v >>= 8n;
  }

  const msg: DepositAttestationMessageStruct = {
    domain: DOMAIN_DEPOSIT_OK_V1,
    chain_id: args.chain_id,
    pool_id,
    operator_set_version: args.operator_set_version,
    threshold: args.threshold,
    vault_addr: args.vault_addr,
    asset_type: args.asset_type,
    commitment: args.commitment,
    amount_tag: args.amount_tag,
    ca_payload_hash: args.ca_payload_hash,
    deposit_nonce: args.deposit_nonce,
    expiry_secs: args.expiry_secs,
  };
  const msg_bytes = bcsEncodeDepositAttestationMessage(msg);
  return { msg, msg_bytes };
}
