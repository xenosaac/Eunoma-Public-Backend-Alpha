// Withdraw attestation message — BCS encoding shared by main-operator (signer)
// and partner-operator (verifier). Partner rebuilds the message from cfg+body
// and verifies the main-op signature against the rebuilt bytes, never against
// bytes received on the wire.

import { Writer } from "./bcs.js";

export const DOMAIN_WITHDRAW_OK_V1: Uint8Array = new TextEncoder().encode("WDR_OK_1");
export const POOL_ID_FR_BYTES: Uint8Array = new Uint8Array(8);

export interface WithdrawAttestationMessage {
  domain: Uint8Array;
  chain_id: number;
  pool_id: Uint8Array;
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: Uint8Array;
  asset_type: Uint8Array;
  nullifier_hash: Uint8Array;
  recipient: Uint8Array;
  recipient_hash: Uint8Array;
  amount_tag: Uint8Array;
  ca_payload_hash: Uint8Array;
  request_hash: Uint8Array;
  vault_sequence: bigint;
  expiry_secs: bigint;
}

export function encodeWithdrawAttestationMessage(msg: WithdrawAttestationMessage): Uint8Array {
  const w = new Writer();
  w.writeVecU8(msg.domain);
  w.writeU8(msg.chain_id);
  w.writeVecU8(msg.pool_id);
  w.writeU64(msg.operator_set_version);
  w.writeU64(msg.threshold);
  w.writeAddress(msg.vault_addr);
  w.writeAddress(msg.asset_type);
  w.writeVecU8(msg.nullifier_hash);
  w.writeAddress(msg.recipient);
  w.writeVecU8(msg.recipient_hash);
  w.writeVecU8(msg.amount_tag);
  w.writeVecU8(msg.ca_payload_hash);
  w.writeVecU8(msg.request_hash);
  w.writeU64(msg.vault_sequence);
  w.writeU64(msg.expiry_secs);
  return w.finish();
}
