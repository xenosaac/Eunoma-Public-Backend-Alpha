// Shared TypeScript types mirroring on-chain Move structs and operator-service
// data flow. Field order in DepositAttestationMessageStruct + CAPayloadForHashStruct
// is LOAD-BEARING: BCS encoders rely on this exact order.

export type Hex = string; // "0x..." or "..." (no 0x); helpers normalize.

export interface DepositAttestationMessageStruct {
  // Order MUST match Move struct at confidential_bridge.move:294-307
  domain: Uint8Array; // vector<u8>
  chain_id: number; // u8
  pool_id: Uint8Array; // vector<u8>
  operator_set_version: bigint; // u64
  threshold: bigint; // u64
  vault_addr: Uint8Array; // address (32 bytes)
  asset_type: Uint8Array; // address (32 bytes) — Object<Metadata> address
  commitment: Uint8Array; // vector<u8>
  amount_tag: Uint8Array; // vector<u8>
  ca_payload_hash: Uint8Array; // vector<u8>
  deposit_nonce: Uint8Array; // vector<u8>
  expiry_secs: bigint; // u64
}

export interface CAPayloadForHashStruct {
  // Order MUST match Move struct at confidential_bridge.move:886-903
  asset_type: Uint8Array; // address (32 bytes)
  vault_addr: Uint8Array; // address (32 bytes)
  new_balance_p: Uint8Array[];
  new_balance_r: Uint8Array[];
  new_balance_r_eff_aud: Uint8Array[];
  amount_p: Uint8Array[];
  amount_r_sender: Uint8Array[];
  amount_r_recip: Uint8Array[];
  amount_r_eff_aud: Uint8Array[];
  ek_volun_auds: Uint8Array[];
  amount_r_volun_auds: Uint8Array[][];
  zkrp_new_balance: Uint8Array;
  zkrp_amount: Uint8Array;
  sigma_proto_comm: Uint8Array[];
  sigma_proto_resp: Uint8Array[];
  memo: Uint8Array;
}

export interface OperatorSetSnapshot {
  operator_set_version: bigint;
  pubkeys: Uint8Array[]; // 7 entries, each 32 bytes Ed25519 pubkey
  main_index: number; // 0..6
  threshold: number; // 4
}

export interface DepositRequestBody {
  // What a user posts to /v1/deposit/request-attestation
  user_addr: string;
  vault_addr: string;
  asset_type: string;

  amount: string; // u64 as decimal string
  deposit_blind: string; // 32-byte LE Fr hex (with or without 0x)
  commitment: string; // 32-byte LE Fr hex
  amount_tag: string; // 32-byte LE Fr hex
  deposit_nonce: string; // hex bytes
  expiry_secs: string; // u64 as decimal

  deposit_binding_proof: string; // 256B uncompressed hex (a||b||c)
  ca_payload: CAPayloadJson;
}

export interface CAPayloadJson {
  asset_type: string;
  vault_addr: string;
  new_balance_p: string[];
  new_balance_r: string[];
  new_balance_r_eff_aud: string[];
  amount_p: string[];
  amount_r_sender: string[];
  amount_r_recip: string[];
  amount_r_eff_aud: string[];
  ek_volun_auds: string[];
  amount_r_volun_auds: string[][];
  zkrp_new_balance: string;
  zkrp_amount: string;
  sigma_proto_comm: string[];
  sigma_proto_resp: string[];
  memo: string;
}

export interface SignatureSlot {
  slot: number; // 0..6
  signature: Uint8Array | null; // 64 bytes Ed25519 sig, or null for empty slot
}

export interface AttestationResult {
  request_id: string;
  status: "complete" | "in_progress" | "failed";
  message_bytes_hex: string;
  signatures: SignatureSlot[];
  threshold_met: boolean;
}

// Phase D Agent D1 c3: 8-byte tag (was 24-byte "APTOSHIELD_DEPOSIT_OK_V1").
// MUST match Move-side DOMAIN_DEPOSIT_OK_V1 in eunoma_bridge.move byte-for-byte.
export const DOMAIN_DEPOSIT_OK_V1 = new TextEncoder().encode("DEP_OK_1");
export const POSEIDON_DOMAIN_ASSET_ID = new TextEncoder().encode(
  "APTOSHIELD_ASSET_ID_V1",
);
export const POSEIDON_DOMAIN_VAULT_ADDR_HASH = new TextEncoder().encode(
  "APTOSHIELD_VAULT_ADDR_HASH_V1",
);

export const FR_BYTES = 32;
export const G1_UNCOMPRESSED_BYTES = 64;
export const G2_UNCOMPRESSED_BYTES = 128;
export const PROOF_BYTES = G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES + G1_UNCOMPRESSED_BYTES;
export const VK_IC_LENGTH = 7;

export const POOL_ID_VALUE = 0n;
