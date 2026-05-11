// 9-step verification of an inbound co-sign request (HANDOFF 6.3).
//
// Partner operator MUST refuse to sign if any check fails.

import {
  bcsEncodeDepositAttestationMessage,
  buildDepositAttestationMessage,
  bytesEqual,
  caPayloadFromJson,
  CAPayloadJson,
  deriveAssetId,
  deriveVaultAddrHash,
  hashConfidentialTransferPayload,
  hexToBytes,
  recomputeAmountTag,
  verifyEd25519,
  verifyGroth16Proof,
  Groth16Proof,
} from "@eunoma/shared";
import { PartnerOperatorConfig } from "../config.js";

export interface CoSignRequestBody {
  request_id: string;
  // Attestation fields
  operator_set_version: string; // bigint as decimal string
  threshold: string;
  vault_addr: string;
  asset_type: string;
  chain_id: number;
  pool_id: string;
  commitment: string;
  amount_tag: string;
  ca_payload_hash: string;
  deposit_nonce: string;
  expiry_secs: string;

  // Disclosed fields the partner uses to recompute amount_tag + ca_payload_hash
  amount: string; // u64 decimal
  deposit_blind: string; // 32-byte LE Fr hex
  ca_payload: CAPayloadJson;

  // Deposit-binding proof (snarkjs JSON shape)
  deposit_binding_proof_snark: Groth16Proof;
  public_inputs: string[]; // 6 decimal strings — for snarkjs verify

  // Main op auth: signature over `request_id || msg_bytes` proving the request
  // came from the main operator (not an unauthenticated attacker).
  main_op_signature: string; // 64-byte Ed25519 sig hex

  // Optional: caller-provided override for the asset_id / vault_addr_hash
  // (used to mirror Gate 4a's test fixture exactly without depending on
  // the bridge's `DepositBindingTestOverride` runtime resource). When
  // present, the partner uses these for amount_tag recomputation. In
  // production this MUST be absent; partner operators recompute via
  // Poseidon-of-address.
  test_override_asset_id?: string;
  test_override_vault_addr_hash?: string;
}

export interface CoSignVerification {
  ok: boolean;
  reason?: string;
  msg_bytes?: Uint8Array;
}

export async function verifyCoSignRequest(
  cfg: PartnerOperatorConfig,
  body: CoSignRequestBody,
  now_secs: number,
): Promise<CoSignVerification> {
  // Step 3 first: rebuild the canonical attestation message so we can validate
  // the rest of the body against it.
  const vault_addr = hexToBytes(body.vault_addr);
  const asset_type = hexToBytes(body.asset_type);
  if (vault_addr.length !== 32) {
    return { ok: false, reason: "vault_addr_wrong_length" };
  }
  if (asset_type.length !== 32) {
    return { ok: false, reason: "asset_type_wrong_length" };
  }

  // Step 3 — operator_set_version match
  const opVer = BigInt(body.operator_set_version);
  if (opVer !== cfg.operator_set_version) {
    return { ok: false, reason: "operator_set_version_mismatch" };
  }
  const threshold = BigInt(body.threshold);
  if (threshold !== cfg.threshold) {
    return { ok: false, reason: "threshold_mismatch" };
  }

  // Step 4 — chain_id, pool_id, vault_addr, asset_type match locally-configured values
  if (body.chain_id !== cfg.chain_id) {
    return { ok: false, reason: "chain_id_mismatch" };
  }
  if (BigInt(body.pool_id) !== cfg.pool_id) {
    return { ok: false, reason: "pool_id_mismatch" };
  }
  if (!bytesEqual(vault_addr, cfg.vault_addr)) {
    return { ok: false, reason: "vault_addr_mismatch" };
  }
  if (!bytesEqual(asset_type, cfg.asset_type)) {
    return { ok: false, reason: "asset_type_mismatch" };
  }

  // Step 5 — expiry valid
  const expiry = BigInt(body.expiry_secs);
  if (expiry <= BigInt(now_secs + cfg.min_expiry_window_secs)) {
    return { ok: false, reason: "expiry_too_soon" };
  }

  // Field bytes
  const commitment = hexToBytes(body.commitment);
  const amount_tag = hexToBytes(body.amount_tag);
  const ca_payload_hash = hexToBytes(body.ca_payload_hash);
  const deposit_nonce = hexToBytes(body.deposit_nonce);
  if (commitment.length !== 32) {
    return { ok: false, reason: "commitment_wrong_length" };
  }
  if (amount_tag.length !== 32) {
    return { ok: false, reason: "amount_tag_wrong_length" };
  }
  if (ca_payload_hash.length !== 32) {
    return { ok: false, reason: "ca_payload_hash_wrong_length" };
  }

  // Step 7 — recompute ca_payload_hash and assert equal
  const ca_payload_struct = caPayloadFromJson(body.ca_payload);
  // Step 8 — CA payload recipient/asset/context match cfg
  if (!bytesEqual(ca_payload_struct.asset_type, cfg.asset_type)) {
    return { ok: false, reason: "ca_payload_asset_type_mismatch" };
  }
  if (!bytesEqual(ca_payload_struct.vault_addr, cfg.vault_addr)) {
    return { ok: false, reason: "ca_payload_vault_addr_mismatch" };
  }
  const recomputed_hash = hashConfidentialTransferPayload(ca_payload_struct);
  if (!bytesEqual(recomputed_hash, ca_payload_hash)) {
    return { ok: false, reason: "ca_payload_hash_mismatch" };
  }

  // Step 5 (continued) — recompute amount_tag from disclosed amount + blind
  const blind = hexToBytes(body.deposit_blind);
  if (blind.length !== 32) {
    return { ok: false, reason: "deposit_blind_wrong_length" };
  }
  const asset_id_le32 = body.test_override_asset_id
    ? hexToBytes(body.test_override_asset_id)
    : await deriveAssetId(asset_type);
  const vault_addr_hash_le32 = body.test_override_vault_addr_hash
    ? hexToBytes(body.test_override_vault_addr_hash)
    : await deriveVaultAddrHash(vault_addr);

  const amount = BigInt(body.amount);
  const recomputed_amount_tag = await recomputeAmountTag({
    amount,
    deposit_blind_le32: blind,
    asset_id_le32,
    vault_addr_hash_le32,
    chain_id: cfg.chain_id,
  });
  if (!bytesEqual(recomputed_amount_tag, amount_tag)) {
    return { ok: false, reason: "amount_tag_mismatch" };
  }

  // Step 6 — verify deposit-binding Groth16 proof. snarkjs format publics +
  // proof. We accept the partner re-running the verifier off-chain (cheap;
  // ~10ms on snarkjs). Public inputs MUST contain commitment, amount_tag,
  // asset_id, vault_addr_hash, chain_id, pool_id (in that order — Gate 4a
  // wire order).
  if (body.public_inputs.length !== 6) {
    return { ok: false, reason: "public_inputs_wrong_length" };
  }
  let proofOk: boolean;
  try {
    proofOk = await verifyGroth16Proof(
      body.deposit_binding_proof_snark,
      body.public_inputs,
    );
  } catch {
    proofOk = false;
  }
  if (!proofOk) {
    return { ok: false, reason: "deposit_binding_proof_invalid" };
  }

  // Step 3 (final) — rebuild attestation message exactly as the main op did.
  const { msg_bytes } = buildDepositAttestationMessage({
    chain_id: cfg.chain_id,
    pool_id: cfg.pool_id,
    operator_set_version: cfg.operator_set_version,
    threshold: cfg.threshold,
    vault_addr: cfg.vault_addr,
    asset_type: cfg.asset_type,
    commitment,
    amount_tag,
    ca_payload_hash,
    deposit_nonce,
    expiry_secs: expiry,
  });

  // Step 1+2 — main operator auth
  const main_sig = hexToBytes(body.main_op_signature);
  // Auth payload = utf8(request_id) || msg_bytes
  const auth_payload = new Uint8Array(
    Buffer.concat([
      Buffer.from(body.request_id, "utf-8"),
      Buffer.from(msg_bytes),
    ]),
  );
  if (!verifyEd25519(main_sig, cfg.main_op_pubkey, auth_payload)) {
    return { ok: false, reason: "main_op_signature_invalid" };
  }

  return { ok: true, msg_bytes };
}
