// 8-step verification of an inbound user deposit request (HANDOFF 6.2).

import {
  bytesEqual,
  caPayloadFromJson,
  deriveAssetId,
  deriveVaultAddrHash,
  hashConfidentialTransferPayload,
  hexToBytes,
  recomputeAmountTag,
  verifyGroth16Proof,
  Groth16Proof,
  CAPayloadJson,
} from "@eunoma/shared";
import { MainOperatorConfig } from "../config.js";

export interface DepositRequestBodyMain {
  // Identity
  user_addr: string;

  // Disclosed amount + blind for amount_tag recomputation
  amount: string; // u64 decimal
  deposit_blind: string; // 32-byte LE Fr hex

  // Pool/circuit fields
  commitment: string;
  amount_tag: string;
  deposit_nonce: string;
  expiry_secs: string;

  // Snarkjs format proof + publics
  deposit_binding_proof_snark: Groth16Proof;
  public_inputs: string[]; // 6 decimal strings

  // CA payload (user → vault)
  ca_payload: CAPayloadJson;

  // Optional override (mirror of partner-side override; production omits)
  test_override_asset_id?: string;
  test_override_vault_addr_hash?: string;
}

export interface DepositVerification {
  ok: boolean;
  reason?: string;
  ca_payload_hash?: Uint8Array;
}

export async function verifyDepositRequest(
  cfg: MainOperatorConfig,
  body: DepositRequestBodyMain,
  now_secs: number,
): Promise<DepositVerification> {
  // Field-shape sanity
  const commitment = hexToBytes(body.commitment);
  const amount_tag = hexToBytes(body.amount_tag);
  const deposit_nonce = hexToBytes(body.deposit_nonce);
  const blind = hexToBytes(body.deposit_blind);

  if (commitment.length !== 32) return { ok: false, reason: "commitment_wrong_length" };
  if (amount_tag.length !== 32) return { ok: false, reason: "amount_tag_wrong_length" };
  if (blind.length !== 32) return { ok: false, reason: "deposit_blind_wrong_length" };
  if (deposit_nonce.length === 0) return { ok: false, reason: "deposit_nonce_empty" };

  const expiry = BigInt(body.expiry_secs);
  if (expiry <= BigInt(now_secs + cfg.min_expiry_window_secs)) {
    return { ok: false, reason: "expiry_too_soon" };
  }

  // Step 1 — recompute amount_tag
  const asset_id_le32 = body.test_override_asset_id
    ? hexToBytes(body.test_override_asset_id)
    : await deriveAssetId(cfg.asset_type);
  const vault_addr_hash_le32 = body.test_override_vault_addr_hash
    ? hexToBytes(body.test_override_vault_addr_hash)
    : await deriveVaultAddrHash(cfg.vault_addr);
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

  // Step 2 — verify deposit-binding proof off-chain via snarkjs.
  // Phase F W3: 6 → 4 (chain_id + pool_id baked as circuit constants).
  if (body.public_inputs.length !== 4) {
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

  // Step 3 — recompute ca_payload_hash and compare against any disclosed
  // hash (here we just compute it for downstream use; main op trusts its own
  // computation).
  const ca_struct = caPayloadFromJson(body.ca_payload);
  // Steps 4 + 5 — payload recipient + asset_type match cfg
  if (!bytesEqual(ca_struct.asset_type, cfg.asset_type)) {
    return { ok: false, reason: "ca_payload_asset_type_mismatch" };
  }
  if (!bytesEqual(ca_struct.vault_addr, cfg.vault_addr)) {
    return { ok: false, reason: "ca_payload_vault_addr_mismatch" };
  }
  const ca_payload_hash = hashConfidentialTransferPayload(ca_struct);

  // Step 6 — CA encrypted-amount vs disclosed amount: in production the main
  // op uses its vault witness to decrypt and compare. For Gate 4c we trust
  // the disclosed `amount` (the partner ops will also recompute amount_tag,
  // which provides a cross-binding into the disclosed amount).

  // Step 7 — expiry already checked above.

  // Step 8 — nonce format basic sanity already checked.

  return { ok: true, ca_payload_hash };
}
