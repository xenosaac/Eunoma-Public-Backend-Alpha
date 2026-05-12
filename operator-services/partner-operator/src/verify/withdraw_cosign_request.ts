// Withdraw cosign request verification (CP4). 10-step pipeline; ANY step
// failure returns {ok:false, reason}. Partner MUST NOT trust:
//   - main-op's chain read (partner reads VaultConfig itself)
//   - the BCS bytes main sent on the wire (partner rebuilds + byte-compares)
//   - the asset_id_le32 inside public_inputs (partner derives from asset_type)
//   - the pubkey_hex echoed back (main verifies sig against cfg-configured pubkey)
//
// PARTNER-CRITICAL: the withdraw CA payload is hashed with `vault_addr` set to
// `body.recipient` — a legacy quirk of CAPayloadForHashStruct reuse (deposit
// uses the real vault address there; withdraw substitutes the recipient).
// Do NOT pass `body.vault_addr` into the hash struct's `vault_addr` slot.

import {
  bytesEqual,
  bytesToHex,
  CAPayloadJson,
  caPayloadFromJson,
  decToLe32,
  deriveAssetId,
  deriveRecipientHash,
  DOMAIN_WITHDRAW_OK_V1,
  encodeWithdrawAttestationMessage,
  hashConfidentialTransferPayload,
  hexToBytes,
  POOL_ID_FR_BYTES,
  verifyEd25519,
  verifyWithdrawalGroth16Proof,
} from "@eunoma/shared";
import { PartnerOperatorConfig } from "../config.js";
import {
  ChainVaultReader,
  defaultReadChainVaultState,
} from "../chain_reader.js";

export interface WithdrawCoSignRequestBody {
  request_id: string;
  operator_set_version: string;
  threshold: string;
  chain_id: number;
  pool_id: string;
  vault_addr: string;
  asset_type: string;
  vault_sequence: string;
  expiry_secs: string;
  recipient: string;
  recipient_hash: string;
  amount_tag: string;
  ca_payload_hash: string;
  request_hash: string;
  nullifier_hash: string;
  public_inputs: [string, string, string, string, string, string, string, string];
  proof_hex: string;
  ca_payload: CAPayloadJson;
  main_op_signature: string;
}

export interface WithdrawCoSignVerification {
  ok: boolean;
  reason?: string;
  msg_bytes?: Uint8Array;
}

export interface WithdrawCoSignVerifyHooks {
  /// Stub for the Groth16 verifier. Default = shared `verifyWithdrawalGroth16Proof`.
  verifyProof?: typeof verifyWithdrawalGroth16Proof;
  /// Stub for the chain VaultConfig reader.
  chainReader?: ChainVaultReader;
}

const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX64_RE = /^0x[0-9a-fA-F]{128}$/;
const HEX256_RE = /^0x[0-9a-fA-F]{512}$/;
const DEC_RE = /^\d+$/;

function frHexEq(hex: string, fr: Uint8Array): boolean {
  if (fr.length !== 32) return false;
  if (!HEX32_RE.test(hex)) return false;
  return bytesEqual(hexToBytes(hex), fr);
}

function publicInputDecEqHex(dec: string, fr: Uint8Array): boolean {
  if (!DEC_RE.test(dec)) return false;
  let candidate: Uint8Array;
  try {
    candidate = decToLe32(dec);
  } catch {
    return false;
  }
  return bytesEqual(candidate, fr);
}

export async function verifyWithdrawCoSignRequest(
  cfg: PartnerOperatorConfig,
  body: WithdrawCoSignRequestBody,
  now_secs: number,
  hooks: WithdrawCoSignVerifyHooks = {},
): Promise<WithdrawCoSignVerification> {
  const verifyProof = hooks.verifyProof ?? verifyWithdrawalGroth16Proof;
  const chainReader = hooks.chainReader ?? defaultReadChainVaultState;

  // ---- Step 1: field shape / format ----
  if (typeof body.request_id !== "string" || body.request_id.length === 0) {
    return { ok: false, reason: "missing_request_id" };
  }
  for (const f of [
    "operator_set_version",
    "threshold",
    "pool_id",
    "vault_sequence",
    "expiry_secs",
  ] as const) {
    if (typeof body[f] !== "string" || !DEC_RE.test(body[f] as string)) {
      return { ok: false, reason: `invalid_${f}_format` };
    }
  }
  if (typeof body.chain_id !== "number" || !Number.isInteger(body.chain_id)) {
    return { ok: false, reason: "invalid_chain_id_format" };
  }
  for (const f of [
    "vault_addr",
    "asset_type",
    "recipient",
    "recipient_hash",
    "amount_tag",
    "ca_payload_hash",
    "request_hash",
    "nullifier_hash",
  ] as const) {
    if (typeof body[f] !== "string" || !HEX32_RE.test(body[f] as string)) {
      return { ok: false, reason: `invalid_${f}_format` };
    }
  }
  if (typeof body.main_op_signature !== "string" || !HEX64_RE.test(body.main_op_signature)) {
    return { ok: false, reason: "invalid_main_op_signature_format" };
  }
  if (typeof body.proof_hex !== "string" || !HEX256_RE.test(body.proof_hex)) {
    return { ok: false, reason: "invalid_proof_length" };
  }
  if (!Array.isArray(body.public_inputs) || body.public_inputs.length !== 8) {
    return { ok: false, reason: "public_inputs_wrong_length" };
  }
  for (let i = 0; i < 8; i++) {
    if (typeof body.public_inputs[i] !== "string" || !DEC_RE.test(body.public_inputs[i])) {
      return { ok: false, reason: `invalid_public_inputs_${i}_format` };
    }
  }

  // ---- Step 2: cfg equality ----
  if (BigInt(body.operator_set_version) !== cfg.operator_set_version) {
    return { ok: false, reason: "operator_set_version_mismatch" };
  }
  if (BigInt(body.threshold) !== cfg.threshold) {
    return { ok: false, reason: "threshold_mismatch" };
  }
  if (body.chain_id !== cfg.chain_id) {
    return { ok: false, reason: "chain_id_mismatch" };
  }
  if (BigInt(body.pool_id) !== cfg.pool_id) {
    return { ok: false, reason: "pool_id_mismatch" };
  }
  const vault_addr = hexToBytes(body.vault_addr);
  const asset_type = hexToBytes(body.asset_type);
  if (!bytesEqual(vault_addr, cfg.vault_addr)) {
    return { ok: false, reason: "vault_addr_mismatch" };
  }
  if (!bytesEqual(asset_type, cfg.asset_type)) {
    return { ok: false, reason: "asset_type_mismatch" };
  }

  // ---- Step 3: expiry window ----
  const expiry = BigInt(body.expiry_secs);
  const nowB = BigInt(now_secs);
  if (expiry <= nowB + BigInt(cfg.min_expiry_window_secs)) {
    return { ok: false, reason: "expiry_too_soon" };
  }
  if (expiry - nowB > BigInt(cfg.max_horizon_secs)) {
    return { ok: false, reason: "expiry_too_far" };
  }

  // ---- Step 4: CA payload rehash with recipient-as-dest legacy quirk ----
  const recipient_bytes = hexToBytes(body.recipient);
  const ca_payload_hash_bytes = hexToBytes(body.ca_payload_hash);
  let recompFrSafe: Uint8Array;
  try {
    const struct = caPayloadFromJson(body.ca_payload);
    const enforced = {
      ...struct,
      asset_type,
      vault_addr: recipient_bytes, // PARTNER-CRITICAL withdraw quirk
    };
    const recompRaw = hashConfidentialTransferPayload(enforced);
    recompFrSafe = new Uint8Array(32);
    recompFrSafe.set(recompRaw.slice(0, 31), 0);
  } catch (err: any) {
    return { ok: false, reason: "ca_payload_rehash_failed" };
  }
  if (!bytesEqual(recompFrSafe, ca_payload_hash_bytes)) {
    return { ok: false, reason: "ca_payload_hash_mismatch" };
  }

  // ---- Step 5: canonical recompute / byte-equal vs public_inputs + body fields ----
  // assetId from asset_type (do NOT trust body's asset_id_le32 — public_inputs[2]).
  const asset_id_le32 = await deriveAssetId(asset_type);
  if (!publicInputDecEqHex(body.public_inputs[2], asset_id_le32)) {
    return { ok: false, reason: "public_input_mismatch:asset_id" };
  }
  const recipient_hash = await deriveRecipientHash(recipient_bytes);
  if (!bytesEqual(recipient_hash, hexToBytes(body.recipient_hash))) {
    return { ok: false, reason: "recipient_hash_mismatch" };
  }
  if (!publicInputDecEqHex(body.public_inputs[3], recipient_hash)) {
    return { ok: false, reason: "public_input_mismatch:recipient_hash" };
  }
  const amount_tag_bytes = hexToBytes(body.amount_tag);
  if (!publicInputDecEqHex(body.public_inputs[4], amount_tag_bytes)) {
    return { ok: false, reason: "public_input_mismatch:amount_tag" };
  }
  if (!publicInputDecEqHex(body.public_inputs[5], ca_payload_hash_bytes)) {
    return { ok: false, reason: "public_input_mismatch:ca_payload_hash" };
  }
  const request_hash_bytes = hexToBytes(body.request_hash);
  if (!publicInputDecEqHex(body.public_inputs[6], request_hash_bytes)) {
    return { ok: false, reason: "public_input_mismatch:request_hash" };
  }
  if (BigInt(body.public_inputs[7]) !== BigInt(body.vault_sequence)) {
    return { ok: false, reason: "public_input_mismatch:vault_sequence" };
  }
  const nullifier_hash_bytes = hexToBytes(body.nullifier_hash);
  if (!publicInputDecEqHex(body.public_inputs[1], nullifier_hash_bytes)) {
    return { ok: false, reason: "public_input_mismatch:nullifier_hash" };
  }

  // ---- Step 6: independent chain VaultConfig fetch ----
  let chain;
  try {
    chain = await chainReader(cfg.bridge_addr);
  } catch (err: any) {
    return { ok: false, reason: "chain_state_unavailable" };
  }
  if (chain.vaultSequence !== BigInt(body.vault_sequence)) {
    return { ok: false, reason: "vault_sequence_mismatch" };
  }
  if (chain.operatorSetVersion !== cfg.operator_set_version) {
    return { ok: false, reason: "operator_set_version_chain_mismatch" };
  }
  if (chain.threshold !== cfg.threshold) {
    return { ok: false, reason: "threshold_chain_mismatch" };
  }

  // ---- Step 7: Groth16 verify ----
  const proofBytes = hexToBytes(body.proof_hex);
  if (proofBytes.length !== 256) {
    return { ok: false, reason: "invalid_proof_length" };
  }
  let proofOk: boolean;
  try {
    proofOk = await verifyProof(proofBytes, body.public_inputs);
  } catch {
    proofOk = false;
  }
  if (!proofOk) {
    return { ok: false, reason: "groth16_proof_invalid" };
  }

  // ---- Step 8: rebuild WithdrawAttestationMessage (partner-side, hardcoded domain) ----
  const msg_bytes = encodeWithdrawAttestationMessage({
    domain: DOMAIN_WITHDRAW_OK_V1,
    chain_id: cfg.chain_id,
    pool_id: POOL_ID_FR_BYTES,
    operator_set_version: cfg.operator_set_version,
    threshold: cfg.threshold,
    vault_addr: cfg.vault_addr,
    asset_type: cfg.asset_type,
    nullifier_hash: nullifier_hash_bytes,
    recipient: recipient_bytes,
    recipient_hash,
    amount_tag: amount_tag_bytes,
    ca_payload_hash: ca_payload_hash_bytes,
    request_hash: request_hash_bytes,
    vault_sequence: BigInt(body.vault_sequence),
    expiry_secs: expiry,
  });

  // ---- Step 9: main_op_signature verify against partner-rebuilt msg_bytes ----
  const main_sig = hexToBytes(body.main_op_signature);
  if (!verifyEd25519(main_sig, cfg.main_op_pubkey, msg_bytes)) {
    return { ok: false, reason: "main_op_signature_invalid" };
  }

  // ---- Step 10: return msg_bytes for the route handler to sign ----
  return { ok: true, msg_bytes };
}

// Silence the bytesToHex import being currently unused in callers; keep the
// re-export shape stable for future debug paths.
void bytesToHex;
