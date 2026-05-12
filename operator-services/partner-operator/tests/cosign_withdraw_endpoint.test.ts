// CP4 — partner POST /v1/cosign/withdraw integration tests (F8 9 cases).
//
// Uses verifyProof stub (real Groth16 verification deferred to CP5 per
// BLOCKER 1). Chain reader is stubbed to return matching VaultConfig.

import { describe, it, expect, beforeAll } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import {
  bytesToHex,
  CAPayloadJson,
  DOMAIN_WITHDRAW_OK_V1,
  deriveAmountTag,
  deriveAssetId,
  deriveRecipientHash,
  deriveRequestHash,
  encodeWithdrawAttestationMessage,
  hashConfidentialTransferPayload,
  hexToBytes,
  InMemoryEd25519Signer,
  le32ToDec,
  POOL_ID_FR_BYTES,
  u64ToFieldLe32,
} from "@eunoma/shared";
import { buildPartnerServer, PartnerServerHooks } from "../src/server.js";
import { defaultTestConfig, PartnerOperatorConfig } from "../src/config.js";
import { ChainVaultState } from "../src/chain_reader.js";
import { WithdrawCoSignRequestBody } from "../src/verify/withdraw_cosign_request.js";

const AUTH_TOKEN = "withdraw-cp4-test-token";
const AUTH = { authorization: `Bearer ${AUTH_TOKEN}` };

const VAULT_ADDR_HEX = "0x" + "be".repeat(32);
const ASSET_TYPE_HEX = "0x" + "0a".padStart(64, "0");
const RECIPIENT_HEX = "0x" + "a1".repeat(32);
const CHAIN_ID = 2;
const VAULT_SEQ = 7n;
const DISCLOSED_AMOUNT = 12345n;

function ca32(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function buildCaPayloadAndHash(opts: {
  asset_type_hex: string;
  dest_hex: string; // PARTNER quirk: dest = recipient for withdraw
}): { ca_payload: CAPayloadJson; ca_payload_hash_fr_safe: Uint8Array } {
  const newBalanceP = [ca32(0x11), ca32(0x12)];
  const newBalanceR = [ca32(0x13), ca32(0x14)];
  const newBalanceREffAud = [ca32(0x15), ca32(0x16)];
  const amountP = [ca32(0x21), ca32(0x22)];
  const amountRSender = [ca32(0x23), ca32(0x24)];
  const amountRRecip = [ca32(0x25), ca32(0x26)];
  const amountREffAud = [ca32(0x27), ca32(0x28)];
  const zkrpNewBalance = new Uint8Array(64).fill(0x31);
  const zkrpAmount = new Uint8Array(64).fill(0x32);
  const sigmaProtoComm = [ca32(0x41), ca32(0x42), ca32(0x43)];
  const sigmaProtoResp = [ca32(0x44), ca32(0x45), ca32(0x46)];
  const memo = new Uint8Array(8).fill(0x51);

  const assetType = hexToBytes(opts.asset_type_hex);
  const destBytes = AccountAddress.from(opts.dest_hex).toUint8Array();
  const hashStruct = {
    asset_type: assetType,
    vault_addr: destBytes,
    new_balance_p: newBalanceP,
    new_balance_r: newBalanceR,
    new_balance_r_eff_aud: newBalanceREffAud,
    amount_p: amountP,
    amount_r_sender: amountRSender,
    amount_r_recip: amountRRecip,
    amount_r_eff_aud: amountREffAud,
    ek_volun_auds: [],
    amount_r_volun_auds: [],
    zkrp_new_balance: zkrpNewBalance,
    zkrp_amount: zkrpAmount,
    sigma_proto_comm: sigmaProtoComm,
    sigma_proto_resp: sigmaProtoResp,
    memo,
  };
  const raw = hashConfidentialTransferPayload(hashStruct);
  const fr = new Uint8Array(32);
  fr.set(raw.slice(0, 31), 0);
  fr[31] = 0;

  const toHex = (b: Uint8Array) => "0x" + bytesToHex(b);
  const ca_payload: CAPayloadJson = {
    asset_type: opts.asset_type_hex,
    vault_addr: opts.dest_hex,
    new_balance_p: newBalanceP.map(toHex),
    new_balance_r: newBalanceR.map(toHex),
    new_balance_r_eff_aud: newBalanceREffAud.map(toHex),
    amount_p: amountP.map(toHex),
    amount_r_sender: amountRSender.map(toHex),
    amount_r_recip: amountRRecip.map(toHex),
    amount_r_eff_aud: amountREffAud.map(toHex),
    ek_volun_auds: [],
    amount_r_volun_auds: [],
    zkrp_new_balance: toHex(zkrpNewBalance),
    zkrp_amount: toHex(zkrpAmount),
    sigma_proto_comm: sigmaProtoComm.map(toHex),
    sigma_proto_resp: sigmaProtoResp.map(toHex),
    memo: toHex(memo),
  };
  return { ca_payload, ca_payload_hash_fr_safe: fr };
}

interface SetupOpts {
  verifyProofReturns?: boolean;
  chainStateOverride?: Partial<ChainVaultState>;
  min_expiry_window_secs?: number;
  max_horizon_secs?: number;
  caPayloadDestHex?: string;
}

interface Setup {
  cfg: PartnerOperatorConfig;
  server: ReturnType<typeof buildPartnerServer>;
  mainSigner: InMemoryEd25519Signer;
  validBody: WithdrawCoSignRequestBody;
  msgBytes: Uint8Array;
  nowSecs: number;
}

async function setupPartner(opts: SetupOpts = {}): Promise<Setup> {
  const mainSigner = new InMemoryEd25519Signer();
  const partnerSigner = new InMemoryEd25519Signer();
  const cfg = defaultTestConfig({
    slot: 1,
    signer: partnerSigner,
    main_op_pubkey: mainSigner.publicKey(),
    bearer_token: AUTH_TOKEN,
  });
  cfg.vault_addr = hexToBytes(VAULT_ADDR_HEX);
  cfg.asset_type = hexToBytes(ASSET_TYPE_HEX);
  cfg.chain_id = CHAIN_ID;
  if (opts.min_expiry_window_secs !== undefined) {
    cfg.min_expiry_window_secs = opts.min_expiry_window_secs;
  }
  if (opts.max_horizon_secs !== undefined) {
    cfg.max_horizon_secs = opts.max_horizon_secs;
  }

  // Server reads wall clock — fixture uses real now so expiry windows are valid.
  const nowSecs = Math.floor(Date.now() / 1000);
  const expirySecs = BigInt(nowSecs + 600);

  const dest_hex = opts.caPayloadDestHex ?? RECIPIENT_HEX;
  const { ca_payload, ca_payload_hash_fr_safe } = buildCaPayloadAndHash({
    asset_type_hex: ASSET_TYPE_HEX,
    dest_hex,
  });

  const assetIdLe32 = await deriveAssetId(cfg.asset_type);
  const recipientBytes = AccountAddress.from(RECIPIENT_HEX).toUint8Array();
  const recipientHash = await deriveRecipientHash(recipientBytes);
  const withdrawBlind = new Uint8Array(32).fill(0x99);
  withdrawBlind[31] = 0;
  const amountTag = await deriveAmountTag({
    amount: DISCLOSED_AMOUNT,
    withdraw_blind: withdrawBlind,
    recipient_hash: recipientHash,
    asset_id_le32: assetIdLe32,
    chain_id: CHAIN_ID,
    vault_sequence: VAULT_SEQ,
  });
  const requestHash = await deriveRequestHash({
    amount_tag: amountTag,
    recipient_hash: recipientHash,
    ca_payload_hash: ca_payload_hash_fr_safe,
    asset_id_le32: assetIdLe32,
    vault_sequence: VAULT_SEQ,
    chain_id: CHAIN_ID,
  });

  const root = new Uint8Array(32).fill(0xaa);
  root[31] = 0;
  const nullifierHash = new Uint8Array(32).fill(0xbb);
  nullifierHash[31] = 0;
  const vault_seq_le32 = u64ToFieldLe32(VAULT_SEQ);

  const msgBytes = encodeWithdrawAttestationMessage({
    domain: DOMAIN_WITHDRAW_OK_V1,
    chain_id: CHAIN_ID,
    pool_id: POOL_ID_FR_BYTES,
    operator_set_version: cfg.operator_set_version,
    threshold: cfg.threshold,
    vault_addr: cfg.vault_addr,
    asset_type: cfg.asset_type,
    nullifier_hash: nullifierHash,
    recipient: recipientBytes,
    recipient_hash: recipientHash,
    amount_tag: amountTag,
    ca_payload_hash: ca_payload_hash_fr_safe,
    request_hash: requestHash,
    vault_sequence: VAULT_SEQ,
    expiry_secs: expirySecs,
  });
  const mainSig = await mainSigner.sign(msgBytes);

  const validBody: WithdrawCoSignRequestBody = {
    request_id: "wd-test-1",
    operator_set_version: cfg.operator_set_version.toString(),
    threshold: cfg.threshold.toString(),
    chain_id: CHAIN_ID,
    pool_id: cfg.pool_id.toString(),
    vault_addr: VAULT_ADDR_HEX,
    asset_type: ASSET_TYPE_HEX,
    vault_sequence: VAULT_SEQ.toString(),
    expiry_secs: expirySecs.toString(),
    recipient: RECIPIENT_HEX,
    recipient_hash: "0x" + bytesToHex(recipientHash),
    amount_tag: "0x" + bytesToHex(amountTag),
    ca_payload_hash: "0x" + bytesToHex(ca_payload_hash_fr_safe),
    request_hash: "0x" + bytesToHex(requestHash),
    nullifier_hash: "0x" + bytesToHex(nullifierHash),
    public_inputs: [
      le32ToDec(root),
      le32ToDec(nullifierHash),
      le32ToDec(assetIdLe32),
      le32ToDec(recipientHash),
      le32ToDec(amountTag),
      le32ToDec(ca_payload_hash_fr_safe),
      le32ToDec(requestHash),
      le32ToDec(vault_seq_le32),
    ],
    proof_hex: "0x" + "00".repeat(256),
    ca_payload,
    main_op_signature: "0x" + bytesToHex(mainSig),
  };

  const baseChain: ChainVaultState = {
    operatorSetVersion: cfg.operator_set_version,
    threshold: cfg.threshold,
    vaultAddrHex: VAULT_ADDR_HEX,
    assetTypeHex: ASSET_TYPE_HEX,
    vaultSequence: VAULT_SEQ,
  };

  const verifyReturns = opts.verifyProofReturns ?? true;
  const hooks: PartnerServerHooks = {
    withdrawVerify: {
      verifyProof: async () => verifyReturns,
      chainReader: async () => ({ ...baseChain, ...opts.chainStateOverride }),
    },
  };
  const server = buildPartnerServer(cfg, hooks);
  return { cfg, server, mainSigner, validBody, msgBytes, nowSecs };
}

async function postWithdrawCoSign(server: any, body: any) {
  const res = await server.inject({
    method: "POST",
    url: "/v1/cosign/withdraw",
    headers: AUTH,
    payload: body,
  });
  return { res, body: res.json() };
}

describe("partner-operator POST /v1/cosign/withdraw (CP4)", () => {
  it("F8.1 happy_path → 200 + 64B signature", async () => {
    const s = await setupPartner();
    const { res, body } = await postWithdrawCoSign(s.server, s.validBody);
    expect(res.statusCode).toBe(200);
    expect(typeof body.signature_hex).toBe("string");
    expect(body.signature_hex.length).toBe(128); // 64 bytes hex
    expect(body.slot).toBe(s.cfg.slot);
  });

  it("F8.2 tampered ca_payload_hash → ca_payload_hash_mismatch", async () => {
    const s = await setupPartner();
    const tampered = "0x" + s.validBody.ca_payload_hash.slice(2, 4).split("").reverse().join("") +
      s.validBody.ca_payload_hash.slice(4);
    const body = { ...s.validBody, ca_payload_hash: tampered };
    const { res, body: rb } = await postWithdrawCoSign(s.server, body);
    expect(res.statusCode).toBe(400);
    expect(rb).toEqual({ error: "cosign_rejected", reason: "ca_payload_hash_mismatch" });
  });

  it("F8.3 tampered public_inputs[4] amount_tag → public_input_mismatch:amount_tag", async () => {
    const s = await setupPartner();
    const pis = [...s.validBody.public_inputs] as WithdrawCoSignRequestBody["public_inputs"];
    pis[4] = (BigInt(pis[4]) ^ 1n).toString();
    const { res, body } = await postWithdrawCoSign(s.server, { ...s.validBody, public_inputs: pis });
    expect(res.statusCode).toBe(400);
    expect(body).toEqual({
      error: "cosign_rejected",
      reason: "public_input_mismatch:amount_tag",
    });
  });

  it("F8.4 invalid_proof (stub returns false) → groth16_proof_invalid", async () => {
    const s = await setupPartner({ verifyProofReturns: false });
    const { res, body } = await postWithdrawCoSign(s.server, s.validBody);
    expect(res.statusCode).toBe(400);
    expect(body).toEqual({ error: "cosign_rejected", reason: "groth16_proof_invalid" });
  });

  it("F8.5 wrong_chain_vault_sequence → vault_sequence_mismatch", async () => {
    const s = await setupPartner({
      chainStateOverride: { vaultSequence: VAULT_SEQ + 1n },
    });
    const { res, body } = await postWithdrawCoSign(s.server, s.validBody);
    expect(res.statusCode).toBe(400);
    expect(body).toEqual({ error: "cosign_rejected", reason: "vault_sequence_mismatch" });
  });

  it("F8.6 expiry_too_soon → expiry_too_soon", async () => {
    const s = await setupPartner({ min_expiry_window_secs: 100_000 });
    const { res, body } = await postWithdrawCoSign(s.server, s.validBody);
    expect(res.statusCode).toBe(400);
    expect(body).toEqual({ error: "cosign_rejected", reason: "expiry_too_soon" });
  });

  it("F8.7 wrong_main_op_signature → main_op_signature_invalid", async () => {
    const s = await setupPartner();
    const fakeSigner = new InMemoryEd25519Signer();
    const fakeSig = await fakeSigner.sign(s.msgBytes);
    const body = { ...s.validBody, main_op_signature: "0x" + bytesToHex(fakeSig) };
    const { res, body: rb } = await postWithdrawCoSign(s.server, body);
    expect(res.statusCode).toBe(400);
    expect(rb).toEqual({ error: "cosign_rejected", reason: "main_op_signature_invalid" });
  });

  it("F8.8 tampered recipient only (hash unchanged) → ca_payload_hash_mismatch (proves recipient-as-dest)", async () => {
    const s = await setupPartner();
    // Change recipient by flipping the last byte from a1→a2; keep ca_payload_hash
    // pointing to original. Partner re-hashes CA payload using NEW recipient as
    // dest; result will not equal stored ca_payload_hash. If implementation
    // (incorrectly) used vault_addr as dest, this test would surface as
    // recipient_hash_mismatch instead — reason lock-in catches that regression.
    const altRecipient =
      s.validBody.recipient.slice(0, s.validBody.recipient.length - 2) + "a2";
    const { res, body } = await postWithdrawCoSign(s.server, {
      ...s.validBody,
      recipient: altRecipient,
    });
    expect(res.statusCode).toBe(400);
    expect(body).toEqual({ error: "cosign_rejected", reason: "ca_payload_hash_mismatch" });
  });

  it("F8.9 positive: implementation uses recipient (not vault_addr) as CA hash dest", async () => {
    // CA payload built with recipient as dest. If implementation wrongly used
    // vault_addr, this happy-path body would fail ca_payload_hash_mismatch.
    expect(VAULT_ADDR_HEX).not.toBe(RECIPIENT_HEX);
    const s = await setupPartner();
    const { res, body } = await postWithdrawCoSign(s.server, s.validBody);
    expect(res.statusCode).toBe(200);
    expect(body.slot).toBe(s.cfg.slot);
  });
});
