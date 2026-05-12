// POST /v1/withdraw/prepare + /v1/withdraw/finalize.
//
// CP3 + CP4. CP3 introduced server-canonical recompute / amount binding;
// CP4 wires partner cosign fanout. The CP3 transitional escape hatch was
// removed — production finalize signs only after 4-of-7 cosign aggregation.
//
// Slot model (4-of-7, F1 of CP4 plan):
//   - main_slot = 0; cfg.partner_pubkeys length = 7 (slot 0..6, slot 0 = main)
//   - cfg.partner_urls / cfg.partner_bearer_tokens length = 6
//   - partner_urls[i] corresponds to slot = i + 1
//   - partner result is valid iff all of: slot ∈ {1..6}, slot === i+1,
//     slot not already used, signature 64B, verifyEd25519 against
//     cfg.partner_pubkeys[slot] (NOT the pubkey echoed back)
//
// Status policy:
//   - hash / proof / public_input mismatch         → row → FAILED   (terminal)
//   - row.expiry <= now at finalize time            → row → EXPIRED
//   - chain vault_sequence drift                    → row → EXPIRED
//   - cosign aggregate < threshold (4)              → row stays PREPARED, 500
//   - cosign aggregate >= threshold                 → row → FINALIZED, 200
//   - store / chain RPC / key load transient        → row UNCHANGED, 5xx

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AccountAddress, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes, randomUUID } from "node:crypto";
import {
  buildWithdrawCAPayload as defaultBuildWithdrawCAPayload,
  DOMAIN_WITHDRAW_OK_V1,
  encodeWithdrawAttestationMessage,
  hashConfidentialTransferPayload,
  loadOperatorKeyForSlot,
  POOL_ID_FR_BYTES,
  deriveAssetId,
  deriveRecipientHash,
  deriveAmountTag,
  deriveRequestHash,
  le32ToDec,
  verifyEd25519,
  verifyWithdrawalGroth16Proof as defaultVerifyWithdrawalGroth16Proof,
  u64ToFieldLe32,
  bytesEqual,
  PrepareInflightError,
  type Store,
  type WithdrawRequestRow,
} from "@eunoma/shared";
import { MainOperatorConfig } from "../config.js";
import {
  fanOutWithdrawCoSignRequests as defaultFanOutWithdrawCoSignRequests,
  PartnerCoSignResult,
} from "../partner_client.js";
import type { WithdrawCoSignRequestBody } from "@eunoma/partner-operator/src/verify/withdraw_cosign_request.js";

const DEFAULT_EXPIRY_SECS = 600n; // 10 minutes

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
function fromHex(s: string): Uint8Array {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  if (h.length % 2 !== 0) throw new Error(`fromHex: odd-length: ${s}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function caBytesArrayToHex(a: Uint8Array[]): string[] { return a.map((b) => "0x" + hex(b)); }
function caBytesMatrixToHex(a: Uint8Array[][]): string[][] { return a.map(caBytesArrayToHex); }
function caHexArrayToBytes(a: string[]): Uint8Array[] { return a.map(fromHex); }
function caHexMatrixToBytes(a: string[][]): Uint8Array[][] { return a.map(caHexArrayToBytes); }

interface ChainVaultState {
  operatorSetVersion: bigint;
  threshold: bigint;
  vaultAddrHex: string;
  vaultSequence: bigint;
}

async function defaultReadChainVaultState(
  aptos: Aptos,
  bridgeAddr: string,
): Promise<ChainVaultState> {
  const vc = (await aptos.getAccountResource({
    accountAddress: bridgeAddr,
    resourceType: `${bridgeAddr}::eunoma_bridge::VaultConfig`,
  })) as any;
  return {
    operatorSetVersion: BigInt(vc.operator_set_version),
    threshold: BigInt(vc.attestation_threshold),
    vaultAddrHex: vc.vault_addr,
    vaultSequence: BigInt(vc.vault_sequence),
  };
}

interface PrepareBody {
  amount: string;
  recipient: string;
  asset_id: string;
  user_audit_pks?: string[];
}

interface FinalizeBody {
  request_id: string;
  public_inputs: {
    root: string;
    nullifier_hash: string;
    asset_id: string;
    recipient_hash: string;
    amount_tag: string;
    ca_payload_hash: string;
    request_hash: string;
    vault_sequence: string;
  };
  proof: string;
  ca_payload: {
    new_balance_p: string[]; new_balance_r: string[]; new_balance_r_eff_aud: string[];
    amount_p: string[]; amount_r_sender: string[]; amount_r_recip: string[];
    amount_r_eff_aud: string[]; ek_volun_auds: string[]; amount_r_volun_auds: string[][];
    zkrp_new_balance: string; zkrp_amount: string;
    sigma_proto_comm: string[]; sigma_proto_resp: string[]; memo: string;
    ca_payload_hash: string;
  };
  recipient: string;
  expiry_secs?: string;
}

export interface WithdrawRouteHooks {
  /// Stub for `buildWithdrawCAPayload`. Tests inject a deterministic version.
  buildCAPayload?: typeof defaultBuildWithdrawCAPayload;
  /// Stub for chain VaultConfig read.
  readChainVaultState?: (aptos: Aptos, bridgeAddr: string) => Promise<ChainVaultState>;
  /// Stub for the Groth16 verifier.
  verifyProof?: typeof defaultVerifyWithdrawalGroth16Proof;
  /// CP3.5: when true, prepare response includes a `diagnostics` block with
  /// decrypted vault balance values. MUST default false in production.
  exposeWithdrawDiagnosticsForTests?: boolean;
  /// Inject a now-secs source for deterministic expiry tests.
  nowSecs?: () => bigint;
  /// CP4 — partner cosign fanout. Tests stub the wire calls.
  fanOutWithdrawCoSign?: typeof defaultFanOutWithdrawCoSignRequests;
  /// Optional override for bridge package address (production reads env).
  bridgeAddr?: string;
}

function addrBytes(hexStr: string): Uint8Array {
  return AccountAddress.from(hexStr).toUint8Array();
}

export function registerWithdrawRoutes(
  fastify: FastifyInstance,
  store: Store,
  cfg: MainOperatorConfig,
  hooks: WithdrawRouteHooks = {},
): void {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const readChainVaultState = hooks.readChainVaultState ?? defaultReadChainVaultState;
  const buildCAPayload = hooks.buildCAPayload ?? defaultBuildWithdrawCAPayload;
  const verifyProof = hooks.verifyProof ?? defaultVerifyWithdrawalGroth16Proof;
  const fanOutWithdrawCoSign = hooks.fanOutWithdrawCoSign ?? defaultFanOutWithdrawCoSignRequests;
  const nowSecs = hooks.nowSecs ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  const bridgeAddr =
    hooks.bridgeAddr ??
    process.env.BRIDGE_PACKAGE_ADDRESS ??
    "0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820";

  const vaultAddrHexCfg = "0x" + hex(cfg.vault_addr);
  const assetTypeHexCfg = "0x" + hex(cfg.asset_type);

  fastify.post("/v1/withdraw/prepare", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as Partial<PrepareBody> | undefined;
    if (!body || typeof body !== "object") return reply.code(400).send({ error: "missing_body" });
    const { amount, recipient, asset_id } = body;
    if (typeof amount !== "string" || !/^\d+$/.test(amount)) {
      return reply.code(400).send({ error: "invalid_amount", detail: "amount must be decimal octas" });
    }
    if (typeof recipient !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(recipient)) {
      return reply.code(400).send({ error: "invalid_recipient" });
    }
    if (typeof asset_id !== "string" || !/^0x[0-9a-fA-F]+$/.test(asset_id)) {
      return reply.code(400).send({ error: "invalid_asset_id" });
    }

    const userAuditPksHex = body.user_audit_pks;
    if (userAuditPksHex !== undefined) {
      if (!Array.isArray(userAuditPksHex)) {
        return reply.code(400).send({ error: "invalid_user_audit_pks" });
      }
      for (const pk of userAuditPksHex) {
        if (typeof pk !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(pk)) {
          return reply.code(400).send({
            error: "invalid_user_audit_pk_format",
            detail: "each user_audit_pk must be 0x-prefixed 32-byte hex (64 chars)",
          });
        }
      }
    }

    const amountOctas = BigInt(amount);

    let vaultSequence: bigint;
    try {
      const chain = await readChainVaultState(aptos, bridgeAddr);
      vaultSequence = chain.vaultSequence;
    } catch (err: any) {
      return reply.code(502).send({
        error: "chain_state_unavailable",
        detail: err?.message ?? String(err),
      });
    }

    const withdrawBlind = (() => {
      const r = randomBytes(31);
      const out = new Uint8Array(32);
      out.set(r, 0);
      return out;
    })();

    let caPayload;
    try {
      caPayload = await buildCAPayload({
        vaultAddrHex: vaultAddrHexCfg,
        recipientAddrHex: recipient,
        amountOctas,
        assetTypeHex: asset_id,
        chainId: cfg.chain_id,
        userAuditPksHex,
      });
    } catch (err: any) {
      return reply.code(502).send({
        error: "ca_payload_build_failed",
        detail: err?.message ?? String(err),
      });
    }

    const decryptedDelta =
      caPayload.vaultAvailableOctasBefore - caPayload.vaultAvailableOctasAfterDecrypted;
    if (decryptedDelta !== amountOctas) {
      return reply.code(502).send({
        error: "ca_payload_amount_mismatch",
        detail: `disclosed=${amountOctas} delta=${decryptedDelta}`,
      });
    }

    const recipientBytes = addrBytes(recipient);
    const recipientHash = await deriveRecipientHash(recipientBytes);
    const assetTypeBytes = addrBytes(asset_id);
    const assetIdLe32 = await deriveAssetId(assetTypeBytes);
    const vaultAddrBytes = cfg.vault_addr;

    const now = nowSecs();
    const row: WithdrawRequestRow = {
      request_id: randomUUID(),
      status: "PREPARED",
      disclosed_amount: amountOctas,
      withdraw_blind: withdrawBlind,
      recipient: recipientBytes,
      recipient_hash: recipientHash,
      vault_addr: vaultAddrBytes,
      asset_type: assetTypeBytes,
      asset_id_le32: assetIdLe32,
      chain_id: cfg.chain_id,
      vault_sequence: vaultSequence,
      ca_payload_hash: caPayload.caPayloadHashFrSafe,
      ca_payload_jsonb: {
        new_balance_p: caBytesArrayToHex(caPayload.newBalanceP),
        new_balance_r: caBytesArrayToHex(caPayload.newBalanceR),
        new_balance_r_eff_aud: caBytesArrayToHex(caPayload.newBalanceREffAud),
        amount_p: caBytesArrayToHex(caPayload.amountP),
        amount_r_sender: caBytesArrayToHex(caPayload.amountRSender),
        amount_r_recip: caBytesArrayToHex(caPayload.amountRRecip),
        amount_r_eff_aud: caBytesArrayToHex(caPayload.amountREffAud),
        ek_volun_auds: caBytesArrayToHex(caPayload.ekVolunAuds),
        amount_r_volun_auds: caBytesMatrixToHex(caPayload.amountRVolunAuds),
        zkrp_new_balance: "0x" + hex(caPayload.zkrpNewBalance),
        zkrp_amount: "0x" + hex(caPayload.zkrpAmount),
        sigma_proto_comm: caBytesArrayToHex(caPayload.sigmaProtoComm),
        sigma_proto_resp: caBytesArrayToHex(caPayload.sigmaProtoResp),
        memo: "0x" + hex(caPayload.memo),
      },
      expiry: now + DEFAULT_EXPIRY_SECS,
      created_at: new Date(),
      finalized_at: null,
    };

    try {
      await store.insertWithdrawRequestActiveOnly(row, now);
    } catch (err) {
      if (err instanceof PrepareInflightError) {
        return reply.code(409).send({
          error: "prepare_inflight",
          detail: `active PREPARED withdraw exists for vault_sequence=${row.vault_sequence}`,
        });
      }
      return reply.code(500).send({
        error: "store_unavailable",
        detail: (err as Error)?.message ?? String(err),
      });
    }

    const respBody: Record<string, unknown> = {
      request_id: row.request_id,
      vault_sequence: Number(vaultSequence),
      withdraw_blind: "0x" + hex(withdrawBlind),
      recipient_hash: "0x" + hex(recipientHash),
      asset_id_le32: "0x" + hex(assetIdLe32),
      expiry_secs: row.expiry.toString(),
      ca_payload_hash: "0x" + hex(caPayload.caPayloadHashFrSafe),
      ca_payload_hash_raw: "0x" + hex(caPayload.caPayloadHashRaw),
      ca_payload: row.ca_payload_jsonb,
    };
    if (hooks.exposeWithdrawDiagnosticsForTests === true) {
      respBody.diagnostics = {
        vault_available_octas_before: caPayload.vaultAvailableOctasBefore.toString(),
        vault_available_octas_after_expected:
          caPayload.vaultAvailableOctasAfterDecrypted.toString(),
      };
    }
    return reply.code(200).send(respBody);
  });

  fastify.post("/v1/withdraw/finalize", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as Partial<FinalizeBody> | undefined;
    if (!body || typeof body !== "object") return reply.code(400).send({ error: "missing_body" });
    const { request_id, public_inputs, proof, ca_payload, recipient } = body;
    if (!public_inputs || typeof public_inputs !== "object") {
      return reply.code(400).send({ error: "invalid_public_inputs" });
    }
    if (typeof proof !== "string" || !/^0x[0-9a-fA-F]+$/.test(proof)) {
      return reply.code(400).send({ error: "invalid_proof" });
    }
    let proofBytes: Uint8Array;
    try {
      proofBytes = fromHex(proof);
    } catch {
      return reply.code(400).send({ error: "invalid_proof" });
    }
    if (proofBytes.length !== 256) {
      return reply.code(400).send({
        error: "invalid_proof_length",
        detail: `expected 256 bytes, got ${proofBytes.length}`,
      });
    }
    if (!ca_payload || typeof ca_payload !== "object") {
      return reply.code(400).send({ error: "invalid_ca_payload" });
    }
    if (typeof recipient !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(recipient)) {
      return reply.code(400).send({ error: "invalid_recipient" });
    }
    if (typeof request_id !== "string" || request_id.length === 0) {
      return reply.code(400).send({ error: "missing_request_id" });
    }

    // -------- 1. row lookup + status/expiry gates --------
    let row: WithdrawRequestRow | null;
    try {
      row = await store.getWithdrawRequest(request_id);
    } catch (err) {
      return reply.code(500).send({
        error: "store_unavailable",
        detail: (err as Error)?.message ?? String(err),
      });
    }
    if (!row) {
      return reply.code(404).send({ error: "unknown_request_id" });
    }
    if (row.status !== "PREPARED") {
      return reply.code(409).send({ error: "invalid_state", status: row.status });
    }
    const now = nowSecs();
    if (now > row.expiry) {
      try {
        await store.updateWithdrawRequestStatus(request_id, "EXPIRED");
      } catch { /* don't mask 410 */ }
      return reply.code(410).send({ error: "expired" });
    }

    // -------- 2. CA payload rehash (recipient is dest, legacy quirk) --------
    let recomputedHashRaw: Uint8Array;
    try {
      recomputedHashRaw = hashConfidentialTransferPayload({
        asset_type: row.asset_type,
        vault_addr: row.recipient, // withdraw legacy quirk
        new_balance_p: caHexArrayToBytes(ca_payload.new_balance_p ?? []),
        new_balance_r: caHexArrayToBytes(ca_payload.new_balance_r ?? []),
        new_balance_r_eff_aud: caHexArrayToBytes(ca_payload.new_balance_r_eff_aud ?? []),
        amount_p: caHexArrayToBytes(ca_payload.amount_p ?? []),
        amount_r_sender: caHexArrayToBytes(ca_payload.amount_r_sender ?? []),
        amount_r_recip: caHexArrayToBytes(ca_payload.amount_r_recip ?? []),
        amount_r_eff_aud: caHexArrayToBytes(ca_payload.amount_r_eff_aud ?? []),
        ek_volun_auds: caHexArrayToBytes(ca_payload.ek_volun_auds ?? []),
        amount_r_volun_auds: caHexMatrixToBytes(ca_payload.amount_r_volun_auds ?? []),
        zkrp_new_balance: fromHex(ca_payload.zkrp_new_balance ?? "0x"),
        zkrp_amount: fromHex(ca_payload.zkrp_amount ?? "0x"),
        sigma_proto_comm: caHexArrayToBytes(ca_payload.sigma_proto_comm ?? []),
        sigma_proto_resp: caHexArrayToBytes(ca_payload.sigma_proto_resp ?? []),
        memo: fromHex(ca_payload.memo ?? "0x"),
      });
    } catch (err: any) {
      await markFailed(store, request_id);
      return reply.code(400).send({
        error: "ca_payload_rehash_failed",
        detail: err?.message ?? String(err),
      });
    }
    const recomputedHashFrSafe = new Uint8Array(32);
    recomputedHashFrSafe.set(recomputedHashRaw.slice(0, 31), 0);
    recomputedHashFrSafe[31] = 0;

    if (!bytesEqual(recomputedHashFrSafe, row.ca_payload_hash)) {
      await markFailed(store, request_id);
      return reply.code(400).send({
        error: "ca_payload_hash_mismatch",
        recomputed: "0x" + hex(recomputedHashFrSafe),
        stored: "0x" + hex(row.ca_payload_hash),
      });
    }

    // -------- 3. server canonical recompute --------
    const amountTagServer = await deriveAmountTag({
      amount: row.disclosed_amount,
      withdraw_blind: row.withdraw_blind,
      recipient_hash: row.recipient_hash,
      asset_id_le32: row.asset_id_le32,
      chain_id: row.chain_id,
      vault_sequence: row.vault_sequence,
    });
    const requestHashServer = await deriveRequestHash({
      amount_tag: amountTagServer,
      recipient_hash: row.recipient_hash,
      ca_payload_hash: row.ca_payload_hash,
      asset_id_le32: row.asset_id_le32,
      vault_sequence: row.vault_sequence,
      chain_id: row.chain_id,
    });

    // -------- 4. byte-equal client public_inputs vs server canonical --------
    const mismatchField = checkPublicInputs(public_inputs, {
      amount_tag: amountTagServer,
      request_hash: requestHashServer,
      recipient_hash: row.recipient_hash,
      ca_payload_hash: row.ca_payload_hash,
      asset_id: row.asset_id_le32,
      vault_sequence: row.vault_sequence,
    });
    if (mismatchField) {
      await markFailed(store, request_id);
      return reply.code(400).send({ error: "public_input_mismatch", field: mismatchField });
    }

    // -------- 5. Groth16 verify --------
    let rootBytes: Uint8Array;
    let nullifierHashBytes: Uint8Array;
    try {
      rootBytes = fromHex(public_inputs.root);
      nullifierHashBytes = fromHex(public_inputs.nullifier_hash);
      if (rootBytes.length !== 32 || nullifierHashBytes.length !== 32) {
        throw new Error(`root/nullifier_hash must be 32B`);
      }
    } catch (err: any) {
      await markFailed(store, request_id);
      return reply.code(400).send({
        error: "invalid_root_or_nullifier",
        detail: err?.message ?? String(err),
      });
    }
    const publicInputsDec: string[] = [
      le32ToDec(rootBytes),
      le32ToDec(nullifierHashBytes),
      le32ToDec(row.asset_id_le32),
      le32ToDec(row.recipient_hash),
      le32ToDec(amountTagServer),
      le32ToDec(row.ca_payload_hash),
      le32ToDec(requestHashServer),
      le32ToDec(u64ToFieldLe32(row.vault_sequence)),
    ];
    let proofOk: boolean;
    try {
      proofOk = await verifyProof(proofBytes, publicInputsDec);
    } catch {
      proofOk = false;
    }
    if (!proofOk) {
      await markFailed(store, request_id);
      return reply.code(400).send({ error: "groth16_proof_invalid" });
    }

    // -------- 6. chain vault_sequence drift check --------
    let chain: ChainVaultState;
    try {
      chain = await readChainVaultState(aptos, bridgeAddr);
    } catch (err: any) {
      return reply.code(502).send({
        error: "chain_state_unavailable",
        detail: err?.message ?? String(err),
      });
    }
    if (chain.vaultSequence !== row.vault_sequence) {
      try {
        await store.updateWithdrawRequestStatus(request_id, "EXPIRED");
      } catch { /* surface 409 regardless */ }
      return reply.code(409).send({
        error: "vault_sequence_changed",
        row_vault_sequence: row.vault_sequence.toString(),
        chain_vault_sequence: chain.vaultSequence.toString(),
      });
    }

    // -------- 7. assemble + sign WithdrawAttestationMessage --------
    let mainKey;
    try {
      mainKey = loadOperatorKeyForSlot(0);
    } catch (err: any) {
      return reply.code(500).send({
        error: "operator_key_load_failed",
        detail: err?.message ?? String(err),
      });
    }

    const msgBytes = encodeWithdrawAttestationMessage({
      domain: DOMAIN_WITHDRAW_OK_V1,
      chain_id: row.chain_id,
      pool_id: POOL_ID_FR_BYTES,
      operator_set_version: chain.operatorSetVersion,
      threshold: chain.threshold,
      vault_addr: row.vault_addr,
      asset_type: row.asset_type,
      nullifier_hash: nullifierHashBytes,
      recipient: row.recipient,
      recipient_hash: row.recipient_hash,
      amount_tag: amountTagServer,
      ca_payload_hash: row.ca_payload_hash,
      request_hash: requestHashServer,
      vault_sequence: row.vault_sequence,
      expiry_secs: row.expiry,
    });
    const mainSig = ed25519.sign(msgBytes, fromHex(mainKey.private_key));

    // -------- 8. CP4 — fan out withdraw cosign request to partners --------
    const cosignBody: WithdrawCoSignRequestBody = {
      request_id,
      operator_set_version: cfg.operator_set_version.toString(),
      threshold: cfg.threshold.toString(),
      chain_id: cfg.chain_id,
      pool_id: cfg.pool_id.toString(),
      vault_addr: vaultAddrHexCfg,
      asset_type: assetTypeHexCfg,
      vault_sequence: row.vault_sequence.toString(),
      expiry_secs: row.expiry.toString(),
      recipient: "0x" + hex(row.recipient),
      recipient_hash: "0x" + hex(row.recipient_hash),
      amount_tag: "0x" + hex(amountTagServer),
      ca_payload_hash: "0x" + hex(row.ca_payload_hash),
      request_hash: "0x" + hex(requestHashServer),
      nullifier_hash: "0x" + hex(nullifierHashBytes),
      public_inputs: publicInputsDec as WithdrawCoSignRequestBody["public_inputs"],
      proof_hex: proof,
      ca_payload: {
        asset_type: assetTypeHexCfg,
        vault_addr: "0x" + hex(row.recipient), // legacy quirk
        new_balance_p: ca_payload.new_balance_p ?? [],
        new_balance_r: ca_payload.new_balance_r ?? [],
        new_balance_r_eff_aud: ca_payload.new_balance_r_eff_aud ?? [],
        amount_p: ca_payload.amount_p ?? [],
        amount_r_sender: ca_payload.amount_r_sender ?? [],
        amount_r_recip: ca_payload.amount_r_recip ?? [],
        amount_r_eff_aud: ca_payload.amount_r_eff_aud ?? [],
        ek_volun_auds: ca_payload.ek_volun_auds ?? [],
        amount_r_volun_auds: ca_payload.amount_r_volun_auds ?? [],
        zkrp_new_balance: ca_payload.zkrp_new_balance ?? "0x",
        zkrp_amount: ca_payload.zkrp_amount ?? "0x",
        sigma_proto_comm: ca_payload.sigma_proto_comm ?? [],
        sigma_proto_resp: ca_payload.sigma_proto_resp ?? [],
        memo: ca_payload.memo ?? "0x",
      },
      main_op_signature: "0x" + hex(mainSig),
    };

    let partnerResults: PartnerCoSignResult[];
    try {
      partnerResults = await fanOutWithdrawCoSign(
        cfg.partner_urls,
        cfg.partner_bearer_tokens,
        cosignBody,
        cfg.partner_request_timeout_ms,
      );
    } catch (err: any) {
      return reply.code(500).send({
        error: "store_unavailable",
        detail: err?.message ?? String(err),
      });
    }

    // -------- F1 strict aggregation --------
    const mainSlot = cfg.main_slot;
    const signatures: Array<{ slot: number; signature_hex: string | null }> = [];
    for (let i = 0; i < 7; i++) {
      signatures.push({ slot: i, signature_hex: null });
    }
    signatures[mainSlot] = { slot: mainSlot, signature_hex: "0x" + hex(mainSig) };

    const validSlots = new Set<number>([mainSlot]);
    for (let i = 0; i < partnerResults.length; i++) {
      const r = partnerResults[i];
      const expectedSlot = i + 1;
      if (!r.signature_bytes) {
        await auditReject(store, request_id, r.slot, i, r.error ?? "no_signature");
        continue;
      }
      if (!Number.isInteger(r.slot) || r.slot < 1 || r.slot > 6) {
        await auditReject(store, request_id, r.slot, i, "slot_out_of_range");
        continue;
      }
      if (r.slot !== expectedSlot) {
        await auditReject(store, request_id, r.slot, i, "slot_idx_mismatch");
        continue;
      }
      if (validSlots.has(r.slot)) {
        await auditReject(store, request_id, r.slot, i, "duplicate_slot");
        continue;
      }
      if (r.signature_bytes.length !== 64) {
        await auditReject(store, request_id, r.slot, i, "wrong_signature_length");
        continue;
      }
      const cfgPubkey = cfg.partner_pubkeys[r.slot];
      if (!cfgPubkey) {
        await auditReject(store, request_id, r.slot, i, "missing_cfg_pubkey");
        continue;
      }
      if (!verifyEd25519(r.signature_bytes, cfgPubkey, msgBytes)) {
        await auditReject(store, request_id, r.slot, i, "ed25519_verify_failed");
        continue;
      }
      validSlots.add(r.slot);
      signatures[r.slot] = {
        slot: r.slot,
        signature_hex: "0x" + hex(r.signature_bytes),
      };
    }

    const count = validSlots.size;
    if (BigInt(count) < cfg.threshold) {
      return reply.code(500).send({
        error: "insufficient_cosigns",
        count,
        threshold: cfg.threshold.toString(),
        request_id,
      });
    }

    try {
      await store.updateWithdrawRequestStatus(request_id, "FINALIZED", new Date());
    } catch (err: any) {
      // Status update transient — refuse to release sigs without persistent
      // FINALIZED record. Row stays PREPARED for retry.
      return reply.code(500).send({
        error: "store_unavailable",
        detail: err?.message ?? String(err),
      });
    }

    return reply.code(200).send({
      request_id,
      attestation_msg_bcs: "0x" + hex(msgBytes),
      signatures,
      threshold_met: true,
    });
  });
}

async function markFailed(store: Store, request_id: string): Promise<void> {
  try {
    await store.updateWithdrawRequestStatus(request_id, "FAILED");
  } catch {
    /* don't mask user-visible error */
  }
}

async function auditReject(
  store: Store,
  request_id: string,
  slot: number,
  idx: number,
  reason: string,
): Promise<void> {
  try {
    await store.insertAuditLog({
      id: randomUUID(),
      request_id,
      event_type: "withdraw_partner_signature_rejected",
      payload_jsonb: { slot, idx, reason },
      timestamp: new Date(),
    });
  } catch {
    /* audit-log failure does not block aggregation */
  }
}

function checkPublicInputs(
  client: {
    asset_id: string;
    recipient_hash: string;
    amount_tag: string;
    ca_payload_hash: string;
    request_hash: string;
    vault_sequence: string;
  },
  server: {
    amount_tag: Uint8Array;
    request_hash: Uint8Array;
    recipient_hash: Uint8Array;
    ca_payload_hash: Uint8Array;
    asset_id: Uint8Array;
    vault_sequence: bigint;
  },
): string | null {
  if (!hexFieldEq(client.amount_tag, server.amount_tag)) return "amount_tag";
  if (!hexFieldEq(client.request_hash, server.request_hash)) return "request_hash";
  if (!hexFieldEq(client.recipient_hash, server.recipient_hash)) return "recipient_hash";
  if (!hexFieldEq(client.ca_payload_hash, server.ca_payload_hash)) return "ca_payload_hash";
  if (!hexFieldEq(client.asset_id, server.asset_id)) return "asset_id";
  let clientSeq: bigint;
  try {
    clientSeq = BigInt(client.vault_sequence);
  } catch {
    return "vault_sequence";
  }
  if (clientSeq !== server.vault_sequence) return "vault_sequence";
  return null;
}

function hexFieldEq(clientHex: string, serverBytes: Uint8Array): boolean {
  try {
    const got = fromHex(clientHex);
    return bytesEqual(got, serverBytes);
  } catch {
    return false;
  }
}
