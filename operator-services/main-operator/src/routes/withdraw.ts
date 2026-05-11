// POST /v1/withdraw/prepare + /v1/withdraw/finalize (Phase 4 W6.5).
//
// Migrated from main-operator/server.ts skeleton (Phase 2.Y / W.9). Replaces
// the standalone skeleton with proper integration into the production
// buildMainServer so W1 bearer-auth + rate-limit apply automatically.
//
// Trust model (alpha):
//   - main op (slot 0) signs the WithdrawAttestationMessage with its own key
//   - alpha deployment runs ALL 7 operator processes on a single host (per
//     vivid-foraging-fern Phase 4 plan), so partner cosign fanout for
//     withdraw is implemented client-side in testnet_withdraw_e2e.ts (reads
//     all 7 keys from OPERATOR_KEYS_JSON_B64). On-chain 4-of-7 verification
//     in eunoma_bridge::withdraw_to_recipient holds either way — software
//     architecture mimics future multi-party even though all keys
//     co-locate today.
//   - v1 (post-funding, external partners): add POST /v1/cosign/withdraw on
//     partner + fanOutCosignWithdraw in main, mirror /v1/cosign/deposit
//     shape. Plan: ~0.5 day when external signers come online.

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AccountAddress, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildWithdrawCAPayload,
  hashConfidentialTransferPayload,
  loadOperatorKeyForSlot,
  Writer,
} from "@eunoma/shared";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = path.resolve(__dirname, "..", "..", "..", "scripts", "testnet_state.json");

const DEFAULT_BRIDGE_ADDR =
  "0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820";
const DEFAULT_ASSET_ID = "0xa";
const DEFAULT_CHAIN_ID = 2;
// Phase D Agent D1 c2: pool_id encoded as 8-byte LE u64 in the canonical
// WithdrawAttestationMessage (was 32-byte LE Fr). Matches Move-side
// pool_id_to_le_u64_bytes() and saves 24 BCS bytes on the signed message
// (which in turn shrinks SHA512 input fed to each ed25519 verify on chain).
// Value 0 (POOL_ID_VALUE) ⇒ 8 zero bytes.
const POOL_ID_FR_BYTES = new Uint8Array(8);
const DOMAIN_WITHDRAW_OK_V1 = new TextEncoder().encode("APTOSHIELD_WITHDRAW_OK_V1");

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

function loadStateDefaults(): { vaultAddrHex: string; assetIdHex: string; chainId: number } {
  if (!fs.existsSync(STATE_PATH)) {
    return { vaultAddrHex: "", assetIdHex: DEFAULT_ASSET_ID, chainId: DEFAULT_CHAIN_ID };
  }
  const s = JSON.parse(fs.readFileSync(STATE_PATH, "utf-8"));
  return {
    vaultAddrHex: s?.vault?.address ?? "",
    assetIdHex: s?.vault?.asset_type ?? DEFAULT_ASSET_ID,
    chainId: s?.chain_id ?? DEFAULT_CHAIN_ID,
  };
}

async function readChainVaultState(aptos: Aptos, bridgeAddr: string) {
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

function encodeWithdrawAttestationMessage(msg: {
  domain: Uint8Array; chain_id: number; pool_id: Uint8Array;
  operator_set_version: bigint; threshold: bigint;
  vault_addr: Uint8Array; asset_type: Uint8Array;
  nullifier_hash: Uint8Array; recipient: Uint8Array; recipient_hash: Uint8Array;
  amount_tag: Uint8Array; ca_payload_hash: Uint8Array; request_hash: Uint8Array;
  vault_sequence: bigint; expiry_secs: bigint;
}): Uint8Array {
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

interface PrepareBody {
  amount: string;       // octas as decimal string
  recipient: string;    // 32-byte hex address
  asset_id: string;     // 0xa or other FA metadata
  // W6.6 selective disclosure (self-audit): zero or more user-chosen audit
  // TwistedEd25519 PUBLIC keys (32-byte hex each). Each key gets a slot in
  // ek_volun_auds + an encrypted amount in amount_r_volun_auds. User keeps
  // the corresponding audit_sk privately and can later decrypt the
  // amount to prove the tx to any third party.
  user_audit_pks?: string[];
}

interface FinalizeBody {
  public_inputs: {
    nullifier_hash: string; recipient_hash: string; amount_tag: string;
    request_hash: string; expiry_secs: string; vault_sequence: string;
  };
  proof: string; // 256-byte uncompressed Groth16 hex
  ca_payload: {
    new_balance_p: string[]; new_balance_r: string[]; new_balance_r_eff_aud: string[];
    amount_p: string[]; amount_r_sender: string[]; amount_r_recip: string[];
    amount_r_eff_aud: string[]; ek_volun_auds: string[]; amount_r_volun_auds: string[][];
    zkrp_new_balance: string; zkrp_amount: string;
    sigma_proto_comm: string[]; sigma_proto_resp: string[]; memo: string;
    ca_payload_hash: string;
  };
  recipient: string;
}

export function registerWithdrawRoutes(fastify: FastifyInstance): void {
  const defaults = loadStateDefaults();
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));

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

    // W6.6: validate optional user audit pubkeys (each 32-byte hex)
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
    const vaultAddrHex = defaults.vaultAddrHex;
    if (!vaultAddrHex) {
      return reply.code(503).send({
        error: "vault_not_initialised",
        detail: "testnet_state.json missing vault.address — run testnet_init_vault first",
      });
    }
    const bridgeAddr = process.env.BRIDGE_PACKAGE_ADDRESS ?? DEFAULT_BRIDGE_ADDR;

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

    // 31 random bytes + zero high byte → fits BN254 Fr.
    const withdrawBlind = (() => {
      const r = randomBytes(31);
      const out = new Uint8Array(32);
      out.set(r, 0);
      return out;
    })();

    let caPayload;
    try {
      caPayload = await buildWithdrawCAPayload({
        vaultAddrHex,
        recipientAddrHex: recipient,
        amountOctas,
        assetTypeHex: asset_id,
        chainId: defaults.chainId,
        userAuditPksHex,
      });
    } catch (err: any) {
      return reply.code(502).send({
        error: "ca_payload_build_failed",
        detail: err?.message ?? String(err),
      });
    }

    return reply.code(200).send({
      vault_sequence: Number(vaultSequence),
      withdraw_blind: "0x" + hex(withdrawBlind),
      ca_payload_hash: "0x" + hex(caPayload.caPayloadHashFrSafe),
      ca_payload_hash_raw: "0x" + hex(caPayload.caPayloadHashRaw),
      ca_payload: {
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
      diagnostics: {
        vault_available_octas_before: caPayload.vaultAvailableOctasBefore.toString(),
        vault_available_octas_after_expected:
          caPayload.vaultAvailableOctasAfterDecrypted.toString(),
      },
    });
  });

  fastify.post("/v1/withdraw/finalize", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as Partial<FinalizeBody> | undefined;
    if (!body || typeof body !== "object") return reply.code(400).send({ error: "missing_body" });
    const { public_inputs, proof, ca_payload, recipient } = body;
    if (!public_inputs || typeof public_inputs !== "object") {
      return reply.code(400).send({ error: "invalid_public_inputs" });
    }
    if (typeof proof !== "string" || !/^0x[0-9a-fA-F]+$/.test(proof)) {
      return reply.code(400).send({ error: "invalid_proof" });
    }
    const proofBytes = fromHex(proof);
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

    // Re-hash CA payload against the recipient to detect tampering.
    let recomputedHashRaw: Uint8Array;
    try {
      recomputedHashRaw = hashConfidentialTransferPayload({
        asset_type: AccountAddress.from(defaults.assetIdHex).toUint8Array(),
        vault_addr: AccountAddress.from(recipient).toUint8Array(),
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
      return reply.code(400).send({
        error: "ca_payload_rehash_failed",
        detail: err?.message ?? String(err),
      });
    }
    const recomputedHashFrSafe = new Uint8Array(32);
    recomputedHashFrSafe.set(recomputedHashRaw.slice(0, 31), 0);
    recomputedHashFrSafe[31] = 0;

    if (typeof ca_payload.ca_payload_hash !== "string") {
      return reply.code(400).send({ error: "missing_ca_payload_hash" });
    }
    const claimedHash = fromHex(ca_payload.ca_payload_hash);
    if (
      claimedHash.length !== 32 ||
      Buffer.from(claimedHash).toString("hex") !==
        Buffer.from(recomputedHashFrSafe).toString("hex")
    ) {
      return reply.code(400).send({
        error: "ca_payload_hash_mismatch",
        recomputed: "0x" + hex(recomputedHashFrSafe),
      });
    }

    const bridgeAddr = process.env.BRIDGE_PACKAGE_ADDRESS ?? DEFAULT_BRIDGE_ADDR;
    const vaultAddrHex = defaults.vaultAddrHex;
    if (!vaultAddrHex) return reply.code(503).send({ error: "vault_not_initialised" });

    let chain;
    try {
      chain = await readChainVaultState(aptos, bridgeAddr);
    } catch (err: any) {
      return reply.code(502).send({
        error: "chain_state_unavailable",
        detail: err?.message ?? String(err),
      });
    }

    const declaredSequence = BigInt(public_inputs.vault_sequence ?? "0");
    if (declaredSequence !== chain.vaultSequence) {
      return reply.code(409).send({
        error: "vault_sequence_mismatch",
        detail: `chain has ${chain.vaultSequence}, request claims ${declaredSequence}`,
      });
    }

    // Main op slot-0 signs. Partner-cosign-fanout for withdraw is a v1 TODO;
    // alpha deployment co-locates all 7 operator processes on one host and
    // the e2e script does local 4-of-7 aggregation client-side from
    // OPERATOR_KEYS_JSON_B64. The Move bridge still verifies the same
    // 4-of-7 attestation set on chain — only off-chain origination differs.
    let mainKey;
    try {
      mainKey = loadOperatorKeyForSlot(0);
    } catch (err: any) {
      return reply.code(500).send({
        error: "operator_key_load_failed",
        detail: err?.message ?? String(err),
      });
    }

    const expirySecs = BigInt(
      public_inputs.expiry_secs ?? Math.floor(Date.now() / 1000) + 3600,
    );
    const msg = {
      domain: DOMAIN_WITHDRAW_OK_V1,
      chain_id: defaults.chainId,
      pool_id: POOL_ID_FR_BYTES,
      operator_set_version: chain.operatorSetVersion,
      threshold: chain.threshold,
      vault_addr: AccountAddress.from(vaultAddrHex).toUint8Array(),
      asset_type: AccountAddress.from(defaults.assetIdHex).toUint8Array(),
      nullifier_hash: fromHex(public_inputs.nullifier_hash ?? "0x"),
      recipient: AccountAddress.from(recipient).toUint8Array(),
      recipient_hash: fromHex(public_inputs.recipient_hash ?? "0x"),
      amount_tag: fromHex(public_inputs.amount_tag ?? "0x"),
      ca_payload_hash: recomputedHashFrSafe,
      request_hash: fromHex(public_inputs.request_hash ?? "0x"),
      vault_sequence: chain.vaultSequence,
      expiry_secs: expirySecs,
    };
    const msgBytes = encodeWithdrawAttestationMessage(msg);
    const sig = ed25519.sign(msgBytes, fromHex(mainKey.private_key));

    return reply.code(200).send({
      attestation_msg_bcs: "0x" + hex(msgBytes),
      main_operator_signature: "0x" + hex(sig),
      main_operator_slot: mainKey.slot,
      main_operator_pubkey: mainKey.public_key,
      ca_payload_hash_used: "0x" + hex(recomputedHashFrSafe),
      vault_sequence: Number(chain.vaultSequence),
      expiry_secs: expirySecs.toString(),
    });
  });
}
