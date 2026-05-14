// CP4 — main-operator /v1/withdraw/finalize partner cosign + fanout tests.
// F7 from plan-for-this-frolicking-wilkes.md — 9 cases. All cases run with
// cfg.threshold = 4n + 6 ephemeral partners (slot 1..6).

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
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
  InMemoryStore,
  le32ToDec,
  POOL_ID_FR_BYTES,
  u64ToFieldLe32,
} from "@eunoma/shared";
import type { PartnerCoSignResult } from "../src/partner_client.js";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const AUTH_TOKEN = "withdraw-cp4-test-token";
const AUTH = { authorization: `Bearer ${AUTH_TOKEN}` };

const RECIPIENT_HEX = "0x" + "a1".repeat(32);
const VAULT_ADDR_HEX = "0x" + "be".repeat(32);
const ASSET_TYPE_HEX = "0x" + "0a".padStart(64, "0");
const CHAIN_ID = 2;
const INITIAL_CHAIN_VAULT_SEQ = 7n;
const DISCLOSED_AMOUNT = 1_000_000n;

function seedOperatorKeysEnv(): void {
  const keys = Array.from({ length: 7 }, (_, slot) => {
    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);
    return {
      slot,
      role: slot === 0 ? "main" : `partner_${slot}`,
      private_key: "0x" + Buffer.from(sk).toString("hex"),
      public_key: "0x" + Buffer.from(pk).toString("hex"),
      address: "0x" + "00".repeat(32),
    };
  });
  process.env.OPERATOR_KEYS_JSON_B64 = Buffer.from(JSON.stringify(keys)).toString("base64");
}

function ca32(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function makeFakeCAPayload() {
  return async (input: {
    vaultAddrHex: string;
    recipientAddrHex: string;
    amountOctas: bigint;
    assetTypeHex: string;
    chainId: number;
  }) => {
    const before = 10_000_000n;
    const after = before - input.amountOctas;
    const newBalanceP = [ca32(0x11), ca32(0x12)];
    const newBalanceR = [ca32(0x13), ca32(0x14)];
    const newBalanceREffAud = [ca32(0x15), ca32(0x16)];
    const amountP = [ca32(0x21), ca32(0x22)];
    const amountRSender = [ca32(0x23), ca32(0x24)];
    const amountRRecip = [ca32(0x25), ca32(0x26)];
    const amountREffAud = [ca32(0x27), ca32(0x28)];
    const sigmaProtoComm = [ca32(0x41), ca32(0x42), ca32(0x43)];
    const sigmaProtoResp = [ca32(0x44), ca32(0x45), ca32(0x46)];
    const zkrpNewBalance = new Uint8Array(64).fill(0x31);
    const zkrpAmount = new Uint8Array(64).fill(0x32);
    const memo = new Uint8Array(8).fill(0x51);

    const hashStruct = {
      asset_type: AccountAddress.from(input.assetTypeHex).toUint8Array(),
      vault_addr: AccountAddress.from(input.recipientAddrHex).toUint8Array(),
      new_balance_p: newBalanceP,
      new_balance_r: newBalanceR,
      new_balance_r_eff_aud: newBalanceREffAud,
      amount_p: amountP,
      amount_r_sender: amountRSender,
      amount_r_recip: amountRRecip,
      amount_r_eff_aud: amountREffAud,
      ek_volun_auds: [] as Uint8Array[],
      amount_r_volun_auds: [] as Uint8Array[][],
      zkrp_new_balance: zkrpNewBalance,
      zkrp_amount: zkrpAmount,
      sigma_proto_comm: sigmaProtoComm,
      sigma_proto_resp: sigmaProtoResp,
      memo,
    };
    const raw = hashConfidentialTransferPayload(hashStruct);
    const fr = new Uint8Array(32);
    fr.set(raw.slice(0, 31), 0);

    return {
      newBalanceP,
      newBalanceR,
      newBalanceREffAud,
      amountP,
      amountRSender,
      amountRRecip,
      amountREffAud,
      ekVolunAuds: [] as Uint8Array[],
      amountRVolunAuds: [] as Uint8Array[][],
      zkrpNewBalance,
      zkrpAmount,
      sigmaProtoComm,
      sigmaProtoResp,
      memo,
      caPayloadHashRaw: raw,
      caPayloadHashFrSafe: fr,
      vaultAvailableOctasBefore: before,
      vaultAvailableOctasAfterDecrypted: after,
    };
  };
}

interface PartnerKey {
  slot: number;
  sk: Uint8Array;
  pk: Uint8Array;
}

interface Cluster {
  server: ReturnType<typeof buildMainServer>["server"];
  store: InMemoryStore;
  partners: PartnerKey[];
  mainPubkey: Uint8Array;
  cfgPartnerPubkeys: Uint8Array[];
  fanoutCalls: Array<{ urls: string[]; body: any }>;
}

interface ClusterOpts {
  partnerCount?: number;
  partnerUrlsOverride?: string[];
  partnerBearerOverride?: string[];
  fanoutStub?: (
    body: any,
    partners: PartnerKey[],
    msgBytes: Uint8Array,
  ) => PartnerCoSignResult[];
  cfgPartnerPubkeysOverride?: (pks: Uint8Array[]) => Uint8Array[];
  chainVaultSeq?: bigint;
}

// Default fanout stub: each partner signs the rebuilt msgBytes with its
// configured key and returns slot = partnerIdx + 1.
function defaultPartnerResponses(
  _body: any,
  partners: PartnerKey[],
  msgBytes: Uint8Array,
): PartnerCoSignResult[] {
  return partners.map((p) => {
    const sig = ed25519.sign(msgBytes, p.sk);
    return {
      slot: p.slot,
      signature_bytes: sig,
      pubkey_hex: Buffer.from(p.pk).toString("hex"),
      message_bytes_hash_hex: "00".repeat(32),
    };
  });
}

function rebuildMsgBytesFromCosignBody(body: any): Uint8Array {
  return encodeWithdrawAttestationMessage({
    domain: DOMAIN_WITHDRAW_OK_V1,
    chain_id: body.chain_id,
    pool_id: POOL_ID_FR_BYTES,
    operator_set_version: BigInt(body.operator_set_version),
    threshold: BigInt(body.threshold),
    vault_addr: hexToBytes(body.vault_addr),
    asset_type: hexToBytes(body.asset_type),
    nullifier_hash: hexToBytes(body.nullifier_hash),
    recipient: hexToBytes(body.recipient),
    recipient_hash: hexToBytes(body.recipient_hash),
    amount_tag: hexToBytes(body.amount_tag),
    ca_payload_hash: hexToBytes(body.ca_payload_hash),
    request_hash: hexToBytes(body.request_hash),
    vault_sequence: BigInt(body.vault_sequence),
    expiry_secs: BigInt(body.expiry_secs),
  });
}

function setupCluster(opts: ClusterOpts = {}): Cluster {
  const mainSk = ed25519.utils.randomPrivateKey();
  // Pull main key from seeded env so route's loadOperatorKeyForSlot(0) is in
  // sync with cfg.signer's pubkey. We re-seed per test.
  // Actually we use env-seeded main key for signing; cfg.signer is unused by
  // the withdraw route. cfg.partner_pubkeys[0] must match the env's slot-0 pk.
  const envKeys = JSON.parse(
    Buffer.from(process.env.OPERATOR_KEYS_JSON_B64 ?? "", "base64").toString("utf-8"),
  );
  const mainPubkey = hexToBytes(envKeys[0].public_key);

  const partnerCount = opts.partnerCount ?? 6;
  const partners: PartnerKey[] = Array.from({ length: partnerCount }, (_, i) => {
    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);
    return { slot: i + 1, sk, pk };
  });

  // cfg.partner_pubkeys must be length 7 (slot 0..6). slot 0 = main. slots
  // 1..6 = configured partner pubkeys (filled from `partners`; trailing slots
  // get random unused pubkeys so the length=7 invariant holds even when
  // partner_urls is shorter).
  let cfgPartnerPubkeys: Uint8Array[] = new Array(7);
  cfgPartnerPubkeys[0] = mainPubkey;
  for (let i = 1; i <= 6; i++) {
    const matching = partners.find((p) => p.slot === i);
    cfgPartnerPubkeys[i] = matching
      ? matching.pk
      : ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
  }
  if (opts.cfgPartnerPubkeysOverride) {
    cfgPartnerPubkeys = opts.cfgPartnerPubkeysOverride(cfgPartnerPubkeys);
  }

  const partner_urls =
    opts.partnerUrlsOverride ??
    partners.map((_, i) => `http://127.0.0.1:${4100 + i}`);
  const partner_bearer_tokens =
    opts.partnerBearerOverride ?? partners.map(() => "partner-test-bearer");

  const cfg = defaultMainConfig({
    signer: new InMemoryEd25519Signer(),
    partner_urls,
    partner_pubkeys: cfgPartnerPubkeys,
    bearer_token: AUTH_TOKEN,
    partner_bearer_tokens,
  });
  cfg.vault_addr = AccountAddress.from(VAULT_ADDR_HEX).toUint8Array();
  cfg.asset_type = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
  cfg.chain_id = CHAIN_ID;
  cfg.threshold = 4n;
  cfg.main_slot = 0;

  const store = new InMemoryStore();
  const fanoutCalls: Cluster["fanoutCalls"] = [];

  const fanoutStub = opts.fanoutStub ?? defaultPartnerResponses;

  const { server } = buildMainServer({
    cfg,
    store,
    withdrawRouteHooks: {
      buildCAPayload: makeFakeCAPayload(),
      readChainVaultState: async () => ({
        operatorSetVersion: 1n,
        threshold: 4n,
        vaultAddrHex: VAULT_ADDR_HEX,
        vaultSequence: opts.chainVaultSeq ?? INITIAL_CHAIN_VAULT_SEQ,
      }),
      verifyProof: async () => true,
      fanOutWithdrawCoSign: async (urls, _tokens, body) => {
        fanoutCalls.push({ urls, body });
        const msgBytes = rebuildMsgBytesFromCosignBody(body);
        return fanoutStub(body, partners, msgBytes);
      },
      submitWithdrawTx: async () => ({
        tx: "0x" + "12".repeat(32),
        success: true,
        vm_status: "Executed successfully",
        gas_used: "12345",
      }),
    },
  });
  return {
    server,
    store,
    partners,
    mainPubkey,
    cfgPartnerPubkeys,
    fanoutCalls,
  };
}

async function callPrepare(server: any) {
  const res = await server.inject({
    method: "POST",
    url: "/v1/withdraw/prepare",
    headers: AUTH,
    payload: {
      amount: DISCLOSED_AMOUNT.toString(),
      recipient: RECIPIENT_HEX,
      asset_id: ASSET_TYPE_HEX,
    },
  });
  return { res, body: res.json() };
}

async function callFinalize(server: any, payload: any) {
  const res = await server.inject({
    method: "POST",
    url: "/v1/withdraw/finalize",
    headers: AUTH,
    payload,
  });
  return { res, body: res.json() };
}

async function buildHappyFinalizeBody(prep: any) {
  const assetType = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
  const assetIdLe32 = await deriveAssetId(assetType);
  const recipientHash = hexToBytes(prep.recipient_hash);
  const withdrawBlind = hexToBytes(prep.withdraw_blind);
  const caHashFrSafe = hexToBytes(prep.ca_payload_hash);

  const amountTag = await deriveAmountTag({
    amount: DISCLOSED_AMOUNT,
    withdraw_blind: withdrawBlind,
    recipient_hash: recipientHash,
    asset_id_le32: assetIdLe32,
    chain_id: CHAIN_ID,
    vault_sequence: BigInt(prep.vault_sequence),
  });
  const requestHash = await deriveRequestHash({
    amount_tag: amountTag,
    recipient_hash: recipientHash,
    ca_payload_hash: caHashFrSafe,
    asset_id_le32: assetIdLe32,
    vault_sequence: BigInt(prep.vault_sequence),
    chain_id: CHAIN_ID,
  });

  const root = new Uint8Array(32).fill(0xaa);
  root[31] = 0;
  const nullifierHash = new Uint8Array(32).fill(0xbb);
  nullifierHash[31] = 0;

  return {
    request_id: prep.request_id,
    public_inputs: {
      root: "0x" + bytesToHex(root),
      nullifier_hash: "0x" + bytesToHex(nullifierHash),
      asset_id: "0x" + bytesToHex(assetIdLe32),
      recipient_hash: prep.recipient_hash,
      amount_tag: "0x" + bytesToHex(amountTag),
      ca_payload_hash: prep.ca_payload_hash,
      request_hash: "0x" + bytesToHex(requestHash),
      vault_sequence: prep.vault_sequence.toString(),
    },
    proof: "0x" + "00".repeat(256),
    ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
    recipient: RECIPIENT_HEX,
  };
}

beforeAll(() => {
  seedOperatorKeysEnv();
});

describe("CP4 /v1/withdraw/finalize partner cosign + fanout", () => {
  it("F7.1 threshold_success: 3 valid partners + main = 4 → 200 + FINALIZED", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners, msgBytes) => {
        // Slot 1,2,3 sign valid; slot 4,5,6 simulate http_400
        return partners.map((p) => {
          if (p.slot <= 3) {
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: p.slot,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          return { slot: -1, signature_bytes: null, error: "http_400" };
        });
      },
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(200);
    expect(Object.keys(body).sort()).toEqual([
      "gas_used",
      "request_id",
      "success",
      "tx",
      "vm_status",
    ]);
    expect(body.success).toBe(true);
    expect(body.tx).toMatch(/^0x[0-9a-f]+$/);
    expect(body.vm_status).toBe("Executed successfully");
    expect(body.gas_used).toBe("12345");
    const row = await cluster.store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("FINALIZED");
  });

  it("F7.2 insufficient_cosigns_all_fail: 6 timeouts → 500 + strict whitelist + row=PREPARED", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners) =>
        partners.map(() => ({ slot: -1, signature_bytes: null, error: "timeout" })),
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(500);
    expect(Object.keys(body).sort()).toEqual(["count", "error", "request_id", "threshold"]);
    expect(body.error).toBe("insufficient_cosigns");
    expect(body.count).toBe(1);
    expect(body.threshold).toBe("4");
    expect(body.request_id).toBe(prep.request_id);
    const row = await cluster.store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("PREPARED");
  });

  it("F7.3 bad_partner_signature: random 32B sig ignored, count=3 → 500", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners, msgBytes) =>
        partners.map((p) => {
          if (p.slot === 1) {
            // Random 64B that won't verify against cfg pubkey
            return {
              slot: p.slot,
              signature_bytes: new Uint8Array(64).fill(0x42),
              pubkey_hex: "00".repeat(32),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          if (p.slot <= 3) {
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: p.slot,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          return { slot: -1, signature_bytes: null, error: "http_400" };
        }),
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(500);
    expect(body.error).toBe("insufficient_cosigns");
    expect(body.count).toBe(3); // main + slot 2 + slot 3
  });

  it("F7.4 partner_spoof_slot_0: slot 0 rejected, other 3 valid → 200", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners, msgBytes) =>
        partners.map((p, idx) => {
          if (idx === 0) {
            // Attempt to spoof slot 0
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: 0,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          if (p.slot >= 2 && p.slot <= 4) {
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: p.slot,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          return { slot: -1, signature_bytes: null, error: "http_400" };
        }),
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(200);
    expect(body.success).toBe(true);
  });

  it("F7.5 partner_duplicate_slot: only first slot=1 counts → 500 when total < 4", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners, msgBytes) =>
        partners.map((p, idx) => {
          if (idx === 0 || idx === 1) {
            // Both partner_urls[0] (expected slot=1) and partner_urls[1] (expected slot=2)
            // return slot=1. Second is rejected by F1 rule #2 (slot_idx_mismatch).
            const slot1 = partners[0];
            const sig = ed25519.sign(msgBytes, slot1.sk);
            return {
              slot: 1,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(slot1.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          if (p.slot === 3) {
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: p.slot,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          return { slot: -1, signature_bytes: null, error: "http_400" };
        }),
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(500);
    expect(body.error).toBe("insufficient_cosigns");
    // main(1) + slot 1 (first) + slot 3 = 3
    expect(body.count).toBe(3);
  });

  it("F7.6 partner_returned_pubkey_mismatch: verify uses cfg pubkey, attacker key ignored", async () => {
    const cluster = setupCluster({
      fanoutStub: (_body, partners, msgBytes) =>
        partners.map((p) => {
          if (p.slot === 1) {
            // Attacker signs with its OWN random key but echoes back its own pubkey.
            // Main verifies against cfg.partner_pubkeys[1] (which is p.pk) → fails.
            const attackerSk = ed25519.utils.randomPrivateKey();
            const attackerPk = ed25519.getPublicKey(attackerSk);
            const sig = ed25519.sign(msgBytes, attackerSk);
            return {
              slot: 1,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(attackerPk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          if (p.slot <= 3) {
            const sig = ed25519.sign(msgBytes, p.sk);
            return {
              slot: p.slot,
              signature_bytes: sig,
              pubkey_hex: Buffer.from(p.pk).toString("hex"),
              message_bytes_hash_hex: "00".repeat(32),
            };
          }
          return { slot: -1, signature_bytes: null, error: "http_400" };
        }),
    });
    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(500);
    expect(body.error).toBe("insufficient_cosigns");
    expect(body.count).toBe(3); // main + slot 2 + slot 3
  });

  it("F7.7 no_configured_partners: partner_urls=[], partner_pubkeys length=7 → 500", async () => {
    const cluster = setupCluster({
      partnerCount: 0,
      partnerUrlsOverride: [],
      partnerBearerOverride: [],
    });
    // partner_pubkeys still length 7 per F1 invariant
    expect(cluster.cfgPartnerPubkeys).toHaveLength(7);

    const { body: prep } = await callPrepare(cluster.server);
    const happy = await buildHappyFinalizeBody(prep);
    const { res, body } = await callFinalize(cluster.server, happy);
    expect(res.statusCode).toBe(500);
    expect(Object.keys(body).sort()).toEqual(["count", "error", "request_id", "threshold"]);
    expect(body.error).toBe("insufficient_cosigns");
    expect(body.count).toBe(1);
  });

  it("F7.8 no_cp3_transitional_path: routes/withdraw.ts free of CP3 transitional strings", () => {
    const src = readFileSync(
      resolve(__dirname, "..", "src", "routes", "withdraw.ts"),
      "utf-8",
    );
    // String-concat the forbidden tokens so this assertion file itself stays
    // outside the F9 grep gate (which must return 0 rows across src + tests).
    const t1 = "cp3" + "TestRelease" + "MainSig";
    const t2 = "cp3" + "_test_release_" + "main_sig";
    const t3 = "cosign_not_" + "wired_yet";
    expect(src.includes(t1)).toBe(false);
    expect(src.includes(t2)).toBe(false);
    expect(src.includes(t3)).toBe(false);
  });

  it("F7.9 prepare_diagnostics_default_absent: diagnostics undefined when flag unset", async () => {
    const cluster = setupCluster();
    const { res, body } = await callPrepare(cluster.server);
    expect(res.statusCode).toBe(200);
    expect(body.diagnostics).toBeUndefined();
  });
});
