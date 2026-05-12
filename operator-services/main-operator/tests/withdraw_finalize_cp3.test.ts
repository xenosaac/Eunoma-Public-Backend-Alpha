// CP3 — main-operator /v1/withdraw/{prepare,finalize} amount-binding tests.
//
// Covers the 8 acceptance cases from plan-for-this-frolicking-wilkes.md:
//   a) prepare amount delta mismatch → 502 ca_payload_amount_mismatch
//   b) finalize tampered amount_tag → 400 public_input_mismatch (amount_tag) + row=FAILED
//   c) tampered request_hash → 400 public_input_mismatch (request_hash) + row=FAILED
//   d) tampered ca_payload → 400 ca_payload_hash_mismatch + row=FAILED
//   e) invalid proof → 400 groth16_proof_invalid + row=FAILED
//   f) expired request → 410 expired + row=EXPIRED
//   g) double finalize → 409 invalid_state
//   h) chain sequence mismatch → 409 vault_sequence_changed + row=EXPIRED (CP3 status policy choice B)
// CP4 removed the CP3↔CP4 transitional signature path; tests below stop at
// pre-fanout errors (a–f, h) or simulate a finalized row directly (g). Full
// cosign aggregation behavior is tested in withdraw_finalize_cp4.test.ts.

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { InMemoryStore } from "@eunoma/shared";
import {
  deriveAmountTag,
  deriveAssetId,
  deriveRecipientHash,
  deriveRequestHash,
  bytesToHex,
  hexToBytes,
  hashConfidentialTransferPayload,
  InMemoryEd25519Signer,
} from "@eunoma/shared";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

const AUTH_TOKEN = "withdraw-cp3-test-token";
const AUTH = { authorization: `Bearer ${AUTH_TOKEN}` };

const RECIPIENT_HEX = "0x" + "a1".repeat(32);
const VAULT_ADDR_HEX = "0x" + "be".repeat(32);
const ASSET_TYPE_HEX = "0x" + "0a".padStart(64, "0");
const CHAIN_ID = 2;
const INITIAL_CHAIN_VAULT_SEQ = 7n;

// Pre-seed OPERATOR_KEYS_JSON_B64 so `loadOperatorKeyForSlot(0)` works in tests.
function seedOperatorKeysEnv(): { mainPubHex: string } {
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
  return { mainPubHex: keys[0].public_key };
}

function caBytesArr(n: number, fill: number): Uint8Array[] {
  return Array.from({ length: n }, () => new Uint8Array(32).fill(fill));
}

// Deterministic CA payload builder. The "decrypted delta" equals the supplied
// amountOctas iff `deltaOverride` is unset, which is what happy-path tests need.
// The delta-mismatch test sets `deltaOverride` to force the route's
// `ca_payload_amount_mismatch` branch.
function makeFakeCAPayload(opts: { deltaOverride?: bigint } = {}) {
  return async (input: {
    vaultAddrHex: string;
    recipientAddrHex: string;
    amountOctas: bigint;
    assetTypeHex: string;
    chainId: number;
    userAuditPksHex?: string[];
  }) => {
    const before = 10_000_000n;
    const delta = opts.deltaOverride ?? input.amountOctas;
    const after = before - delta;
    // Make tiny deterministic payload arrays so re-hash at finalize time
    // matches byte-for-byte. Real builder produces 32-byte chunks; we mimic.
    const newBalanceP = caBytesArr(2, 0x11);
    const newBalanceR = caBytesArr(2, 0x12);
    const newBalanceREffAud = caBytesArr(2, 0x13);
    const amountP = caBytesArr(2, 0x21);
    const amountRSender = caBytesArr(2, 0x22);
    const amountRRecip = caBytesArr(2, 0x23);
    const amountREffAud = caBytesArr(2, 0x24);
    const ekVolunAuds: Uint8Array[] = [];
    const amountRVolunAuds: Uint8Array[][] = [];
    const zkrpNewBalance = new Uint8Array(64).fill(0x31);
    const zkrpAmount = new Uint8Array(64).fill(0x32);
    const sigmaProtoComm = caBytesArr(3, 0x41);
    const sigmaProtoResp = caBytesArr(3, 0x42);
    const memo = new Uint8Array(8).fill(0x51);

    // Compute the canonical CA payload hash so finalize can re-hash and match.
    const hashInput = {
      asset_type: AccountAddress.from(input.assetTypeHex).toUint8Array(),
      // Route passes vault_addr=recipient (legacy quirk preserved in handler).
      vault_addr: AccountAddress.from(input.recipientAddrHex).toUint8Array(),
      new_balance_p: newBalanceP,
      new_balance_r: newBalanceR,
      new_balance_r_eff_aud: newBalanceREffAud,
      amount_p: amountP,
      amount_r_sender: amountRSender,
      amount_r_recip: amountRRecip,
      amount_r_eff_aud: amountREffAud,
      ek_volun_auds: ekVolunAuds,
      amount_r_volun_auds: amountRVolunAuds,
      zkrp_new_balance: zkrpNewBalance,
      zkrp_amount: zkrpAmount,
      sigma_proto_comm: sigmaProtoComm,
      sigma_proto_resp: sigmaProtoResp,
      memo,
    };
    const caPayloadHashRaw = hashConfidentialTransferPayload(hashInput);
    const caPayloadHashFrSafe = new Uint8Array(32);
    caPayloadHashFrSafe.set(caPayloadHashRaw.slice(0, 31), 0);
    caPayloadHashFrSafe[31] = 0;

    return {
      newBalanceP,
      newBalanceR,
      newBalanceREffAud,
      amountP,
      amountRSender,
      amountRRecip,
      amountREffAud,
      ekVolunAuds,
      amountRVolunAuds,
      zkrpNewBalance,
      zkrpAmount,
      sigmaProtoComm,
      sigmaProtoResp,
      memo,
      caPayloadHashRaw,
      caPayloadHashFrSafe,
      vaultAvailableOctasBefore: before,
      vaultAvailableOctasAfterDecrypted: after,
    };
  };
}

interface FinalizePayload {
  request_id: string;
  public_inputs: {
    root: string; nullifier_hash: string; asset_id: string;
    recipient_hash: string; amount_tag: string; ca_payload_hash: string;
    request_hash: string; vault_sequence: string;
  };
  proof: string;
  ca_payload: any;
  recipient: string;
}

async function computeHappyPathFinalizeBody(args: {
  request_id: string;
  ca_payload: any;
  recipient_hash_hex: string;
  amount: bigint;
  withdraw_blind_hex: string;
  vault_sequence: bigint;
  chain_id: number;
  asset_type_hex: string;
}): Promise<FinalizePayload & {
  amountTagBytes: Uint8Array;
  requestHashBytes: Uint8Array;
  caPayloadHashFrSafe: Uint8Array;
  assetIdLe32Bytes: Uint8Array;
  recipientHashBytes: Uint8Array;
}> {
  const assetType = AccountAddress.from(args.asset_type_hex).toUint8Array();
  const assetIdLe32 = await deriveAssetId(assetType);
  const recipientHash = hexToBytes(args.recipient_hash_hex);
  const withdrawBlind = hexToBytes(args.withdraw_blind_hex);
  const caPayloadHashFrSafe = hexToBytes(args.ca_payload.ca_payload_hash);

  const amountTag = await deriveAmountTag({
    amount: args.amount,
    withdraw_blind: withdrawBlind,
    recipient_hash: recipientHash,
    asset_id_le32: assetIdLe32,
    chain_id: args.chain_id,
    vault_sequence: args.vault_sequence,
  });
  const requestHash = await deriveRequestHash({
    amount_tag: amountTag,
    recipient_hash: recipientHash,
    ca_payload_hash: caPayloadHashFrSafe,
    asset_id_le32: assetIdLe32,
    vault_sequence: args.vault_sequence,
    chain_id: args.chain_id,
  });

  // Synthetic 256B proof — verifier is mocked.
  const proof = "0x" + "00".repeat(256);
  const root = new Uint8Array(32).fill(0xaa);
  root[31] = 0;
  const nullifierHash = new Uint8Array(32).fill(0xbb);
  nullifierHash[31] = 0;

  return {
    request_id: args.request_id,
    public_inputs: {
      root: "0x" + bytesToHex(root),
      nullifier_hash: "0x" + bytesToHex(nullifierHash),
      asset_id: "0x" + bytesToHex(assetIdLe32),
      recipient_hash: args.recipient_hash_hex,
      amount_tag: "0x" + bytesToHex(amountTag),
      ca_payload_hash: args.ca_payload.ca_payload_hash,
      request_hash: "0x" + bytesToHex(requestHash),
      vault_sequence: args.vault_sequence.toString(),
    },
    proof,
    ca_payload: args.ca_payload,
    recipient: RECIPIENT_HEX,
    amountTagBytes: amountTag,
    requestHashBytes: requestHash,
    caPayloadHashFrSafe,
    assetIdLe32Bytes: assetIdLe32,
    recipientHashBytes: recipientHash,
  };
}

interface BuildOpts {
  chainVaultSeq?: bigint;
  buildCAPayloadOverride?: ReturnType<typeof makeFakeCAPayload>;
  verifyProofReturns?: boolean;
  nowOverride?: bigint;
}

function buildTestServer(opts: BuildOpts = {}) {
  const mainSigner = new InMemoryEd25519Signer();
  const partnerPubkeys = Array.from({ length: 7 }, () =>
    new InMemoryEd25519Signer().publicKey(),
  );
  partnerPubkeys[0] = mainSigner.publicKey();

  const cfg = defaultMainConfig({
    signer: mainSigner,
    partner_urls: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${100 + i}`),
    partner_pubkeys: partnerPubkeys,
    bearer_token: AUTH_TOKEN,
  });
  // CP4: cfg owns vault_addr/asset_type/chain_id (no more vaultStateDefaults hook).
  cfg.vault_addr = AccountAddress.from(VAULT_ADDR_HEX).toUint8Array();
  cfg.asset_type = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
  cfg.chain_id = CHAIN_ID;

  const store = new InMemoryStore();
  const verifyReturns = opts.verifyProofReturns ?? true;

  const { server } = buildMainServer({
    cfg,
    store,
    withdrawRouteHooks: {
      buildCAPayload: opts.buildCAPayloadOverride ?? makeFakeCAPayload(),
      readChainVaultState: async () => ({
        operatorSetVersion: 1n,
        threshold: 4n,
        vaultAddrHex: VAULT_ADDR_HEX,
        vaultSequence: opts.chainVaultSeq ?? INITIAL_CHAIN_VAULT_SEQ,
      }),
      verifyProof: async () => verifyReturns,
      // CP3 tests cover only pre-fanout error paths; provide an empty fanout
      // so the route doesn't try to reach `http://127.0.0.1:100..105`. The
      // success path (4-of-7) is exercised in withdraw_finalize_cp4.test.ts.
      fanOutWithdrawCoSign: async () => [],
      nowSecs: opts.nowOverride !== undefined ? () => opts.nowOverride! : undefined,
    },
  });
  return { server, store };
}

async function callPrepare(
  server: ReturnType<typeof buildTestServer>["server"],
  amount: bigint,
): Promise<any> {
  const res = await server.inject({
    method: "POST",
    url: "/v1/withdraw/prepare",
    headers: AUTH,
    payload: {
      amount: amount.toString(),
      recipient: RECIPIENT_HEX,
      asset_id: ASSET_TYPE_HEX,
    },
  });
  return { res, body: res.json() };
}

async function callFinalize(
  server: ReturnType<typeof buildTestServer>["server"],
  payload: any,
): Promise<{ res: Awaited<ReturnType<typeof server.inject>>; body: any }> {
  const res = await server.inject({
    method: "POST",
    url: "/v1/withdraw/finalize",
    headers: AUTH,
    payload,
  });
  return { res, body: res.json() };
}

beforeAll(() => {
  seedOperatorKeysEnv();
});

describe("CP3 /v1/withdraw — amount binding + status policy", () => {
  // ---- case a ----
  it("case a: prepare amount delta mismatch → 502 ca_payload_amount_mismatch", async () => {
    const { server } = buildTestServer({
      buildCAPayloadOverride: makeFakeCAPayload({ deltaOverride: 999_999n }), // != amount
    });
    const { res, body } = await callPrepare(server, 1_000_000n);
    expect(res.statusCode).toBe(502);
    expect(body.error).toBe("ca_payload_amount_mismatch");
  });

  // ---- case b ----
  it("case b: tampered amount_tag → 400 public_input_mismatch(amount_tag) + row=FAILED", async () => {
    const { server, store } = buildTestServer();
    const { body: prep } = await callPrepare(server, 1_000_000n);
    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const tampered = { ...happy.public_inputs, amount_tag: "0x" + "ff".repeat(32) };
    const { res, body } = await callFinalize(server, {
      ...happy,
      public_inputs: tampered,
    });
    expect(res.statusCode).toBe(400);
    expect(body.error).toBe("public_input_mismatch");
    expect(body.field).toBe("amount_tag");
    const row = await store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("FAILED");
    expect(body).not.toHaveProperty("main_operator_signature");
  });

  // ---- case c ----
  it("case c: tampered request_hash → 400 public_input_mismatch(request_hash) + row=FAILED", async () => {
    const { server, store } = buildTestServer();
    const { body: prep } = await callPrepare(server, 1_000_000n);
    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const tampered = { ...happy.public_inputs, request_hash: "0x" + "ee".repeat(32) };
    const { res, body } = await callFinalize(server, {
      ...happy,
      public_inputs: tampered,
    });
    expect(res.statusCode).toBe(400);
    expect(body.error).toBe("public_input_mismatch");
    expect(body.field).toBe("request_hash");
    const row = await store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("FAILED");
  });

  // ---- case d ----
  it("case d: tampered ca_payload → 400 ca_payload_hash_mismatch + row=FAILED", async () => {
    const { server, store } = buildTestServer();
    const { body: prep } = await callPrepare(server, 1_000_000n);
    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    // Mutate one byte of CA payload memo so re-hash mismatches the stored hash.
    const tamperedCA = { ...happy.ca_payload, memo: "0x" + "ff".repeat(8) };
    const { res, body } = await callFinalize(server, {
      ...happy,
      ca_payload: tamperedCA,
    });
    expect(res.statusCode).toBe(400);
    expect(body.error).toBe("ca_payload_hash_mismatch");
    const row = await store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("FAILED");
  });

  // ---- case e ----
  it("case e: invalid proof → 400 groth16_proof_invalid + row=FAILED", async () => {
    const { server, store } = buildTestServer({ verifyProofReturns: false });
    const { body: prep } = await callPrepare(server, 1_000_000n);
    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const { res, body } = await callFinalize(server, happy);
    expect(res.statusCode).toBe(400);
    expect(body.error).toBe("groth16_proof_invalid");
    const row = await store.getWithdrawRequest(prep.request_id);
    expect(row?.status).toBe("FAILED");
    expect(body).not.toHaveProperty("main_operator_signature");
  });

  // ---- case f ----
  it("case f: expired request → 410 expired + row=EXPIRED", async () => {
    // Prepare at t=1000, finalize at t=2000 (well past expiry default 600s).
    const t0 = 1000n;
    const tLate = 2000n;
    const { server, store } = buildTestServer({ nowOverride: t0 });
    const { body: prep } = await callPrepare(server, 1_000_000n);
    expect(BigInt(prep.expiry_secs)).toBe(t0 + 600n);

    // Rebuild server with later clock so finalize sees expiry elapsed.
    const { server: server2 } = buildTestServer({ nowOverride: tLate });
    // But server2 has its own InMemoryStore — we need the same row.
    // Easier: rebuild with same store reference via direct call.

    // Inject expiry by directly mutating row via store passed to our server.
    // Cleaner: build a second server that shares the same store.
    // Approach: don't rebuild — use single server but override `nowSecs` via
    // a closure that flips before finalize. The cleanest path is one server
    // configured with a mutable now.
    let nowVal = t0;
    const { server: dynServer, store: dynStore } = (() => {
      const mainSigner = new InMemoryEd25519Signer();
      const partnerPubkeys = Array.from({ length: 7 }, () => new InMemoryEd25519Signer().publicKey());
      partnerPubkeys[0] = mainSigner.publicKey();
      const cfg = defaultMainConfig({
        signer: mainSigner,
        partner_urls: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${200 + i}`),
        partner_pubkeys: partnerPubkeys,
        bearer_token: AUTH_TOKEN,
      });
      cfg.vault_addr = AccountAddress.from(VAULT_ADDR_HEX).toUint8Array();
      cfg.asset_type = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
      cfg.chain_id = CHAIN_ID;
      const s = new InMemoryStore();
      const built = buildMainServer({
        cfg,
        store: s,
        withdrawRouteHooks: {
          buildCAPayload: makeFakeCAPayload(),
          readChainVaultState: async () => ({
            operatorSetVersion: 1n,
            threshold: 4n,
            vaultAddrHex: VAULT_ADDR_HEX,
            vaultSequence: INITIAL_CHAIN_VAULT_SEQ,
          }),
          verifyProof: async () => true,
          fanOutWithdrawCoSign: async () => [],
          nowSecs: () => nowVal,
        },
      });
      return { server: built.server, store: s };
    })();

    const prepResp = await dynServer.inject({
      method: "POST",
      url: "/v1/withdraw/prepare",
      headers: AUTH,
      payload: { amount: "1000000", recipient: RECIPIENT_HEX, asset_id: ASSET_TYPE_HEX },
    });
    const prepBody = prepResp.json();
    expect(prepResp.statusCode).toBe(200);

    nowVal = tLate;

    const happy = await computeHappyPathFinalizeBody({
      request_id: prepBody.request_id,
      ca_payload: { ...prepBody.ca_payload, ca_payload_hash: prepBody.ca_payload_hash },
      recipient_hash_hex: prepBody.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prepBody.withdraw_blind,
      vault_sequence: BigInt(prepBody.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const finRes = await dynServer.inject({
      method: "POST",
      url: "/v1/withdraw/finalize",
      headers: AUTH,
      payload: happy,
    });
    expect(finRes.statusCode).toBe(410);
    expect(finRes.json().error).toBe("expired");
    const row = await dynStore.getWithdrawRequest(prepBody.request_id);
    expect(row?.status).toBe("EXPIRED");
  });

  // ---- case g ----
  it("case g: double finalize → 409 invalid_state", async () => {
    // Simulate post-cosign FINALIZED row directly (cosign aggregation lives
    // in withdraw_finalize_cp4.test.ts). Any non-PREPARED state must yield
    // 409 invalid_state on a finalize attempt.
    const { server, store } = buildTestServer();
    const { body: prep } = await callPrepare(server, 1_000_000n);
    await store.updateWithdrawRequestStatus(prep.request_id, "FINALIZED", new Date());

    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const second = await callFinalize(server, happy);
    expect(second.res.statusCode).toBe(409);
    expect(second.body.error).toBe("invalid_state");
  });

  // ---- case h ----
  it("case h: chain sequence mismatch → 409 vault_sequence_changed + row=EXPIRED + no signature", async () => {
    // Prepare with chain_seq=7. Then for finalize, chain returns a different value.
    // Pattern: same approach as case f — single server, mutable readChainVaultState.
    let chainSeq = INITIAL_CHAIN_VAULT_SEQ; // 7
    const mainSigner = new InMemoryEd25519Signer();
    const partnerPubkeys = Array.from({ length: 7 }, () => new InMemoryEd25519Signer().publicKey());
    partnerPubkeys[0] = mainSigner.publicKey();
    const cfg = defaultMainConfig({
      signer: mainSigner,
      partner_urls: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${300 + i}`),
      partner_pubkeys: partnerPubkeys,
      bearer_token: AUTH_TOKEN,
    });
    cfg.vault_addr = AccountAddress.from(VAULT_ADDR_HEX).toUint8Array();
    cfg.asset_type = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
    cfg.chain_id = CHAIN_ID;
    const store = new InMemoryStore();
    const { server } = buildMainServer({
      cfg,
      store,
      withdrawRouteHooks: {
        buildCAPayload: makeFakeCAPayload(),
        readChainVaultState: async () => ({
          operatorSetVersion: 1n,
          threshold: 4n,
          vaultAddrHex: VAULT_ADDR_HEX,
          vaultSequence: chainSeq,
        }),
        verifyProof: async () => true,
        fanOutWithdrawCoSign: async () => [],
      },
    });

    const { body: prep } = await callPrepare(server, 1_000_000n);
    expect(BigInt(prep.vault_sequence)).toBe(INITIAL_CHAIN_VAULT_SEQ);

    chainSeq = 99n; // chain advanced after prepare
    const happy = await computeHappyPathFinalizeBody({
      request_id: prep.request_id,
      ca_payload: { ...prep.ca_payload, ca_payload_hash: prep.ca_payload_hash },
      recipient_hash_hex: prep.recipient_hash,
      amount: 1_000_000n,
      withdraw_blind_hex: prep.withdraw_blind,
      vault_sequence: BigInt(prep.vault_sequence),
      chain_id: CHAIN_ID,
      asset_type_hex: ASSET_TYPE_HEX,
    });
    const { res, body } = await callFinalize(server, happy);
    expect(res.statusCode).toBe(409);
    expect(body.error).toBe("vault_sequence_changed");
    expect(body.row_vault_sequence).toBe(INITIAL_CHAIN_VAULT_SEQ.toString());
    expect(body.chain_vault_sequence).toBe("99");
    expect(body).not.toHaveProperty("main_operator_signature");
    const row = await store.getWithdrawRequest(prep.request_id);
    // CP3 status policy choice B: chain drift → EXPIRED (see CP3 report).
    expect(row?.status).toBe("EXPIRED");
  });

  // CP4 removed the CP3↔CP4 transitional path. Full cosign aggregation + the
  // signature-absence whitelist for insufficient cosigns live in
  // withdraw_finalize_cp4.test.ts.

  // ---- CP3.5: prepare default response must NOT leak operator-side
  // decrypted vault balance via a `diagnostics` block.
  it("CP3.5: default prepare response omits `diagnostics`", async () => {
    const { server } = buildTestServer(); // exposeWithdrawDiagnosticsForTests not set
    const { res, body } = await callPrepare(server, 1_000_000n);
    expect(res.statusCode).toBe(200);
    expect(body.diagnostics).toBeUndefined();
  });

  it("CP3.5: prepare returns `diagnostics` only when explicitly enabled", async () => {
    // Inject the flag via a custom hooks object since buildTestServer doesn't
    // surface it; mirror the helper inline.
    const mainSigner = new InMemoryEd25519Signer();
    const partnerPubkeys = Array.from({ length: 7 }, () =>
      new InMemoryEd25519Signer().publicKey(),
    );
    partnerPubkeys[0] = mainSigner.publicKey();
    const cfg = defaultMainConfig({
      signer: mainSigner,
      partner_urls: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${200 + i}`),
      partner_pubkeys: partnerPubkeys,
      bearer_token: AUTH_TOKEN,
    });
    cfg.vault_addr = AccountAddress.from(VAULT_ADDR_HEX).toUint8Array();
    cfg.asset_type = AccountAddress.from(ASSET_TYPE_HEX).toUint8Array();
    cfg.chain_id = CHAIN_ID;
    const { server } = buildMainServer({
      cfg,
      store: new InMemoryStore(),
      withdrawRouteHooks: {
        buildCAPayload: makeFakeCAPayload(),
        readChainVaultState: async () => ({
          operatorSetVersion: 1n,
          threshold: 4n,
          vaultAddrHex: VAULT_ADDR_HEX,
          vaultSequence: INITIAL_CHAIN_VAULT_SEQ,
        }),
        verifyProof: async () => true,
        exposeWithdrawDiagnosticsForTests: true,
        fanOutWithdrawCoSign: async () => [],
      },
    });
    const { res, body } = await callPrepare(server, 1_000_000n);
    expect(res.statusCode).toBe(200);
    expect(body.diagnostics).toBeDefined();
    expect(body.diagnostics.vault_available_octas_before).toBeTypeOf("string");
    expect(body.diagnostics.vault_available_octas_after_expected).toBeTypeOf("string");
  });
});
