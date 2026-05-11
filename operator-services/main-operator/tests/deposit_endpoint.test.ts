// Main operator deposit endpoint integration test (Pass criterion #8).
//
// Spins up 6 real partner-operator Fastify servers on ephemeral ports + 1
// main-operator instance. POSTs a valid deposit-attestation request; asserts:
//   - 200 OK
//   - 7-slot signature vector with 4+ non-empty slots including main slot
//   - DB persistence: deposit_request row + 4+ attestation_signature rows.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  hexToBytes,
  bytesToHex,
  GATE_4A_FIXTURE,
  InMemoryEd25519Signer,
  InMemoryStore,
  recomputeAmountTag,
  verifyEd25519,
} from "@eunoma/shared";
import { buildPartnerServer } from "@eunoma/partner-operator/src/server.js";
import { defaultTestConfig as defaultPartnerConfig } from "@eunoma/partner-operator/src/config.js";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";
import { DepositRequestBodyMain } from "../src/verify/deposit_request.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AddressInfo } from "node:net";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = resolve(__dirname, "../../../circuits/generated");

function loadJson(p: string): any {
  return JSON.parse(readFileSync(resolve(CIRCUITS_DIR, p), "utf-8"));
}

describe("main-operator POST /v1/deposit/request-attestation", () => {
  const main_signer = new InMemoryEd25519Signer();
  // 7 partner signers (slots 0..6); main op uses slot 0.
  const partner_signers: InMemoryEd25519Signer[] = [];
  for (let i = 0; i < 7; i++) partner_signers.push(new InMemoryEd25519Signer());

  // The main-op signer for slot 0 is `main_signer`. Override slot 0's
  // partner_signers entry with `main_signer` so partner-pubkey lookup picks
  // up the same identity.
  partner_signers[0] = main_signer;

  const partner_pubkeys = partner_signers.map((s) => s.publicKey());

  // Spin up 6 partner servers (slots 1..6).
  const partnerServers: ReturnType<typeof buildPartnerServer>[] = [];
  const partnerUrls: string[] = [];

  // Common vault/asset config for all partners.
  const VAULT = new Uint8Array(32).fill(0x11);
  const ASSET = new Uint8Array(32).fill(0x22);

  beforeAll(async () => {
    for (let slot = 1; slot < 7; slot++) {
      const cfg = defaultPartnerConfig({
        slot,
        signer: partner_signers[slot],
        main_op_pubkey: main_signer.publicKey(),
        port: 0,
      });
      cfg.vault_addr = VAULT;
      cfg.asset_type = ASSET;
      const server = buildPartnerServer(cfg);
      await server.listen({ port: 0, host: "127.0.0.1" });
      const addr = server.server.address() as AddressInfo;
      partnerServers.push(server);
      partnerUrls.push(`http://127.0.0.1:${addr.port}`);
    }
  });

  afterAll(async () => {
    for (const s of partnerServers) {
      await s.close();
    }
  });

  it("main_deposit_request_attestation_returns_4_of_7_signatures", async () => {
    const main_cfg = defaultMainConfig({
      signer: main_signer,
      partner_urls: partnerUrls,
      partner_pubkeys,
    });
    main_cfg.vault_addr = VAULT;
    main_cfg.asset_type = ASSET;

    const store = new InMemoryStore();
    const { server: mainServer } = buildMainServer({ cfg: main_cfg, store });

    // Build a valid deposit request body using Gate 4a's fixture.
    const priv = JSON.parse(
      readFileSync(resolve(CIRCUITS_DIR, "../inputs/valid_input.json"), "utf-8"),
    );
    function decimalToLe32(dec: string): Uint8Array {
      const n = BigInt(dec);
      const out = new Uint8Array(32);
      let v = n;
      for (let i = 0; i < 32; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
      }
      return out;
    }
    const blind = decimalToLe32(priv.deposit_blind);
    const amount = BigInt(priv.amount);
    // Phase F W3: chain_id is no longer in valid_input.json (it's a circuit
    // compile-time constant now). For the off-circuit amount_tag recomputation
    // we still need the value — hardcoded to 2 (testnet, matching the circuit's
    // baked CHAIN_ID).
    const chainId = priv.chain_id !== undefined ? Number(priv.chain_id) : 2;

    const recomputed = await recomputeAmountTag({
      amount,
      deposit_blind_le32: blind,
      asset_id_le32: hexToBytes(GATE_4A_FIXTURE.asset_id_le32),
      vault_addr_hash_le32: hexToBytes(GATE_4A_FIXTURE.vault_addr_hash_le32),
      chain_id: chainId,
    });

    const proofValid = loadJson("proof_valid.json");
    const publicValid = loadJson("public_valid.json") as string[];

    const body: DepositRequestBodyMain = {
      user_addr: "0xuser",
      amount: amount.toString(),
      deposit_blind: bytesToHex(blind),
      commitment: GATE_4A_FIXTURE.commitment_le32,
      amount_tag: bytesToHex(recomputed),
      deposit_nonce: "deadbeef00000001",
      expiry_secs: (Math.floor(Date.now() / 1000) + 3600).toString(),
      deposit_binding_proof_snark: proofValid,
      public_inputs: publicValid,
      ca_payload: {
        asset_type: bytesToHex(ASSET),
        vault_addr: bytesToHex(VAULT),
        new_balance_p: [],
        new_balance_r: [],
        new_balance_r_eff_aud: [],
        amount_p: [],
        amount_r_sender: [],
        amount_r_recip: [],
        amount_r_eff_aud: [],
        ek_volun_auds: [],
        amount_r_volun_auds: [],
        zkrp_new_balance: "",
        zkrp_amount: "",
        sigma_proto_comm: [],
        sigma_proto_resp: [],
        memo: "",
      },
      test_override_asset_id: GATE_4A_FIXTURE.asset_id_le32,
      test_override_vault_addr_hash: GATE_4A_FIXTURE.vault_addr_hash_le32,
    };

    const res = await mainServer.inject({
      method: "POST",
      url: "/v1/deposit/request-attestation",
      headers: { authorization: `Bearer ${main_cfg.bearer_token}` },
      payload: body,
    });
    if (res.statusCode !== 200) {
      throw new Error(`Expected 200, got ${res.statusCode}: ${res.body}`);
    }
    const j = res.json();
    expect(j.signatures).toHaveLength(7);
    const non_empty = j.signatures.filter(
      (s: { signature_hex: string | null }) => s.signature_hex !== null,
    );
    expect(non_empty.length).toBeGreaterThanOrEqual(4);
    // Main slot (0) must be present.
    expect(j.signatures[0].signature_hex).not.toBeNull();
    expect(j.threshold_met).toBe(true);

    // Verify each non-empty signature against its slot's pubkey.
    const msg_bytes = hexToBytes(j.message_bytes_hex);
    for (const s of j.signatures) {
      if (s.signature_hex) {
        const ok = verifyEd25519(
          hexToBytes(s.signature_hex),
          partner_pubkeys[s.slot],
          msg_bytes,
        );
        expect(ok).toBe(true);
      }
    }

    // DB persistence: 1 deposit_request row.
    const allDeposits = (store as InMemoryStore)._allDeposits();
    expect(allDeposits).toHaveLength(1);
    expect(allDeposits[0].status).toBe("complete");

    // 7 attestation signature rows (1 main + 6 partners; all valid).
    const allSigs = (store as InMemoryStore)._allSignatures();
    expect(allSigs.length).toBeGreaterThanOrEqual(4);
    expect(allSigs.some((r) => r.operator_slot === 0)).toBe(true);

    await mainServer.close();
  });

  it("main_deposit_request_rejects_wrong_amount_tag", async () => {
    const main_cfg = defaultMainConfig({
      signer: main_signer,
      partner_urls: partnerUrls,
      partner_pubkeys,
    });
    main_cfg.vault_addr = VAULT;
    main_cfg.asset_type = ASSET;
    const store = new InMemoryStore();
    const { server: mainServer } = buildMainServer({ cfg: main_cfg, store });

    const proofValid = loadJson("proof_valid.json");
    const publicValid = loadJson("public_valid.json");

    const body: DepositRequestBodyMain = {
      user_addr: "0xuser2",
      amount: "1000000000",
      deposit_blind:
        "0000000000000000000000000000000000000000000000000000000000000001",
      commitment: GATE_4A_FIXTURE.commitment_le32,
      amount_tag:
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      deposit_nonce: "deadbeef00000002",
      expiry_secs: (Math.floor(Date.now() / 1000) + 3600).toString(),
      deposit_binding_proof_snark: proofValid,
      public_inputs: publicValid,
      ca_payload: {
        asset_type: bytesToHex(ASSET),
        vault_addr: bytesToHex(VAULT),
        new_balance_p: [],
        new_balance_r: [],
        new_balance_r_eff_aud: [],
        amount_p: [],
        amount_r_sender: [],
        amount_r_recip: [],
        amount_r_eff_aud: [],
        ek_volun_auds: [],
        amount_r_volun_auds: [],
        zkrp_new_balance: "",
        zkrp_amount: "",
        sigma_proto_comm: [],
        sigma_proto_resp: [],
        memo: "",
      },
      test_override_asset_id: GATE_4A_FIXTURE.asset_id_le32,
      test_override_vault_addr_hash: GATE_4A_FIXTURE.vault_addr_hash_le32,
    };

    const res = await mainServer.inject({
      method: "POST",
      url: "/v1/deposit/request-attestation",
      headers: { authorization: `Bearer ${main_cfg.bearer_token}` },
      payload: body,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().reason).toBe("amount_tag_mismatch");

    await mainServer.close();
  });

  it("main_health_endpoint_responds", async () => {
    const main_cfg = defaultMainConfig({
      signer: main_signer,
      partner_urls: partnerUrls,
      partner_pubkeys,
    });
    const { server } = buildMainServer({ cfg: main_cfg });
    const res = await server.inject({ method: "GET", url: "/v1/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json().ok).toBe(true);
    await server.close();
  });

  it("main_operator_set_endpoint_responds", async () => {
    const main_cfg = defaultMainConfig({
      signer: main_signer,
      partner_urls: partnerUrls,
      partner_pubkeys,
    });
    const { server } = buildMainServer({ cfg: main_cfg });
    const res = await server.inject({
      method: "GET",
      url: "/v1/operator-set",
      headers: { authorization: `Bearer ${main_cfg.bearer_token}` },
    });
    expect(res.statusCode).toBe(200);
    const j = res.json();
    expect(j.pubkeys_hex).toHaveLength(7);
    expect(j.threshold).toBe("4");
    expect(j.main_index).toBe(0);
    await server.close();
  });
});
