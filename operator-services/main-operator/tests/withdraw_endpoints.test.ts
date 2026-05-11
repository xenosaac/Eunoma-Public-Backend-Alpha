// Phase 4 W6.5 — /v1/withdraw/prepare + /v1/withdraw/finalize validation tests.
//
// Validation paths (400-class) run unconditionally. Success path hits live
// testnet + needs OPERATOR_KEYS_JSON_B64 + VAULT_DECRYPTION_KEY_HEX so is
// NETWORK_E2E-gated.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { InMemoryEd25519Signer } from "@eunoma/shared";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

const NETWORK_E2E = !!process.env.NETWORK_E2E;

describe("main-operator W6.5 /v1/withdraw/* validation", () => {
  const main_signer = new InMemoryEd25519Signer();
  const partner_pubkeys = Array.from({ length: 7 }, () =>
    new InMemoryEd25519Signer().publicKey(),
  );
  partner_pubkeys[0] = main_signer.publicKey();

  const cfg = defaultMainConfig({
    signer: main_signer,
    partner_urls: ["http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3", "http://127.0.0.1:4", "http://127.0.0.1:5", "http://127.0.0.1:6"],
    partner_pubkeys,
    bearer_token: "withdraw-test-token",
  });

  let server: ReturnType<typeof buildMainServer>["server"];
  const AUTH = { authorization: `Bearer ${cfg.bearer_token}` };

  beforeAll(async () => {
    server = buildMainServer({ cfg }).server;
  });

  afterAll(async () => {
    await server.close();
  });

  describe("/v1/withdraw/prepare", () => {
    it("missing auth → 401", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        payload: { amount: "1000", recipient: "0x" + "a".repeat(64), asset_id: "0xa" },
      });
      expect(res.statusCode).toBe(401);
    });

    it("missing body → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("missing_body");
    });

    it("invalid amount → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: { amount: "not-a-number", recipient: "0x" + "a".repeat(64), asset_id: "0xa" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_amount");
    });

    it("invalid recipient → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: { amount: "1000", recipient: "not-hex", asset_id: "0xa" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_recipient");
    });

    it("invalid asset_id → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: { amount: "1000", recipient: "0x" + "a".repeat(64), asset_id: "not-hex" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_asset_id");
    });

    // W6.6 — selective disclosure (self-audit) input validation
    it("user_audit_pks not an array → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: {
          amount: "1000",
          recipient: "0x" + "a".repeat(64),
          asset_id: "0xa",
          user_audit_pks: "not-an-array",
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_user_audit_pks");
    });

    it("user_audit_pks entry wrong length → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: {
          amount: "1000",
          recipient: "0x" + "a".repeat(64),
          asset_id: "0xa",
          user_audit_pks: ["0xdeadbeef"], // too short
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_user_audit_pk_format");
    });

    it("user_audit_pks entry not hex → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: {
          amount: "1000",
          recipient: "0x" + "a".repeat(64),
          asset_id: "0xa",
          user_audit_pks: ["0x" + "z".repeat(64)],
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_user_audit_pk_format");
    });

    it("empty user_audit_pks array → passes validation (falls through to backend)", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/prepare",
        headers: AUTH,
        payload: {
          amount: "1000",
          recipient: "0x" + "a".repeat(64),
          asset_id: "0xa",
          user_audit_pks: [],
        },
      });
      // Not 400 from our validation; will be 503/502 (no testnet_state.json
      // in test env) or 200 (with NETWORK_E2E). Just assert NOT a validation
      // error.
      expect([200, 502, 503]).toContain(res.statusCode);
    });
  });

  describe("/v1/withdraw/finalize", () => {
    it("missing auth → 401", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/finalize",
        payload: {},
      });
      expect(res.statusCode).toBe(401);
    });

    it("missing body → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/finalize",
        headers: AUTH,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("missing_body");
    });

    it("missing public_inputs → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/finalize",
        headers: AUTH,
        payload: {},
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_public_inputs");
    });

    it("malformed proof → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/finalize",
        headers: AUTH,
        payload: {
          public_inputs: { nullifier_hash: "0x", recipient_hash: "0x", amount_tag: "0x", request_hash: "0x", expiry_secs: "0", vault_sequence: "0" },
          proof: "not-hex",
          ca_payload: {},
          recipient: "0x" + "a".repeat(64),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_proof");
    });

    it("wrong proof length → 400", async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/withdraw/finalize",
        headers: AUTH,
        payload: {
          public_inputs: { nullifier_hash: "0x", recipient_hash: "0x", amount_tag: "0x", request_hash: "0x", expiry_secs: "0", vault_sequence: "0" },
          proof: "0x" + "ab".repeat(100), // 100 bytes, want 256
          ca_payload: {},
          recipient: "0x" + "a".repeat(64),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_proof_length");
    });
  });

  // NETWORK_E2E-gated full prepare round-trip
  it.skipIf(!NETWORK_E2E)("prepare against live testnet returns CA payload", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/withdraw/prepare",
      headers: AUTH,
      payload: {
        amount: "1000000",
        recipient: "0xa2f32e7b3dca7710b6dc3e45ad3bff5a74a76e226212d729ed4c68336cb4c334",
        asset_id: "0xa",
      },
    });
    if (res.statusCode !== 200) {
      throw new Error(`expected 200, got ${res.statusCode}: ${res.body}`);
    }
    const j = res.json();
    expect(j.ca_payload).toBeDefined();
    expect(j.ca_payload_hash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(typeof j.vault_sequence).toBe("number");
  });
});
