// Phase 4 W5 — POST /v1/recipient/rollover endpoint test.
//
// The endpoint builds (does not sign / submit) a rollover SimpleTransaction.
// Build path hits the live testnet to fetch sender sequence + chain id, so
// the "success" test requires NETWORK_E2E=1 to keep CI fast and offline.
// The 400-class validation tests run unconditionally.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { InMemoryEd25519Signer } from "@eunoma/shared";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

const NETWORK_E2E = !!process.env.NETWORK_E2E;

describe("main-operator POST /v1/recipient/rollover", () => {
  const main_signer = new InMemoryEd25519Signer();
  const partner_pubkeys = Array.from({ length: 7 }, () =>
    new InMemoryEd25519Signer().publicKey(),
  );
  partner_pubkeys[0] = main_signer.publicKey();

  const cfg = defaultMainConfig({
    signer: main_signer,
    partner_urls: ["http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3", "http://127.0.0.1:4", "http://127.0.0.1:5", "http://127.0.0.1:6"],
    partner_pubkeys,
    bearer_token: "rollover-test-token",
  });

  let server: ReturnType<typeof buildMainServer>["server"];

  beforeAll(async () => {
    server = buildMainServer({ cfg }).server;
  });

  afterAll(async () => {
    await server.close();
  });

  const AUTH = { authorization: `Bearer ${cfg.bearer_token}` };

  it("missing body → 400", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/recipient/rollover",
      headers: AUTH,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("missing_body");
  });

  it("missing recipient_addr → 400", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/recipient/rollover",
      headers: AUTH,
      payload: {},
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("invalid_recipient_addr");
  });

  it("garbage recipient_addr → 400", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/recipient/rollover",
      headers: AUTH,
      payload: { recipient_addr: "not-a-hex-address" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("invalid_recipient_addr");
  });

  it("missing auth → 401", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/recipient/rollover",
      payload: { recipient_addr: "0x" + "a".repeat(64) },
    });
    expect(res.statusCode).toBe(401);
  });

  it.skipIf(!NETWORK_E2E)(
    "valid recipient → 200 with unsigned_tx_hex",
    async () => {
      const res = await server.inject({
        method: "POST",
        url: "/v1/recipient/rollover",
        headers: AUTH,
        payload: {
          recipient_addr: "0xa2f32e7b3dca7710b6dc3e45ad3bff5a74a76e226212d729ed4c68336cb4c334",
        },
      });
      if (res.statusCode !== 200) {
        throw new Error(`expected 200, got ${res.statusCode}: ${res.body}`);
      }
      const j = res.json();
      expect(j.unsigned_tx_hex).toMatch(/^[0-9a-f]+$/);
      expect(j.sender.toLowerCase()).toContain("a2f32e7b");
      expect(j.function_id).toBe("0x1::confidential_asset::rollover_pending_balance");
      expect(j.asset_id).toBe("0x000000000000000000000000000000000000000000000000000000000000000a");
    },
  );
});
