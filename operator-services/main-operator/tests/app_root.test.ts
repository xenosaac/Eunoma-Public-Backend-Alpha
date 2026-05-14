import { describe, it, expect } from "vitest";
import { InMemoryEd25519Signer } from "@eunoma/shared";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

function testCfg() {
  const signer = new InMemoryEd25519Signer();
  const partnerPubkeys = Array.from({ length: 7 }, () =>
    new InMemoryEd25519Signer().publicKey(),
  );
  partnerPubkeys[0] = signer.publicKey();
  const cfg = defaultMainConfig({
    signer,
    partner_urls: Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:${5000 + i}`),
    partner_pubkeys: partnerPubkeys,
    bearer_token: "app-root-token",
  });
  cfg.bridge_package_address = "0x" + "ab".repeat(32);
  cfg.vault_ek_hex = "4e2ad0287370d2fc539ad05eab2d0322d9368c3503177fcae497067922459f34";
  cfg.vault_addr = new Uint8Array(32).fill(0x11);
  cfg.asset_type = new Uint8Array(32).fill(0x22);
  return cfg;
}

describe("closed-alpha public config, CORS, and root routes", () => {
  it("GET /v1/app/config is public and contains only browser-safe fields", async () => {
    const cfg = testCfg();
    const { server } = buildMainServer({
      cfg,
      appConfigRouteHooks: {
        readVaultConfig: async () => ({
          operator_set_version: 7n,
          threshold: 4n,
          vault_addr: "0x" + "33".repeat(32),
          asset_type: "0x" + "44".repeat(32),
        }),
      },
    });
    const res = await server.inject({ method: "GET", url: "/v1/app/config" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toEqual({
      network: "testnet",
      chain_id: 2,
      bridge_package: cfg.bridge_package_address,
      vault: "0x" + "33".repeat(32),
      asset_type: "0x" + "44".repeat(32),
      vault_ek_hex: cfg.vault_ek_hex,
      pool_id: "0",
      operator_set_version: "7",
      threshold: "4",
    });
    const joinedKeys = Object.keys(body).join(" ").toLowerCase();
    expect(joinedKeys).not.toContain("token");
    expect(joinedKeys).not.toContain("secret");
    await server.close();
  });

  it("GET /v1/root/current is public", async () => {
    const { server } = buildMainServer({
      cfg: testCfg(),
      rootRouteHooks: {
        readRootCurrent: async () => ({
          current_finalized_root: "0x" + "00".repeat(32),
          root_history_length: "1",
          last_batch_id: "0",
          next_unfinalized_index: "0",
          pending_next_index: "0",
          pending_count: "0",
        }),
      },
    });
    const res = await server.inject({ method: "GET", url: "/v1/root/current" });
    expect(res.statusCode).toBe(200);
    expect(res.json().pending_count).toBe("0");
    await server.close();
  });

  it("CORS preflight succeeds without bearer while protected writes stay protected", async () => {
    const { server } = buildMainServer({ cfg: testCfg() });
    const preflight = await server.inject({
      method: "OPTIONS",
      url: "/v1/withdraw/prepare",
      headers: {
        origin: "https://app.eunoma.xyz",
        "access-control-request-method": "POST",
      },
    });
    expect(preflight.statusCode).toBe(204);
    expect(preflight.headers["access-control-allow-origin"]).toBe("https://app.eunoma.xyz");

    const write = await server.inject({
      method: "POST",
      url: "/v1/withdraw/prepare",
      headers: { origin: "https://app.eunoma.xyz" },
      payload: {},
    });
    expect(write.statusCode).toBe(401);
    expect(write.headers["access-control-allow-origin"]).toBe("https://app.eunoma.xyz");
    await server.close();
  });

  it("POST /v1/root/update is bearer-protected and supports noop/update results", async () => {
    const cfg = testCfg();
    const unauth = buildMainServer({ cfg }).server;
    const blocked = await unauth.inject({
      method: "POST",
      url: "/v1/root/update",
      payload: { max_batch_size: 32 },
    });
    expect(blocked.statusCode).toBe(401);
    await unauth.close();

    const authHeader = { authorization: `Bearer ${cfg.bearer_token}` };
    const noop = buildMainServer({
      cfg,
      rootRouteHooks: {
        updateRootBatch: async () => ({ status: "noop", reason: "no_pending_deposits" }),
      },
    }).server;
    const noopRes = await noop.inject({
      method: "POST",
      url: "/v1/root/update",
      headers: authHeader,
      payload: { max_batch_size: 32 },
    });
    expect(noopRes.statusCode).toBe(200);
    expect(noopRes.json()).toEqual({ status: "noop", reason: "no_pending_deposits" });
    await noop.close();

    const updated = buildMainServer({
      cfg,
      rootRouteHooks: {
        updateRootBatch: async ({ max_batch_size }) => {
          expect(max_batch_size).toBe(16);
          return {
            status: "updated",
            tx: "0x" + "12".repeat(32),
            success: true,
            vm_status: "Executed successfully",
            gas_used: "1417",
            start_index: "0",
            end_index: "1",
            new_root: "0x" + "34".repeat(32),
            rollover_tx: null,
          };
        },
      },
    }).server;
    const updateRes = await updated.inject({
      method: "POST",
      url: "/v1/root/update",
      headers: authHeader,
      payload: { max_batch_size: 16 },
    });
    expect(updateRes.statusCode).toBe(200);
    expect(updateRes.json().tx).toMatch(/^0x[0-9a-f]+$/);
    await updated.close();
  });

  it("malformed browser deposit payloads return 400", async () => {
    const cfg = testCfg();
    const { server } = buildMainServer({ cfg });
    const res = await server.inject({
      method: "POST",
      url: "/v1/deposit/request-attestation",
      headers: { authorization: `Bearer ${cfg.bearer_token}` },
      payload: { commitment: 123 },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().reason).toBe("malformed_payload");
    await server.close();
  });
});
