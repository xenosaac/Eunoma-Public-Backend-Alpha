// Phase 4 W1 — auth + rate limit test for main-operator.
//
// Verifies:
//   - missing Authorization header → 401
//   - wrong bearer token → 401
//   - /v1/health bypasses auth (200 with no header)
//   - rate limit on /v1/deposit/request-attestation triggers 429 past threshold

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { InMemoryEd25519Signer } from "@eunoma/shared";
import { buildMainServer } from "../src/server.js";
import { defaultMainConfig } from "../src/config.js";

describe("main-operator W1 bearer-token + rate-limit", () => {
  const main_signer = new InMemoryEd25519Signer();
  const partner_pubkeys = Array.from({ length: 7 }, () =>
    new InMemoryEd25519Signer().publicKey(),
  );
  partner_pubkeys[0] = main_signer.publicKey();

  const cfg = defaultMainConfig({
    signer: main_signer,
    partner_urls: ["http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3", "http://127.0.0.1:4", "http://127.0.0.1:5", "http://127.0.0.1:6"],
    partner_pubkeys,
    bearer_token: "deadbeef-main",
  });
  // Tight rate limit so the test can trip it cheaply.
  cfg.rate_limit_max_per_window = 3;
  cfg.rate_limit_window_ms = 5_000;

  let server: ReturnType<typeof buildMainServer>["server"];

  beforeAll(async () => {
    server = buildMainServer({ cfg }).server;
  });

  afterAll(async () => {
    await server.close();
  });

  it("missing Authorization header returns 401", async () => {
    const res = await server.inject({ method: "GET", url: "/v1/operator-set" });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("missing_authorization");
  });

  it("malformed Authorization header returns 401", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/v1/operator-set",
      headers: { authorization: "Token xyz" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("invalid_authorization_format");
  });

  it("wrong bearer token returns 401", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/v1/operator-set",
      headers: { authorization: "Bearer wrong-token" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("invalid_token");
  });

  it("correct bearer token returns 200", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/v1/operator-set",
      headers: { authorization: "Bearer deadbeef-main" },
    });
    expect(res.statusCode).toBe(200);
  });

  it("/v1/health is auth-exempt (200 with no header)", async () => {
    const res = await server.inject({ method: "GET", url: "/v1/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json().ok).toBe(true);
  });

  it("rate limit triggers 429 after threshold on /v1/deposit/request-attestation", async () => {
    // maxPerWindow = 3. First 3 requests pass auth+rate gates (handler may
    // 400/500 depending on body shape — point is they are NOT 429). 4th = 429.
    for (let i = 0; i < 3; i++) {
      const res = await server.inject({
        method: "POST",
        url: "/v1/deposit/request-attestation",
        headers: { authorization: "Bearer deadbeef-main" },
        payload: {},
      });
      expect(res.statusCode).not.toBe(429);
    }
    const blocked = await server.inject({
      method: "POST",
      url: "/v1/deposit/request-attestation",
      headers: { authorization: "Bearer deadbeef-main" },
      payload: {},
    });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json().error).toBe("rate_limit_exceeded");
  });

  it("rate limit does NOT apply to non-listed paths", async () => {
    // /v1/operator-set is not in rateLimit.paths — many calls in a row should all succeed.
    for (let i = 0; i < 10; i++) {
      const res = await server.inject({
        method: "GET",
        url: "/v1/operator-set",
        headers: { authorization: "Bearer deadbeef-main" },
      });
      expect(res.statusCode).toBe(200);
    }
  });
});
