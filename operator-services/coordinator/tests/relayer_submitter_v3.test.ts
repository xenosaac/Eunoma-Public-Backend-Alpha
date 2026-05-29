import { describe, expect, it } from "vitest";
import {
  buildDefaultDepositRelayerSubmitter,
  buildDefaultRelayerSubmitter,
  type CoordinatorConfig,
} from "../src/config.js";

function cfg(over: Partial<CoordinatorConfig>): CoordinatorConfig {
  return {
    host: "127.0.0.1",
    port: 4200,
    nodeBearerTokens: {},
    relayerUrl: "http://relayer.example",
    ...over,
  } as CoordinatorConfig;
}

function mockFetch(body: unknown, ok = true, status = 200): { fn: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fn = (async (url: string) => {
    calls.push(String(url));
    return { ok, status, json: async () => body };
  }) as unknown as typeof fetch;
  return { fn, calls };
}

describe("buildDefaultRelayerSubmitter — v2/v3 cutover", () => {
  it("v2 (default) posts to /v2/relayer/submit/withdraw and reads txHash", async () => {
    const { fn, calls } = mockFetch({ accepted: true, txHash: "0xabc", simulated: true });
    const submit = buildDefaultRelayerSubmitter(cfg({ relayerUseV3: false }), fn)!;
    const r = await submit({});
    expect(calls[0]).toContain("/v2/relayer/submit/withdraw");
    expect(r.txHash).toBe("0xabc");
    expect(r.simulated).toBe(true);
  });

  it("v3 posts to /v3/relayer/submit/withdraw and maps txHashes[last] → txHash", async () => {
    const { fn, calls } = mockFetch({
      accepted: true,
      simulated: false,
      txHashes: ["0x1", "0x2", "0x3", "0x4", "0x5"],
    });
    const submit = buildDefaultRelayerSubmitter(cfg({ relayerUseV3: true }), fn)!;
    const r = await submit({});
    expect(calls[0]).toContain("/v3/relayer/submit/withdraw");
    expect(r.txHash).toBe("0x5"); // step2b settlement hash
    expect(r.simulated).toBe(false);
  });

  it("v3 self_submit (200) surfaces as a relayer_self_submit error for client fallback", async () => {
    const { fn } = mockFetch({ action: "self_submit", reason: "gas_price_circuit_breaker_open" });
    const submit = buildDefaultRelayerSubmitter(cfg({ relayerUseV3: true }), fn)!;
    await expect(submit({})).rejects.toThrow(/relayer_self_submit: gas_price_circuit_breaker_open/);
  });

  it("v3 rejects a malformed response (missing txHashes)", async () => {
    const { fn } = mockFetch({ accepted: true, simulated: true });
    const submit = buildDefaultRelayerSubmitter(cfg({ relayerUseV3: true }), fn)!;
    await expect(submit({})).rejects.toThrow(/v3 response missing required fields/);
  });

  it("returns undefined when no relayerUrl is configured", () => {
    expect(buildDefaultRelayerSubmitter(cfg({ relayerUrl: undefined }), fetch)).toBeUndefined();
  });
});

describe("buildDefaultDepositRelayerSubmitter (deposit-delegate)", () => {
  it("POSTs to /v3/relayer/submit/deposit and returns the 2 tx hashes", async () => {
    const { fn, calls } = mockFetch({
      accepted: true,
      simulated: true,
      txHashes: ["0xprepare", "0xstep2a"],
    });
    const submit = buildDefaultDepositRelayerSubmitter(cfg({}), fn)!;
    const r = await submit({ userAddr: "0x1" });
    expect(calls[0]).toContain("/v3/relayer/submit/deposit");
    expect(r.txHashes).toEqual(["0xprepare", "0xstep2a"]);
    expect(r.simulated).toBe(true);
  });

  it("surfaces a self_submit response as relayer_self_submit error", async () => {
    const { fn } = mockFetch({ action: "self_submit", reason: "reserve_low" });
    const submit = buildDefaultDepositRelayerSubmitter(cfg({}), fn)!;
    await expect(submit({})).rejects.toThrow(/relayer_self_submit: reserve_low/);
  });

  it("rejects a malformed response", async () => {
    const { fn } = mockFetch({ accepted: true, simulated: true });
    const submit = buildDefaultDepositRelayerSubmitter(cfg({}), fn)!;
    await expect(submit({})).rejects.toThrow(/deposit response missing required fields/);
  });

  it("returns undefined when no relayerUrl is configured", () => {
    expect(buildDefaultDepositRelayerSubmitter(cfg({ relayerUrl: undefined }), fetch)).toBeUndefined();
  });
});
