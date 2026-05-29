import { describe, expect, it } from "vitest";
import { createGasGuard, type FetchFn, type GasGuardConfig } from "../src/gas_guard.js";

const CFG: GasGuardConfig = {
  aptosNodeUrl: "https://node.example/v1",
  reserveAccountAddress: "0xreserve",
  maxGasPriceOctas: 200n,
  reserveMinBalanceOctas: 1_000_000n,
};

/** Build a fetch mock keyed by URL substring. */
function mockFetch(routes: {
  gasPrice?: { ok?: boolean; status?: number; body?: unknown };
  reserve?: { ok?: boolean; status?: number; body?: unknown };
  reserveView?: { ok?: boolean; status?: number; body?: unknown };
  reserveResource?: { ok?: boolean; status?: number; body?: unknown };
  throwOn?: "gas" | "reserve";
}): FetchFn {
  return async (url: string) => {
    const which = url.includes("estimate_gas_price") ? "gas" : "reserve";
    if (routes.throwOn === which) throw new Error("network down");
    const reserveRoute = url.endsWith("/view")
      ? routes.reserveView ?? routes.reserve
      : routes.reserveResource ?? routes.reserve;
    const r = which === "gas" ? routes.gasPrice : reserveRoute;
    return {
      ok: r?.ok ?? true,
      status: r?.status ?? 200,
      json: async () => r?.body ?? {},
    };
  };
}

describe("createGasGuard", () => {
  it("allows when gas price ≤ max and reserve ≥ min", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({
        gasPrice: { body: { gas_estimate: 100, prioritized_gas_estimate: 150 } },
        reserve: { body: { data: { coin: { value: "5000000" } } } },
      }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(true);
    expect(d.gasUnitPrice).toBe(150n); // uses the prioritized (higher) estimate
    expect(d.reserveBalanceOctas).toBe(5_000_000n);
  });

  it("refuses (gas_price_circuit_breaker_open) when gas spikes above max", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({
        gasPrice: { body: { gas_estimate: 100, prioritized_gas_estimate: 250 } }, // > 200
        reserve: { body: { data: { coin: { value: "5000000" } } } },
      }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(false);
    expect(d.reason).toBe("gas_price_circuit_breaker_open");
    expect(d.gasUnitPrice).toBe(250n);
  });

  it("refuses (reserve_low) when reserve is below the minimum", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({
        gasPrice: { body: { gas_estimate: 100 } },
        reserve: { body: { data: { coin: { value: "999999" } } } }, // < 1_000_000
      }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(false);
    expect(d.reason).toBe("reserve_low");
    expect(d.reserveBalanceOctas).toBe(999_999n);
  });

  it("allows when the reserve CoinStore is absent but the balance view returns funds", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({
        gasPrice: { body: { gas_estimate: 100 } },
        reserveView: { body: ["5000000"] },
        reserveResource: { status: 404, ok: false },
      }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(true);
    expect(d.reserveBalanceOctas).toBe(5_000_000n);
  });

  it("fail-closed (read_failed) when a read throws", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({ throwOn: "gas" }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(false);
    expect(d.reason).toBe("read_failed");
  });

  it("fail-closed (read_failed) on a non-2xx gas-price response", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({ gasPrice: { ok: false, status: 503 } }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(false);
    expect(d.reason).toBe("read_failed");
  });

  it("treats a 404 reserve CoinStore as zero balance → reserve_low (fail-safe)", async () => {
    const guard = createGasGuard(CFG, {
      fetchFn: mockFetch({
        gasPrice: { body: { gas_estimate: 100 } },
        reserve: { status: 404, ok: false },
      }),
    });
    const d = await guard.check();
    expect(d.allow).toBe(false);
    expect(d.reason).toBe("reserve_low");
    expect(d.reserveBalanceOctas).toBe(0n);
  });
});
