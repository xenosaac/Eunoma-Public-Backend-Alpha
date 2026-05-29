// CP3: gas circuit breaker + reserve guard.
//
// Before submitting a withdraw, the relayer checks (1) the network gas unit price and (2) the
// communal plain-APT reserve balance. If gas has spiked above `maxGasPriceOctas`, or the reserve is
// below `reserveMinBalanceOctas`, the relayer REFUSES to submit and signals the client to
// self-submit instead (protects the reserve from draining at a loss; the user can still withdraw by
// re-running step2a under their own key while the FROST attestation is unexpired).
//
// FAIL-CLOSED: any read error (RPC down, non-2xx, malformed body, missing reserve store) returns
// allow=false (refuse + self-submit). The relayer NEVER submits "blind" when it cannot confirm
// gas/reserve are within bounds.
//
// IMPORTANT: the gas-guard decision must be taken STRICTLY BEFORE the relayer submits
// withdraw_step2a — once step2a lands, the pending finalization is keyed to the relayer's address
// and only the relayer can finish it (the user's self-submit fallback could no longer take over).

/** Minimal fetch shape (matches global fetch Response) so tests can inject a deterministic mock. */
export type FetchFn = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

export interface GasGuardConfig {
  aptosNodeUrl: string;
  reserveAccountAddress: string;
  /** Refuse if the network gas unit price exceeds this (octas per gas unit). */
  maxGasPriceOctas: bigint;
  /** Refuse if the reserve plain-APT balance is below this (octas). */
  reserveMinBalanceOctas: bigint;
}

export type GasGuardRefusal = "gas_price_circuit_breaker_open" | "reserve_low" | "read_failed";

export interface GasGuardDecision {
  /** true → safe to submit; false → refuse and signal self-submit. */
  allow: boolean;
  reason?: GasGuardRefusal;
  gasUnitPrice?: bigint;
  reserveBalanceOctas?: bigint;
}

const APT_COIN_STORE = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>";
const APT_COIN_BALANCE_VIEW = "0x1::coin::balance";
const APT_COIN_TYPE = "0x1::aptos_coin::AptosCoin";

async function readGasUnitPrice(fetchFn: FetchFn, nodeUrl: string): Promise<bigint> {
  const res = await fetchFn(`${nodeUrl.replace(/\/$/, "")}/estimate_gas_price`);
  if (!res.ok) throw new Error(`estimate_gas_price HTTP ${res.status}`);
  const body = (await res.json()) as { gas_estimate?: number; prioritized_gas_estimate?: number };
  // Use the (higher) prioritized estimate when present so the breaker is conservative.
  const estimate = body.prioritized_gas_estimate ?? body.gas_estimate;
  if (typeof estimate !== "number" || !Number.isFinite(estimate)) {
    throw new Error("estimate_gas_price: missing/invalid gas_estimate");
  }
  return BigInt(Math.ceil(estimate));
}

async function readReserveBalanceOctas(
  fetchFn: FetchFn,
  nodeUrl: string,
  reserveAddr: string,
): Promise<bigint> {
  const baseUrl = nodeUrl.replace(/\/$/, "");
  const viewUrl = `${baseUrl}/view`;
  try {
    const viewRes = await fetchFn(viewUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        function: APT_COIN_BALANCE_VIEW,
        type_arguments: [APT_COIN_TYPE],
        arguments: [reserveAddr],
      }),
    });
    if (!viewRes.ok) throw new Error(`reserve balance view HTTP ${viewRes.status}`);
    const body = await viewRes.json();
    if (!Array.isArray(body) || typeof body[0] !== "string" || !/^[0-9]+$/.test(body[0])) {
      throw new Error("reserve balance view: missing/invalid balance");
    }
    return BigInt(body[0]);
  } catch {
    // Fall back to the legacy CoinStore resource shape for older nodes/tests.
  }

  const url = `${baseUrl}/accounts/${reserveAddr}/resource/${encodeURIComponent(APT_COIN_STORE)}`;
  const res = await fetchFn(url);
  // 404 = no CoinStore yet → treat as zero balance (fail-safe: triggers reserve_low refusal).
  if (res.status === 404) return 0n;
  if (!res.ok) throw new Error(`reserve resource HTTP ${res.status}`);
  const body = (await res.json()) as { data?: { coin?: { value?: string } } };
  const value = body.data?.coin?.value;
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error("reserve CoinStore: missing/invalid coin.value");
  }
  return BigInt(value);
}

export interface GasGuard {
  check(): Promise<GasGuardDecision>;
}

export function createGasGuard(cfg: GasGuardConfig, opts: { fetchFn?: FetchFn } = {}): GasGuard {
  const fetchFn = opts.fetchFn ?? (globalThis.fetch as unknown as FetchFn);
  if (!fetchFn) {
    throw new Error("createGasGuard: no fetch available; pass opts.fetchFn");
  }
  return {
    async check(): Promise<GasGuardDecision> {
      try {
        const gasUnitPrice = await readGasUnitPrice(fetchFn, cfg.aptosNodeUrl);
        if (gasUnitPrice > cfg.maxGasPriceOctas) {
          return { allow: false, reason: "gas_price_circuit_breaker_open", gasUnitPrice };
        }
        const reserveBalanceOctas = await readReserveBalanceOctas(
          fetchFn,
          cfg.aptosNodeUrl,
          cfg.reserveAccountAddress,
        );
        if (reserveBalanceOctas < cfg.reserveMinBalanceOctas) {
          return { allow: false, reason: "reserve_low", gasUnitPrice, reserveBalanceOctas };
        }
        return { allow: true, gasUnitPrice, reserveBalanceOctas };
      } catch {
        // Fail-closed: never submit when gas/reserve cannot be confirmed.
        return { allow: false, reason: "read_failed" };
      }
    },
  };
}
