// Chainalysis KYT curation feed — screens each deposit's SENDER (deposit-side only; withdraw
// makes ZERO KYT calls). Alpha uses the FREE Sanctions Screening API (US/EU/UN). Off-chain REST
// → 0 Aptos gas. mainnet upgrades to the paid KYT API by swapping the provider impl.
//
// IMPORTANT (owner): this ACTUALLY EXECUTES per-deposit — no admin-override stub. testnet
// addresses return clean (not on any sanctions list) but the call really runs. Revocation is
// driven by periodic re-screen (an address newly added to a sanctions list → re-fork excludes).
//
// KytProvider interface: async screenAddress(address) -> { sanctioned: boolean, source, raw }

// Free Sanctions Screening API: GET https://public.chainalysis.com/api/v1/address/{address}
// header X-API-Key. Response { identifications: [...] }; non-empty => on a sanctions list.
export class ChainalysisSanctionsProvider {
  constructor({ apiKey, baseUrl = "https://public.chainalysis.com/api/v1", fetchImpl } = {}) {
    if (!apiKey) throw new Error("ChainalysisSanctionsProvider: apiKey required (free Sanctions API key from chainalysis.com)");
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.fetch = fetchImpl ?? globalThis.fetch;
    if (!this.fetch) throw new Error("no fetch available (Node >=18 or pass fetchImpl)");
    this.kind = "chainalysis-sanctions";
  }

  async screenAddress(address) {
    const addr = String(address ?? "").trim();
    if (!addr) throw new Error("screenAddress: empty address");
    const res = await this.fetch(`${this.baseUrl}/address/${encodeURIComponent(addr)}`, {
      method: "GET",
      headers: { "X-API-Key": this.apiKey, Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`chainalysis sanctions API ${res.status}: ${await res.text().catch(() => "")}`);
    const body = await res.json();
    const ids = Array.isArray(body?.identifications) ? body.identifications : [];
    return { sanctioned: ids.length > 0, source: this.kind, raw: ids };
  }
}

// Test-only provider: returns sanctioned for addresses in a configurable set. Used to exercise
// approve/revoke flows on testnet (where real Chainalysis has no data). NOT a production path.
export class MockKytProvider {
  constructor({ sanctioned = [] } = {}) {
    this.sanctioned = new Set([...sanctioned].map((a) => String(a).toLowerCase()));
    this.kind = "mock-kyt";
    this.calls = [];
  }
  async screenAddress(address) {
    const addr = String(address ?? "").toLowerCase();
    this.calls.push(addr);
    return { sanctioned: this.sanctioned.has(addr), source: this.kind, raw: null };
  }
  flag(address) { this.sanctioned.add(String(address).toLowerCase()); }
  unflag(address) { this.sanctioned.delete(String(address).toLowerCase()); }
}

// Production factory: requires a real Chainalysis key (no silent stub — owner directive).
export function makeKytProvider(env = process.env) {
  if (env.CHAINALYSIS_API_KEY) {
    return new ChainalysisSanctionsProvider({
      apiKey: env.CHAINALYSIS_API_KEY,
      baseUrl: env.CHAINALYSIS_SANCTIONS_BASE_URL || undefined,
    });
  }
  throw new Error(
    "CHAINALYSIS_API_KEY not set. The curation feed must really execute (no admin-override stub). " +
      "Get a FREE Sanctions Screening API key at https://www.chainalysis.com/free-cryptocurrency-sanctions-screening-tools/ " +
      "and set CHAINALYSIS_API_KEY. For tests, inject MockKytProvider directly.",
  );
}

// Screen a batch of {commitment, sender} deposits → approved commitments (sender not sanctioned).
// Returns { approved: [{commitment, sender}], rejected: [{commitment, sender, raw}] }.
export async function screenDeposits(provider, deposits) {
  const approved = [], rejected = [];
  for (const d of deposits) {
    const r = await provider.screenAddress(d.sender);
    if (r.sanctioned) rejected.push({ ...d, raw: r.raw });
    else approved.push({ commitment: d.commitment, sender: d.sender });
  }
  return { approved, rejected };
}
