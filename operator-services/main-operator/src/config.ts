// Main operator configuration.

import { InMemoryEd25519Signer, Signer } from "@eunoma/shared";

export interface MainOperatorConfig {
  port: number;
  main_slot: number; // 0..6
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: Uint8Array;
  asset_type: Uint8Array;
  chain_id: number;
  pool_id: bigint;
  signer: Signer;
  partner_urls: string[]; // 6 entries (operator_set_size - 1)
  partner_pubkeys: Uint8Array[]; // 7 entries (full operator set; main slot = signer's pubkey)
  partner_request_timeout_ms: number;
  min_expiry_window_secs: number;
  // W1 — auth + rate limit
  bearer_token: string; // token main expects in `Authorization: Bearer <...>` from external callers
  partner_bearer_tokens: string[]; // 6 entries — tokens main uses when calling each partner (parallel to partner_urls)
  rate_limit_max_per_window: number;
  rate_limit_window_ms: number;
}

export function defaultMainConfig(opts: {
  signer?: Signer;
  partner_urls: string[];
  partner_pubkeys: Uint8Array[];
  bearer_token?: string;
  partner_bearer_tokens?: string[];
}): MainOperatorConfig {
  const signer = opts.signer ?? new InMemoryEd25519Signer();
  return {
    port: 0,
    main_slot: 0,
    operator_set_version: 1n,
    threshold: 4n,
    vault_addr: new Uint8Array(32).fill(0x11),
    asset_type: new Uint8Array(32).fill(0x22),
    chain_id: 2,
    pool_id: 0n,
    signer,
    partner_urls: opts.partner_urls,
    partner_pubkeys: opts.partner_pubkeys,
    partner_request_timeout_ms: 5000,
    min_expiry_window_secs: 30,
    bearer_token: opts.bearer_token ?? "test-main-token",
    partner_bearer_tokens:
      opts.partner_bearer_tokens ?? opts.partner_urls.map(() => "test-partner-token"),
    rate_limit_max_per_window: 100, // dev-friendly default; prod tightens via env
    rate_limit_window_ms: 60_000,
  };
}
