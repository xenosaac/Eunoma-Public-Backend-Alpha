// Partner operator configuration. Loaded from env at boot.

import { InMemoryEd25519Signer, Signer } from "@eunoma/shared";

export interface PartnerOperatorConfig {
  port: number;
  slot: number; // 0..6, this partner's index in the operator set
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: Uint8Array; // 32 bytes
  asset_type: Uint8Array; // 32 bytes
  chain_id: number;
  pool_id: bigint;
  signer: Signer; // Ed25519 signing identity (in-memory test impl by default)
  main_op_pubkey: Uint8Array; // 32-byte Ed25519 pubkey for verifying main-op auth
  min_expiry_window_secs: number; // reject requests that expire too soon
  max_horizon_secs: number;       // reject withdraw expiries farther than this in the future
  bridge_addr: string;            // Aptos package address — used by partner to read VaultConfig
  // W1 — auth + rate limit
  bearer_token: string; // token this partner expects from main in Authorization header
  rate_limit_max_per_window: number;
  rate_limit_window_ms: number;
}

export function defaultTestConfig(opts: {
  slot: number;
  signer?: Signer;
  main_op_pubkey: Uint8Array;
  port?: number;
  bearer_token?: string;
}): PartnerOperatorConfig {
  return {
    port: opts.port ?? 0, // ephemeral
    slot: opts.slot,
    operator_set_version: 1n,
    threshold: 4n,
    vault_addr: new Uint8Array(32).fill(0x11),
    asset_type: new Uint8Array(32).fill(0x22),
    chain_id: 2,
    pool_id: 0n,
    signer: opts.signer ?? new InMemoryEd25519Signer(),
    main_op_pubkey: opts.main_op_pubkey,
    min_expiry_window_secs: 30,
    max_horizon_secs: 3600,
    // TESTS ONLY: synthetic sentinel (0x11..11) so unit tests stay env-
    // independent. NEVER a real bridge address. Tests that exercise a chain
    // reader must pass `bridge_addr` directly when building the cfg (CP4
    // partner tests stub the chain reader so this sentinel is never
    // dereferenced as a real address). Production reads from env via
    // partner-operator/src/bin/start.ts (env-or-throw).
    bridge_addr: "0x" + "11".repeat(32),
    bearer_token: opts.bearer_token ?? "test-partner-token",
    rate_limit_max_per_window: 100,
    rate_limit_window_ms: 60_000,
  };
}
