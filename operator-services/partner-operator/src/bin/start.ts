// Production entrypoint for partner-operator (Phase 4 W6.5).
//
// Run once per slot (1..6):
//   PARTNER_SLOT=1 PARTNER_OPERATOR_PORT=3001 tsx --env-file=.env src/bin/start.ts
//
// All 6 partner processes plus the main share the same .env (per-slot fields
// disambiguate via PARTNER_*_SLOT_<N>).

import { AccountAddress, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import {
  InMemoryEd25519Signer,
  loadOperatorKeyForSlot,
} from "@eunoma/shared";
import { buildPartnerServer } from "../server.js";
import type { PartnerOperatorConfig } from "../config.js";

async function main() {
  const slot = Number(process.env.PARTNER_SLOT);
  if (!slot || slot < 1 || slot > 6) {
    throw new Error(`PARTNER_SLOT must be 1..6, got ${process.env.PARTNER_SLOT}`);
  }
  const port = Number(process.env.PARTNER_OPERATOR_PORT ?? 3000 + slot);

  const myKey = loadOperatorKeyForSlot(slot);
  const mainKey = loadOperatorKeyForSlot(0);
  const myBearer = process.env[`PARTNER_BEARER_TOKEN_SLOT_${slot}`];
  if (!myBearer) {
    throw new Error(`PARTNER_BEARER_TOKEN_SLOT_${slot} not set in env`);
  }

  const signer = new InMemoryEd25519Signer(
    new Uint8Array(Buffer.from(myKey.private_key.replace(/^0x/, ""), "hex")),
  );

  // Read on-chain VaultConfig at boot. Attestation bytes must match these
  // values exactly; fail fast instead of starting against stale defaults.
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const bridgeAddr = process.env.BRIDGE_PACKAGE_ADDRESS;
  if (!bridgeAddr) {
    throw new Error(
      "BRIDGE_PACKAGE_ADDRESS env var is required — refuse to default to a stale bridge address",
    );
  }
  const vc = (await aptos.getAccountResource({
    accountAddress: bridgeAddr,
    resourceType: `${bridgeAddr}::eunoma_bridge::VaultConfig`,
  })) as any;
  const vaultAddr = AccountAddress.from(vc.vault_addr).toUint8Array();
  const assetType = AccountAddress.from(vc.asset_type.inner).toUint8Array();
  const operatorSetVersion = BigInt(vc.operator_set_version);
  const threshold = BigInt(vc.attestation_threshold);

  const cfg: PartnerOperatorConfig = {
    port,
    slot,
    operator_set_version: operatorSetVersion,
    threshold,
    vault_addr: vaultAddr,
    asset_type: assetType,
    chain_id: 2,
    pool_id: 0n,
    signer,
    main_op_pubkey: new Uint8Array(Buffer.from(mainKey.public_key.replace(/^0x/, ""), "hex")),
    min_expiry_window_secs: 30,
    max_horizon_secs: Number(process.env.MAX_HORIZON_SECS ?? 3600),
    bridge_addr: bridgeAddr,
    bearer_token: myBearer,
    rate_limit_max_per_window: Number(process.env.RATE_LIMIT_MAX_PER_WINDOW ?? 10),
    rate_limit_window_ms: Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000),
  };

  const server = buildPartnerServer(cfg);
  const url = await server.listen({ port, host: process.env.HOST ?? "127.0.0.1" });
  console.log(`[partner-operator] listening on ${url} (slot=${slot})`);
}

main().catch((err) => {
  console.error("[partner-operator] fatal:", err);
  process.exit(1);
});
