// Production entrypoint for main-operator.
//
// Reads env-based config (W3 secrets, W2 DATABASE_URL, W1 bearer tokens) and
// starts the Fastify server on MAIN_OPERATOR_PORT.
//
//   tsx --env-file=.env src/bin/start.ts
//
// All previous CA / batch / withdraw script paths still work in parallel.

import { AccountAddress, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import {
  InMemoryStore,
  PostgresStore,
  loadOperatorKeyForSlot,
  type Store,
} from "@eunoma/shared";
import { buildMainServer } from "../server.js";
import type { MainOperatorConfig } from "../config.js";

async function main() {
  const port = Number(process.env.MAIN_OPERATOR_PORT ?? 3000);
  const databaseUrl = process.env.DATABASE_URL;
  let store: Store;
  if (databaseUrl) {
    store = await PostgresStore.create(databaseUrl);
    console.log(`[main-operator] persistence: postgres (${databaseUrl.split("@").pop()})`);
  } else {
    store = new InMemoryStore();
    console.warn("[main-operator] persistence: in-memory (set DATABASE_URL to persist)");
  }

  // Operator set: load all 7 pubkeys + main's signer.
  const mainSlot = 0;
  const mainKey = loadOperatorKeyForSlot(mainSlot);

  // For partner URLs / bearers: production reads from PARTNER_URL_SLOT_<n> +
  // PARTNER_BEARER_TOKEN_SLOT_<n> env. Default to localhost ports 3001..3006
  // (matches the Mac-mini-single-host deployment plan).
  const partnerUrls: string[] = [];
  const partnerBearerTokens: string[] = [];
  for (let s = 1; s <= 6; s++) {
    const u = process.env[`PARTNER_URL_SLOT_${s}`] ?? `http://127.0.0.1:${3000 + s}`;
    const t = process.env[`PARTNER_BEARER_TOKEN_SLOT_${s}`];
    if (!t) {
      throw new Error(`partner auth token for slot ${s} is not configured`);
    }
    partnerUrls.push(u);
    partnerBearerTokens.push(t);
  }

  const bearerToken = process.env.OPERATOR_BEARER_TOKEN;
  if (!bearerToken) throw new Error("operator auth token is not configured");

  // Load all 7 pubkeys for the operator set vector (main is slot 0).
  const allPubkeys: Uint8Array[] = [];
  for (let s = 0; s < 7; s++) {
    const k = loadOperatorKeyForSlot(s);
    allPubkeys.push(new Uint8Array(Buffer.from(k.public_key.replace(/^0x/, ""), "hex")));
  }

  // signer wraps mainKey.private_key for slot 0.
  const { InMemoryEd25519Signer } = await import("@eunoma/shared");
  const signer = new InMemoryEd25519Signer(
    new Uint8Array(Buffer.from(mainKey.private_key.replace(/^0x/, ""), "hex")),
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

  const cfg: MainOperatorConfig = {
    port,
    network: "testnet",
    bridge_package_address: bridgeAddr,
    vault_ek_hex: process.env.VAULT_EK_HEX,
    main_slot: mainSlot,
    operator_set_version: operatorSetVersion,
    threshold,
    vault_addr: vaultAddr,
    asset_type: assetType,
    chain_id: 2,
    pool_id: 0n,
    signer,
    partner_urls: partnerUrls,
    partner_pubkeys: allPubkeys,
    partner_request_timeout_ms: 5000,
    min_expiry_window_secs: 30,
    bearer_token: bearerToken,
    partner_bearer_tokens: partnerBearerTokens,
    rate_limit_max_per_window: Number(process.env.RATE_LIMIT_MAX_PER_WINDOW ?? 10),
    rate_limit_window_ms: Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000),
  };

  const { server } = buildMainServer({ cfg, store });
  const url = await server.listen({ port, host: process.env.HOST ?? "127.0.0.1" });
  console.log(`[main-operator] listening on ${url} (slot=${mainSlot})`);
}

main().catch((err) => {
  void err;
  console.error("[main-operator] fatal: startup_failed");
  process.exit(1);
});
