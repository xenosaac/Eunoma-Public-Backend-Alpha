import type { FastifyInstance } from "fastify";
import { Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import type { MainOperatorConfig } from "../config.js";

export interface PublicVaultConfig {
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: string;
  asset_type: string;
}

export interface AppConfigRouteHooks {
  readVaultConfig?: () => Promise<PublicVaultConfig>;
}

function hex(b: Uint8Array): string {
  return "0x" + Buffer.from(b).toString("hex");
}

function networkFromConfig(cfg: MainOperatorConfig): Network {
  if (cfg.network === "mainnet") return Network.MAINNET;
  if (cfg.network === "devnet") return Network.DEVNET;
  return Network.TESTNET;
}

function assetTypeFromVaultConfig(vc: any, fallback: string): string {
  if (typeof vc.asset_type === "string") return vc.asset_type;
  if (vc.asset_type && typeof vc.asset_type.inner === "string") return vc.asset_type.inner;
  return fallback;
}

async function defaultReadVaultConfig(cfg: MainOperatorConfig): Promise<PublicVaultConfig> {
  const bridgeAddr = cfg.bridge_package_address ?? process.env.BRIDGE_PACKAGE_ADDRESS;
  if (!bridgeAddr) {
    return {
      operator_set_version: cfg.operator_set_version,
      threshold: cfg.threshold,
      vault_addr: hex(cfg.vault_addr),
      asset_type: hex(cfg.asset_type),
    };
  }

  const aptos = new Aptos(new AptosConfig({ network: networkFromConfig(cfg) }));
  const vc = (await aptos.getAccountResource({
    accountAddress: bridgeAddr,
    resourceType: `${bridgeAddr}::eunoma_bridge::VaultConfig`,
  })) as any;
  return {
    operator_set_version: BigInt(vc.operator_set_version),
    threshold: BigInt(vc.attestation_threshold),
    vault_addr: vc.vault_addr ?? hex(cfg.vault_addr),
    asset_type: assetTypeFromVaultConfig(vc, hex(cfg.asset_type)),
  };
}

export function registerAppConfigRoute(
  fastify: FastifyInstance,
  cfg: MainOperatorConfig,
  hooks: AppConfigRouteHooks = {},
): void {
  fastify.get("/v1/app/config", async (_req, reply) => {
    const bridgePackage = cfg.bridge_package_address ?? process.env.BRIDGE_PACKAGE_ADDRESS ?? null;
    try {
      const vc = await (hooks.readVaultConfig ?? (() => defaultReadVaultConfig(cfg)))();
      return reply.code(200).send({
        network: cfg.network ?? "testnet",
        chain_id: cfg.chain_id,
        bridge_package: bridgePackage,
        vault: vc.vault_addr,
        asset_type: vc.asset_type,
        vault_ek_hex: cfg.vault_ek_hex ?? process.env.VAULT_EK_HEX ?? null,
        pool_id: cfg.pool_id.toString(),
        operator_set_version: vc.operator_set_version.toString(),
        threshold: vc.threshold.toString(),
      });
    } catch {
      return reply.code(502).send({ error: "chain_state_unavailable" });
    }
  });
}
