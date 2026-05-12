// Partner-side independent reader of on-chain VaultConfig. Partner MUST NOT
// trust the main operator's chain read; it queries fullnode itself and
// byte-compares against the cosign request body fields.

import { Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";

export interface ChainVaultState {
  operatorSetVersion: bigint;
  threshold: bigint;
  vaultAddrHex: string;
  assetTypeHex: string;
  vaultSequence: bigint;
}

export type ChainVaultReader = (bridgeAddr: string) => Promise<ChainVaultState>;

let cachedAptos: Aptos | null = null;
function getAptos(): Aptos {
  if (!cachedAptos) {
    cachedAptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  }
  return cachedAptos;
}

export const defaultReadChainVaultState: ChainVaultReader = async (bridgeAddr) => {
  const vc = (await getAptos().getAccountResource({
    accountAddress: bridgeAddr,
    resourceType: `${bridgeAddr}::eunoma_bridge::VaultConfig`,
  })) as any;
  return {
    operatorSetVersion: BigInt(vc.operator_set_version),
    threshold: BigInt(vc.attestation_threshold),
    vaultAddrHex: vc.vault_addr,
    assetTypeHex: vc.asset_type,
    vaultSequence: BigInt(vc.vault_sequence),
  };
};
