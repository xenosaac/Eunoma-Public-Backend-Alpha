// CP5 RC2 + RC4 unit tests — asset-registry-driven config derivation and the
// rollover/normalize ACTIVE-only filter. Both read the init_v4 artifact
// <stateRoot>/coordinator/asset_registry.json (NOT hand-edited env).
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadActiveAssetAddrs } from "../src/bridge_maintenance_pipeline.js";
import {
  configFromEnv,
  assetRegistryFromStateRoot,
  deriveBridgeAssetTypeFromRegistry,
} from "../src/config.js";

const APT = {
  symbol: "ConfidentialAPT",
  plainSymbol: "APT",
  metadata: `0x${"0a".repeat(32)}`,
  assetType: "0x1::aptos_coin::AptosCoin",
  assetIdFr: `0x${"11".repeat(32)}`,
  decimals: 8,
  vault: `0x${"cc".repeat(32)}`,
  vaultEkHex: `0x${"ee".repeat(32)}`,
  poolId: "0",
  status: "ACTIVE",
};
const CUSDC = {
  symbol: "cUSDC",
  plainSymbol: "USDC",
  metadata: `0x${"0b".repeat(32)}`,
  assetType: "0xUSDC::coin::T",
  assetIdFr: `0x${"22".repeat(32)}`,
  decimals: 6,
  vault: `0x${"cc".repeat(32)}`,
  vaultEkHex: `0x${"ee".repeat(32)}`,
  poolId: "0",
  status: 0, // numeric DORMANT
};

let stateRoot: string;
let coordinatorDir: string;

async function writeRegistry(body: unknown): Promise<void> {
  await writeFile(join(coordinatorDir, "asset_registry.json"), JSON.stringify(body));
}

beforeEach(async () => {
  stateRoot = await mkdtemp(join(tmpdir(), "eunoma-v4-registry-"));
  coordinatorDir = join(stateRoot, "coordinator");
  await mkdir(coordinatorDir, { recursive: true });
});
afterEach(async () => {
  await rm(stateRoot, { recursive: true, force: true });
});

describe("RC4: loadActiveAssetAddrs — rollover/normalize ACTIVE-only filter", () => {
  it("returns ONLY the ACTIVE asset addrs (DORMANT stablecoin dropped)", async () => {
    await writeRegistry([APT, CUSDC]);
    expect(loadActiveAssetAddrs(stateRoot)).toEqual([APT.metadata]);
  });

  it("returns [] (empty, not null) when the registry has zero ACTIVE assets → early-return path", async () => {
    await writeRegistry([CUSDC, { ...APT, status: "PAUSED" }]);
    expect(loadActiveAssetAddrs(stateRoot)).toEqual([]);
  });

  it("accepts the { assets: [...] } envelope", async () => {
    await writeRegistry({ assets: [APT, CUSDC] });
    expect(loadActiveAssetAddrs(stateRoot)).toEqual([APT.metadata]);
  });

  it("returns null when the artifact is missing (legacy single-asset fallback — never bricks)", () => {
    expect(loadActiveAssetAddrs(stateRoot)).toBeNull();
  });

  it("returns null when stateRoot is unset", () => {
    expect(loadActiveAssetAddrs(undefined)).toBeNull();
  });

  it("returns null on a malformed row (fail closed to fallback)", async () => {
    await writeRegistry([{ status: "ACTIVE" }]); // missing metadata
    expect(loadActiveAssetAddrs(stateRoot)).toBeNull();
  });
});

describe("RC2: assetRegistryFromStateRoot + deriveBridgeAssetTypeFromRegistry", () => {
  it("derives bridgeAssetType from the single ACTIVE asset", async () => {
    await writeRegistry([APT, CUSDC]);
    const reg = assetRegistryFromStateRoot(stateRoot);
    expect(deriveBridgeAssetTypeFromRegistry(reg)).toBe(APT.assetType);
  });

  it("returns undefined (fail closed) when MORE than one asset is ACTIVE (ambiguous gate)", async () => {
    await writeRegistry([APT, { ...CUSDC, status: "ACTIVE" }]);
    const reg = assetRegistryFromStateRoot(stateRoot);
    expect(deriveBridgeAssetTypeFromRegistry(reg)).toBeUndefined();
  });

  it("returns undefined when no asset is ACTIVE", async () => {
    await writeRegistry([CUSDC]);
    const reg = assetRegistryFromStateRoot(stateRoot);
    expect(deriveBridgeAssetTypeFromRegistry(reg)).toBeUndefined();
  });
});

describe("RC2: configFromEnv sources bridgeAssetType from the registry, env overrides", () => {
  const h32 = (b: string) => b.repeat(64);
  const baseEnv = (): NodeJS.ProcessEnv => ({
    DEOPERATOR_ROSTER_JSON: JSON.stringify({
      operatorSetVersion: "1",
      dkgEpoch: "1",
      caDkgScheme: "ca_dkg_v2",
      threshold: 5,
      frostGroupPubkey: h32("a"),
      vaultEk: h32("b"),
      circuitVersions: {
        depositBinding: "deposit-v2",
        withdraw: "withdraw-v2",
        caPayload: "aptos-ca-v1",
      },
      nodes: Array.from({ length: 7 }, (_, slot) => ({
        slot,
        nodeId: `node-${slot}`,
        endpoint: `http://node-${slot}.invalid`,
        hpkePublicKey: h32("c"),
        transcriptPublicKey: h32("d"),
        frostVerifyingShare: h32("e"),
      })),
    }),
    EUNOMA_STATE_ROOT: stateRoot,
  });

  it("derives bridgeAssetType from the registry when BRIDGE_ASSET_TYPE is unset", async () => {
    await writeRegistry([APT, CUSDC]);
    const cfg = configFromEnv(baseEnv());
    expect(cfg.bridgeAssetType).toBe(APT.assetType);
  });

  it("an explicit BRIDGE_ASSET_TYPE still wins (test / staged cutover)", async () => {
    await writeRegistry([APT, CUSDC]);
    const cfg = configFromEnv({ ...baseEnv(), BRIDGE_ASSET_TYPE: "0xOVERRIDE::x::Y" });
    expect(cfg.bridgeAssetType).toBe("0xOVERRIDE::x::Y");
  });

  it("bridgeAssetType is undefined when neither env nor a single-ACTIVE registry is present", () => {
    // No registry written → derivation returns undefined, env unset.
    const cfg = configFromEnv(baseEnv());
    expect(cfg.bridgeAssetType).toBeUndefined();
  });
});
