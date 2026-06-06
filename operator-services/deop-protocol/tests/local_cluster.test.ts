import { describe, expect, it } from "vitest";
import { buildLocalClusterPlan, DEOPERATOR_COUNT, rosterHash } from "../src/index.js";

const h32 = (byte: string) => byte.repeat(64);

function deterministicHex() {
  let counter = 0;
  return () => {
    counter += 1;
    return counter.toString(16).padStart(64, "0");
  };
}

describe("local cluster planning", () => {
  it("generates fixed localhost ports for seven nodes and workers", () => {
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    });

    expect(plan.coordinator.port).toBe(4200);
    expect(plan.relayer.port).toBe(4300);
    expect(plan.nodes.map((node) => node.port)).toEqual([4100, 4101, 4102, 4103, 4104, 4105, 4106]);
    expect(plan.workers.map((worker) => worker.port)).toEqual([4400, 4401, 4402, 4403, 4404, 4405, 4406]);
    expect(plan.roster.caDkgScheme).toBe("ca_local");
    expect(plan.rosterHash).toBe(rosterHash(plan.roster));
  });

  it("propagates BRIDGE_PACKAGE_ADDRESS to every worker env when supplied (M11 resync)", () => {
    const pkg = `0x${"a08850b1".repeat(8)}`;
    const baseInput = {
      vaultEk: h32("a"),
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    };
    const withPkg = buildLocalClusterPlan({ ...baseInput, bridgePackageAddress: pkg });
    for (const worker of withPkg.workers) {
      expect(worker.env.BRIDGE_PACKAGE_ADDRESS).toBe(pkg);
    }
    // Omitted when not supplied (optional — resync still fails closed at runtime).
    const withoutPkg = buildLocalClusterPlan(baseInput);
    for (const worker of withoutPkg.workers) {
      expect(worker.env.BRIDGE_PACKAGE_ADDRESS).toBeUndefined();
    }
  });

  it("propagates bridge vault and asset config to coordinator and workers", () => {
    const bridgeVaultAddress = `0x${"9415c478".repeat(8)}`;
    const bridgeAssetType = "0xa";
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      bridgeVaultAddress,
      bridgeAssetType,
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    });

    expect(plan.coordinator.env.BRIDGE_VAULT_ADDRESS).toBe(bridgeVaultAddress);
    expect(plan.coordinator.env.BRIDGE_ASSET_TYPE).toBe(bridgeAssetType);
    for (const worker of plan.workers) {
      expect(worker.env.BRIDGE_VAULT_ADDRESS).toBe(bridgeVaultAddress);
      expect(worker.env.BRIDGE_ASSET_TYPE).toBe(bridgeAssetType);
    }
  });

  it("propagates local cluster signer profiles for route refresh and relayer submit", () => {
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      adminProfile: "bridge-user",
      relayerProfile: "testnet-asp-relayer",
      refreshSignerMode: "admin",
      refreshAdminProfile: "bridge-user",
      refreshAspRecorderProfile: "bridge-user",
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    });

    expect(plan.coordinator.env.ADMIN_PROFILE).toBe("bridge-user");
    expect(plan.coordinator.env.EUNOMA_REFRESH_SIGNER_MODE).toBe("admin");
    expect(plan.coordinator.env.EUNOMA_REFRESH_ADMIN_PROFILE).toBe("bridge-user");
    expect(plan.coordinator.env.EUNOMA_REFRESH_ASP_RECORDER_PROFILE).toBe("bridge-user");
    expect(plan.relayer.env.RELAYER_PROFILE).toBe("testnet-asp-relayer");
  });

  it("generates v3 relayer gas-reserve env with a nonzero reserve floor", () => {
    const bridgePackageAddress = `0x${"acb0f899".repeat(8)}`;
    const reserveAccountAddress = `0x${"1347ad32".repeat(8)}`;
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      bridgePackageAddress,
      bridgeVaultAddress: `0x${"9415c478".repeat(8)}`,
      bridgeAssetType: "0xa",
      adminProfile: "bridge-user",
      relayerProfile: "testnet-asp-relayer",
      relayerReserveAccountAddress: reserveAccountAddress,
      relayerReserveMinBalanceOctas: "0",
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    });

    expect(plan.relayer.env.BRIDGE_PACKAGE_ADDRESS).toBe(bridgePackageAddress);
    expect(plan.relayer.env.RELAYER_USE_V3).toBe("1");
    expect(plan.relayer.env.RELAYER_SUBMIT_ENABLED).toBe("1");
    expect(plan.relayer.env.RESERVE_ACCOUNT_ADDRESS).toBe(reserveAccountAddress);
    expect(plan.relayer.env.RELAYER_MAX_GAS_PRICE_OCTAS).toBe("1000");
    expect(plan.relayer.env.RELAYER_RESERVE_MIN_BALANCE_OCTAS).toBe("200000000");
    expect(plan.relayer.env.BRIDGE_VAULT_ADDRESS).toBe(`0x${"9415c478".repeat(8)}`);
    expect(plan.relayer.env.BRIDGE_ASSET_TYPE).toBe("0xa");
    expect(plan.relayer.env.ADMIN_PROFILE).toBe("bridge-user");
  });

  it("keeps bearer tokens out of the public roster", () => {
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      randomHex: deterministicHex(),
    });

    const rosterJson = JSON.stringify(plan.roster);
    for (const token of Object.values(plan.nodeBearerTokens)) {
      expect(rosterJson).not.toContain(token);
    }
  });

  it("requires a real vaultEk input from CA DKG or registration tooling", () => {
    expect(() =>
      buildLocalClusterPlan({
        vaultEk: "",
        frost: {
          groupPublicKey: h32("b"),
          verifyingShares: [],
        },
      }),
    ).toThrow(/vaultEk/);
  });

  it("assembles caDkgV2Roster and frostDkgV2Roster from the same HPKE keys", () => {
    const plan = buildLocalClusterPlan({
      vaultEk: h32("a"),
      frost: {
        groupPublicKey: h32("b"),
        verifyingShares: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          frostVerifyingShare: String(slot + 1).repeat(64),
        })),
      },
      caDkgV2: {
        hpkePublicKeys: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
          slot,
          hpkePublicKey: (slot + 9).toString(16).padStart(64, "0"),
        })),
      },
      randomHex: deterministicHex(),
    });
    expect(plan.caDkgV2Roster).toBeDefined();
    expect(plan.frostDkgV2Roster).toBeDefined();
    expect(plan.caDkgV2Roster!.caDkgScheme).toBe("ca_dkg_v2");
    expect(plan.frostDkgV2Roster!.caDkgScheme).toBe("frost_dkg_v2");
    for (let slot = 0; slot < DEOPERATOR_COUNT; slot += 1) {
      expect(plan.frostDkgV2Roster!.nodes[slot].hpkePublicKey).toBe(
        plan.caDkgV2Roster!.nodes[slot].hpkePublicKey,
      );
    }
    expect(plan.frostDkgV2RosterHash).toBeDefined();
    expect(plan.frostDkgV2RosterHash).not.toBe(plan.caDkgV2RosterHash);
    expect(plan.coordinator.env.CA_DKG_V2_ROSTER_JSON_PATH).toBe(
      ".agent-local/eunoma-v2/cluster/ca-dkg-v2-roster.json",
    );
    expect(plan.coordinator.env.FROST_DKG_V2_ROSTER_JSON).toBeDefined();
    for (const node of plan.nodes) {
      expect(node.env.FROST_DKG_V2_ROSTER_JSON).toBeDefined();
    }
  });
});
