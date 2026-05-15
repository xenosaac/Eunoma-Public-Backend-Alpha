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
});
