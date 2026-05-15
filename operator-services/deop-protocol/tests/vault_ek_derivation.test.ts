import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  caDkgV2RosterHash,
  type CaDkgV2Roster,
  type VaultEkContribution,
} from "../src/index.js";
import {
  assembleVaultEkTranscript,
  ED25519_SCALAR_Q,
  lagrangeCoefficientsAtZero,
  scalarHexFromBigint,
  VaultEkDerivationError,
  workerTranscriptHashCanonical,
} from "../src/vault_ek_derivation.js";

const h32 = (byte: string) => byte.repeat(64);

function caDkgRoster(epoch = "3"): CaDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: epoch,
    caDkgScheme: "ca_dkg_v2",
    threshold: 5,
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://127.0.0.1:80${slot}`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("c"),
    })),
  };
}

function buildContribution(args: {
  slot: number;
  hContribution: string;
  dkgEpoch: string;
  caDkgTranscriptHash: string;
  rosterHash: string;
  sortedSelectedSlots: number[];
}): VaultEkContribution {
  const workerTranscriptHash = workerTranscriptHashCanonical({
    dkgEpoch: args.dkgEpoch,
    caDkgTranscriptHash: args.caDkgTranscriptHash,
    rosterHash: args.rosterHash,
    sortedSelectedSlots: args.sortedSelectedSlots,
    slot: args.slot,
    hContribution: args.hContribution,
  });
  return {
    slot: args.slot,
    hContribution: args.hContribution,
    schnorrProof: { R: h32(args.slot.toString(16)), s: h32("a") },
    workerTranscriptHash,
  };
}

const CA = h32("a");
const DKG_EPOCH = "3";
const SLOTS = [0, 1, 2, 3, 4];

describe("assembleVaultEkTranscript", () => {
  it("returns a normalized transcript on the happy path", () => {
    const roster = caDkgRoster(DKG_EPOCH);
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    const out = assembleVaultEkTranscript({
      dkgEpoch: DKG_EPOCH,
      caDkgTranscriptHash: CA,
      selectedSlots: SLOTS,
      rosterHash,
      contributions,
      roster,
    });
    expect(out.scheme).toBe("vault_ek_derivation_v1");
    expect(out.selectedSlots).toEqual(SLOTS);
    expect(out.dkgEpoch).toBe(DKG_EPOCH);
    expect(out.caDkgTranscriptHash).toBe(CA);
    expect(out.rosterHash).toBe(rosterHash);
    expect(out.contributions).toHaveLength(5);
  });

  it("preserves byte-identity for dkgEpoch / caDkgTranscriptHash / rosterHash", () => {
    const roster = caDkgRoster(DKG_EPOCH);
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    const out = assembleVaultEkTranscript({
      dkgEpoch: DKG_EPOCH,
      caDkgTranscriptHash: CA,
      selectedSlots: SLOTS,
      rosterHash,
      contributions,
      roster,
    });
    expect(out.dkgEpoch).toBe(DKG_EPOCH);
    expect(out.caDkgTranscriptHash).toBe(CA.toLowerCase());
    expect(out.rosterHash).toBe(rosterHash);
  });

  it("UNDER_QUORUM when contributions length != 5", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    expect(() =>
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions: [],
        roster,
      }),
    ).toThrow(VaultEkDerivationError);
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions: [],
        roster,
      });
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("UNDER_QUORUM");
    }
  });

  it("UNDER_QUORUM when selectedSlots length != 5", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: [0, 1, 2, 3],
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("UNDER_QUORUM");
    }
  });

  it("DUPLICATE_SLOT when selectedSlots has duplicates", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: [0, 0, 1, 2, 3],
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("DUPLICATE_SLOT");
    }
  });

  it("DUPLICATE_SLOT when contributions repeat a slot", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((_, idx) =>
      buildContribution({
        slot: 0,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("DUPLICATE_SLOT");
    }
  });

  it("UNKNOWN_SLOT when selectedSlots entry is out of range", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: [0, 1, 2, 3, 9],
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("UNKNOWN_SLOT");
    }
  });

  it("STALE_DKG_EPOCH when roster.dkgEpoch differs from input.dkgEpoch", () => {
    const roster = caDkgRoster("4");
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("STALE_DKG_EPOCH");
    }
  });

  it("STALE_ROSTER_HASH when input.rosterHash != caDkgV2RosterHash(roster)", () => {
    const roster = caDkgRoster();
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash: h32("f"),
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash: h32("f"),
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("STALE_ROSTER_HASH");
    }
  });

  it("STALE_CA_DKG_TRANSCRIPT_HASH when caDkgTranscriptHash is not 32 bytes", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: "abcd",
        selectedSlots: SLOTS,
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("STALE_CA_DKG_TRANSCRIPT_HASH");
    }
  });

  it("INVALID_CONTRIBUTION_SHAPE when a contribution's worker_transcript_hash diverges", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const contributions = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    // Corrupt the 3rd contribution's workerTranscriptHash
    contributions[2] = {
      ...contributions[2],
      workerTranscriptHash: h32("0"),
    };
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("INVALID_CONTRIBUTION_SHAPE");
    }
  });

  it("INVALID_CONTRIBUTION_SHAPE when hContribution is not 32 bytes", () => {
    const roster = caDkgRoster();
    const rosterHash = caDkgV2RosterHash(roster);
    const valid = SLOTS.map((slot, idx) =>
      buildContribution({
        slot,
        hContribution: h32((idx + 1).toString(16)),
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        rosterHash,
        sortedSelectedSlots: SLOTS,
      }),
    );
    valid[1] = { ...valid[1], hContribution: "abcd" };
    try {
      assembleVaultEkTranscript({
        dkgEpoch: DKG_EPOCH,
        caDkgTranscriptHash: CA,
        selectedSlots: SLOTS,
        rosterHash,
        contributions: valid,
        roster,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as VaultEkDerivationError).code).toBe("INVALID_CONTRIBUTION_SHAPE");
    }
  });

  it("matches the Rust parity fixture", () => {
    const fixturePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "crypto-worker-rust",
      "tests",
      "fixtures",
      "vault_ek_derivation_parity.json",
    );
    const raw = readFileSync(fixturePath, "utf8");
    const fixture = JSON.parse(raw) as {
      dkgEpoch: string;
      caDkgTranscriptHash: string;
      rosterHash: string;
      sortedSelectedSlots: number[];
      slot: number;
      hContribution: string;
      workerTranscriptHash: string;
      workerTranscriptDomain: string;
    };
    const observed = workerTranscriptHashCanonical({
      dkgEpoch: fixture.dkgEpoch,
      caDkgTranscriptHash: fixture.caDkgTranscriptHash,
      rosterHash: fixture.rosterHash,
      sortedSelectedSlots: fixture.sortedSelectedSlots,
      slot: fixture.slot,
      hContribution: fixture.hContribution,
    });
    expect(observed).toBe(fixture.workerTranscriptHash);
    expect(fixture.workerTranscriptDomain).toBe("EUNOMA_VAULT_EK_DERIVATION_V1");
  });

  it("Lagrange coefficients match the Rust parity fixture", () => {
    const fixturePath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "crypto-worker-rust",
      "tests",
      "fixtures",
      "vault_ek_lagrange_parity.json",
    );
    const raw = readFileSync(fixturePath, "utf8");
    const fixture = JSON.parse(raw) as Record<
      string,
      { sortedSelectedSlots: number[]; lagrangeCoefficients: string[] }
    >;
    for (const [label, { sortedSelectedSlots, lagrangeCoefficients }] of Object.entries(
      fixture,
    )) {
      const observed = lagrangeCoefficientsAtZero(sortedSelectedSlots).map(scalarHexFromBigint);
      expect(observed, `Lagrange parity mismatch for ${label}`).toEqual(lagrangeCoefficients);
    }
  });

  it("Lagrange reconstruction recovers f(0) for an arbitrary degree-4 polynomial", () => {
    // f(x) = 7 + 3x + 9x^2 + 11x^3 + 5x^4 mod Q. Σ λ_i * f(x_i) must equal f(0) = 7.
    const slots = [0, 2, 3, 4, 6];
    const coeffs = [7n, 3n, 9n, 11n, 5n];
    const q = ED25519_SCALAR_Q;
    const lambdas = lagrangeCoefficientsAtZero(slots);
    let acc = 0n;
    for (let i = 0; i < slots.length; i += 1) {
      const x = BigInt(slots[i] + 1);
      // Horner mod Q
      let fx = coeffs[4];
      for (let k = 3; k >= 0; k -= 1) {
        fx = (fx * x + coeffs[k]) % q;
      }
      acc = (acc + lambdas[i] * fx) % q;
    }
    expect(acc).toBe(7n);
  });

  it("scalarHexFromBigint encodes 32 bytes little-endian", () => {
    expect(scalarHexFromBigint(0n)).toBe("00".repeat(32));
    expect(scalarHexFromBigint(1n)).toBe("01" + "00".repeat(31));
    expect(scalarHexFromBigint(256n)).toBe("0001" + "00".repeat(30));
    // Values are reduced mod Q.
    expect(scalarHexFromBigint(ED25519_SCALAR_Q)).toBe("00".repeat(32));
  });
});
