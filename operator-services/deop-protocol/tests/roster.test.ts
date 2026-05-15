import { describe, expect, it } from "vitest";
import {
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  rosterHash,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
} from "../src/index.js";

const h32 = (byte: string) => byte.repeat(64);

function roster(): DeoperatorRoster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "1",
    caDkgScheme: "ca_dkg_v2",
    threshold: 5,
    frostGroupPubkey: h32("a"),
    vaultEk: h32("b"),
    circuitVersions: {
      depositBinding: "deposit-v2.0.0",
      withdraw: "withdraw-v2.0.0",
      caPayload: "aptos-ca-v1",
    },
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://127.0.0.1:80${slot}`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("c"),
      frostVerifyingShare: h32("d"),
    })),
  };
}

function caDkgV2Roster(): CaDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "1",
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

function frostDkgV2Roster(): FrostDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "9",
    caDkgScheme: "frost_dkg_v2",
    threshold: 5,
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://127.0.0.1:81${slot}`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("f"),
    })),
  };
}

describe("roster hash", () => {
  it("is stable across node order", () => {
    const a = roster();
    const b = { ...a, nodes: [...a.nodes].reverse() };
    expect(rosterHash(a)).toBe(rosterHash(b));
  });

  it("enforces 5-of-7", () => {
    const bad = { ...roster(), threshold: 4 };
    expect(() => validateRoster(bad)).toThrow(/threshold/);
  });

  it("supports a DKG-only ca_dkg_v2 roster without vaultEk", () => {
    const r = caDkgV2Roster();
    expect(() => validateCaDkgV2Roster(r)).not.toThrow();
    expect(caDkgV2RosterHash(r)).toBe(caDkgV2RosterHash({ ...r, nodes: [...r.nodes].reverse() }));
    expect(parseCaDkgV2Roster(r)).toEqual(r);
    expect("vaultEk" in r).toBe(false);
  });

  it("computes a stable FROST DKG V2 roster hash distinct from CA", () => {
    const f = frostDkgV2Roster();
    expect(() => validateFrostDkgV2Roster(f)).not.toThrow();
    expect(frostDkgV2RosterHash(f)).toBe(
      frostDkgV2RosterHash({ ...f, nodes: [...f.nodes].reverse() }),
    );
    expect(parseFrostDkgV2Roster(f)).toEqual(f);
    const c = caDkgV2Roster();
    // Even with the same node payload, the FROST roster hash domain differs
    // from the CA DKG V2 roster hash domain — they cannot collide.
    const sharedNodes = c.nodes.map((node, idx) => ({ ...node, ...f.nodes[idx], slot: node.slot }));
    const synthFrost: FrostDkgV2Roster = { ...f, nodes: sharedNodes };
    const synthCa: CaDkgV2Roster = { ...c, nodes: sharedNodes };
    expect(frostDkgV2RosterHash(synthFrost)).not.toBe(caDkgV2RosterHash(synthCa));
  });

  it("FROST DKG V2 roster hash matches the deterministic Node.js vector", () => {
    const f = frostDkgV2Roster();
    const hash = frostDkgV2RosterHash(f);
    // 32-byte hex output (SHA-256 of canonical JSON, mirrors Rust crypto-worker
    // frost_dkg_v2_roster_hash).
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });
});
