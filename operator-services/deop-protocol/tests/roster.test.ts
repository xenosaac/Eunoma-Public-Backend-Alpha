import { describe, expect, it } from "vitest";
import {
  applyFrostRotationToRoster,
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  prepareFrostRotationTx,
  rosterHash,
  StaleRotationStateError,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostChainView,
  type FrostDkgV2Roster,
  type FrostDkgV2WorkerArtifact,
  type FrostRotationSnapshot,
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

function workerArtifacts(shareHex: (slot: number) => string): FrostDkgV2WorkerArtifact[] {
  return Array.from({ length: 7 }, (_, slot) => ({
    slot,
    artifactHash: h32("a"),
    frostKeyPackageHash: h32("b"),
    frostPublicPackageHash: h32("c"),
    frostVerifyingShare: shareHex(slot),
  }));
}

describe("applyFrostRotationToRoster", () => {
  it("rotates shares, group key, and dkgEpoch then recomputes rosterHash", () => {
    const before = roster();
    const result = applyFrostRotationToRoster(before, {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: workerArtifacts((slot) => h32(String(slot === 0 ? 1 : slot))),
    });
    expect(result.previousRosterHash).toBe(rosterHash(before));
    expect(result.previousDkgEpoch).toBe("1");
    expect(result.previousGroupPublicKey).toBe(h32("a"));
    expect(result.roster.dkgEpoch).toBe("2");
    expect(result.roster.frostGroupPubkey).toBe(h32("9"));
    for (const node of result.roster.nodes) {
      expect(node.frostVerifyingShare).toBe(h32(String(node.slot === 0 ? 1 : node.slot)));
    }
    expect(result.rosterHash).toBe(rosterHash(result.roster));
    expect(result.rosterHash).not.toBe(result.previousRosterHash);
  });

  it("preserves operatorSetVersion, caDkgScheme, threshold, vaultEk, circuit versions, and per-node identity", () => {
    const before = roster();
    const result = applyFrostRotationToRoster(before, {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: workerArtifacts(() => h32("e")),
    });
    expect(result.roster.operatorSetVersion).toBe(before.operatorSetVersion);
    expect(result.roster.caDkgScheme).toBe(before.caDkgScheme);
    expect(result.roster.threshold).toBe(before.threshold);
    expect(result.roster.vaultEk).toBe(before.vaultEk);
    expect(result.roster.circuitVersions).toEqual(before.circuitVersions);
    for (const [idx, node] of result.roster.nodes.entries()) {
      expect(node.nodeId).toBe(before.nodes[idx].nodeId);
      expect(node.endpoint).toBe(before.nodes[idx].endpoint);
      expect(node.hpkePublicKey).toBe(before.nodes[idx].hpkePublicKey);
      expect(node.transcriptPublicKey).toBe(before.nodes[idx].transcriptPublicKey);
    }
  });

  it("does not mutate the input roster", () => {
    const before = roster();
    const snapshot = JSON.parse(JSON.stringify(before));
    applyFrostRotationToRoster(before, {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: workerArtifacts(() => h32("e")),
    });
    expect(before).toEqual(snapshot);
  });

  it("is deterministic across two calls with the same input", () => {
    const before = roster();
    const input = {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: workerArtifacts((slot) => h32(String(slot + 1))),
    };
    const first = applyFrostRotationToRoster(before, input);
    const second = applyFrostRotationToRoster(before, input);
    expect(first.rosterHash).toBe(second.rosterHash);
    expect(first.roster).toEqual(second.roster);
  });

  it("ignores workerArtifacts ordering — input shuffle yields identical rosterHash", () => {
    const before = roster();
    const ordered = workerArtifacts((slot) => h32(String(slot + 1)));
    const shuffled = [ordered[3], ordered[0], ordered[5], ordered[2], ordered[6], ordered[1], ordered[4]];
    const a = applyFrostRotationToRoster(before, {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: ordered,
    });
    const b = applyFrostRotationToRoster(before, {
      groupPublicKey: h32("9"),
      dkgEpoch: "2",
      workerArtifacts: shuffled,
    });
    expect(a.rosterHash).toBe(b.rosterHash);
    expect(a.roster).toEqual(b.roster);
  });

  it("rejects worker artifacts with fewer than 7 entries", () => {
    const before = roster();
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "2",
        workerArtifacts: workerArtifacts(() => h32("e")).slice(0, 6),
      }),
    ).toThrow(/7 entries/);
  });

  it("rejects duplicate slots in worker artifacts", () => {
    const before = roster();
    const arts = workerArtifacts(() => h32("e"));
    arts[3] = { ...arts[3], slot: 0 };
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "2",
        workerArtifacts: arts,
      }),
    ).toThrow(/duplicate/);
  });

  it("rejects missing slot in worker artifacts", () => {
    const before = roster();
    const arts = workerArtifacts(() => h32("e"));
    arts[3] = { ...arts[3], slot: 9 };
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "2",
        workerArtifacts: arts,
      }),
    ).toThrow(/invalid workerArtifacts slot/);
  });

  it("rejects a verifying share of wrong length", () => {
    const before = roster();
    const arts = workerArtifacts(() => h32("e"));
    arts[2] = { ...arts[2], frostVerifyingShare: "abcd" };
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "2",
        workerArtifacts: arts,
      }),
    ).toThrow(/frostVerifyingShare/);
  });

  it("rejects a group public key of wrong length", () => {
    const before = roster();
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: "deadbeef",
        dkgEpoch: "2",
        workerArtifacts: workerArtifacts(() => h32("e")),
      }),
    ).toThrow(/groupPublicKey/);
  });

  it("rejects a dkgEpoch equal to the current one", () => {
    const before = roster();
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "1",
        workerArtifacts: workerArtifacts(() => h32("e")),
      }),
    ).toThrow(/strictly greater/);
  });

  it("rejects a dkgEpoch lower than the current one", () => {
    const before = { ...roster(), dkgEpoch: "5" };
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "4",
        workerArtifacts: workerArtifacts(() => h32("e")),
      }),
    ).toThrow(/strictly greater/);
  });

  it("rejects a non-decimal dkgEpoch", () => {
    const before = roster();
    expect(() =>
      applyFrostRotationToRoster(before, {
        groupPublicKey: h32("9"),
        dkgEpoch: "0x2",
        workerArtifacts: workerArtifacts(() => h32("e")),
      }),
    ).toThrow(/decimal string/);
  });
});

function realRoster(): DeoperatorRoster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "3",
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
      nodeId: `deop-${slot}.real.example`,
      endpoint: `https://deop-${slot}.real.example:8443`,
      hpkePublicKey: h32(((slot + 1) % 16).toString(16)),
      transcriptPublicKey: h32(((slot + 8) % 16).toString(16)),
      frostVerifyingShare: h32("d"),
    })),
  };
}

function rotationFixture(): {
  currentRoster: DeoperatorRoster;
  chainView: FrostChainView;
  snapshot: FrostRotationSnapshot;
  dkgArtifact: { groupPublicKey: string; workerArtifactHashes: FrostDkgV2WorkerArtifact[] };
} {
  const currentRoster = realRoster();
  const chainView: FrostChainView = {
    operatorSetVersion: currentRoster.operatorSetVersion,
    dkgEpoch: currentRoster.dkgEpoch,
    rosterHash: rosterHash(currentRoster),
    frostGroupPubkey: currentRoster.frostGroupPubkey,
    vaultEk: currentRoster.vaultEk,
  };
  const snapshot: FrostRotationSnapshot = {
    operatorSetVersion: currentRoster.operatorSetVersion,
    dkgEpoch: currentRoster.dkgEpoch,
    vaultEk: currentRoster.vaultEk,
    depositCircuitVersion: h32("5"),
    withdrawCircuitVersion: h32("6"),
    caPayloadCircuitVersion: h32("7"),
    fallbackPubkeys: Array.from({ length: 7 }, (_, i) => h32((i + 1).toString(16))),
  };
  const dkgArtifact = {
    groupPublicKey: h32("9"),
    workerArtifactHashes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      artifactHash: h32("a"),
      frostKeyPackageHash: h32("b"),
      frostPublicPackageHash: h32("c"),
      frostVerifyingShare: h32(((slot + 2) % 16).toString(16)),
    })),
  };
  return { currentRoster, chainView, snapshot, dkgArtifact };
}

describe("prepareFrostRotationTx", () => {
  it("happy path: rotates roster + assembles moveCallArgs with chain-anchored fields", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const out = prepareFrostRotationTx({ currentRoster, chainView, snapshot, dkgArtifact });
    expect(out.previousRosterHash).toBe(rosterHash(currentRoster));
    expect(out.rotatedRoster.dkgEpoch).toBe("4");
    expect(out.rotatedRoster.frostGroupPubkey).toBe(h32("9"));
    expect(out.rotatedRosterHash).toBe(rosterHash(out.rotatedRoster));
    expect(out.rotatedRosterHash).not.toBe(out.previousRosterHash);
    expect(out.moveCallArgs.operatorSetVersion).toBe(currentRoster.operatorSetVersion);
    expect(out.moveCallArgs.newDkgEpoch).toBe("4");
    expect(out.moveCallArgs.rotatedRosterHash).toBe(out.rotatedRosterHash);
    expect(out.moveCallArgs.rotatedFrostGroupPubkey).toBe(out.rotatedRoster.frostGroupPubkey);
    expect(out.moveCallArgs.vaultEk).toBe(snapshot.vaultEk);
    expect(out.moveCallArgs.depositCircuitVersion).toBe(snapshot.depositCircuitVersion);
    expect(out.moveCallArgs.withdrawCircuitVersion).toBe(snapshot.withdrawCircuitVersion);
    expect(out.moveCallArgs.caPayloadCircuitVersion).toBe(snapshot.caPayloadCircuitVersion);
    expect(out.moveCallArgs.fallbackPubkeys).toEqual(snapshot.fallbackPubkeys);
  });

  it("preserves operator_set_version, caDkgScheme, threshold, vaultEk, circuit versions, per-node identity", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const out = prepareFrostRotationTx({ currentRoster, chainView, snapshot, dkgArtifact });
    expect(out.rotatedRoster.operatorSetVersion).toBe(currentRoster.operatorSetVersion);
    expect(out.rotatedRoster.caDkgScheme).toBe(currentRoster.caDkgScheme);
    expect(out.rotatedRoster.threshold).toBe(currentRoster.threshold);
    expect(out.rotatedRoster.vaultEk).toBe(currentRoster.vaultEk);
    expect(out.rotatedRoster.circuitVersions).toEqual(currentRoster.circuitVersions);
    for (const [idx, node] of out.rotatedRoster.nodes.entries()) {
      expect(node.nodeId).toBe(currentRoster.nodes[idx].nodeId);
      expect(node.endpoint).toBe(currentRoster.nodes[idx].endpoint);
      expect(node.hpkePublicKey).toBe(currentRoster.nodes[idx].hpkePublicKey);
      expect(node.transcriptPublicKey).toBe(currentRoster.nodes[idx].transcriptPublicKey);
    }
  });

  it("throws STALE_ROSTER_HASH when a synthetic placeholder roster is passed in place of the real one", () => {
    const { chainView, snapshot, dkgArtifact } = rotationFixture();
    const syntheticRoster: DeoperatorRoster = {
      operatorSetVersion: chainView.operatorSetVersion,
      dkgEpoch: chainView.dkgEpoch,
      caDkgScheme: "ca_dkg_v2",
      threshold: 5,
      frostGroupPubkey: chainView.frostGroupPubkey,
      vaultEk: chainView.vaultEk,
      circuitVersions: {
        depositBinding: "deposit-v2.0.0",
        withdraw: "withdraw-v2.0.0",
        caPayload: "aptos-ca-v1",
      },
      nodes: Array.from({ length: 7 }, (_, slot) => ({
        slot,
        nodeId: `chain-deop-${slot}`,
        endpoint: `chain://deop-${slot}`,
        hpkePublicKey: "00".repeat(32),
        transcriptPublicKey: "00".repeat(32),
        frostVerifyingShare: "00".repeat(32),
      })),
    };
    expect(() =>
      prepareFrostRotationTx({ currentRoster: syntheticRoster, chainView, snapshot, dkgArtifact }),
    ).toThrow(StaleRotationStateError);
    try {
      prepareFrostRotationTx({ currentRoster: syntheticRoster, chainView, snapshot, dkgArtifact });
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_ROSTER_HASH");
    }
  });

  it("throws STALE_ROSTER_HASH when the real roster's hash drifts from chain.rosterHash", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const drifted: FrostChainView = { ...chainView, rosterHash: h32("f") };
    try {
      prepareFrostRotationTx({ currentRoster, chainView: drifted, snapshot, dkgArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_ROSTER_HASH");
    }
  });

  it("throws STALE_CHAIN_OPERATOR_SET_VERSION when currentRoster.operatorSetVersion disagrees with chain", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedChain: FrostChainView = { ...chainView, operatorSetVersion: "2" };
    const driftedSnapshot: FrostRotationSnapshot = { ...snapshot, operatorSetVersion: "2" };
    try {
      prepareFrostRotationTx({
        currentRoster,
        chainView: driftedChain,
        snapshot: driftedSnapshot,
        dkgArtifact,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_CHAIN_OPERATOR_SET_VERSION");
    }
  });

  it("throws STALE_CHAIN_DKG_EPOCH when currentRoster.dkgEpoch disagrees with chain", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedChain: FrostChainView = { ...chainView, dkgEpoch: "99" };
    const driftedSnapshot: FrostRotationSnapshot = { ...snapshot, dkgEpoch: "99" };
    try {
      prepareFrostRotationTx({
        currentRoster,
        chainView: driftedChain,
        snapshot: driftedSnapshot,
        dkgArtifact,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_CHAIN_DKG_EPOCH");
    }
  });

  it("throws STALE_CHAIN_VAULT_EK when currentRoster.vaultEk disagrees with chain", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedRoster: DeoperatorRoster = { ...currentRoster, vaultEk: h32("e") };
    const realignedChain: FrostChainView = {
      ...chainView,
      rosterHash: rosterHash(driftedRoster),
    };
    try {
      prepareFrostRotationTx({
        currentRoster: driftedRoster,
        chainView: realignedChain,
        snapshot,
        dkgArtifact,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_CHAIN_VAULT_EK");
    }
  });

  it("throws STALE_CHAIN_FROST_GROUP_PUBKEY when currentRoster.frostGroupPubkey disagrees with chain", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedRoster: DeoperatorRoster = { ...currentRoster, frostGroupPubkey: h32("e") };
    const realignedChain: FrostChainView = {
      ...chainView,
      rosterHash: rosterHash(driftedRoster),
    };
    try {
      prepareFrostRotationTx({
        currentRoster: driftedRoster,
        chainView: realignedChain,
        snapshot,
        dkgArtifact,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_CHAIN_FROST_GROUP_PUBKEY");
    }
  });

  it("throws STALE_SNAPSHOT_OPERATOR_SET_VERSION when snapshot drifts from chain", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedSnapshot: FrostRotationSnapshot = { ...snapshot, operatorSetVersion: "2" };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot: driftedSnapshot, dkgArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_SNAPSHOT_OPERATOR_SET_VERSION");
    }
  });

  it("throws STALE_SNAPSHOT_DKG_EPOCH when snapshot.dkgEpoch disagrees with chain.dkgEpoch", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedSnapshot: FrostRotationSnapshot = { ...snapshot, dkgEpoch: "99" };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot: driftedSnapshot, dkgArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_SNAPSHOT_DKG_EPOCH");
    }
  });

  it("throws STALE_SNAPSHOT_VAULT_EK when snapshot.vaultEk disagrees with chain.vaultEk", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const driftedSnapshot: FrostRotationSnapshot = { ...snapshot, vaultEk: h32("e") };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot: driftedSnapshot, dkgArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("STALE_SNAPSHOT_VAULT_EK");
    }
  });

  it("throws INVALID_FALLBACK_PUBKEYS for wrong length or wrong hex byte count", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const shortFallback: FrostRotationSnapshot = {
      ...snapshot,
      fallbackPubkeys: snapshot.fallbackPubkeys.slice(0, 6),
    };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot: shortFallback, dkgArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("INVALID_FALLBACK_PUBKEYS");
    }
    const wrongLenFallback: FrostRotationSnapshot = {
      ...snapshot,
      fallbackPubkeys: snapshot.fallbackPubkeys.map((_, i) => (i === 0 ? "abcd" : snapshot.fallbackPubkeys[i])),
    };
    try {
      prepareFrostRotationTx({
        currentRoster,
        chainView,
        snapshot: wrongLenFallback,
        dkgArtifact,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("INVALID_FALLBACK_PUBKEYS");
    }
  });

  it("throws INVALID_DKG_ARTIFACT for wrong-count workerArtifactHashes or wrong-length groupPublicKey", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const shortArtifact = {
      ...dkgArtifact,
      workerArtifactHashes: dkgArtifact.workerArtifactHashes.slice(0, 6),
    };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot, dkgArtifact: shortArtifact });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("INVALID_DKG_ARTIFACT");
    }
    const shortKey = { ...dkgArtifact, groupPublicKey: "deadbeef" };
    try {
      prepareFrostRotationTx({ currentRoster, chainView, snapshot, dkgArtifact: shortKey });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(StaleRotationStateError);
      expect((err as StaleRotationStateError).code).toBe("INVALID_DKG_ARTIFACT");
    }
  });

  it("honors newDkgEpoch override and refuses non-monotonic overrides", () => {
    const { currentRoster, chainView, snapshot, dkgArtifact } = rotationFixture();
    const out = prepareFrostRotationTx({
      currentRoster,
      chainView,
      snapshot,
      dkgArtifact,
      newDkgEpoch: "42",
    });
    expect(out.rotatedRoster.dkgEpoch).toBe("42");
    expect(out.moveCallArgs.newDkgEpoch).toBe("42");
    expect(() =>
      prepareFrostRotationTx({
        currentRoster,
        chainView,
        snapshot,
        dkgArtifact,
        newDkgEpoch: currentRoster.dkgEpoch,
      }),
    ).toThrow(/strictly greater/);
  });
});
