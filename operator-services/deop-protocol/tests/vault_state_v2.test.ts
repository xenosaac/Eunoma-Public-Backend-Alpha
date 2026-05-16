import { describe, expect, it } from "vitest";
import {
  assembleVaultStateV2InitTranscript,
  assembleVaultStateV2ObserveDepositTranscript,
  parseObserveDepositRequest,
  parseObserveDepositResponse,
  parseVaultStateV2InitRequest,
  parseVaultStateV2InitResponse,
  vaultStateV2InitFinalTranscriptHash,
  vaultStateV2InitWorkerTranscriptHash,
  vaultStateV2ObserveFinalTranscriptHash,
  vaultStateV2ObserveWorkerTranscriptHash,
  VaultStateV2InitError,
  VaultStateV2ObserveDepositError,
} from "../src/vault_state_v2.js";

const HEX32_A = "aa".repeat(32);
const HEX32_B = "bb".repeat(32);
const HEX32_C = "cc".repeat(32);
const HEX32_D = "dd".repeat(32);
const HEX32_E = "ee".repeat(32);
const HEX32_F = "ff".repeat(32);
const HEX32_1 = "11".repeat(32);
const HEX32_2 = "22".repeat(32);

function validInitRequestBody(): Record<string, unknown> {
  return {
    dkgEpoch: "1",
    requestId: "req-1",
    sessionId: "sess-1",
    caDkgTranscriptHash: HEX32_A,
    vaultEkTranscriptHash: HEX32_B,
    registrationTranscriptHash: HEX32_C,
    rosterHash: HEX32_D,
    selectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_E,
    senderAddress: HEX32_F,
    assetType: HEX32_1,
    chainId: 2,
    aggregateCommitment: HEX32_2,
    aggregateResponse: HEX32_A,
    challenge: HEX32_B,
  };
}

describe("vault_state_v2 protocol", () => {
  it("worker transcript hash is byte-stable for identical inputs", () => {
    const args = {
      sessionId: "sess-x",
      requestId: "req-x",
      dkgEpoch: "1",
      caDkgTranscriptHash: HEX32_A,
      vaultEkTranscriptHash: HEX32_B,
      registrationTranscriptHash: HEX32_C,
      rosterHash: HEX32_D,
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 2,
      playerId: 2,
      vaultEk: HEX32_E,
      senderAddress: HEX32_F,
      assetType: HEX32_1,
      chainId: 2,
      aggregateCommitment: HEX32_2,
      aggregateResponse: HEX32_A,
      challenge: HEX32_B,
      vaultSequence: 0,
      depositCountObserved: 0,
    };
    const a = vaultStateV2InitWorkerTranscriptHash(args);
    const b = vaultStateV2InitWorkerTranscriptHash(args);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("worker transcript hash changes when ANY binding changes", () => {
    const base = {
      sessionId: "sess-x",
      requestId: "req-x",
      dkgEpoch: "1",
      caDkgTranscriptHash: HEX32_A,
      vaultEkTranscriptHash: HEX32_B,
      registrationTranscriptHash: HEX32_C,
      rosterHash: HEX32_D,
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 2,
      playerId: 2,
      vaultEk: HEX32_E,
      senderAddress: HEX32_F,
      assetType: HEX32_1,
      chainId: 2,
      aggregateCommitment: HEX32_2,
      aggregateResponse: HEX32_A,
      challenge: HEX32_B,
      vaultSequence: 0,
      depositCountObserved: 0,
    };
    const baseHash = vaultStateV2InitWorkerTranscriptHash(base);
    expect(
      vaultStateV2InitWorkerTranscriptHash({ ...base, dkgEpoch: "2" }),
    ).not.toBe(baseHash);
    expect(
      vaultStateV2InitWorkerTranscriptHash({ ...base, vaultSequence: 1 }),
    ).not.toBe(baseHash);
    expect(
      vaultStateV2InitWorkerTranscriptHash({ ...base, depositCountObserved: 1 }),
    ).not.toBe(baseHash);
    expect(
      vaultStateV2InitWorkerTranscriptHash({ ...base, selfSlot: 3, playerId: 3 }),
    ).not.toBe(baseHash);
    expect(vaultStateV2InitWorkerTranscriptHash({ ...base, vaultEk: HEX32_F })).not.toBe(
      baseHash,
    );
    expect(
      vaultStateV2InitWorkerTranscriptHash({
        ...base,
        sortedSelectedSlots: [1, 2, 3, 4, 5],
      }),
    ).not.toBe(baseHash);
  });

  it("final transcript hash binds every per-slot contribution", () => {
    const slots = [0, 1, 2, 3, 4];
    const perSlotA = slots.map((slot) => ({
      slot,
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      vaultSequence: 0,
      depositCountObserved: 0,
      initialized: true,
    }));
    const perSlotB = perSlotA.map((c) =>
      c.slot === 2 ? { ...c, vaultSequence: 1 } : c,
    );
    const input = {
      dkgEpoch: "1",
      caDkgTranscriptHash: HEX32_A,
      vaultEkTranscriptHash: HEX32_B,
      registrationTranscriptHash: HEX32_C,
      rosterHash: HEX32_D,
      sortedSelectedSlots: slots,
      vaultEk: HEX32_E,
      senderAddress: HEX32_F,
      assetType: HEX32_1,
      chainId: 2,
      aggregateCommitment: HEX32_2,
      aggregateResponse: HEX32_A,
      challenge: HEX32_B,
    };
    const a = vaultStateV2InitFinalTranscriptHash({
      ...input,
      perSlotContributions: perSlotA,
    });
    const b = vaultStateV2InitFinalTranscriptHash({
      ...input,
      perSlotContributions: perSlotB,
    });
    expect(a).not.toBe(b);
  });

  it("assembleVaultStateV2InitTranscript rejects under-quorum", () => {
    const slots = [0, 1, 2, 3];
    expect(() =>
      assembleVaultStateV2InitTranscript({
        dkgEpoch: "1",
        caDkgTranscriptHash: HEX32_A,
        vaultEkTranscriptHash: HEX32_B,
        registrationTranscriptHash: HEX32_C,
        rosterHash: HEX32_D,
        selectedSlots: slots,
        vaultEk: HEX32_E,
        senderAddress: HEX32_F,
        assetType: HEX32_1,
        chainId: 2,
        aggregateCommitment: HEX32_2,
        aggregateResponse: HEX32_A,
        challenge: HEX32_B,
        perSlotContributions: [],
      }),
    ).toThrow(VaultStateV2InitError);
  });

  it("assembleVaultStateV2InitTranscript rejects duplicate slots", () => {
    expect(() =>
      assembleVaultStateV2InitTranscript({
        dkgEpoch: "1",
        caDkgTranscriptHash: HEX32_A,
        vaultEkTranscriptHash: HEX32_B,
        registrationTranscriptHash: HEX32_C,
        rosterHash: HEX32_D,
        selectedSlots: [0, 1, 2, 3, 3],
        vaultEk: HEX32_E,
        senderAddress: HEX32_F,
        assetType: HEX32_1,
        chainId: 2,
        aggregateCommitment: HEX32_2,
        aggregateResponse: HEX32_A,
        challenge: HEX32_B,
        perSlotContributions: [],
      }),
    ).toThrow(VaultStateV2InitError);
  });

  it("assembleVaultStateV2InitTranscript happy path produces stable transcriptHash", () => {
    const slots = [0, 1, 2, 3, 4];
    const perSlot = slots.map((slot) => ({
      slot,
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      vaultSequence: 0,
      depositCountObserved: 0,
      initialized: true,
    }));
    const t = assembleVaultStateV2InitTranscript({
      dkgEpoch: "1",
      caDkgTranscriptHash: HEX32_A,
      vaultEkTranscriptHash: HEX32_B,
      registrationTranscriptHash: HEX32_C,
      rosterHash: HEX32_D,
      selectedSlots: slots,
      vaultEk: HEX32_E,
      senderAddress: HEX32_F,
      assetType: HEX32_1,
      chainId: 2,
      aggregateCommitment: HEX32_2,
      aggregateResponse: HEX32_A,
      challenge: HEX32_B,
      perSlotContributions: perSlot,
    });
    expect(t.scheme).toBe("vault_state_v2");
    expect(t.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(t.perSlotContributions).toHaveLength(5);
  });

  it("parseVaultStateV2InitRequest accepts a valid wire body", () => {
    const body = validInitRequestBody();
    const parsed = parseVaultStateV2InitRequest(body);
    expect(parsed.dkgEpoch).toBe("1");
    expect(parsed.selfSlot).toBe(2);
    expect(parsed.playerId).toBe(2);
    expect(parsed.chainId).toBe(2);
  });

  it("parseVaultStateV2InitRequest rejects under-quorum selectedSlots", () => {
    const body = { ...validInitRequestBody(), selectedSlots: [0, 1, 2] };
    expect(() => parseVaultStateV2InitRequest(body)).toThrow(VaultStateV2InitError);
  });

  it("parseVaultStateV2InitRequest rejects 33-byte vaultEk", () => {
    const body = { ...validInitRequestBody(), vaultEk: "aa".repeat(33) };
    expect(() => parseVaultStateV2InitRequest(body)).toThrow(VaultStateV2InitError);
  });

  it("parseVaultStateV2InitRequest fires forbidden-plaintext-field guard", () => {
    const body = { ...validInitRequestBody(), dkShare: "abc" };
    expect(() => parseVaultStateV2InitRequest(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseVaultStateV2InitRequest fires forbidden-plaintext-field guard on nested", () => {
    const body = {
      ...validInitRequestBody(),
      metadata: { secret: "leak" },
    };
    expect(() => parseVaultStateV2InitRequest(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseVaultStateV2InitResponse accepts a valid worker response", () => {
    const r = parseVaultStateV2InitResponse({
      slot: 2,
      playerId: 2,
      vaultStatePath: "/var/state/slot-2/vault_state_v2.json",
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      vaultSequence: 0,
      depositCountObserved: 0,
      createdAtUnixMs: 1700000000000,
      initialized: true,
    });
    expect(r.slot).toBe(2);
    expect(r.initialized).toBe(true);
    expect(r.vaultStateHash).toBe(HEX32_A);
  });

  it("parseVaultStateV2InitResponse rejects missing initialized field", () => {
    expect(() =>
      parseVaultStateV2InitResponse({
        slot: 2,
        playerId: 2,
        vaultStatePath: "/p",
        vaultStateHash: HEX32_A,
        workerTranscriptHash: HEX32_B,
        vaultSequence: 0,
        depositCountObserved: 0,
        createdAtUnixMs: 1,
        // initialized missing
      }),
    ).toThrow(VaultStateV2InitError);
  });
});

// =================================================================================================
// Milestone 2 sub-milestone 2b — observe_deposit transcript types.
// =================================================================================================
function validObserveRequestBody(): Record<string, unknown> {
  return {
    dkgEpoch: "1",
    requestId: "obs-1",
    sessionId: "obs-1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    rosterHash: HEX32_C,
    selectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_D,
    senderAddress: HEX32_E,
    assetType: HEX32_F,
    chainId: 2,
    depositCount: 1,
    commitment: HEX32_1,
    amountTag: HEX32_2,
    caPayloadHash: HEX32_A,
    depositNonce: HEX32_B,
    sequenceNumber: "0",
    txVersion: "1234567",
    eventGuid: "0:0xdeadbeef",
    previousDepositCountObserved: 0,
    newDepositCountObserved: 1,
  };
}

describe("vault_state_v2 observe_deposit protocol", () => {
  it("observe worker transcript hash is byte-stable for identical inputs", () => {
    const args = {
      sessionId: "sess-x",
      requestId: "req-x",
      dkgEpoch: "1",
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 2,
      playerId: 2,
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultEk: HEX32_C,
      senderAddress: HEX32_D,
      assetType: HEX32_E,
      chainId: 2,
      depositCount: 3,
      commitment: HEX32_F,
      amountTag: HEX32_1,
      caPayloadHash: HEX32_2,
      depositNonce: HEX32_A,
      sequenceNumber: "2",
      txVersion: "9876543",
      eventGuid: "0:0xfeed",
      previousDepositCountObserved: 2,
      newDepositCountObserved: 3,
    };
    const a = vaultStateV2ObserveWorkerTranscriptHash(args);
    const b = vaultStateV2ObserveWorkerTranscriptHash(args);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("observe worker transcript hash changes when ANY binding changes", () => {
    const base = {
      sessionId: "sess-x",
      requestId: "req-x",
      dkgEpoch: "1",
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 2,
      playerId: 2,
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultEk: HEX32_C,
      senderAddress: HEX32_D,
      assetType: HEX32_E,
      chainId: 2,
      depositCount: 3,
      commitment: HEX32_F,
      amountTag: HEX32_1,
      caPayloadHash: HEX32_2,
      depositNonce: HEX32_A,
      sequenceNumber: "2",
      txVersion: "9876543",
      eventGuid: "0:0xfeed",
      previousDepositCountObserved: 2,
      newDepositCountObserved: 3,
    };
    const baseHash = vaultStateV2ObserveWorkerTranscriptHash(base);
    // KILLER: every field, when flipped, MUST move the hash.
    const mutators: Array<(b: typeof base) => typeof base> = [
      (b) => ({ ...b, sessionId: "sess-y" }),
      (b) => ({ ...b, requestId: "req-y" }),
      (b) => ({ ...b, dkgEpoch: "2" }),
      (b) => ({ ...b, sortedSelectedSlots: [1, 2, 3, 4, 5] }),
      (b) => ({ ...b, selfSlot: 3, playerId: 3 }),
      (b) => ({ ...b, vaultEkTranscriptHash: HEX32_F }),
      (b) => ({ ...b, registrationTranscriptHash: HEX32_F }),
      (b) => ({ ...b, vaultEk: HEX32_F }),
      (b) => ({ ...b, senderAddress: HEX32_F }),
      (b) => ({ ...b, assetType: HEX32_F }),
      (b) => ({ ...b, chainId: 3 }),
      (b) => ({ ...b, depositCount: 4, newDepositCountObserved: 4 }),
      (b) => ({ ...b, commitment: HEX32_1 }),
      (b) => ({ ...b, amountTag: HEX32_F }),
      (b) => ({ ...b, caPayloadHash: HEX32_F }),
      (b) => ({ ...b, depositNonce: HEX32_F }),
      (b) => ({ ...b, sequenceNumber: "3" }),
      (b) => ({ ...b, txVersion: "0" }),
      (b) => ({ ...b, eventGuid: "1:0xbeef" }),
      (b) => ({ ...b, previousDepositCountObserved: 1 }),
    ];
    for (const mutate of mutators) {
      const mutated = mutate(base);
      const mutatedHash = vaultStateV2ObserveWorkerTranscriptHash(mutated);
      expect(mutatedHash, JSON.stringify(mutated)).not.toBe(baseHash);
    }
  });

  it("observe final transcript hash binds every per-slot contribution", () => {
    const slots = [0, 1, 2, 3, 4];
    const perSlotA = slots.map((slot) => ({
      slot,
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      previousDepositCountObserved: 0,
      depositCountObserved: 1,
      vaultSequence: 0,
    }));
    const perSlotB = perSlotA.map((c) =>
      c.slot === 2 ? { ...c, vaultStateHash: HEX32_F } : c,
    );
    const input = {
      dkgEpoch: "1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      rosterHash: HEX32_C,
      sortedSelectedSlots: slots,
      vaultEk: HEX32_D,
      senderAddress: HEX32_E,
      assetType: HEX32_F,
      chainId: 2,
      depositCount: 1,
      commitment: HEX32_1,
      amountTag: HEX32_2,
      caPayloadHash: HEX32_A,
      depositNonce: HEX32_B,
      sequenceNumber: "0",
      txVersion: "1234567",
      eventGuid: "0:0xdeadbeef",
      previousDepositCountObserved: 0,
      newDepositCountObserved: 1,
    };
    const a = vaultStateV2ObserveFinalTranscriptHash({
      ...input,
      perSlotContributions: perSlotA,
    });
    const b = vaultStateV2ObserveFinalTranscriptHash({
      ...input,
      perSlotContributions: perSlotB,
    });
    expect(a).not.toBe(b);
  });

  it("assembleVaultStateV2ObserveDepositTranscript happy path", () => {
    const slots = [0, 1, 2, 3, 4];
    const perSlot = slots.map((slot) => ({
      slot,
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      previousDepositCountObserved: 0,
      depositCountObserved: 1,
      vaultSequence: 0,
    }));
    const t = assembleVaultStateV2ObserveDepositTranscript({
      dkgEpoch: "1",
      requestId: "obs-1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      rosterHash: HEX32_C,
      selectedSlots: slots,
      vaultEk: HEX32_D,
      senderAddress: HEX32_E,
      assetType: HEX32_F,
      chainId: 2,
      depositCount: 1,
      commitment: HEX32_1,
      amountTag: HEX32_2,
      caPayloadHash: HEX32_A,
      depositNonce: HEX32_B,
      sequenceNumber: "0",
      txVersion: "1234567",
      eventGuid: "0:0xdeadbeef",
      previousDepositCountObserved: 0,
      newDepositCountObserved: 1,
      perSlotContributions: perSlot,
    });
    expect(t.scheme).toBe("vault_state_v2_observe_deposit");
    expect(t.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.perSlotContributions).toHaveLength(5);
    expect(t.depositCount).toBe(1);
  });

  it("assembleVaultStateV2ObserveDepositTranscript rejects stale_deposit_count", () => {
    const slots = [0, 1, 2, 3, 4];
    const perSlot = slots.map((slot) => ({
      slot,
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      previousDepositCountObserved: 5,
      depositCountObserved: 5,
      vaultSequence: 0,
    }));
    expect(() =>
      assembleVaultStateV2ObserveDepositTranscript({
        dkgEpoch: "1",
        requestId: "obs-stale",
        vaultEkTranscriptHash: HEX32_A,
        registrationTranscriptHash: HEX32_B,
        rosterHash: HEX32_C,
        selectedSlots: slots,
        vaultEk: HEX32_D,
        senderAddress: HEX32_E,
        assetType: HEX32_F,
        chainId: 2,
        depositCount: 5, // <= previousDepositCountObserved → stale
        commitment: HEX32_1,
        amountTag: HEX32_2,
        caPayloadHash: HEX32_A,
        depositNonce: HEX32_B,
        sequenceNumber: "4",
        txVersion: "100",
        eventGuid: "0:0xfeed",
        previousDepositCountObserved: 5,
        newDepositCountObserved: 5,
        perSlotContributions: perSlot,
      }),
    ).toThrow(VaultStateV2ObserveDepositError);
  });

  it("parseObserveDepositRequest accepts a valid wire body", () => {
    const body = validObserveRequestBody();
    const parsed = parseObserveDepositRequest(body);
    expect(parsed.depositCount).toBe(1);
    expect(parsed.sequenceNumber).toBe("0");
    expect(parsed.selfSlot).toBe(2);
    expect(parsed.eventGuid).toBe("0:0xdeadbeef");
  });

  it("parseObserveDepositRequest rejects under-quorum selectedSlots", () => {
    const body = { ...validObserveRequestBody(), selectedSlots: [0, 1, 2] };
    expect(() => parseObserveDepositRequest(body)).toThrow(VaultStateV2ObserveDepositError);
  });

  it("parseObserveDepositRequest rejects 33-byte commitment", () => {
    const body = { ...validObserveRequestBody(), commitment: "aa".repeat(33) };
    expect(() => parseObserveDepositRequest(body)).toThrow(VaultStateV2ObserveDepositError);
  });

  it("parseObserveDepositRequest rejects non-decimal sequenceNumber", () => {
    const body = { ...validObserveRequestBody(), sequenceNumber: "0xabc" };
    expect(() => parseObserveDepositRequest(body)).toThrow(VaultStateV2ObserveDepositError);
  });

  it("parseObserveDepositRequest fires forbidden-plaintext-field guard", () => {
    const body = { ...validObserveRequestBody(), dkShare: "abc" };
    expect(() => parseObserveDepositRequest(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseObserveDepositRequest fires forbidden-plaintext-field guard on nullifier", () => {
    const body = { ...validObserveRequestBody(), nullifier: "abc" };
    expect(() => parseObserveDepositRequest(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseObserveDepositRequest fires forbidden-plaintext-field guard on nested", () => {
    const body = { ...validObserveRequestBody(), metadata: { secret: "leak" } };
    expect(() => parseObserveDepositRequest(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseObserveDepositResponse accepts a valid worker response", () => {
    const r = parseObserveDepositResponse({
      slot: 2,
      playerId: 2,
      vaultStatePath: "/var/state/slot-2/vault_state_v2.json",
      vaultStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      previousDepositCountObserved: 0,
      depositCountObserved: 1,
      vaultSequence: 0,
      observedAtUnixMs: 1700000000000,
      observed: true,
    });
    expect(r.slot).toBe(2);
    expect(r.depositCountObserved).toBe(1);
    expect(r.observed).toBe(true);
  });

  it("parseObserveDepositResponse rejects observed=false", () => {
    expect(() =>
      parseObserveDepositResponse({
        slot: 2,
        playerId: 2,
        vaultStatePath: "/p",
        vaultStateHash: HEX32_A,
        workerTranscriptHash: HEX32_B,
        previousDepositCountObserved: 0,
        depositCountObserved: 1,
        vaultSequence: 0,
        observedAtUnixMs: 1,
        observed: false,
      }),
    ).toThrow(VaultStateV2ObserveDepositError);
  });
});
