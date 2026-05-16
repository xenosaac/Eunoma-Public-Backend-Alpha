import { describe, expect, it } from "vitest";
import {
  assembleVaultStateV2InitTranscript,
  parseVaultStateV2InitRequest,
  parseVaultStateV2InitResponse,
  vaultStateV2InitFinalTranscriptHash,
  vaultStateV2InitWorkerTranscriptHash,
  VaultStateV2InitError,
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
