import { describe, expect, it } from "vitest";
import type { HexString } from "@eunoma/shared";
import type { HpkeEnvelope } from "../src/types.js";
import {
  assembleMpccaWithdrawTranscript,
  buildCaPayloadFromFinalizeArtifact,
  canonicalJsonStringify,
  DK_BASE_INDICES_CANONICAL,
  EUNOMA_M1_AMOUNT_INGRESS_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1,
  EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2,
  ingressEnvelopesHash,
  m1IngressAad,
  MpccaWithdrawV2Error,
  mpccaWithdrawFinalTranscriptHash,
  mpccaWithdrawFinalizeAggregatedCommitmentsHash,
  mpccaWithdrawFinalizeAggregateHash,
  mpccaWithdrawFinalizeWorkerTranscriptHash,
  mpccaWithdrawProveWorkerTranscriptHash,
  mpccaWithdrawRound1WorkerTranscriptHash,
  mpccaWithdrawRound2AggregateHash,
  mpccaWithdrawRound2StatementInputsHash,
  mpccaWithdrawRound2WorkerTranscriptHash,
  parseMpccaWithdrawFinalizeDkResult,
  parseMpccaWithdrawFinalizeOrchestrateRequest,
  parseMpccaWithdrawFinalizeRequest,
  parseMpccaWithdrawFinalizeResponse,
  parseMpccaWithdrawProveRequest,
  parseMpccaWithdrawProveResponse,
  parseMpccaWithdrawRound1Request,
  parseMpccaWithdrawRound1Response,
  parseMpccaWithdrawRound2DkResult,
  parseMpccaWithdrawRound2OrchestrateRequest,
  parseMpccaWithdrawRound2Request,
  parseMpccaWithdrawRound2Response,
  perShareCommitmentsHash,
  ROUND2_ELL,
  ROUND2_N,
  USER_SIGMA_COMMITMENTS_LEN,
  USER_SIGMA_RESPONSE_SHARES_LEN,
  type MpccaWithdrawRound2StatementInputFields,
} from "../src/mpcca_withdraw_v2.js";

const HEX32_A = "aa".repeat(32);
const HEX32_B = "bb".repeat(32);
const HEX32_C = "cc".repeat(32);
const HEX32_D = "dd".repeat(32);
const HEX32_E = "ee".repeat(32);
const HEX32_F = "ff".repeat(32);
const HEX32_1 = "11".repeat(32);
const HEX32_2 = "22".repeat(32);
const HEX32_3 = "33".repeat(32);
const HEX32_4 = "44".repeat(32);
const HEX32_5 = "55".repeat(32);
const HEX32_6 = "66".repeat(32);
const HEX32_7 = "77".repeat(32);
const HEX32_8 = "88".repeat(32);
const HEX32_9 = "99".repeat(32);
const HEX32_0 = "00".repeat(32);

function mockEnvelope(seed: number): HpkeEnvelope {
  const seedByte = seed.toString(16).padStart(2, "0");
  return {
    kem: "DHKEM_X25519_HKDF_SHA256",
    kdf: "HKDF_SHA256",
    aead: "AES_256_GCM",
    enc: seedByte.repeat(32),
    // 80-byte ciphertext = 64-byte plaintext + 16-byte GCM tag.
    ciphertext: seedByte.repeat(80),
    aadHash: seedByte.repeat(32),
  };
}

const VALID_INGRESS = {
  amountCommitment: "ac".repeat(32),
  perShareCommitments: [
    "11".repeat(32),
    "22".repeat(32),
    "33".repeat(32),
    "44".repeat(32),
    "55".repeat(32),
  ],
  ingressEnvelopes: [
    mockEnvelope(0x11),
    mockEnvelope(0x22),
    mockEnvelope(0x33),
    mockEnvelope(0x44),
    mockEnvelope(0x55),
  ],
};

function validRound1Body(): Record<string, unknown> {
  return {
    dkgEpoch: "1",
    requestId: "withdraw-r1",
    sessionId: "withdraw-r1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D, HEX32_E],
    rosterHash: HEX32_F,
    selectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    amountCommitment: VALID_INGRESS.amountCommitment,
    perShareCommitments: [...VALID_INGRESS.perShareCommitments],
    ingressEnvelopes: VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e })),
  };
}

function validChainedBody(): Record<string, unknown> {
  const body = validRound1Body();
  // Chained rounds do NOT carry ingress fields — drop them.
  delete (body as Record<string, unknown>).amountCommitment;
  delete (body as Record<string, unknown>).perShareCommitments;
  delete (body as Record<string, unknown>).ingressEnvelopes;
  return {
    ...body,
    previousRoundTranscriptHash: HEX32_0,
    previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
  };
}

/**
 * M4 Commit 1+2 — fixed Statement inputs for byte-parity tests with Rust. Each entry uses
 * a deterministic distinct hex pattern so a single-field swap visibly changes the hash.
 * Lengths match the canonical Aptos CA TransferV1 shape (ell=8, n=4). Every hex string
 * is exactly 64 chars = 32 bytes.
 */
function genHex32(group: string, i: number): string {
  // 4 hex chars per "slot": group(2) + idx(2). Repeated 16 times → 64 chars = 32 bytes.
  const idx = i.toString(16).padStart(2, "0");
  return (group + idx).repeat(16);
}
const VALID_STATEMENT_INPUTS: MpccaWithdrawRound2StatementInputFields = {
  recipientEk: "a1".repeat(32),
  oldBalanceC: Array.from({ length: ROUND2_ELL }, (_, i) => genHex32("b0", i)),
  oldBalanceD: Array.from({ length: ROUND2_ELL }, (_, i) => genHex32("c0", i)),
  newBalanceC: Array.from({ length: ROUND2_ELL }, (_, i) => genHex32("d0", i)),
  newBalanceD: Array.from({ length: ROUND2_ELL }, (_, i) => genHex32("e0", i)),
  transferAmountC: Array.from({ length: ROUND2_N }, (_, i) => genHex32("f0", i)),
  transferAmountDSender: Array.from({ length: ROUND2_N }, (_, i) =>
    genHex32("12", i),
  ),
  transferAmountDRecipient: Array.from({ length: ROUND2_N }, (_, i) =>
    genHex32("23", i),
  ),
};

function validChainedRound2Body(): Record<string, unknown> {
  return { ...validChainedBody(), ...VALID_STATEMENT_INPUTS };
}

const VALID_USER_SIGMA_COMMITMENTS = Array.from(
  { length: USER_SIGMA_COMMITMENTS_LEN },
  (_, i) => genHex32("34", i),
);
const VALID_USER_SIGMA_RESPONSE_SHARES = Array.from(
  { length: USER_SIGMA_RESPONSE_SHARES_LEN },
  (_, i) => genHex32("45", i),
);
const VALID_PER_CHUNK_COMMITMENTS_AMOUNT = Array.from(
  { length: ROUND2_N },
  (_, i) => genHex32("56", i),
);
const VALID_PER_CHUNK_COMMITMENTS_NEW_BALANCE = Array.from(
  { length: ROUND2_ELL },
  (_, i) => genHex32("67", i),
);

function validRound2OrchestrateBody(): Record<string, unknown> {
  const base = validRound1Body();
  delete (base as Record<string, unknown>).amountCommitment;
  delete (base as Record<string, unknown>).perShareCommitments;
  delete (base as Record<string, unknown>).ingressEnvelopes;
  return {
    ...base,
    ...VALID_STATEMENT_INPUTS,
    userSigmaCommitmentsHex: VALID_USER_SIGMA_COMMITMENTS,
    userSigmaResponseSharesHex: VALID_USER_SIGMA_RESPONSE_SHARES,
    bulletproofZkrpAmountHex: "ab".repeat(96),
    bulletproofZkrpNewBalanceHex: "cd".repeat(160),
    perChunkCommitmentsAmountHex: VALID_PER_CHUNK_COMMITMENTS_AMOUNT,
    perChunkCommitmentsNewBalanceHex: VALID_PER_CHUNK_COMMITMENTS_NEW_BALANCE,
  };
}

function validRound2DkResultBody(slot = 2): Record<string, unknown> {
  return {
    slot,
    playerId: slot,
    sessionStatePath: `/tmp/state/mpc-sessions/wdr/mpcca_withdraw_v2_round2.json`,
    sessionStateHash: HEX32_A,
    workerTranscriptHash: HEX32_B,
    observedAtUnixMs: 1_700_000_000_000,
    completed: true,
    partialDkCommitments: [
      { index: 0, commitmentHex: HEX32_1 },
      { index: 17, commitmentHex: HEX32_2 },
    ],
    dkBaseIndicesUsed: [0, 17],
  };
}

function validStubResponseBody(notImplementedPhase: string): Record<string, unknown> {
  return {
    slot: 2,
    playerId: 2,
    sessionStatePath: "/tmp/state/mpc-sessions/withdraw-r1__withdraw-r1/mpcca_withdraw_v2_round1.json",
    sessionStateHash: HEX32_A,
    workerTranscriptHash: HEX32_B,
    observedAtUnixMs: 1_700_000_000_000,
    completed: false,
    notImplementedPhase,
  };
}

function validRound1ResponseBody(): Record<string, unknown> {
  return {
    slot: 2,
    playerId: 2,
    sessionStatePath: "/tmp/state/mpc-sessions/withdraw-r1__withdraw-r1/mpcca_withdraw_v2_round1.json",
    sessionStateHash: HEX32_A,
    workerTranscriptHash: HEX32_B,
    observedAtUnixMs: 1_700_000_000_000,
    completed: true,
    ingressTranscriptHash: HEX32_B,
  };
}

describe("mpcca_withdraw_v2 protocol — domain constants are distinct per round", () => {
  it("each round has its own domain string", () => {
    const all = new Set([
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2,
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2,
      EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1,
      EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
      EUNOMA_M1_AMOUNT_INGRESS_V1,
    ]);
    expect(all.size).toBe(7);
  });
});

describe("mpcca_withdraw_v2 round1 worker transcript hash (M1 V2 with ingress binding)", () => {
  const base = {
    sessionId: "sess-x",
    requestId: "req-x",
    dkgEpoch: "1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D, HEX32_E],
    rosterHash: HEX32_F,
    sortedSelectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    amountCommitment: VALID_INGRESS.amountCommitment,
    perShareCommitments: VALID_INGRESS.perShareCommitments,
    ingressEnvelopesHash: ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes),
  };

  it("round1 hash is byte-stable for identical inputs", () => {
    const a = mpccaWithdrawRound1WorkerTranscriptHash(base);
    const b = mpccaWithdrawRound1WorkerTranscriptHash(base);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round1 hash changes when ANY single field changes (including new ingress fields)", () => {
    const baseHash = mpccaWithdrawRound1WorkerTranscriptHash(base);
    const mutators: Array<(b: typeof base) => typeof base> = [
      (b) => ({ ...b, sessionId: "sess-y" }),
      (b) => ({ ...b, requestId: "req-y" }),
      (b) => ({ ...b, dkgEpoch: "2" }),
      (b) => ({ ...b, vaultEkTranscriptHash: HEX32_F }),
      (b) => ({ ...b, registrationTranscriptHash: HEX32_F }),
      (b) => ({ ...b, vaultStateInitTranscriptHash: HEX32_F }),
      (b) => ({ ...b, observedDepositTranscriptHashes: [HEX32_D] }),
      (b) => ({ ...b, observedDepositTranscriptHashes: [HEX32_E, HEX32_D] }), // ordering
      (b) => ({ ...b, rosterHash: HEX32_0 }),
      (b) => ({ ...b, sortedSelectedSlots: [1, 2, 3, 4, 5] }),
      (b) => ({ ...b, selfSlot: 3, playerId: 3 }),
      (b) => ({ ...b, vaultEk: HEX32_F }),
      (b) => ({ ...b, senderAddress: HEX32_F }),
      (b) => ({ ...b, assetType: HEX32_F }),
      (b) => ({ ...b, chainId: 3 }),
      (b) => ({ ...b, root: HEX32_F }),
      (b) => ({ ...b, nullifierHash: HEX32_F }),
      (b) => ({ ...b, recipient: HEX32_F }),
      (b) => ({ ...b, recipientHash: HEX32_F }),
      (b) => ({ ...b, amountTag: HEX32_F }),
      (b) => ({ ...b, vaultSequence: 5 }),
      (b) => ({ ...b, expirySecs: 1_700_000_001 }),
      (b) => ({ ...b, requestHash: HEX32_F }),
      (b) => ({ ...b, depositCount: 8 }),
      // M1 ingress fields — every one must flip the round1 hash.
      (b) => ({ ...b, amountCommitment: HEX32_F }),
      (b) => ({
        ...b,
        perShareCommitments: [HEX32_F, HEX32_2, HEX32_3, HEX32_4, HEX32_5],
      }),
      (b) => ({ ...b, ingressEnvelopesHash: HEX32_F }),
    ];
    for (const mutate of mutators) {
      const mutated = mutate(base);
      expect(mpccaWithdrawRound1WorkerTranscriptHash(mutated), JSON.stringify(mutated)).not.toBe(
        baseHash,
      );
    }
  });

  it("round1 hash uses domain V2 (binds the ingress fields)", () => {
    // A V1-style hash (no ingress fields) would necessarily differ from V2: the V2 domain
    // string is bigger and the appended ingress bytes shift the input. We don't expose a
    // V1 hash function publicly (V1 stub-mode is gone); this test just confirms the V2
    // domain is non-empty and the export name matches.
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2).toBe("EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2");
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2).not.toBe(EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V1);
  });
});

describe("mpcca_withdraw_v2 chained rounds (round2/prove/finalize)", () => {
  const chainedBase = {
    sessionId: "sess-x",
    requestId: "req-x",
    dkgEpoch: "1",
    vaultEkTranscriptHash: HEX32_A,
    registrationTranscriptHash: HEX32_B,
    vaultStateInitTranscriptHash: HEX32_C,
    observedDepositTranscriptHashes: [HEX32_D],
    rosterHash: HEX32_F,
    sortedSelectedSlots: [0, 1, 2, 3, 4],
    selfSlot: 2,
    playerId: 2,
    vaultEk: HEX32_1,
    senderAddress: HEX32_2,
    assetType: HEX32_3,
    chainId: 2,
    root: HEX32_4,
    nullifierHash: HEX32_5,
    recipient: HEX32_6,
    recipientHash: HEX32_7,
    amountTag: HEX32_8,
    vaultSequence: 4,
    expirySecs: 1_700_000_000,
    requestHash: HEX32_9,
    depositCount: 7,
    previousRoundTranscriptHash: HEX32_0,
    previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
  };
  const round2Base = { ...chainedBase, statementInputs: VALID_STATEMENT_INPUTS };
  const FINALIZE_AGG: HexString[] = Array.from({ length: 30 }, (_, i) =>
    `${(0x70 + i).toString(16).padStart(2, "0")}`.repeat(32),
  );
  const FINALIZE_CHALLENGE_HEX = HEX32_B;
  const finalizeBase = {
    ...chainedBase,
    statementInputs: VALID_STATEMENT_INPUTS,
    aggregatedSigmaCommitmentsHex: FINALIZE_AGG,
    challengeHex: FINALIZE_CHALLENGE_HEX,
  };

  it("each chained round returns distinct hashes for the same body", () => {
    const r2 = mpccaWithdrawRound2WorkerTranscriptHash(round2Base);
    const pr = mpccaWithdrawProveWorkerTranscriptHash(chainedBase);
    const fin = mpccaWithdrawFinalizeWorkerTranscriptHash(finalizeBase);
    expect(new Set([r2, pr, fin]).size).toBe(3);
    expect(r2).toMatch(/^[0-9a-f]{64}$/);
    expect(pr).toMatch(/^[0-9a-f]{64}$/);
    expect(fin).toMatch(/^[0-9a-f]{64}$/);
  });

  it("round2 chained hash changes when previousRoundTranscriptHash flips", () => {
    const baseHash = mpccaWithdrawRound2WorkerTranscriptHash(round2Base);
    expect(
      mpccaWithdrawRound2WorkerTranscriptHash({
        ...round2Base,
        previousRoundTranscriptHash: HEX32_F,
      }),
    ).not.toBe(baseHash);
  });

  it("chained hash changes when ANY previousRoundCommitments entry flips", () => {
    const baseHash = mpccaWithdrawProveWorkerTranscriptHash(chainedBase);
    const mutated = {
      ...chainedBase,
      previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_F, HEX32_D, HEX32_E],
    };
    expect(mpccaWithdrawProveWorkerTranscriptHash(mutated)).not.toBe(baseHash);
  });

  // M4 Commit 1+2 — round2 worker_transcript_hash now binds Statement input fields.
  // A single flip in ANY Statement field MUST change the round2 hash. This is the
  // load-bearing wedge that prevents a coordinator from forwarding tampered Statement
  // inputs without all 5 workers diverging at the transcript-hash cross-check.
  it("round2 hash binds the Statement input set (single-field flips)", () => {
    const baseHash = mpccaWithdrawRound2WorkerTranscriptHash(round2Base);
    const flipped: Array<MpccaWithdrawRound2StatementInputFields> = [
      { ...VALID_STATEMENT_INPUTS, recipientEk: HEX32_F },
      {
        ...VALID_STATEMENT_INPUTS,
        oldBalanceC: [
          HEX32_F,
          ...VALID_STATEMENT_INPUTS.oldBalanceC.slice(1),
        ],
      },
      {
        ...VALID_STATEMENT_INPUTS,
        newBalanceD: [
          ...VALID_STATEMENT_INPUTS.newBalanceD.slice(0, 4),
          HEX32_F,
          ...VALID_STATEMENT_INPUTS.newBalanceD.slice(5),
        ],
      },
      {
        ...VALID_STATEMENT_INPUTS,
        transferAmountC: [
          HEX32_F,
          ...VALID_STATEMENT_INPUTS.transferAmountC.slice(1),
        ],
      },
      {
        ...VALID_STATEMENT_INPUTS,
        transferAmountDRecipient: [
          ...VALID_STATEMENT_INPUTS.transferAmountDRecipient.slice(0, 3),
          HEX32_F,
        ],
      },
    ];
    for (const stmt of flipped) {
      expect(
        mpccaWithdrawRound2WorkerTranscriptHash({
          ...round2Base,
          statementInputs: stmt,
        }),
      ).not.toBe(baseHash);
    }
  });

  it("round2 hash is byte-stable for identical Statement inputs", () => {
    const a = mpccaWithdrawRound2WorkerTranscriptHash(round2Base);
    const b = mpccaWithdrawRound2WorkerTranscriptHash({
      ...round2Base,
      statementInputs: { ...VALID_STATEMENT_INPUTS },
    });
    expect(a).toBe(b);
  });

  it("round2 statement_inputs hash is byte-stable + length 64", () => {
    const h = mpccaWithdrawRound2StatementInputsHash(VALID_STATEMENT_INPUTS);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe(mpccaWithdrawRound2StatementInputsHash(VALID_STATEMENT_INPUTS));
  });

  /**
   * M4 Commit 2 — TS↔Rust byte-parity. The Rust test
   * `mpcca_withdraw_v2_round2_statement_inputs_hash_byte_parity_with_ts_fixture` asserts
   * the same hex. If either side drifts, BOTH tests fail in lockstep; we then know the
   * round2 worker_transcript_hash byte-parity is broken and the coordinator's worker-
   * hash cross-check would reject every legitimate worker reply.
   */
  it("round2 statement_inputs hash matches the canonical Rust output (TS↔Rust byte parity)", () => {
    expect(mpccaWithdrawRound2StatementInputsHash(VALID_STATEMENT_INPUTS)).toBe(
      "ffa00e43e67bf54fb188596887ce58bcf3e0223d7a7a9e9f9576cde8ef25ef8d",
    );
  });

  it("round2 statement_inputs hash flips on any single field change", () => {
    const base = mpccaWithdrawRound2StatementInputsHash(VALID_STATEMENT_INPUTS);
    expect(
      mpccaWithdrawRound2StatementInputsHash({
        ...VALID_STATEMENT_INPUTS,
        recipientEk: HEX32_F,
      }),
    ).not.toBe(base);
    expect(
      mpccaWithdrawRound2StatementInputsHash({
        ...VALID_STATEMENT_INPUTS,
        transferAmountDSender: [
          HEX32_F,
          ...VALID_STATEMENT_INPUTS.transferAmountDSender.slice(1),
        ],
      }),
    ).not.toBe(base);
  });
});

describe("mpcca_withdraw_v2 round2 aggregate hash (M4 commit 2)", () => {
  const baseInput = {
    statementInputs: VALID_STATEMENT_INPUTS,
    dkBaseIndicesUsed: [...DK_BASE_INDICES_CANONICAL],
    perSlotContributions: [0, 1, 2, 3, 4].map((slot) => ({
      slot,
      workerTranscriptHash: HEX32_A,
      partialDkCommitments: [
        { index: 0, commitmentHex: HEX32_1 },
        { index: 17, commitmentHex: HEX32_2 },
      ],
    })),
  };

  it("aggregate hash is byte-stable + 64 hex chars", () => {
    const a = mpccaWithdrawRound2AggregateHash(baseInput);
    const b = mpccaWithdrawRound2AggregateHash({
      ...baseInput,
      perSlotContributions: [...baseInput.perSlotContributions].reverse(),
    });
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    // Order-independence on the contribution list: sort is internal.
    expect(a).toBe(b);
  });

  it("aggregate hash flips on Statement input change", () => {
    const base = mpccaWithdrawRound2AggregateHash(baseInput);
    expect(
      mpccaWithdrawRound2AggregateHash({
        ...baseInput,
        statementInputs: { ...VALID_STATEMENT_INPUTS, recipientEk: HEX32_F },
      }),
    ).not.toBe(base);
  });

  it("aggregate hash flips when ANY per-slot worker_transcript_hash flips", () => {
    const base = mpccaWithdrawRound2AggregateHash(baseInput);
    const mutated = {
      ...baseInput,
      perSlotContributions: baseInput.perSlotContributions.map((c, i) =>
        i === 2 ? { ...c, workerTranscriptHash: HEX32_F } : c,
      ),
    };
    expect(mpccaWithdrawRound2AggregateHash(mutated)).not.toBe(base);
  });

  it("aggregate hash flips when ANY partial dk commitment flips", () => {
    const base = mpccaWithdrawRound2AggregateHash(baseInput);
    const mutated = {
      ...baseInput,
      perSlotContributions: baseInput.perSlotContributions.map((c, i) =>
        i === 1
          ? {
              ...c,
              partialDkCommitments: [
                { index: 0, commitmentHex: HEX32_F },
                { index: 17, commitmentHex: HEX32_2 },
              ],
            }
          : c,
      ),
    };
    expect(mpccaWithdrawRound2AggregateHash(mutated)).not.toBe(base);
  });

  it("aggregate hash uses its own domain (not round2 or final)", () => {
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1).toBe(
      "EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1",
    );
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1).not.toBe(
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2,
    );
    expect(EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1).not.toBe(
      EUNOMA_MPCCA_WITHDRAW_V2_FINAL_V1,
    );
  });
});

describe("mpcca_withdraw_v2 finalize hashes (M4 commit 3 + 4)", () => {
  const FINALIZE_AGG_FIXTURE: HexString[] = Array.from({ length: 30 }, (_, i) =>
    `${(0x70 + i).toString(16).padStart(2, "0")}`.repeat(32),
  );
  const FINALIZE_CHALLENGE_HEX = HEX32_B;

  it("aggregated commitments hash is byte-stable + 64 hex chars + flips on entry change", () => {
    const h = mpccaWithdrawFinalizeAggregatedCommitmentsHash(FINALIZE_AGG_FIXTURE);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe(mpccaWithdrawFinalizeAggregatedCommitmentsHash(FINALIZE_AGG_FIXTURE));
    const mutated = [...FINALIZE_AGG_FIXTURE];
    mutated[5] = HEX32_F;
    expect(mpccaWithdrawFinalizeAggregatedCommitmentsHash(mutated)).not.toBe(h);
  });

  function finalizeArgs() {
    return {
      sessionId: "sess",
      requestId: "req",
      dkgEpoch: "1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultStateInitTranscriptHash: HEX32_C,
      observedDepositTranscriptHashes: [HEX32_D],
      rosterHash: HEX32_F,
      sortedSelectedSlots: [0, 1, 2, 3, 4],
      selfSlot: 2,
      playerId: 2,
      vaultEk: HEX32_1,
      senderAddress: HEX32_2,
      assetType: HEX32_3,
      chainId: 2,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipient: HEX32_6,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      expirySecs: 1_700_000_000,
      requestHash: HEX32_9,
      depositCount: 7,
      previousRoundTranscriptHash: HEX32_0,
      previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E],
      statementInputs: VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: FINALIZE_AGG_FIXTURE,
      challengeHex: FINALIZE_CHALLENGE_HEX,
    };
  }

  it("finalize worker_transcript_hash is byte-stable", () => {
    const base = finalizeArgs();
    expect(mpccaWithdrawFinalizeWorkerTranscriptHash(base)).toBe(
      mpccaWithdrawFinalizeWorkerTranscriptHash(base),
    );
  });

  it("finalize worker_transcript_hash flips on aggregated A change", () => {
    const base = finalizeArgs();
    const baseHash = mpccaWithdrawFinalizeWorkerTranscriptHash(base);
    const mutatedAgg = [...base.aggregatedSigmaCommitmentsHex];
    mutatedAgg[7] = HEX32_F;
    expect(
      mpccaWithdrawFinalizeWorkerTranscriptHash({
        ...base,
        aggregatedSigmaCommitmentsHex: mutatedAgg,
      }),
    ).not.toBe(baseHash);
  });

  it("finalize worker_transcript_hash flips on challenge change", () => {
    const base = finalizeArgs();
    const baseHash = mpccaWithdrawFinalizeWorkerTranscriptHash(base);
    expect(
      mpccaWithdrawFinalizeWorkerTranscriptHash({ ...base, challengeHex: HEX32_F }),
    ).not.toBe(baseHash);
  });

  it("finalize worker_transcript_hash flips on Statement input change", () => {
    const base = finalizeArgs();
    const baseHash = mpccaWithdrawFinalizeWorkerTranscriptHash(base);
    expect(
      mpccaWithdrawFinalizeWorkerTranscriptHash({
        ...base,
        statementInputs: { ...VALID_STATEMENT_INPUTS, recipientEk: HEX32_F },
      }),
    ).not.toBe(baseHash);
  });

  it("finalize aggregate hash is byte-stable + flips on aggregated A change", () => {
    const baseInput = {
      statementInputs: VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: FINALIZE_AGG_FIXTURE,
      challengeHex: FINALIZE_CHALLENGE_HEX,
      dkBaseIndicesUsed: [...DK_BASE_INDICES_CANONICAL],
      perSlotContributions: [0, 1, 2, 3, 4].map((slot) => ({
        slot,
        workerTranscriptHash: HEX32_A,
        partialResponseDkHex: HEX32_1,
      })),
    };
    const a = mpccaWithdrawFinalizeAggregateHash(baseInput);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(mpccaWithdrawFinalizeAggregateHash(baseInput));
    const mutatedAgg = [...baseInput.aggregatedSigmaCommitmentsHex];
    mutatedAgg[3] = HEX32_F;
    expect(
      mpccaWithdrawFinalizeAggregateHash({
        ...baseInput,
        aggregatedSigmaCommitmentsHex: mutatedAgg,
      }),
    ).not.toBe(a);
  });

  it("finalize aggregate hash flips on per-slot partial response change", () => {
    const baseInput = {
      statementInputs: VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: FINALIZE_AGG_FIXTURE,
      challengeHex: FINALIZE_CHALLENGE_HEX,
      dkBaseIndicesUsed: [...DK_BASE_INDICES_CANONICAL],
      perSlotContributions: [0, 1, 2, 3, 4].map((slot) => ({
        slot,
        workerTranscriptHash: HEX32_A,
        partialResponseDkHex: HEX32_1,
      })),
    };
    const base = mpccaWithdrawFinalizeAggregateHash(baseInput);
    const mutated = {
      ...baseInput,
      perSlotContributions: baseInput.perSlotContributions.map((c, i) =>
        i === 2 ? { ...c, partialResponseDkHex: HEX32_F } : c,
      ),
    };
    expect(mpccaWithdrawFinalizeAggregateHash(mutated)).not.toBe(base);
  });

  it("finalize aggregate hash uses its own domain distinct from round2 aggregate", () => {
    expect(EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1).toBe(
      "EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1",
    );
    expect(EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_AGGREGATE_V1).not.toBe(
      EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_AGGREGATE_V1,
    );
  });

  it("parseMpccaWithdrawFinalizeOrchestrateRequest accepts a base identity body", () => {
    const body = validChainedBody();
    // Strip chained-round-only fields the orchestrate body shouldn't carry.
    const { previousRoundTranscriptHash: _drop1, previousRoundCommitments: _drop2, ...base } =
      body;
    void _drop1;
    void _drop2;
    const parsed = parseMpccaWithdrawFinalizeOrchestrateRequest(base);
    expect(parsed.dkgEpoch).toBe("1");
    expect(parsed.selectedSlots).toHaveLength(5);
  });

  it("parseMpccaWithdrawFinalizeRequest rejects wrong aggregated commitments length", () => {
    const body = {
      ...validChainedBody(),
      ...VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: Array.from({ length: 29 }, () => HEX32_A),
      challengeHex: HEX32_B,
    };
    expect(() => parseMpccaWithdrawFinalizeRequest(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawFinalizeRequest rejects wrong challengeHex length", () => {
    const body = {
      ...validChainedBody(),
      ...VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: Array.from({ length: 30 }, () => HEX32_A),
      challengeHex: "01",
    };
    expect(() => parseMpccaWithdrawFinalizeRequest(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawFinalizeDkResult accepts a completed M4-c3 reply", () => {
    const body = {
      slot: 0,
      playerId: 0,
      sessionStatePath: "/tmp/session",
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      observedAtUnixMs: 1_700_000_000_000,
      completed: true,
      partialResponseDkHex: HEX32_1,
      dkBaseIndicesUsed: [0, 17],
    };
    const parsed = parseMpccaWithdrawFinalizeDkResult(body);
    expect(parsed.completed).toBe(true);
    expect(parsed.partialResponseDkHex).toBe(HEX32_1);
    expect(parsed.dkBaseIndicesUsed).toEqual([0, 17]);
  });

  it("parseMpccaWithdrawFinalizeDkResult rejects out-of-canonical-set dk indices", () => {
    const body = {
      slot: 0,
      playerId: 0,
      sessionStatePath: "/tmp/session",
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      observedAtUnixMs: 1_700_000_000_000,
      completed: true,
      partialResponseDkHex: HEX32_1,
      dkBaseIndicesUsed: [0, 99],
    };
    expect(() => parseMpccaWithdrawFinalizeDkResult(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawFinalizeDkResult rejects wrong partialResponseDkHex length", () => {
    const body = {
      slot: 0,
      playerId: 0,
      sessionStatePath: "/tmp/session",
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      observedAtUnixMs: 1_700_000_000_000,
      completed: true,
      partialResponseDkHex: "01".repeat(16), // 16 bytes, not 32
      dkBaseIndicesUsed: [0, 17],
    };
    expect(() => parseMpccaWithdrawFinalizeDkResult(body)).toThrow(MpccaWithdrawV2Error);
  });
});

describe("buildCaPayloadFromFinalizeArtifact (M5 prep — CA payload assembly)", () => {
  function makeMpccaArtifact() {
    return {
      aggregatedSigmaCommitmentsHex: Array.from(
        { length: 30 },
        (_, i) => `${(0x60 + i).toString(16).padStart(2, "0")}`.repeat(32),
      ),
      sigmaResponseHex: Array.from(
        { length: 25 },
        (_, i) => `${(0x80 + i).toString(16).padStart(2, "0")}`.repeat(32),
      ),
      bulletproofZkrpAmountHex: "ab".repeat(96),
      bulletproofZkrpNewBalanceHex: "cd".repeat(160),
    };
  }

  it("maps M4 finalize artifact + Statement → 27-field CA payload with correct field provenance", () => {
    const stmt = VALID_STATEMENT_INPUTS;
    const artifact = makeMpccaArtifact();
    const payload = buildCaPayloadFromFinalizeArtifact({
      recipientAddressHex: "11".repeat(32),
      assetTypeHex: "22".repeat(32),
      statementInputs: stmt,
      mpccaArtifact: artifact,
    });
    // 7 chunked-ciphertext fields drawn from Statement
    expect(payload.newBalanceP).toEqual(stmt.newBalanceC.map((h) => h.toLowerCase()));
    expect(payload.newBalanceR).toEqual(stmt.newBalanceD.map((h) => h.toLowerCase()));
    expect(payload.amountP).toEqual(stmt.transferAmountC.map((h) => h.toLowerCase()));
    expect(payload.amountRSender).toEqual(stmt.transferAmountDSender.map((h) => h.toLowerCase()));
    expect(payload.amountRRecip).toEqual(
      stmt.transferAmountDRecipient.map((h) => h.toLowerCase()),
    );
    // Auditor fields are empty in alpha
    expect(payload.newBalanceREffAud).toEqual([]);
    expect(payload.amountREffAud).toEqual([]);
    expect(payload.ekVolunAuds).toEqual([]);
    expect(payload.amountRVolunAuds).toEqual([]);
    // Bulletproof + sigma fields drawn from MPCCA finalize artifact
    expect(payload.zkrpAmount).toBe(artifact.bulletproofZkrpAmountHex);
    expect(payload.zkrpNewBalance).toBe(artifact.bulletproofZkrpNewBalanceHex);
    expect(payload.sigmaProtoComm).toEqual(
      artifact.aggregatedSigmaCommitmentsHex.map((h) => h.toLowerCase()),
    );
    expect(payload.sigmaProtoResp).toEqual(
      artifact.sigmaResponseHex.map((h) => h.toLowerCase()),
    );
    // memo defaults to empty
    expect(payload.memo).toBe("");
  });

  it("rejects under/over-count Statement entries", () => {
    const artifact = makeMpccaArtifact();
    const stmt = { ...VALID_STATEMENT_INPUTS, newBalanceC: VALID_STATEMENT_INPUTS.newBalanceC.slice(1) };
    expect(() =>
      buildCaPayloadFromFinalizeArtifact({
        recipientAddressHex: "11".repeat(32),
        assetTypeHex: "22".repeat(32),
        statementInputs: stmt,
        mpccaArtifact: artifact,
      }),
    ).toThrow(/newBalanceC must have 8/);
  });

  it("rejects wrong aggregated commitments or response length", () => {
    expect(() =>
      buildCaPayloadFromFinalizeArtifact({
        recipientAddressHex: "11".repeat(32),
        assetTypeHex: "22".repeat(32),
        statementInputs: VALID_STATEMENT_INPUTS,
        mpccaArtifact: {
          ...makeMpccaArtifact(),
          aggregatedSigmaCommitmentsHex: Array.from({ length: 29 }, () => HEX32_A),
        },
      }),
    ).toThrow(/aggregatedSigmaCommitmentsHex must have 30/);
    expect(() =>
      buildCaPayloadFromFinalizeArtifact({
        recipientAddressHex: "11".repeat(32),
        assetTypeHex: "22".repeat(32),
        statementInputs: VALID_STATEMENT_INPUTS,
        mpccaArtifact: {
          ...makeMpccaArtifact(),
          sigmaResponseHex: Array.from({ length: 24 }, () => HEX32_A),
        },
      }),
    ).toThrow(/sigmaResponseHex must have 25/);
  });

  it("custom memo is preserved (normalised)", () => {
    const payload = buildCaPayloadFromFinalizeArtifact({
      recipientAddressHex: "11".repeat(32),
      assetTypeHex: "22".repeat(32),
      statementInputs: VALID_STATEMENT_INPUTS,
      mpccaArtifact: makeMpccaArtifact(),
      memoHex: "deadbeef",
    });
    expect(payload.memo).toBe("deadbeef");
  });
});

describe("mpcca_withdraw_v2 final transcript hash", () => {
  function fixture() {
    const slots = [0, 1, 2, 3, 4];
    return {
      dkgEpoch: "1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultStateInitTranscriptHash: HEX32_C,
      observedDepositTranscriptHashes: [HEX32_D],
      rosterHash: HEX32_F,
      sortedSelectedSlots: slots,
      vaultEk: HEX32_1,
      senderAddress: HEX32_2,
      assetType: HEX32_3,
      chainId: 2,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipient: HEX32_6,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      expirySecs: 1_700_000_000,
      requestHash: HEX32_9,
      depositCount: 7,
      round1Contributions: slots.map((slot) => ({
        slot,
        sessionStateHash: HEX32_A,
        workerTranscriptHash: HEX32_B,
        completed: true as const,
        ingressTranscriptHash: HEX32_B,
      })),
      round2Contributions: [],
      proveContributions: [],
      finalizeContributions: [],
    };
  }

  it("binds every per-slot round1 contribution", () => {
    const a = mpccaWithdrawFinalTranscriptHash(fixture());
    const mutated = fixture();
    mutated.round1Contributions[2] = {
      ...mutated.round1Contributions[2],
      sessionStateHash: HEX32_F,
    };
    expect(mpccaWithdrawFinalTranscriptHash(mutated)).not.toBe(a);
  });

  it("binds every per-slot ingressTranscriptHash (round1 V2 layout)", () => {
    const a = mpccaWithdrawFinalTranscriptHash(fixture());
    const mutated = fixture();
    mutated.round1Contributions[3] = {
      ...mutated.round1Contributions[3],
      ingressTranscriptHash: HEX32_F,
    };
    expect(mpccaWithdrawFinalTranscriptHash(mutated)).not.toBe(a);
  });
});

describe("mpcca_withdraw_v2 assembleMpccaWithdrawTranscript", () => {
  it("happy path produces stable transcriptHash", () => {
    const slots = [0, 1, 2, 3, 4];
    const round1Contributions = slots.map((slot) => ({
      slot,
      sessionStateHash: HEX32_A,
      workerTranscriptHash: HEX32_B,
      completed: true as const,
      ingressTranscriptHash: HEX32_B,
    }));
    const t = assembleMpccaWithdrawTranscript({
      dkgEpoch: "1",
      requestId: "wdr-1",
      vaultEkTranscriptHash: HEX32_A,
      registrationTranscriptHash: HEX32_B,
      vaultStateInitTranscriptHash: HEX32_C,
      observedDepositTranscriptHashes: [HEX32_D],
      rosterHash: HEX32_F,
      selectedSlots: slots,
      vaultEk: HEX32_1,
      senderAddress: HEX32_2,
      assetType: HEX32_3,
      chainId: 2,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipient: HEX32_6,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      expirySecs: 1_700_000_000,
      requestHash: HEX32_9,
      depositCount: 7,
      round1Contributions,
      round2Contributions: [],
      proveContributions: [],
      finalizeContributions: [],
    });
    expect(t.scheme).toBe("mpcca_withdraw_v2");
    expect(t.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.selectedSlots).toEqual([0, 1, 2, 3, 4]);
    expect(t.round1Contributions).toHaveLength(5);
    expect(t.round2Contributions).toHaveLength(0);
  });

  it("rejects under-quorum selectedSlots", () => {
    expect(() =>
      assembleMpccaWithdrawTranscript({
        dkgEpoch: "1",
        requestId: "wdr-quorum",
        vaultEkTranscriptHash: HEX32_A,
        registrationTranscriptHash: HEX32_B,
        vaultStateInitTranscriptHash: HEX32_C,
        observedDepositTranscriptHashes: [],
        rosterHash: HEX32_F,
        selectedSlots: [0, 1, 2],
        vaultEk: HEX32_1,
        senderAddress: HEX32_2,
        assetType: HEX32_3,
        chainId: 2,
        root: HEX32_4,
        nullifierHash: HEX32_5,
        recipient: HEX32_6,
        recipientHash: HEX32_7,
        amountTag: HEX32_8,
        vaultSequence: 4,
        expirySecs: 1_700_000_000,
        requestHash: HEX32_9,
        depositCount: 7,
        round1Contributions: [],
        round2Contributions: [],
        proveContributions: [],
        finalizeContributions: [],
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });
});

describe("mpcca_withdraw_v2 parsers", () => {
  it("parseMpccaWithdrawRound1Request accepts a valid wire body (with M1 ingress)", () => {
    const parsed = parseMpccaWithdrawRound1Request(validRound1Body());
    expect(parsed.dkgEpoch).toBe("1");
    expect(parsed.selfSlot).toBe(2);
    expect(parsed.depositCount).toBe(7);
    expect(parsed.observedDepositTranscriptHashes).toHaveLength(2);
    expect(parsed.amountCommitment).toBe(VALID_INGRESS.amountCommitment);
    expect(parsed.perShareCommitments).toHaveLength(5);
    expect(parsed.ingressEnvelopes).toHaveLength(5);
    expect(parsed.ingressEnvelopes[0].kem).toBe("DHKEM_X25519_HKDF_SHA256");
  });

  it("parseMpccaWithdrawRound1Request rejects under-quorum selectedSlots", () => {
    const body = { ...validRound1Body(), selectedSlots: [0, 1, 2] };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects 33-byte vaultEk", () => {
    const body = { ...validRound1Body(), vaultEk: "aa".repeat(33) };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects 31-byte root", () => {
    const body = { ...validRound1Body(), root: "aa".repeat(31) };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  // KILLER guard test: forbidden plaintext field smuggled into the body must be rejected.
  it("parseMpccaWithdrawRound1Request fires forbidden guard on `secret`", () => {
    const body = { ...validRound1Body(), secret: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on `dkShare`", () => {
    const body = { ...validRound1Body(), dkShare: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on `blind`", () => {
    const body = { ...validRound1Body(), blind: "abc" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request fires forbidden guard on nested `secret`", () => {
    const body = { ...validRound1Body(), metadata: { secret: "leak" } };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawRound1Request rejects non-decimal dkgEpoch", () => {
    const body = { ...validRound1Body(), dkgEpoch: "0x10" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Request rejects missing observedDepositTranscriptHashes", () => {
    const body = { ...validRound1Body() };
    delete (body as Record<string, unknown>).observedDepositTranscriptHashes;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Request accepts a chained body with Statement inputs", () => {
    const parsed = parseMpccaWithdrawRound2Request(validChainedRound2Body());
    expect(parsed.previousRoundTranscriptHash).toBe(HEX32_0);
    expect(parsed.previousRoundCommitments).toHaveLength(5);
    expect(parsed.recipientEk).toBe(VALID_STATEMENT_INPUTS.recipientEk);
    expect(parsed.oldBalanceC).toHaveLength(ROUND2_ELL);
    expect(parsed.transferAmountC).toHaveLength(ROUND2_N);
  });

  it("parseMpccaWithdrawRound2Request rejects missing previousRoundTranscriptHash", () => {
    const body = { ...validChainedRound2Body() };
    delete (body as Record<string, unknown>).previousRoundTranscriptHash;
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Request rejects under-quorum previousRoundCommitments", () => {
    const body = {
      ...validChainedRound2Body(),
      previousRoundCommitments: [HEX32_A, HEX32_B, HEX32_C, HEX32_D],
    };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Request rejects missing recipientEk", () => {
    const body = { ...validChainedRound2Body() };
    delete (body as Record<string, unknown>).recipientEk;
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(/recipientEk/);
  });

  it("parseMpccaWithdrawRound2Request rejects under-length oldBalanceC", () => {
    const body = {
      ...validChainedRound2Body(),
      oldBalanceC: VALID_STATEMENT_INPUTS.oldBalanceC.slice(0, 7),
    };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(/oldBalanceC/);
  });

  it("parseMpccaWithdrawRound2Request rejects over-length transferAmountC", () => {
    const body = {
      ...validChainedRound2Body(),
      transferAmountC: [
        ...VALID_STATEMENT_INPUTS.transferAmountC,
        VALID_STATEMENT_INPUTS.transferAmountC[0],
      ],
    };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(/transferAmountC/);
  });

  it("parseMpccaWithdrawRound2Request rejects non-32-byte recipientEk", () => {
    const body = { ...validChainedRound2Body(), recipientEk: "aa".repeat(33) };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(/recipientEk/);
  });

  it("parseMpccaWithdrawRound2Request fires forbidden guard on amount field", () => {
    const body = { ...validChainedRound2Body(), amount: "100" };
    expect(() => parseMpccaWithdrawRound2Request(body)).toThrow(/forbidden plaintext field/);
  });

  // =================================================================================================
  // M4 Commit 2 — orchestrate request parser
  // =================================================================================================
  it("parseMpccaWithdrawRound2OrchestrateRequest accepts a complete body", () => {
    const parsed = parseMpccaWithdrawRound2OrchestrateRequest(validRound2OrchestrateBody());
    expect(parsed.userSigmaCommitmentsHex).toHaveLength(USER_SIGMA_COMMITMENTS_LEN);
    expect(parsed.userSigmaResponseSharesHex).toHaveLength(USER_SIGMA_RESPONSE_SHARES_LEN);
    expect(parsed.perChunkCommitmentsAmountHex).toHaveLength(ROUND2_N);
    expect(parsed.perChunkCommitmentsNewBalanceHex).toHaveLength(ROUND2_ELL);
    expect(parsed.recipientEk).toBe(VALID_STATEMENT_INPUTS.recipientEk);
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects userSigmaCommitmentsHex.length=28", () => {
    const body = {
      ...validRound2OrchestrateBody(),
      userSigmaCommitmentsHex: VALID_USER_SIGMA_COMMITMENTS.slice(0, 28),
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /userSigmaCommitmentsHex/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects userSigmaResponseSharesHex.length=23", () => {
    const body = {
      ...validRound2OrchestrateBody(),
      userSigmaResponseSharesHex: VALID_USER_SIGMA_RESPONSE_SHARES.slice(0, 23),
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /userSigmaResponseSharesHex/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects empty bulletproof bytes", () => {
    const body = { ...validRound2OrchestrateBody(), bulletproofZkrpAmountHex: "" };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /bulletproofZkrpAmountHex/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects wrong perChunkCommitmentsAmount length", () => {
    const body = {
      ...validRound2OrchestrateBody(),
      perChunkCommitmentsAmountHex: VALID_PER_CHUNK_COMMITMENTS_AMOUNT.slice(0, 3),
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /perChunkCommitmentsAmountHex/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects wrong perChunkCommitmentsNewBalance length", () => {
    const body = {
      ...validRound2OrchestrateBody(),
      perChunkCommitmentsNewBalanceHex: VALID_PER_CHUNK_COMMITMENTS_NEW_BALANCE.slice(0, 6),
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /perChunkCommitmentsNewBalanceHex/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest fires forbidden guard on amount", () => {
    const body = { ...validRound2OrchestrateBody(), amount: "100" };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /forbidden plaintext field/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest fires forbidden guard on blind", () => {
    const body = { ...validRound2OrchestrateBody(), blind: "1234" };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /forbidden plaintext field/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest fires forbidden guard on dkShare", () => {
    const body = { ...validRound2OrchestrateBody(), dkShare: "abc" };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /forbidden plaintext field/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest fires forbidden guard on nested secret", () => {
    const body = {
      ...validRound2OrchestrateBody(),
      metadata: { nested: { secret: "leak" } },
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(
      /forbidden plaintext field/,
    );
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest rejects non-32-byte perChunk entry", () => {
    const bad = [...VALID_PER_CHUNK_COMMITMENTS_AMOUNT];
    bad[1] = "ab".repeat(31);
    const body = { ...validRound2OrchestrateBody(), perChunkCommitmentsAmountHex: bad };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).toThrow(/32-byte hex/);
  });

  it("parseMpccaWithdrawRound2OrchestrateRequest body must NOT carry previousRoundTranscriptHash", () => {
    // The coordinator lifts these from __round1.json; if a caller smuggles them in, they
    // are simply ignored by the orchestrate parser (parseBaseRequest doesn't extract them).
    // This isn't a security risk but is documented behavior.
    const body = {
      ...validRound2OrchestrateBody(),
      previousRoundTranscriptHash: HEX32_F,
      previousRoundCommitments: Array(5).fill(HEX32_F),
    };
    expect(() => parseMpccaWithdrawRound2OrchestrateRequest(body)).not.toThrow();
  });

  // =================================================================================================
  // M4 Commit 1 — Round2DkResult parser
  // =================================================================================================
  it("parseMpccaWithdrawRound2DkResult accepts the canonical body", () => {
    const r = parseMpccaWithdrawRound2DkResult(validRound2DkResultBody());
    expect(r.completed).toBe(true);
    expect(r.partialDkCommitments).toHaveLength(2);
    expect(r.dkBaseIndicesUsed).toEqual([0, 17]);
  });

  it("parseMpccaWithdrawRound2DkResult rejects completed=false", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        completed: false,
      }),
    ).toThrow(/completed: true/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects empty partialDkCommitments", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        partialDkCommitments: [],
      }),
    ).toThrow(/non-empty array/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects duplicate index", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        partialDkCommitments: [
          { index: 0, commitmentHex: HEX32_1 },
          { index: 0, commitmentHex: HEX32_2 },
        ],
        dkBaseIndicesUsed: [0, 0],
      }),
    ).toThrow(/duplicate/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects out-of-set index", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        partialDkCommitments: [
          { index: 0, commitmentHex: HEX32_1 },
          { index: 5, commitmentHex: HEX32_2 },
        ],
        dkBaseIndicesUsed: [0, 5],
      }),
    ).toThrow(/canonical BASE_DK_SET/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects non-32-byte commitmentHex", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        partialDkCommitments: [
          { index: 0, commitmentHex: "ab".repeat(31) },
          { index: 17, commitmentHex: HEX32_2 },
        ],
      }),
    ).toThrow(/32-byte hex/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects mismatched dkBaseIndicesUsed length", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        dkBaseIndicesUsed: [0],
      }),
    ).toThrow(/length must equal/);
  });

  it("parseMpccaWithdrawRound2DkResult rejects mismatched dkBaseIndicesUsed entries", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        dkBaseIndicesUsed: [0, 3],
      }),
    ).toThrow(/(must match|canonical BASE_DK_SET)/);
  });

  it("parseMpccaWithdrawRound2DkResult fires forbidden-field guard on amount", () => {
    expect(() =>
      parseMpccaWithdrawRound2DkResult({
        ...validRound2DkResultBody(),
        amount: 42,
      }),
    ).toThrow(/forbidden plaintext field/);
  });

  it("parseMpccaWithdrawProveRequest accepts a chained body", () => {
    expect(parseMpccaWithdrawProveRequest(validChainedBody()).previousRoundCommitments).toHaveLength(
      5,
    );
  });

  it("parseMpccaWithdrawFinalizeRequest accepts a finalize body (chained + statement + aggregated + challenge)", () => {
    const body = {
      ...validChainedBody(),
      ...VALID_STATEMENT_INPUTS,
      aggregatedSigmaCommitmentsHex: Array.from(
        { length: 30 },
        (_, i) => `${(0x70 + i).toString(16).padStart(2, "0")}`.repeat(32),
      ),
      challengeHex: HEX32_B,
    };
    const parsed = parseMpccaWithdrawFinalizeRequest(body);
    expect(parsed.previousRoundCommitments).toHaveLength(5);
    expect(parsed.aggregatedSigmaCommitmentsHex).toHaveLength(30);
    expect(parsed.challengeHex).toBe(HEX32_B);
    expect(parsed.recipientEk).toBe(VALID_STATEMENT_INPUTS.recipientEk);
  });

  it("parseMpccaWithdrawRound1Response accepts a completed M1 response", () => {
    const r = parseMpccaWithdrawRound1Response(validRound1ResponseBody());
    expect(r.completed).toBe(true);
    expect(r.ingressTranscriptHash).toBe(HEX32_B);
  });

  it("parseMpccaWithdrawRound1Response rejects completed=false (M3a stub shape)", () => {
    expect(() =>
      parseMpccaWithdrawRound1Response({
        ...validRound1ResponseBody(),
        completed: false,
        notImplementedPhase: "any",
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound1Response rejects ingressTranscriptHash mismatch with workerTranscriptHash", () => {
    expect(() =>
      parseMpccaWithdrawRound1Response({
        ...validRound1ResponseBody(),
        ingressTranscriptHash: HEX32_F,
      }),
    ).toThrow(MpccaWithdrawV2Error);
  });

  it("parseMpccaWithdrawRound2Response accepts a stub response", () => {
    const r = parseMpccaWithdrawRound2Response(
      validStubResponseBody("mpcca_withdraw_v2_round2_partial_sigma_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("round2");
  });

  it("parseMpccaWithdrawProveResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawProveResponse(
      validStubResponseBody("mpcca_withdraw_v2_prove_collaborative_bulletproof_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("prove");
  });

  it("parseMpccaWithdrawFinalizeResponse accepts a stub response", () => {
    const r = parseMpccaWithdrawFinalizeResponse(
      validStubResponseBody("mpcca_withdraw_v2_finalize_aggregate_pending_milestone4"),
    );
    expect(r.notImplementedPhase).toContain("finalize");
  });
});

// =================================================================================================
// Milestone 1 — killer tests for the ingress envelope wire shape, AAD canonical-JSON parity,
// and helper byte-stability. These are the round1-specific guards that protect the no-plaintext
// invariant at the wire boundary.
// =================================================================================================
describe("mpcca_withdraw_v2 M1 — ingress envelope wire validation", () => {
  it("rejects perShareCommitments with wrong count (4 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, HEX32_C, HEX32_D];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/perShareCommitments must have/);
  });

  it("rejects perShareCommitments with wrong count (6 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, HEX32_C, HEX32_D, HEX32_E, HEX32_F];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/perShareCommitments must have/);
  });

  it("rejects perShareCommitments with non-32-byte hex entries", () => {
    const body = { ...validRound1Body() };
    body.perShareCommitments = [HEX32_A, HEX32_B, "ab".repeat(31), HEX32_D, HEX32_E];
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/must be 32-byte hex/);
  });

  it("rejects ingressEnvelopes with wrong count (4 instead of 5)", () => {
    const body = { ...validRound1Body() };
    body.ingressEnvelopes = VALID_INGRESS.ingressEnvelopes.slice(0, 4);
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/ingressEnvelopes must have/);
  });

  it("rejects ingressEnvelopes with mismatched ciphersuite", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    (mutated[2] as Record<string, unknown>).kem = "DHKEM_P256";
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/DHKEM_X25519_HKDF_SHA256/);
  });

  it("rejects ingressEnvelopes with wrong ciphertext length (not 80 bytes)", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[1] = { ...mutated[1], ciphertext: "11".repeat(48) };
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/80-byte hex/);
  });

  it("rejects ingressEnvelopes with non-32-byte enc (KEM ephemeral)", () => {
    const body = { ...validRound1Body() };
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[1] = { ...mutated[1], enc: "11".repeat(33) };
    body.ingressEnvelopes = mutated;
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/32-byte hex \(X25519 KEM ephemeral\)/);
  });

  it("rejects amountCommitment with wrong byte length", () => {
    const body = { ...validRound1Body() };
    body.amountCommitment = "ab".repeat(33);
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/32-byte hex/);
  });

  it("forbidden-field guard still trips when ingress fields are valid (defense in depth)", () => {
    const body = { ...validRound1Body(), secret: "leak" };
    expect(() => parseMpccaWithdrawRound1Request(body)).toThrow(/forbidden plaintext field/);
  });

  it("ingressEnvelopes field name is NOT caught by forbidden-field guard", () => {
    // Sanity: 'ingressEnvelopes' contains no banned token. This protects against accidental
    // future regressions that add 'envelope' or similar to the banned set.
    expect(() => parseMpccaWithdrawRound1Request(validRound1Body())).not.toThrow(
      /forbidden plaintext field/,
    );
  });

  it("perShareCommitments field name is NOT caught by forbidden-field guard", () => {
    // 'share' is not a banned token by itself; only banned tokens like 'secretshare',
    // 'shamir_share', 'dk_share' trip. Defense-in-depth: ensure naming convention holds.
    expect(() => parseMpccaWithdrawRound1Request(validRound1Body())).not.toThrow(
      /forbidden plaintext field/,
    );
  });
});

describe("mpcca_withdraw_v2 M1 — ingress helper byte-stability", () => {
  it("ingressEnvelopesHash is byte-stable", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const b = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ingressEnvelopesHash changes when any envelope flips", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const mutated = VALID_INGRESS.ingressEnvelopes.map((e) => ({ ...e }));
    mutated[3] = { ...mutated[3], ciphertext: "ff".repeat(80) };
    expect(ingressEnvelopesHash(mutated)).not.toBe(a);
  });

  it("ingressEnvelopesHash changes when envelope ORDER flips", () => {
    const a = ingressEnvelopesHash(VALID_INGRESS.ingressEnvelopes);
    const reordered = [
      VALID_INGRESS.ingressEnvelopes[1],
      VALID_INGRESS.ingressEnvelopes[0],
      VALID_INGRESS.ingressEnvelopes[2],
      VALID_INGRESS.ingressEnvelopes[3],
      VALID_INGRESS.ingressEnvelopes[4],
    ];
    expect(ingressEnvelopesHash(reordered)).not.toBe(a);
  });

  it("perShareCommitmentsHash is byte-stable + changes on commitment edit", () => {
    const a = perShareCommitmentsHash(VALID_INGRESS.perShareCommitments);
    const b = perShareCommitmentsHash(VALID_INGRESS.perShareCommitments);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    const mutated = [...VALID_INGRESS.perShareCommitments];
    mutated[2] = HEX32_F;
    expect(perShareCommitmentsHash(mutated)).not.toBe(a);
  });

  it("canonicalJsonStringify sorts keys deterministically", () => {
    expect(canonicalJsonStringify({ b: 2, a: 1, c: 3 })).toBe('{"a":1,"b":2,"c":3}');
    expect(canonicalJsonStringify({ nested: { y: 1, x: 0 } })).toBe(
      '{"nested":{"x":0,"y":1}}',
    );
    expect(canonicalJsonStringify([{ b: 1, a: 2 }, { d: 3, c: 4 }])).toBe(
      '[{"a":2,"b":1},{"c":4,"d":3}]',
    );
  });

  it("m1IngressAad produces stable bytes and changes on any field flip", () => {
    const args = {
      requestId: "req-1",
      sessionId: "sess-1",
      dkgEpoch: "1",
      selfSlot: 2,
      playerId: 1,
      rosterHash: HEX32_F,
      vaultEk: HEX32_1,
      root: HEX32_4,
      nullifierHash: HEX32_5,
      recipientHash: HEX32_7,
      amountTag: HEX32_8,
      vaultSequence: 4,
      depositCount: 7,
      amountCommitment: VALID_INGRESS.amountCommitment,
      perShareCommitments: VALID_INGRESS.perShareCommitments,
    };
    const a = m1IngressAad(args);
    const b = m1IngressAad(args);
    expect(a).toEqual(b);

    const flipSlot = m1IngressAad({ ...args, selfSlot: 3 });
    expect(flipSlot).not.toEqual(a);

    const flipPlayer = m1IngressAad({ ...args, playerId: 4 });
    expect(flipPlayer).not.toEqual(a);

    const flipCommit = m1IngressAad({
      ...args,
      perShareCommitments: [HEX32_F, ...args.perShareCommitments.slice(1)],
    });
    expect(flipCommit).not.toEqual(a);

    const flipDomain = JSON.parse(new TextDecoder().decode(a));
    expect(flipDomain.domain).toBe(EUNOMA_M1_AMOUNT_INGRESS_V1);
  });
});
