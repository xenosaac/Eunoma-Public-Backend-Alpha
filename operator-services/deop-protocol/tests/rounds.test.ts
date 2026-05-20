import { describe, expect, it } from "vitest";
import {
  parseAttestationPartialRequest,
  parseCaRegistrationAggregateRequest,
  parseCaRegistrationChallengeRequest,
  parseDkgRoundRequest,
  parseMpccaRoundRequest,
  parseMpccaRoundResult,
  parseQuorumSlots5,
  UnderQuorumError,
} from "../src/index.js";

const h32 = (byte: string) => byte.repeat(64);

describe("multi-round DKG and MPCCA validation", () => {
  it("parses exactly five unique quorum slots", () => {
    expect(parseQuorumSlots5([0, 1, 2, 3, 4])).toEqual([0, 1, 2, 3, 4]);
    expect(() => parseQuorumSlots5([0, 1, 2, 3])).toThrow(UnderQuorumError);
    expect(() => parseQuorumSlots5([0, 1, 2, 3, 4, 5])).toThrow(/exactly 5/);
    expect(() => parseQuorumSlots5([0, 1, 2, 3, 3])).toThrow(/duplicate quorum slot/);
  });

  it("parses a CA DKG round without plaintext witness fields", () => {
    const parsed = parseDkgRoundRequest({
      requestId: "dkg-r",
      sessionId: "dkg-s",
      protocol: "ca",
      round: "round1",
      operatorSetVersion: "1",
      dkgEpoch: "3",
      rosterHash: h32("1"),
      threshold: 5,
      participantSlots: [0, 1, 2, 3, 4, 5, 6],
      slot: 0,
      commitments: [h32("2")],
      encryptedShares: [
        {
          toSlot: 1,
          hpke: {
            kem: "DHKEM_X25519_HKDF_SHA256",
            kdf: "HKDF_SHA256",
            aead: "AES_256_GCM",
            enc: h32("3"),
            ciphertext: "44",
            aadHash: h32("5"),
          },
        },
      ],
    });
    expect(parsed.protocol).toBe("ca");
    expect(parsed.participantSlots).toHaveLength(7);
  });

  it("rejects non V2 DKG threshold", () => {
    expect(() =>
      parseDkgRoundRequest({
        requestId: "dkg-r",
        sessionId: "dkg-s",
        protocol: "frost",
        round: "round1",
        operatorSetVersion: "1",
        dkgEpoch: "3",
        rosterHash: h32("1"),
        threshold: 4,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [h32("2")],
        encryptedShares: [],
        frostDkgV2Roster: {
          operatorSetVersion: "1",
          dkgEpoch: "3",
          caDkgScheme: "frost_dkg_v2",
          threshold: 5,
          nodes: Array.from({ length: 7 }, (_, slot) => ({
            slot,
            nodeId: `node-${slot}`,
            endpoint: `http://127.0.0.1:81${slot}`,
            hpkePublicKey: h32(String(slot + 1)),
            transcriptPublicKey: h32("f"),
          })),
        },
        frostDkgV2RosterHash: h32("a"),
      }),
    ).toThrow(/threshold must be 5/);
  });

  it("parses FROST DKG V2 round1 requests with the FROST roster", () => {
    const parsed = parseDkgRoundRequest({
      requestId: "frost-r",
      sessionId: "frost-s",
      protocol: "frost",
      round: "round1",
      operatorSetVersion: "1",
      dkgEpoch: "9",
      threshold: 5,
      participantSlots: [0, 1, 2, 3, 4, 5, 6],
      slot: 0,
      commitments: [],
      encryptedShares: [],
      frostDkgV2RosterHash: h32("a"),
      frostDkgV2Roster: {
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
      },
    });
    expect(parsed.protocol).toBe("frost");
    expect(parsed.round).toBe("round1");
    expect(parsed.frostDkgV2Roster?.caDkgScheme).toBe("frost_dkg_v2");
  });

  it("rejects FROST round2_send without seven round1 broadcasts", () => {
    expect(() =>
      parseDkgRoundRequest({
        requestId: "frost-r",
        sessionId: "frost-s",
        protocol: "frost",
        round: "round2_send",
        operatorSetVersion: "1",
        dkgEpoch: "9",
        threshold: 5,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [],
        encryptedShares: [],
        frostDkgV2RosterHash: h32("a"),
        frostRound1Broadcasts: [
          {
            slot: 0,
            packageHex: "ab",
            packageHash: h32("1"),
            transcriptHash: h32("2"),
          },
        ],
      }),
    ).toThrow(/round2_send requires 7 frostRound1Broadcasts/);
  });

  it("rejects FROST round2_receive when an envelope is addressed to a different slot", () => {
    const rosterNodes = Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://127.0.0.1:81${slot}`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("f"),
    }));
    const broadcasts = rosterNodes.map((node) => ({
      slot: node.slot,
      packageHex: "ab",
      packageHash: h32("1"),
      transcriptHash: h32("2"),
    }));
    const envelopes = [1, 2, 3, 4, 5, 6].map((dealerSlot) => ({
      dealerSlot,
      toSlot: 1,
      packageCommitment: h32("3"),
      hpke: {
        kem: "DHKEM_X25519_HKDF_SHA256",
        kdf: "HKDF_SHA256",
        aead: "AES_256_GCM",
        enc: h32("4"),
        ciphertext: "55",
        aadHash: h32("6"),
      },
    }));
    expect(() =>
      parseDkgRoundRequest({
        requestId: "frost-r",
        sessionId: "frost-s",
        protocol: "frost",
        round: "round2_receive",
        operatorSetVersion: "1",
        dkgEpoch: "9",
        threshold: 5,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [],
        encryptedShares: [],
        frostDkgV2RosterHash: h32("a"),
        frostRound1Broadcasts: broadcasts,
        frostRound2Envelopes: envelopes,
      }),
    ).toThrow(/toSlot must equal slot/);
  });

  it("parses a withdraw MPCCA round request", () => {
    const parsed = parseMpccaRoundRequest({
      requestId: "mpcca-r",
      sessionId: "mpcca-s",
      protocol: "withdraw",
      round: "prove",
      rosterHash: h32("1"),
      slot: 3,
      quorumSlots: [0, 1, 2, 3, 4],
      root: h32("2"),
      nullifierHash: h32("3"),
      recipient: h32("4"),
      recipientHash: h32("5"),
      amountTag: h32("6"),
      vaultSequence: "9",
      shareCommitments: [h32("7")],
      transcriptHash: h32("8"),
      publicInputsHash: h32("9"),
      roundCommitments: [h32("a")],
    });
    expect(parsed.round).toBe("prove");
    expect(parsed.slot).toBe(3);
    expect(parsed.quorumSlots).toEqual([0, 1, 2, 3, 4]);
  });

  it("rejects MPCCA prove/finalize under-quorum requests", () => {
    expect(() =>
      parseMpccaRoundRequest({
        requestId: "mpcca-r",
        sessionId: "mpcca-s",
        protocol: "withdraw",
        round: "finalize",
        rosterHash: h32("1"),
        slot: 3,
        quorumSlots: [0, 1, 2, 3],
        root: h32("2"),
        nullifierHash: h32("3"),
        recipient: h32("4"),
        recipientHash: h32("5"),
        amountTag: h32("6"),
        vaultSequence: "9",
        shareCommitments: [h32("7")],
        transcriptHash: h32("8"),
        publicInputsHash: h32("9"),
        roundCommitments: [h32("a")],
      }),
    ).toThrow(UnderQuorumError);
  });

  it("rejects MPCCA finalize results that do not carry a real CA payload", () => {
    expect(() =>
      parseMpccaRoundResult({
        requestId: "mpcca-r",
        sessionId: "mpcca-s",
        protocol: "withdraw",
        round: "finalize",
        slot: 3,
        accepted: true,
        transcriptHash: h32("8"),
        artifactHash: h32("9"),
      }),
    ).toThrow(/finalize result must include caPayload/);
  });

  it("parses threshold CA registration messages", () => {
    const challenge = parseCaRegistrationChallengeRequest({
      vaultEk: h32("1"),
      senderAddress: h32("2"),
      assetType: h32("3"),
      chainId: 2,
      commitments: [0, 1, 2, 3, 4].map((slot) => ({
        slot,
        commitment: h32("4"),
      })),
    });
    expect(challenge.commitments).toHaveLength(5);
    expect(challenge.quorumSlots).toEqual([0, 1, 2, 3, 4]);

    const aggregate = parseCaRegistrationAggregateRequest({
      ...challenge,
      responses: [0, 1, 2, 3, 4].map((slot) => ({
        slot,
        response: h32("5"),
      })),
    });
    expect(aggregate.responses.map((item) => item.slot)).toEqual([0, 1, 2, 3, 4]);
  });

  it("rejects under-quorum CA registration aggregate input", () => {
    expect(() =>
      parseCaRegistrationAggregateRequest({
        vaultEk: h32("1"),
        senderAddress: h32("2"),
        assetType: h32("3"),
        chainId: 2,
        commitments: [0, 1, 2, 3].map((slot) => ({
          slot,
          commitment: h32("4"),
        })),
        responses: [0, 1, 2, 3].map((slot) => ({
          slot,
          response: h32("5"),
        })),
      }),
    ).toThrow(UnderQuorumError);
  });

  it("rejects duplicate and over-quorum CA registration aggregate input", () => {
    expect(() =>
      parseCaRegistrationAggregateRequest({
        vaultEk: h32("1"),
        senderAddress: h32("2"),
        assetType: h32("3"),
        chainId: 2,
        commitments: [0, 1, 2, 3, 3].map((slot) => ({
          slot,
          commitment: h32("4"),
        })),
        responses: [0, 1, 2, 3, 3].map((slot) => ({
          slot,
          response: h32("5"),
        })),
      }),
    ).toThrow(/duplicate quorum slot/);

    expect(() =>
      parseCaRegistrationAggregateRequest({
        vaultEk: h32("1"),
        senderAddress: h32("2"),
        assetType: h32("3"),
        chainId: 2,
        commitments: [0, 1, 2, 3, 4, 5].map((slot) => ({
          slot,
          commitment: h32("4"),
        })),
        responses: [0, 1, 2, 3, 4, 5].map((slot) => ({
          slot,
          response: h32("5"),
        })),
      }),
    ).toThrow(/exactly 5/);
  });

  it("requires exactly five quorum slots for FROST attestation partials", () => {
    const parsed = parseAttestationPartialRequest({
      requestId: "att-r",
      sessionId: "att-s",
      rosterHash: h32("1"),
      quorumSlots: [0, 1, 2, 3, 4],
      messageBytes: "abcd",
      caPayloadHash: h32("2"),
      groth16ProofHash: h32("3"),
      transcriptHash: h32("4"),
    });
    expect(parsed.quorumSlots).toEqual([0, 1, 2, 3, 4]);

    expect(() =>
      parseAttestationPartialRequest({
        requestId: "att-r",
        sessionId: "att-s",
        rosterHash: h32("1"),
        quorumSlots: [0, 1, 2, 3],
        messageBytes: "abcd",
        caPayloadHash: h32("2"),
        groth16ProofHash: h32("3"),
        transcriptHash: h32("4"),
      }),
    ).toThrow(UnderQuorumError);
  });
});
