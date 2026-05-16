import { describe, expect, it } from "vitest";
import type { CryptoWorker } from "@eunoma/crypto-worker-client";
import type { CaDkgV2Roster, DeoperatorRoster, FrostDkgV2Roster } from "@eunoma/deop-protocol";
import { caDkgV2RosterHash, frostDkgV2RosterHash, rosterHash } from "@eunoma/deop-protocol";
import { buildDeoperatorNodeServer } from "../src/index.js";
import { configFromEnv } from "../src/config.js";

const h32 = (byte: string) => byte.repeat(64);

function testRoster(): DeoperatorRoster {
  return {
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
  };
}

function testDkgRoster(): CaDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "1",
    caDkgScheme: "ca_dkg_v2",
    threshold: 5,
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://node-${slot}.invalid`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("d"),
    })),
  };
}

function testFrostDkgRoster(): FrostDkgV2Roster {
  return {
    operatorSetVersion: "1",
    dkgEpoch: "9",
    caDkgScheme: "frost_dkg_v2",
    threshold: 5,
    nodes: Array.from({ length: 7 }, (_, slot) => ({
      slot,
      nodeId: `node-${slot}`,
      endpoint: `http://node-${slot}.invalid`,
      hpkePublicKey: h32(String(slot + 1)),
      transcriptPublicKey: h32("f"),
    })),
  };
}

function worker(slot: number): CryptoWorker {
  return {
    async getLocalState() {
      return {
        slot,
        state_dir: `.agent-local/eunoma-v2/slot-${slot}`,
        has_frost_key_package: true,
        has_frost_public_package: true,
        pending_frost_nonces: 0,
      };
    },
    async acceptSessionShare(input) {
      return { accepted: true, transcriptHash: input.transcriptHash ?? h32("1") };
    },
    async runDkgRound(input) {
      return {
        requestId: input.requestId,
        sessionId: input.sessionId,
        protocol: input.protocol,
        round: input.round,
        operatorSetVersion: input.operatorSetVersion,
        dkgEpoch: input.dkgEpoch,
        slot,
        accepted: true,
        transcriptHash: input.transcriptHash ?? h32("1"),
        artifactHash: h32("6"),
      };
    },
    async runMpccaRound(input) {
      return {
        requestId: input.requestId,
        sessionId: input.sessionId,
        protocol: input.protocol,
        round: input.round,
        slot,
        accepted: true,
        transcriptHash: input.transcriptHash,
        artifactHash: h32("7"),
      };
    },
    async startDkgCa() {
      throw new Error("not used");
    },
    async startDkgFrost() {
      throw new Error("not used");
    },
    async bindDeposit(input) {
      return {
        requestId: input.requestId,
        sessionId: input.sessionId,
        slot,
        accepted: true,
        transcriptHash: input.transcriptHash,
        bindingProofShare: h32("2"),
      };
    },
    async buildWithdrawCAPayload(input) {
      return {
        requestId: input.requestId,
        sessionId: input.sessionId,
        slot,
        accepted: true,
        transcriptHash: input.transcriptHash,
        caPayloadShare: h32("3"),
        caPayloadHashShare: h32("4"),
      };
    },
    async partialAttestation(input) {
      return {
        requestId: input.requestId,
        sessionId: input.sessionId,
        slot,
        accepted: true,
        transcriptHash: input.transcriptHash,
        frostSignatureShare: h32("5"),
      };
    },
    async frostNonceCommit() {
      return {
        nonce_id: h32("6"),
        commitment_hash: h32("7"),
        commitments: {},
        transcript_hash: h32("8"),
      };
    },
    async frostPartialSign() {
      return {
        nonce_id: h32("6"),
        signature_share_hash: h32("7"),
        signature_share: {},
        transcript_hash: h32("8"),
      };
    },
    async frostAggregate() {
      return {
        signature: "99".repeat(64),
        signature_hash: h32("7"),
        transcript_hash: h32("8"),
      };
    },
    async caRegistrationNonceCommit() {
      return {
        nonce_id: h32("1"),
        commitment: h32("2"),
        commitment_hash: h32("3"),
        transcript_hash: h32("4"),
      };
    },
    async caRegistrationChallenge() {
      return {
        aggregateCommitment: h32("2"),
        challenge: h32("3"),
      };
    },
    async caRegistrationPartial() {
      return {
        nonce_id: h32("1"),
        response: h32("4"),
        response_hash: h32("5"),
        transcript_hash: h32("6"),
      };
    },
    async caRegistrationAggregate() {
      return {
        sigma_proto_comm: [h32("2")],
        sigma_proto_resp: [h32("4")],
        challenge: h32("3"),
        proof_hash: h32("5"),
        transcript_hash: h32("6"),
      };
    },
  };
}

describe("deoperator node", () => {
  it("rejects ca_local in production config", () => {
    const r = { ...testRoster(), caDkgScheme: "ca_local" as const };
    expect(() =>
      configFromEnv({
        NODE_ENV: "production",
        DEOPERATOR_SLOT: "0",
        DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
      }),
    ).toThrow(/ca_dkg_v2/);
  });

  it("rejects plaintext witness fields", async () => {
    const roster = testRoster();
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster,
      cryptoWorker: worker(0),
    });

    const res = await server.inject({
      method: "POST",
      url: "/deop/v2/deposit/bind",
      payload: { amount: "1000" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("accepts an encrypted session share for its slot", async () => {
    const roster = testRoster();
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster,
      cryptoWorker: worker(0),
    });
    const hash = rosterHash(roster);
    const res = await server.inject({
      method: "POST",
      url: "/deop/v2/session-share",
      payload: {
        requestId: "r",
        sessionId: "s",
        phase: "deposit-bind",
        rosterHash: hash,
        senderHpkePublicKey: h32("7"),
        shareCommitments: [h32("8")],
        envelopes: [
          {
            slot: 0,
            shareCommitment: h32("8"),
            hpke: {
              kem: "DHKEM_X25519_HKDF_SHA256",
              kdf: "HKDF_SHA256",
              aead: "AES_256_GCM",
              enc: h32("9"),
              ciphertext: "aa",
              aadHash: h32("a"),
            },
          },
        ],
        transcriptHash: h32("b"),
      },
    });
    expect(res.statusCode).toBe(202);
    expect(res.json().accepted).toBe(true);
  });

  it("routes typed DKG rounds to the local crypto worker", async () => {
    const roster = testRoster();
    const { server, store } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster,
      cryptoWorker: worker(0),
    });
    const res = await server.inject({
      method: "POST",
      url: "/deop/v2/dkg/ca/round1",
      payload: {
        requestId: "dkg-r",
        sessionId: "dkg-s",
        operatorSetVersion: "1",
        dkgEpoch: "1",
        rosterHash: rosterHash(roster),
        threshold: 5,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [h32("1")],
        encryptedShares: [],
      },
    });
    expect(res.statusCode).toBe(202);
    expect(res.json().artifactHash).toBe(h32("6"));
    await expect(store.status("dkg-r")).resolves.toMatchObject({ dkgRoundArtifacts: 1 });
  });

  it("routes ca_dkg_v2 using only the DKG roster", async () => {
    const caDkgV2Roster = testDkgRoster();
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      caDkgV2Roster,
      cryptoWorker: worker(0),
    });
    const res = await server.inject({
      method: "POST",
      url: "/deop/v2/dkg/ca/round1",
      payload: {
        requestId: "dkg-v2-r",
        sessionId: "dkg-v2-s",
        operatorSetVersion: "1",
        dkgEpoch: "1",
        rosterHash: caDkgV2RosterHash(caDkgV2Roster),
        threshold: 5,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [],
        encryptedShares: [],
        caDkgScheme: "ca_dkg_v2",
        caDkgV2Roster,
      },
    });
    expect(res.statusCode).toBe(202);
    expect(res.json().artifactHash).toBe(h32("6"));

    const registration = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/nonce-commit",
      payload: { requestId: "blocked" },
    });
    expect(registration.statusCode).toBe(400);
    expect(registration.json().message).toMatch(/DEOPERATOR_ROSTER_JSON/);
  });

  it("routes CA registration proof steps to the local crypto worker", async () => {
    const roster = testRoster();
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster,
      cryptoWorker: worker(0),
    });
    const nonce = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/nonce-commit",
      payload: { requestId: "ca-register-r" },
    });
    expect(nonce.statusCode).toBe(200);
    expect(nonce.json().nonce_id).toBe(h32("1"));

    const challenge = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/challenge",
      payload: {
        vaultEk: roster.vaultEk,
        senderAddress: h32("9"),
        assetType: h32("a"),
        chainId: 2,
        commitments: [0, 1, 2, 3, 4].map((slot) => ({ slot, commitment: h32("2") })),
      },
    });
    expect(challenge.statusCode).toBe(200);
    expect(challenge.json().challenge).toBe(h32("3"));

    const partial = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/partial",
      payload: { nonceId: h32("1"), challenge: h32("3") },
    });
    expect(partial.statusCode).toBe(200);
    expect(partial.json().response).toBe(h32("4"));

    const aggregate = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/aggregate",
      payload: {
        vaultEk: roster.vaultEk,
        senderAddress: h32("9"),
        assetType: h32("a"),
        chainId: 2,
        commitments: [0, 1, 2, 3, 4].map((slot) => ({ slot, commitment: h32("2") })),
        responses: [0, 1, 2, 3, 4].map((slot) => ({ slot, response: h32("4") })),
      },
    });
    expect(aggregate.statusCode).toBe(200);
    expect(aggregate.json().sigma_proto_resp).toEqual([h32("4")]);
  });

  it("rejects CA registration aggregate under-quorum at the API boundary", async () => {
    const roster = testRoster();
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster,
      cryptoWorker: worker(0),
    });

    const aggregate = await server.inject({
      method: "POST",
      url: "/deop/v2/ca/registration/aggregate",
      payload: {
        vaultEk: roster.vaultEk,
        senderAddress: h32("9"),
        assetType: h32("a"),
        chainId: 2,
        commitments: [0, 1, 2, 3].map((slot) => ({ slot, commitment: h32("2") })),
        responses: [0, 1, 2, 3].map((slot) => ({ slot, response: h32("4") })),
      },
    });

    expect(aggregate.statusCode).toBe(400);
    expect(aggregate.json().error).toBe("under_quorum");
  });

  it("forwards FROST DKG V2 round1/round2_send/round2_receive/finalize to the crypto worker", async () => {
    const frostRoster = testFrostDkgRoster();
    const seen: string[] = [];
    const localWorker: CryptoWorker = {
      ...worker(0),
      async runDkgRound(input) {
        seen.push(`${input.protocol}/${input.round}`);
        return {
          requestId: input.requestId,
          sessionId: input.sessionId,
          protocol: input.protocol,
          round: input.round,
          operatorSetVersion: input.operatorSetVersion,
          dkgEpoch: input.dkgEpoch,
          slot: 0,
          accepted: true,
          transcriptHash: h32("1"),
          artifactHash: h32("2"),
        };
      },
    };
    const { server } = buildDeoperatorNodeServer({
      slot: 0,
      nodeId: "node-0",
      roster: testRoster(),
      frostDkgV2Roster: frostRoster,
      cryptoWorker: localWorker,
    });
    const fHash = frostDkgV2RosterHash(frostRoster);
    for (const round of ["round1", "round2_send", "round2_receive", "finalize"] as const) {
      const res = await server.inject({
        method: "POST",
        url: `/deop/v2/dkg/frost/${round}`,
        payload: {
          requestId: "frost-r",
          sessionId: "frost-s",
          operatorSetVersion: "1",
          dkgEpoch: "9",
          threshold: 5,
          participantSlots: [0, 1, 2, 3, 4, 5, 6],
          slot: 0,
          commitments: [],
          encryptedShares: [],
          frostDkgV2RosterHash: fHash,
          ...(round === "round1"
            ? { frostDkgV2Roster: frostRoster }
            : round === "round2_send"
              ? {
                  frostRound1Broadcasts: Array.from({ length: 7 }, (_, slot) => ({
                    slot,
                    packageHex: "ab",
                    packageHash: h32("3"),
                    transcriptHash: h32("4"),
                  })),
                }
              : round === "round2_receive"
                ? {
                    frostRound1Broadcasts: Array.from({ length: 7 }, (_, slot) => ({
                      slot,
                      packageHex: "ab",
                      packageHash: h32("3"),
                      transcriptHash: h32("4"),
                    })),
                    frostRound2Envelopes: [1, 2, 3, 4, 5, 6].map((dealerSlot) => ({
                      dealerSlot,
                      toSlot: 0,
                      packageCommitment: h32("5"),
                      hpke: {
                        kem: "DHKEM_X25519_HKDF_SHA256",
                        kdf: "HKDF_SHA256",
                        aead: "AES_256_GCM",
                        enc: h32("6"),
                        ciphertext: "aa",
                        aadHash: h32("7"),
                      },
                    })),
                  }
                : { transcriptHash: h32("8") }),
        },
      });
      expect(res.statusCode).toBe(202);
    }
    expect(seen).toEqual([
      "frost/round1",
      "frost/round2_send",
      "frost/round2_receive",
      "frost/finalize",
    ]);
  });

  it("vault_ek round0 passthrough rejects mismatched rosterHash before forwarding", async () => {
    // Codex P1 #4 round0: the deop-node passthrough must validate rosterHash + selfSlot
    // BEFORE forwarding to the local crypto worker. Otherwise a stale-roster or
    // wrong-slot request can persist a round0 commitment under the wrong identity.
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
      });
      const res = await server.inject({
        method: "POST",
        url: "/worker/v2/derive/vault_ek/round0",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          rosterHash: h32("d"), // bogus — not the configured CA DKG V2 roster hash
          selectedSlots: [0, 1, 2, 3, 4],
          selfSlot: 0,
          requestId: "vault-ek-r0-bogus",
          sessionId: "vault-ek-r0-bogus",
          playerId: 0,
          peerAddresses: Array.from({ length: 5 }, (_, i) => `127.0.0.1:${14000 + i}`),
          lagrangeCoefficients: Array.from({ length: 5 }, () => h32("0")),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("vault_ek round0 passthrough rejects wrong selfSlot before forwarding", async () => {
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
      });
      const res = await server.inject({
        method: "POST",
        url: "/worker/v2/derive/vault_ek/round0",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          rosterHash: caDkgV2RosterHash(caDkgV2Roster),
          selectedSlots: [0, 1, 2, 3, 4],
          selfSlot: 4, // wrong: this node is slot 0
          requestId: "vault-ek-r0-wrong-slot",
          sessionId: "vault-ek-r0-wrong-slot",
          playerId: 4,
          peerAddresses: Array.from({ length: 5 }, (_, i) => `127.0.0.1:${14000 + i}`),
          lagrangeCoefficients: Array.from({ length: 5 }, () => h32("0")),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("vault_ek round1 passthrough rejects mismatched rosterHash before forwarding", async () => {
    // Codex P1 #5: the new /worker/v2/derive/vault_ek/round1 + /verify passthroughs must
    // validate rosterHash (against CA_DKG_V2_ROSTER_JSON) and selfSlot before forwarding to
    // the local crypto worker. Otherwise stale or wrong-roster contexts reach MP-SPDZ.
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
      });
      const res = await server.inject({
        method: "POST",
        url: "/worker/v2/derive/vault_ek/round1",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          rosterHash: h32("d"), // bogus — not the configured CA DKG V2 roster hash
          selectedSlots: [0, 1, 2, 3, 4],
          selfSlot: 0,
          requestId: "vault-ek-bogus",
          sessionId: "vault-ek-bogus",
          playerId: 0,
          peerAddresses: Array.from({ length: 5 }, (_, i) => `127.0.0.1:${14000 + i}`),
          lagrangeCoefficients: Array.from({ length: 5 }, () => h32("0")),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("vault_ek round1 passthrough rejects wrong selfSlot before forwarding", async () => {
    // Codex P1 #5: selfSlot must equal the node's configured slot.
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
      });
      const res = await server.inject({
        method: "POST",
        url: "/worker/v2/derive/vault_ek/round1",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          rosterHash: caDkgV2RosterHash(caDkgV2Roster),
          selectedSlots: [0, 1, 2, 3, 4],
          selfSlot: 2, // wrong: this node is slot 0
          requestId: "vault-ek-wrong-slot",
          sessionId: "vault-ek-wrong-slot",
          playerId: 2,
          peerAddresses: Array.from({ length: 5 }, (_, i) => `127.0.0.1:${14000 + i}`),
          lagrangeCoefficients: Array.from({ length: 5 }, () => h32("0")),
        },
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("vault_ek verify passthrough rejects mismatched rosterHash", async () => {
    const caDkgV2Roster = testDkgRoster();
    let workerCalled = false;
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      workerCalled = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const { server } = buildDeoperatorNodeServer({
        slot: 0,
        nodeId: "node-0",
        caDkgV2Roster,
        cryptoWorker: worker(0),
        cryptoWorkerUrl: "http://localhost:9000",
      });
      const res = await server.inject({
        method: "POST",
        url: "/worker/v2/derive/vault_ek/verify",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          rosterHash: h32("d"),
          selectedSlots: [0, 1, 2, 3, 4],
          contributions: [],
        },
      });
      expect(res.statusCode).toBe(400);
      expect(workerCalled).toBe(false);
    } finally {
      globalThis.fetch = oldFetch;
    }
  });
});
