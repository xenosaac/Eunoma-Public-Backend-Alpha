import { describe, expect, it } from "vitest";
import { HttpCryptoWorkerClient } from "../src/index.js";

describe("HttpCryptoWorkerClient", () => {
  it("rejects forbidden fields before worker transport", async () => {
    const client = new HttpCryptoWorkerClient("http://worker.invalid", async () => {
      throw new Error("fetch should not run");
    });

    await expect(
      client.bindDeposit({
        requestId: "r",
        sessionId: "s",
        rosterHash: "00".repeat(32),
        commitment: "00".repeat(32),
        amountTag: "11".repeat(32),
        caPayloadHash: "22".repeat(32),
        depositNonce: "33",
        shareCommitments: ["44".repeat(32)],
        transcriptHash: "55".repeat(32),
        amount: "1",
      } as never),
    ).rejects.toThrow(/forbidden plaintext field/);
  });

  it("posts multi-round DKG and MPCCA requests to protocol-specific worker endpoints", async () => {
    const paths: string[] = [];
    const client = new HttpCryptoWorkerClient("http://worker.invalid", async (url) => {
      paths.push(new URL(url).pathname);
      if (paths.at(-1) === "/worker/v2/local/state") {
        return new Response(
          JSON.stringify({
            slot: 0,
            state_dir: ".agent-local/eunoma-v2/slot-0",
            has_frost_key_package: true,
            has_frost_public_package: true,
            pending_frost_nonces: 0,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (paths.at(-1)?.includes("/frost/sign/")) {
        return new Response(
          JSON.stringify({
            nonce_id: "11".repeat(32),
            commitment_hash: "22".repeat(32),
            commitments: {},
            transcript_hash: "33".repeat(32),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (paths.at(-1)?.includes("/ca/registration/")) {
        return new Response(
          JSON.stringify({
            nonce_id: "11".repeat(32),
            commitment: "22".repeat(32),
            commitment_hash: "33".repeat(32),
            transcript_hash: "44".repeat(32),
            aggregateCommitment: "22".repeat(32),
            challenge: "55".repeat(32),
            response: "66".repeat(32),
            response_hash: "77".repeat(32),
            sigma_proto_comm: ["22".repeat(32)],
            sigma_proto_resp: ["66".repeat(32)],
            proof_hash: "88".repeat(32),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          requestId: "r",
          sessionId: "s",
          protocol: paths.at(-1)?.includes("/mpcca/") ? "withdraw" : "ca",
          round: paths.at(-1)?.endsWith("/prove") ? "prove" : "round1",
          operatorSetVersion: "1",
          dkgEpoch: "2",
          slot: 0,
          accepted: true,
          transcriptHash: "11".repeat(32),
          artifactHash: "22".repeat(32),
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    });

    await client.getLocalState();
    await client.runDkgRound({
      requestId: "r",
      sessionId: "s",
      protocol: "ca",
      round: "round1",
      operatorSetVersion: "1",
      dkgEpoch: "2",
      rosterHash: "00".repeat(32),
      threshold: 5,
      participantSlots: [0, 1, 2, 3, 4, 5, 6],
      slot: 0,
      commitments: ["33".repeat(32)],
      encryptedShares: [],
    });
    await client.runMpccaRound({
      requestId: "r",
      sessionId: "s",
      protocol: "withdraw",
      round: "prove",
      rosterHash: "00".repeat(32),
      slot: 0,
      root: "44".repeat(32),
      nullifierHash: "55".repeat(32),
      recipient: "66".repeat(32),
      recipientHash: "77".repeat(32),
      amountTag: "88".repeat(32),
      vaultSequence: "1",
      shareCommitments: ["99".repeat(32)],
      transcriptHash: "aa".repeat(32),
      publicInputsHash: "bb".repeat(32),
      roundCommitments: ["cc".repeat(32)],
    });
    await client.frostNonceCommit({ requestId: "r" });
    await client.caRegistrationNonceCommit({ requestId: "r" });
    await client.caRegistrationChallenge({
      vaultEk: "11".repeat(32),
      senderAddress: "22".repeat(32),
      assetType: "33".repeat(32),
      chainId: 2,
      quorumSlots: [0, 1, 2, 3, 4],
      commitments: [0, 1, 2, 3, 4].map((slot) => ({ slot, commitment: "44".repeat(32) })),
    });

    expect(paths).toEqual([
      "/worker/v2/local/state",
      "/worker/v2/dkg/ca/round1",
      "/worker/v2/mpcca/withdraw/prove",
      "/worker/v2/frost/sign/nonce-commit",
      "/worker/v2/ca/registration/nonce-commit",
      "/worker/v2/ca/registration/challenge",
    ]);
  });

  it("routes FROST DKG V2 rounds to /worker/v2/dkg/frost/{round}", async () => {
    const paths: string[] = [];
    const bodies: unknown[] = [];
    const client = new HttpCryptoWorkerClient("http://worker.invalid", async (url, init) => {
      paths.push(new URL(url).pathname);
      bodies.push(JSON.parse(String(init?.body)));
      return new Response(
        JSON.stringify({
          requestId: "r",
          sessionId: "s",
          protocol: "frost",
          round: paths.at(-1)?.split("/").pop(),
          operatorSetVersion: "1",
          dkgEpoch: "9",
          slot: 0,
          accepted: true,
          transcriptHash: "11".repeat(32),
          artifactHash: "22".repeat(32),
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    });
    for (const round of ["round1", "round2_send", "round2_receive", "finalize"] as const) {
      await client.runDkgRound({
        requestId: "r",
        sessionId: "s",
        protocol: "frost",
        round,
        operatorSetVersion: "1",
        dkgEpoch: "9",
        rosterHash: "00".repeat(32),
        threshold: 5,
        participantSlots: [0, 1, 2, 3, 4, 5, 6],
        slot: 0,
        commitments: [],
        encryptedShares: [],
        frostDkgV2RosterHash: "00".repeat(32),
      });
    }
    expect(paths).toEqual([
      "/worker/v2/dkg/frost/round1",
      "/worker/v2/dkg/frost/round2_send",
      "/worker/v2/dkg/frost/round2_receive",
      "/worker/v2/dkg/frost/finalize",
    ]);
    expect((bodies[0] as { protocol: string }).protocol).toBe("frost");
  });
});
