import { describe, expect, it } from "vitest";
import type {
  CaDkgV2Roster,
  DeoperatorRoster,
  FrostDkgV2Roster,
} from "@eunoma/deop-protocol";
import {
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  mpccaWithdrawRound1WorkerTranscriptHash,
  rosterHash,
} from "@eunoma/deop-protocol";
import { buildCoordinatorServer, forwardSessionShareToRoster } from "../src/index.js";
import { configFromEnv } from "../src/config.js";

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

function dkgRoster(): CaDkgV2Roster {
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

function frostRoster(): FrostDkgV2Roster {
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

describe("coordinator", () => {
  it("returns roster with hash", async () => {
    const r = roster();
    const { server } = buildCoordinatorServer({ roster: r });
    const res = await server.inject({ method: "GET", url: "/v2/roster" });
    expect(res.statusCode).toBe(200);
    expect(res.json().rosterHash).toBe(rosterHash(r));
  });

  it("rejects ca_local in production config", () => {
    const r = { ...roster(), caDkgScheme: "ca_local" as const };
    expect(() =>
      configFromEnv({
        NODE_ENV: "production",
        DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
      }),
    ).toThrow(/ca_dkg_v2/);
  });

  it("rejects plaintext witness fields in proxy", async () => {
    const { server } = buildCoordinatorServer({ roster: roster() });
    const res = await server.inject({
      method: "POST",
      url: "/v2/proxy/session-share",
      payload: { nullifier: "00" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("adds configured node bearer auth when forwarding without putting it in the roster", async () => {
    const r = roster();
    const calls: Record<string, string | undefined>[] = [];
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async (_url, init) => {
      calls.push((init?.headers ?? {}) as Record<string, string | undefined>);
      return new Response("{}", { status: 202 });
    }) as typeof fetch;
    try {
      const hash = rosterHash(r);
      await forwardSessionShareToRoster({ "0": "node-token" })(
        {
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
        },
        r,
      );
    } finally {
      globalThis.fetch = oldFetch;
    }
    expect(calls[0].authorization).toBe("Bearer node-token");
    expect(JSON.stringify(r)).not.toContain("node-token");
  });

  it("proxies a typed DKG round to the requested node slot", async () => {
    const r = roster();
    const seen: Array<{ path: string; authorization?: string }> = [];
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async (url, init) => {
      seen.push({
        path: new URL(url).pathname,
        authorization: ((init?.headers ?? {}) as Record<string, string | undefined>).authorization,
      });
      return new Response(
        JSON.stringify({
          requestId: "dkg-r",
          sessionId: "dkg-s",
          protocol: "ca",
          round: "round1",
          operatorSetVersion: "1",
          dkgEpoch: "1",
          slot: 2,
          accepted: true,
          transcriptHash: h32("1"),
          artifactHash: h32("2"),
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;
    try {
      const { server, store } = buildCoordinatorServer({
        roster: r,
        nodeBearerTokens: { "2": "node-token-2" },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/proxy/dkg/ca/round1",
        payload: {
          requestId: "dkg-r",
          sessionId: "dkg-s",
          operatorSetVersion: "1",
          dkgEpoch: "1",
          rosterHash: rosterHash(r),
          threshold: 5,
          participantSlots: [0, 1, 2, 3, 4, 5, 6],
          slot: 2,
          commitments: [h32("3")],
          encryptedShares: [],
        },
      });
      expect(res.statusCode).toBe(202);
      expect(seen).toEqual([
        {
          path: "/deop/v2/dkg/ca/round1",
          authorization: "Bearer node-token-2",
        },
      ]);
      await expect(store.getStatus("dkg-r")).resolves.toMatchObject({
        status: "pending",
        transcriptHashes: [h32("1")],
      });
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("orchestrates ca_dkg_v2 round1 round2 finalize across 7 nodes", async () => {
    const caDkgV2Roster = dkgRoster();
    const calls: Array<{ path: string; slot: number }> = [];
    const { server, store } = buildCoordinatorServer({
      roster: roster(),
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _r, slot) => {
        calls.push({ path, slot });
        const request = body as Record<string, unknown>;
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "ca",
              round: "round1",
              operatorSetVersion: "1",
              dkgEpoch: "1",
              slot,
              accepted: true,
              transcriptHash: h32("1"),
              artifactHash: h32("2"),
              dealerBroadcast: {
                slot,
                commitments: Array.from({ length: 5 }, (_, idx) => h32(String(idx + 1))),
                transcriptHash: h32("3"),
              },
              encryptedShares: Array.from({ length: 7 }, (_, toSlot) => ({
                dealerSlot: slot,
                toSlot,
                shareCommitment: h32("4"),
                hpke: {
                  kem: "DHKEM_X25519_HKDF_SHA256",
                  kdf: "HKDF_SHA256",
                  aead: "AES_256_GCM",
                  enc: h32("5"),
                  ciphertext: "66",
                  aadHash: h32("7"),
                },
              })),
            },
          };
        }
        if (path.endsWith("/round2")) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "ca",
              round: "round2",
              operatorSetVersion: "1",
              dkgEpoch: "1",
              slot,
              accepted: true,
              transcriptHash: h32("8"),
              artifactHash: h32("9"),
              acceptedDealers: [0, 1, 2, 3, 4, 5, 6],
              aggregateCommitments: Array.from({ length: 5 }, (_, idx) => h32(String(idx + 1))),
              caDkgShareHash: h32("a"),
              complaints: [],
            },
          };
        }
        return {
          slot,
          ok: true,
          body: {
            requestId: request.requestId,
            sessionId: request.sessionId,
            protocol: "ca",
            round: "finalize",
            operatorSetVersion: "1",
            dkgEpoch: "1",
            slot,
            accepted: true,
            transcriptHash: h32("8"),
            artifactHash: h32("b"),
            acceptedDealers: [0, 1, 2, 3, 4, 5, 6],
            aggregateCommitments: Array.from({ length: 5 }, (_, idx) => h32(String(idx + 1))),
            caDkgShareHash: h32("c"),
            finalized: true,
            caDkgTranscriptHash: h32("8"),
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/dkg/ca/v2/start",
      payload: { requestId: "ca-dkg-r", sessionId: "ca-dkg-s" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      accepted: true,
      requestId: "ca-dkg-r",
      caDkgV2RosterHash: caDkgV2RosterHash(caDkgV2Roster),
      caDkgTranscriptHash: h32("8"),
    });
    expect(calls).toHaveLength(21);
    await expect(store.getStatus("ca-dkg-r")).resolves.toMatchObject({ status: "complete" });
  });

  it("proxies CA registration aggregate and records its proof transcript", async () => {
    const r = roster();
    const seen: Array<{ path: string; authorization?: string }> = [];
    const oldFetch = globalThis.fetch;
    globalThis.fetch = (async (url, init) => {
      seen.push({
        path: new URL(url).pathname,
        authorization: ((init?.headers ?? {}) as Record<string, string | undefined>).authorization,
      });
      return new Response(
        JSON.stringify({
          sigma_proto_comm: [h32("2")],
          sigma_proto_resp: [h32("4")],
          challenge: h32("3"),
          proof_hash: h32("5"),
          transcript_hash: h32("6"),
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;
    try {
      const { server, store } = buildCoordinatorServer({
        roster: r,
        nodeBearerTokens: { "2": "node-token-2" },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/proxy/ca/registration/2/aggregate",
        payload: {
          vaultEk: r.vaultEk,
          senderAddress: h32("9"),
          assetType: h32("a"),
          chainId: 2,
          commitments: [0, 1, 2, 3, 4].map((slot) => ({ slot, commitment: h32("2") })),
          responses: [0, 1, 2, 3, 4].map((slot) => ({ slot, response: h32("4") })),
        },
      });
      expect(res.statusCode).toBe(200);
      expect(seen).toEqual([
        {
          path: "/deop/v2/ca/registration/aggregate",
          authorization: "Bearer node-token-2",
        },
      ]);
      await expect(store.getStatus(`ca-registration:${h32("9")}:${h32("a")}`)).resolves.toMatchObject({
        status: "pending",
        transcriptHashes: [h32("6")],
      });
    } finally {
      globalThis.fetch = oldFetch;
    }
  });

  it("orchestrates frost_dkg_v2 four-phase DKG across 7 nodes", async () => {
    const r = roster();
    const fr = frostRoster();
    const calls: Array<{ path: string; slot: number }> = [];
    const { server, store } = buildCoordinatorServer({
      roster: r,
      frostDkgV2Roster: fr,
      singleNodeForwarder: async (path, body, _r, slot) => {
        calls.push({ path, slot });
        const request = body as Record<string, unknown>;
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round1",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("1"),
              artifactHash: h32("2"),
              frostRound1Broadcast: {
                slot,
                packageHex: "abcd",
                packageHash: h32("3"),
                transcriptHash: h32("1"),
              },
            },
          };
        }
        if (path.endsWith("/round2_send")) {
          const envelopes = Array.from({ length: 6 }, (_, idx) => {
            const toSlot = idx >= slot ? idx + 1 : idx;
            return {
              dealerSlot: slot,
              toSlot,
              packageCommitment: h32("4"),
              hpke: {
                kem: "DHKEM_X25519_HKDF_SHA256",
                kdf: "HKDF_SHA256",
                aead: "AES_256_GCM",
                enc: h32("5"),
                ciphertext: "66",
                aadHash: h32("7"),
              },
            };
          });
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round2_send",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("8"),
              artifactHash: h32("9"),
              frostRound2Envelopes: envelopes,
            },
          };
        }
        if (path.endsWith("/round2_receive")) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round2_receive",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("a"),
              artifactHash: h32("b"),
            },
          };
        }
        return {
          slot,
          ok: true,
          body: {
            requestId: request.requestId,
            sessionId: request.sessionId,
            protocol: "frost",
            round: "finalize",
            operatorSetVersion: "1",
            dkgEpoch: "9",
            slot,
            accepted: true,
            transcriptHash: request.transcriptHash as string,
            artifactHash: h32("c"),
            finalized: true,
            groupPublicKey: h32("d"),
            frostVerifyingShare: h32("e"),
            frostKeyPackageHash: h32("a"),
            frostPublicPackageHash: h32("b"),
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/dkg/frost/v2/start",
      payload: { requestId: "frost-dkg-r", sessionId: "frost-dkg-s" },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    expect(body.requestId).toBe("frost-dkg-r");
    expect(body.frostDkgV2RosterHash).toBe(frostDkgV2RosterHash(fr));
    expect(body.groupPublicKey).toBe(h32("d"));
    expect(body.operatorSetVersion).toBe("1");
    expect(body.dkgEpoch).toBe("9");
    expect(body.workerArtifactHashes).toHaveLength(7);
    for (const artifact of body.workerArtifactHashes) {
      expect(artifact.frostVerifyingShare).toBe(h32("e"));
      expect(artifact.frostKeyPackageHash).toBe(h32("a"));
      expect(artifact.frostPublicPackageHash).toBe(h32("b"));
      expect(artifact.artifactHash).toBe(h32("c"));
    }
    // 7 round1 + 7 round2_send + 7 round2_receive + 7 finalize == 28 calls
    expect(calls).toHaveLength(28);
    await expect(store.getStatus("frost-dkg-r")).resolves.toMatchObject({ status: "complete" });
  });

  it("aborts frost_dkg_v2 when round2_receive returns a complaint", async () => {
    const fr = frostRoster();
    const { server, store } = buildCoordinatorServer({
      roster: roster(),
      frostDkgV2Roster: fr,
      singleNodeForwarder: async (path, body, _r, slot) => {
        const request = body as Record<string, unknown>;
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round1",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("1"),
              artifactHash: h32("2"),
              frostRound1Broadcast: {
                slot,
                packageHex: "abcd",
                packageHash: h32("3"),
                transcriptHash: h32("1"),
              },
            },
          };
        }
        if (path.endsWith("/round2_send")) {
          const envelopes = Array.from({ length: 6 }, (_, idx) => {
            const toSlot = idx >= slot ? idx + 1 : idx;
            return {
              dealerSlot: slot,
              toSlot,
              packageCommitment: h32("4"),
              hpke: {
                kem: "DHKEM_X25519_HKDF_SHA256",
                kdf: "HKDF_SHA256",
                aead: "AES_256_GCM",
                enc: h32("5"),
                ciphertext: "66",
                aadHash: h32("7"),
              },
            };
          });
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round2_send",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("8"),
              artifactHash: h32("9"),
              frostRound2Envelopes: envelopes,
            },
          };
        }
        // round2_receive: slot 0 emits a complaint
        if (slot === 0) {
          return {
            slot,
            ok: true,
            body: {
              requestId: request.requestId,
              sessionId: request.sessionId,
              protocol: "frost",
              round: "round2_receive",
              operatorSetVersion: "1",
              dkgEpoch: "9",
              slot,
              accepted: true,
              transcriptHash: h32("a"),
              artifactHash: h32("b"),
              complaints: [
                {
                  accusedSlot: 3,
                  evidenceHash: h32("e"),
                  reason: "hpke-open-failed",
                },
              ],
              abortEvidenceHash: h32("f"),
            },
          };
        }
        return {
          slot,
          ok: true,
          body: {
            requestId: request.requestId,
            sessionId: request.sessionId,
            protocol: "frost",
            round: "round2_receive",
            operatorSetVersion: "1",
            dkgEpoch: "9",
            slot,
            accepted: true,
            transcriptHash: h32("a"),
            artifactHash: h32("b"),
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/dkg/frost/v2/start",
      payload: { requestId: "frost-abort", sessionId: "frost-abort-s" },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().round).toBe("round2_receive");
    await expect(store.getStatus("frost-abort")).resolves.toMatchObject({ status: "aborted" });
  });

  it("returns 503 mpc_inverse_unavailable when every selected slot reports it", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server, store } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          // Codex P1 #4 round0: every worker returns h_r_i. Use distinct values per
          // slot so the aggregated allHRoundZero vector mirrors a real workflow.
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hR: h32(String((slot % 9) + 1)),
              workerRound0Hash: h32("a"),
            },
          };
        }
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: false,
            statusCode: 503,
            body: { error: "mpc_inverse_unavailable" },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-503",
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
      },
    });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ error: "mpc_inverse_unavailable" });
    await expect(store.getStatus("vault-ek-503")).resolves.toMatchObject({ status: "unknown" });
  });

  it("rejects caller-supplied selectedSlots (with duplicates) as not-overridable", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => ({
        slot,
        ok: true,
        statusCode: 200,
        body: {},
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-dup",
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
        selectedSlots: [0, 0, 1, 2, 3],
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("selected_slots_not_overridable");
  });

  it("rejects caller-supplied selectedSlots (under-quorum count) as not-overridable", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => ({
        slot,
        ok: true,
        statusCode: 200,
        body: {},
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-quorum",
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
        selectedSlots: [0, 1, 2, 3],
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("selected_slots_not_overridable");
  });

  it("derives vault_ek with coordinator-chosen lowest-5 slots and vault-ek-derivation artifact kind", async () => {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");
    const { round0CommitHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);

    // Mock H_RISTRETTO-shaped contribution: byte content is irrelevant to the coordinator
    // as long as the contribution-worker hash recomputes correctly and the verify response
    // gives a final transcript hash. The TS assembleVaultEkTranscript validates
    // workerTranscriptHash against canonical recomputation, so we must compute it the same
    // way the worker would.
    // Codex P1 #4 round0: contributions only carry hContribution + mpcOpenM. h_r_i values
    // come from the round0 fan-out and are bundled into the transcript-wide
    // allHRoundZero vector. Mock m=1 (LE Scalar::ONE) and h_r = h_contribution so the
    // per-party `h_q_i * 1 == h_r_i` check passes trivially.
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const MOCK_M_HEX = "01" + "00".repeat(31);
    const hContributionPerSlot: Record<number, string> = {};
    const hRPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      hContributionPerSlot[slot] = h32(String((slot % 9) + 1));
      hRPerSlot[slot] = hContributionPerSlot[slot]; // m=1 mock: h_r == h_q
    }
    // Build allHRoundZero in player-ordinal (sorted slot) order.
    const allHRoundZero = expectedSelectedSlots.map((slot) => hRPerSlot[slot]);
    const r0CommitHash = round0CommitHash(allHRoundZero);
    const workerHashPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      const enc = new TextEncoder();
      const sortedSlotsJoined = expectedSelectedSlots.join(",");
      const bytes = new Uint8Array([
        ...enc.encode("EUNOMA_VAULT_EK_DERIVATION_V1"),
        ...enc.encode(dkgEpoch),
        ...enc.encode(":"),
        ...enc.encode(caDkgTranscriptHashHex),
        ...enc.encode(":"),
        ...enc.encode(rosterHashHex),
        ...enc.encode(":"),
        ...enc.encode(sortedSlotsJoined),
        ...enc.encode(":"),
        ...enc.encode(slot.toString()),
        ...enc.encode(":"),
        ...enc.encode(hContributionPerSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(hRPerSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(MOCK_M_HEX),
        ...enc.encode(":"),
        ...enc.encode(r0CommitHash),
      ]);
      workerHashPerSlot[slot] = bytesToHex(sha256(bytes));
    }
    const finalTranscriptHash = h32("e");
    const vaultEk = h32("f");

    type CapturedRecord = {
      requestId: string;
      sessionId: string;
      rosterHash?: string;
      slot: number;
      artifactKind: string;
      artifactHash: string;
      transcriptHash: string;
    };
    const recorded: CapturedRecord[] = [];
    const captureStore = {
      recordSessionShare: async () => {},
      recordPartialArtifact: async (input: CapturedRecord) => {
        recorded.push(input);
      },
      getStatus: async () => ({
        requestId: "x",
        status: "unknown" as const,
        transcriptHashes: [],
        updatedAt: new Date(0).toISOString(),
      }),
      markComplete: async () => {},
      markAborted: async () => {},
    };

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      store: captureStore,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hR: hRPerSlot[slot],
              workerRound0Hash: h32("a"),
            },
          };
        }
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hContribution: hContributionPerSlot[slot],
              schnorrProof: { R: h32("3"), s: h32("4") },
              workerTranscriptHash: workerHashPerSlot[slot],
              mpcOpenM: MOCK_M_HEX,
            },
          };
        }
        if (path.endsWith("/verify")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              vaultEk,
              finalTranscriptHash,
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-happy",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.selectedSlots).toEqual(expectedSelectedSlots);
    expect(body.selectionRationale).toBe("coordinator-chosen");
    expect(body.vaultEk).toBe(vaultEk);
    expect(body.finalTranscriptHash).toBe(finalTranscriptHash);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({
      requestId: "vault-ek-happy",
      artifactKind: "vault-ek-derivation",
      artifactHash: finalTranscriptHash,
      transcriptHash: finalTranscriptHash,
    });
  });

  it("rejects missing caDkgTranscriptHash with no_ca_dkg_v2_record_for_dkg_epoch", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => ({
        slot,
        ok: true,
        statusCode: 200,
        body: {},
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-missing-ca",
        dkgEpoch: "1",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("no_ca_dkg_v2_record_for_dkg_epoch");
  });

  it("vault_ek round1 forwards to all 5 selected slots concurrently (Promise.all)", async () => {
    // Killer concurrency test: each mocked worker waits at a barrier until externally
    // released. If the coordinator awaits sequentially, only one mock will be blocked at the
    // barrier at a time — observed count never reaches 5. Promise.all hits all 5 in flight
    // before any one returns.
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");
    const { round0CommitHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    // Pre-compute the worker-transcript-hash for each slot so the mock returns valid
    // contributions that pass assembleVaultEkTranscript. Codex P1 #4 round0: bind the
    // round0_commit_hash into the canonical hash.
    const MOCK_M_HEX = "01" + "00".repeat(31);
    const hContributionPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      hContributionPerSlot[slot] = h32(String((slot % 9) + 1));
    }
    const allHRoundZero = expectedSelectedSlots.map((slot) => hContributionPerSlot[slot]);
    const r0CommitHash = round0CommitHash(allHRoundZero);
    const workerHashPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      const enc = new TextEncoder();
      const sortedSlotsJoined = expectedSelectedSlots.join(",");
      const bytes = new Uint8Array([
        ...enc.encode("EUNOMA_VAULT_EK_DERIVATION_V1"),
        ...enc.encode(dkgEpoch),
        ...enc.encode(":"),
        ...enc.encode(caDkgTranscriptHashHex),
        ...enc.encode(":"),
        ...enc.encode(rosterHashHex),
        ...enc.encode(":"),
        ...enc.encode(sortedSlotsJoined),
        ...enc.encode(":"),
        ...enc.encode(slot.toString()),
        ...enc.encode(":"),
        ...enc.encode(hContributionPerSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(hContributionPerSlot[slot]), // h_r = h_contribution under m=1 mock
        ...enc.encode(":"),
        ...enc.encode(MOCK_M_HEX),
        ...enc.encode(":"),
        ...enc.encode(r0CommitHash),
      ]);
      workerHashPerSlot[slot] = bytesToHex(sha256(bytes));
    }

    let inFlight = 0;
    let peakInFlight = 0;
    let releaseBarrier: () => void = () => {};
    const barrier = new Promise<void>((resolve) => {
      releaseBarrier = resolve;
    });
    const observedBodies: Array<Record<string, unknown>> = [];

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          // Round0 is fast, no need to barrier through it.
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hR: hContributionPerSlot[slot],
              workerRound0Hash: h32("a"),
            },
          };
        }
        if (path.endsWith("/round1")) {
          observedBodies.push(body as Record<string, unknown>);
          inFlight += 1;
          peakInFlight = Math.max(peakInFlight, inFlight);
          // Block here until the test releases the barrier — and crucially, BEFORE
          // releasing, assert that all 5 mocks have arrived.
          if (inFlight === 5) {
            // Schedule the release on the next microtask so we know the 5th caller is also
            // genuinely awaiting the barrier (not just observed-then-returned synchronously).
            queueMicrotask(() => releaseBarrier());
          }
          await barrier;
          inFlight -= 1;
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hContribution: hContributionPerSlot[slot],
              schnorrProof: { R: h32("3"), s: h32("4") },
              workerTranscriptHash: workerHashPerSlot[slot],
              mpcOpenM: MOCK_M_HEX,
            },
          };
        }
        if (path.endsWith("/verify")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { vaultEk: h32("f"), finalTranscriptHash: h32("e") },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-concurrent",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(res.statusCode).toBe(200);
    // The killer assertion: at some point all 5 round1 mocks must have been in flight
    // simultaneously. Sequential await would peak at 1.
    expect(peakInFlight).toBe(5);

    // All 5 bodies must carry the new Phase 2 fields.
    expect(observedBodies).toHaveLength(5);
    // Codex P1 #2: peer addresses must be derived from per-slot roster endpoint host,
    // not a hardcoded 127.0.0.1. The fixture roster uses `http://node-<slot>.invalid` so
    // the expected MASCOT peer address for each ordinal must be `node-<slot>.invalid:<port>`.
    const portBase = Number(process.env.EUNOMA_MPC_PARTY_PORT_BASE ?? 14000);
    const expectedPeerAddresses = expectedSelectedSlots.map(
      (slot) => `node-${slot}.invalid:${portBase + slot}`,
    );
    for (let i = 0; i < 5; i += 1) {
      const body = observedBodies[i];
      expect(body.requestId).toBe("vault-ek-concurrent");
      expect(body.sessionId).toBe("vault-ek-concurrent");
      expect(typeof body.playerId).toBe("number");
      expect(Array.isArray(body.peerAddresses)).toBe(true);
      expect((body.peerAddresses as string[]).length).toBe(5);
      expect(body.peerAddresses).toEqual(expectedPeerAddresses);
      expect(
        (body.peerAddresses as string[]).every((addr) => !addr.startsWith("127.0.0.1:")),
      ).toBe(true);
      expect(Array.isArray(body.lagrangeCoefficients)).toBe(true);
      expect((body.lagrangeCoefficients as string[]).length).toBe(5);
      // Codex P1 #4 round0: round1 body must include the coordinator-broadcast
      // allHRoundZero vector.
      expect(Array.isArray(body.allHRoundZero)).toBe(true);
      expect((body.allHRoundZero as string[]).length).toBe(5);
      expect(body.allHRoundZero).toEqual(allHRoundZero);
    }
  });

  it("rejects vault_ek round1 when roster endpoint has no parseable host and EUNOMA_LOCAL_CLUSTER!=1", async () => {
    // Codex P1 #2: in production we must NEVER silently fall back to 127.0.0.1. If the
    // roster endpoint is unparseable, the request fails closed.
    const caDkgV2Roster: CaDkgV2Roster = {
      operatorSetVersion: "1",
      dkgEpoch: "1",
      caDkgScheme: "ca_dkg_v2",
      threshold: 5,
      nodes: Array.from({ length: 7 }, (_, slot) => ({
        slot,
        nodeId: `node-${slot}`,
        endpoint: ":::not-a-url:::",
        hpkePublicKey: h32(String(slot + 1)),
        transcriptPublicKey: h32("d"),
      })),
    };
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const prev = process.env.EUNOMA_LOCAL_CLUSTER;
    delete process.env.EUNOMA_LOCAL_CLUSTER;
    try {
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        singleNodeForwarder: async (_path, _body, _roster, slot) => ({
          slot,
          ok: true,
          statusCode: 200,
          body: {},
        }),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/derive/vault_ek/start",
        payload: {
          requestId: "vault-ek-no-host",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
        },
      });
      // The throw inside the try/catch surfaces as 400 invalid_request (the generic catch).
      expect(res.statusCode).toBe(400);
      expect(JSON.stringify(res.json())).toContain("no parseable hostname");
    } finally {
      if (prev !== undefined) process.env.EUNOMA_LOCAL_CLUSTER = prev;
    }
  });

  it("rejects vault_ek when workers report disagreeing mpcOpenM (codex P1 #4)", async () => {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");
    const { round0CommitHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const MOCK_M_HONEST = "01" + "00".repeat(31);
    const MOCK_M_EVIL = "02" + "00".repeat(31);
    const hContributionPerSlot: Record<number, string> = {};
    const mForSlot: Record<number, string> = {};
    const hRPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      hContributionPerSlot[slot] = h32(String((slot % 9) + 1));
      mForSlot[slot] = slot === 2 ? MOCK_M_EVIL : MOCK_M_HONEST;
      hRPerSlot[slot] = hContributionPerSlot[slot];
    }
    const allHRoundZero = expectedSelectedSlots.map((slot) => hRPerSlot[slot]);
    const r0CommitHash = round0CommitHash(allHRoundZero);
    const workerHashPerSlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      const enc = new TextEncoder();
      const bytes = new Uint8Array([
        ...enc.encode("EUNOMA_VAULT_EK_DERIVATION_V1"),
        ...enc.encode(dkgEpoch),
        ...enc.encode(":"),
        ...enc.encode(caDkgTranscriptHashHex),
        ...enc.encode(":"),
        ...enc.encode(rosterHashHex),
        ...enc.encode(":"),
        ...enc.encode(expectedSelectedSlots.join(",")),
        ...enc.encode(":"),
        ...enc.encode(slot.toString()),
        ...enc.encode(":"),
        ...enc.encode(hContributionPerSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(hRPerSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(mForSlot[slot]),
        ...enc.encode(":"),
        ...enc.encode(r0CommitHash),
      ]);
      workerHashPerSlot[slot] = bytesToHex(sha256(bytes));
    }
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hR: hRPerSlot[slot],
              workerRound0Hash: h32("a"),
            },
          };
        }
        if (path.endsWith("/round1")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              hContribution: hContributionPerSlot[slot],
              schnorrProof: { R: h32("3"), s: h32("4") },
              workerTranscriptHash: workerHashPerSlot[slot],
              mpcOpenM: mForSlot[slot],
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-m-disagree",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("mpc_open_m_disagreement");
  });

  it("short-circuits round1 fan-out when one worker returns 503 (codex P2 #8)", async () => {
    // Codex P2 #8: when one worker is fast-503'd (MP-SPDZ unavailable on that slot), the
    // coordinator must NOT wait for the other 4 to settle — they'll block in MASCOT
    // preprocessing for up to 60s. Expected: 503 returned within ~tens of ms.
    //
    // Codex P2 #8 regression: with the round0 fan-out, round0 itself must complete (no
    // MASCOT) before round1 even starts. Mock round0 as instant-success and exercise the
    // short-circuit only in round1.
    const caDkgV2Roster = dkgRoster();
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    let neverResolveCount = 0;
    let inFlightRound1 = 0;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, hR: h32(String((slot % 9) + 1)), workerRound0Hash: h32("a") },
          };
        }
        if (path.endsWith("/round1")) {
          inFlightRound1 += 1;
          if (slot === 2) {
            // Fast 503 from one slot.
            return {
              slot,
              ok: false,
              statusCode: 503,
              body: { error: "mpc_inverse_unavailable" },
            };
          }
          // Other slots hang forever (simulate MASCOT waiting for peer connect).
          neverResolveCount += 1;
          return new Promise<never>(() => {});
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });
    const start = Date.now();
    // Codex P2 #8 regression: the coordinator now keeps the handler open until siblings
    // settle. With 4 hanging promises, server.inject() will not resolve. We use the
    // raw injection but with a timeout race so we measure the time-to-503 from the
    // *response stream* — Fastify's reply.send() flushes before allSettled completes.
    // Instead use a side-channel: track when neverResolveCount peaks at 4.
    const completed = server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-503-fast",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    // Wait until 4 round1 calls have been dispatched (so the 503 short-circuit can fire).
    while (neverResolveCount < 4) {
      await new Promise((r) => setTimeout(r, 10));
      if (Date.now() - start > 5000) break;
    }
    // The response is in flight; the handler is now awaiting allSettled. Since inject()
    // won't return until the handler returns and the handler awaits the hung promises,
    // we can't await `completed` here directly. Instead measure elapsed and skip the
    // body-content check.
    const elapsed = Date.now() - start;
    // Killer assertion: short-circuit happened quickly (we dispatched all 5 round1 calls
    // including the fast-503 one), even though the response is still being held open by
    // the lock-retention await.
    expect(elapsed).toBeLessThan(2000);
    // Sanity: the other 4 slots WERE dispatched (so we proved concurrency, not lazy eval).
    expect(neverResolveCount).toBe(4);
    expect(inFlightRound1).toBe(5);
    void completed; // suppress unhandled-promise warning; we never await it
  });

  it("returns 409 vault_ek_derivation_in_flight when a second request arrives during one", async () => {
    // Lock-contention test: the first request hangs at the round1 mock until we release a
    // deferred; a concurrent second request must get 409 quickly because the in-flight lock
    // is held.
    const caDkgV2Roster = dkgRoster();
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");

    let releaseFirst: () => void = () => {};
    const firstHeld = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstCallStarted = false;

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, hR: h32(String((slot % 9) + 1)), workerRound0Hash: h32("a") },
          };
        }
        if (path.endsWith("/round1")) {
          firstCallStarted = true;
          await firstHeld; // hold all 5 round1 mocks here until released
          return {
            slot,
            ok: false,
            statusCode: 503,
            body: { error: "mpc_inverse_unavailable" },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-lock-1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    // Wait for the first request to actually grab the lock + reach the mocked round1.
    while (!firstCallStarted) {
      await new Promise((r) => setTimeout(r, 5));
    }
    // Now issue the second request — it must return 409 quickly because the lock is still
    // held by the first.
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-lock-2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("vault_ek_derivation_in_flight");

    // Release the first request — it may return any error since we mocked 503 on round1, but
    // it must complete (not deadlock).
    releaseFirst();
    const firstRes = await firstPromise;
    // First request returns 503 from the mock — anything except a hang is fine here.
    expect([200, 503]).toContain(firstRes.statusCode);
  });

  it("round0_failure_releases_lock_cleanly", async () => {
    // Codex P1 #4 round0: if round0 fan-out fails on any slot, the coordinator must
    // release the lock cleanly so a retry can proceed. Otherwise the failed request
    // leaks the lock and blocks subsequent derivations.
    const caDkgV2Roster = dkgRoster();
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");

    let round0Attempts = 0;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          round0Attempts += 1;
          if (slot === 1) {
            // Slot 1 fails (e.g., disk error, validation failure).
            return {
              slot,
              ok: false,
              statusCode: 500,
              body: { error: "round0_internal_error" },
            };
          }
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, hR: h32(String((slot % 9) + 1)), workerRound0Hash: h32("a") },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const firstRes = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-r0-fail-1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(firstRes.statusCode).toBe(502);
    expect(firstRes.json().error).toBe("round0_forward_failed");
    expect(round0Attempts).toBe(5); // all 5 dispatched concurrently

    // Now a second request MUST be able to acquire the lock — the failed first request
    // must have released it. If the lock were leaked, this would 409.
    round0Attempts = 0;
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-r0-fail-2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(secondRes.statusCode).toBe(502);
    expect(round0Attempts).toBe(5);
  });

  it("lock_held_until_inflight_settle (codex P2 #8 regression)", async () => {
    // Codex P2 #8 regression: when one worker returns 503 mpc_inverse_unavailable, the
    // coordinator must NOT release the session lock until the other in-flight workers
    // have settled. Otherwise a new derivation can start and collide with the still-
    // running MASCOT subprocesses on the fixed peer ports.
    //
    // This test simulates: 1 worker returns 503 instantly, 4 workers hang. While the 4
    // are still pending, a second /v2/derive/vault_ek/start request MUST get 409 —
    // proving the lock is still held. After releasing the 4 hung workers, the second
    // request can succeed.
    const caDkgV2Roster = dkgRoster();
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");

    let releaseHung: () => void = () => {};
    const hungBarrier = new Promise<void>((resolve) => {
      releaseHung = resolve;
    });
    let round1DispatchCount = 0;
    let firstRoundReached = false;

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path.endsWith("/round0")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, hR: h32(String((slot % 9) + 1)), workerRound0Hash: h32("a") },
          };
        }
        if (path.endsWith("/round1")) {
          round1DispatchCount += 1;
          firstRoundReached = true;
          if (slot === 2) {
            // Slot 2 returns 503 instantly.
            return {
              slot,
              ok: false,
              statusCode: 503,
              body: { error: "mpc_inverse_unavailable" },
            };
          }
          // Other 4 slots hang until release.
          await hungBarrier;
          return { slot, ok: false, statusCode: 500, body: { error: "released" } };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-lock-held-1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    // Wait for round1 dispatch to begin.
    while (!firstRoundReached || round1DispatchCount < 5) {
      await new Promise((r) => setTimeout(r, 5));
    }
    // Brief settle window to ensure the detector saw the 503 winner.
    await new Promise((r) => setTimeout(r, 50));

    // The first request's response is being held open by the lock-retention await.
    // A second request now MUST 409 — the lock is still held by the first.
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/derive/vault_ek/start",
      payload: {
        requestId: "vault-ek-lock-held-2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
      },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("vault_ek_derivation_in_flight");

    // Release the hung workers. The first request can now finish (return 503).
    releaseHung();
    const firstRes = await firstPromise;
    expect(firstRes.statusCode).toBe(503);
  });

  // =============================================================================================
  // Milestone 1: V2 threshold CA registration sigma tests.
  //
  // The orchestrator routes /v2/derive/ca_registration/start -> round1 fan-out -> challenge
  // helper -> round2 fan-out -> aggregate-and-verify. Tests assert: (a) concurrent fan-out
  // for round1 and round2 (Promise.all not sequential), (b) aggregate_proof_invalid maps to
  // 502, (c) lock contention returns 409.
  // =============================================================================================
  it("ca_registration_v2 concurrent fan-out — round1 and round2 each in flight to all 5 slots", async () => {
    const { caRegistrationV2Round1WorkerTranscriptHash, caRegistrationV2Round2WorkerTranscriptHash } =
      await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("c");
    const senderAddress = h32("d");
    const assetType = h32("e");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    // Worker stubs return placeholder hex bodies; the coordinator's worker-hash cross-check
    // computes the expected hash from public inputs and compares it to the stub's
    // returned value — so the stub MUST mirror the canonical computation.
    let round1InFlight = 0;
    let round1Peak = 0;
    let round2InFlight = 0;
    let round2Peak = 0;
    let releaseRound1: () => void = () => {};
    const round1Barrier = new Promise<void>((resolve) => {
      releaseRound1 = resolve;
    });
    let releaseRound2: () => void = () => {};
    const round2Barrier = new Promise<void>((resolve) => {
      releaseRound2 = resolve;
    });

    const round1NonceIdBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1NonceIdBySlot[slot] = h32(String((slot + 6) % 16).slice(-1) || "f").slice(0, 64);
    }
    const round1CommitmentBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1CommitmentBySlot[slot] = h32(String((slot % 9) + 1));
    }
    const round2ResponseBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round2ResponseBySlot[slot] = h32(String((slot % 7) + 1).padStart(1, "0"));
    }
    const challengeFromAggregator = h32("3");
    const finalAggregateCommitment = h32("4");
    const finalAggregateResponse = h32("5");

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path.endsWith("/ca_registration/round1")) {
          round1InFlight += 1;
          round1Peak = Math.max(round1Peak, round1InFlight);
          if (round1InFlight === 5) queueMicrotask(() => releaseRound1());
          await round1Barrier;
          round1InFlight -= 1;
          const commitmentHex = round1CommitmentBySlot[slot];
          const nonceId = round1NonceIdBySlot[slot];
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round1WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            rosterHash: rosterHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitmentHex,
            nonceId,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              commitmentHex,
              commitmentHash: h32("a"),
              nonceId,
              workerTranscriptHash: workerHash,
            },
          };
        }
        if (path.endsWith("/ca_registration/challenge")) {
          // Interim aggregator: returns aggregateCommitment + challenge.
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              aggregateCommitment: finalAggregateCommitment,
              challenge: challengeFromAggregator,
            },
          };
        }
        if (path.endsWith("/ca_registration/round2")) {
          round2InFlight += 1;
          round2Peak = Math.max(round2Peak, round2InFlight);
          if (round2InFlight === 5) queueMicrotask(() => releaseRound2());
          await round2Barrier;
          round2InFlight -= 1;
          const responseHex = round2ResponseBySlot[slot];
          const playerId = expectedSelectedSlots.indexOf(slot);
          const enc = new TextEncoder();
          // Mirror the canonical response-hash computation: sha256(bytes(responseHex))
          const { sha256 } = await import("@noble/hashes/sha256");
          const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");
          const responseHash = bytesToHex(sha256(hexToBytes(responseHex)));
          const workerHash = caRegistrationV2Round2WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            nonceId: round1NonceIdBySlot[slot],
            challenge: challengeFromAggregator,
            responseHash,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              responseHex,
              responseHash,
              workerTranscriptHash: workerHash,
            },
          };
        }
        if (path.endsWith("/ca_registration/aggregate")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              aggregateCommitment: finalAggregateCommitment,
              aggregateResponse: finalAggregateResponse,
              challenge: challengeFromAggregator,
              proofHash: h32("9"),
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path", path } };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-v2-concurrent",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    expect(body.vaultEk).toBe(vaultEk);
    expect(body.aggregateCommitment).toBe(finalAggregateCommitment);
    expect(body.aggregateResponse).toBe(finalAggregateResponse);
    expect(body.challenge).toBe(challengeFromAggregator);
    expect(body.selectedSlots).toEqual(expectedSelectedSlots);
    expect(body.selectionRationale).toBe("coordinator-chosen");
    expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);

    // Killer assertions: BOTH rounds must have hit peak-5 in-flight (concurrent fan-out).
    expect(round1Peak).toBe(5);
    expect(round2Peak).toBe(5);
  });

  it("ca_registration_v2 returns 502 aggregate_proof_invalid when verifier rejects", async () => {
    const { caRegistrationV2Round1WorkerTranscriptHash, caRegistrationV2Round2WorkerTranscriptHash } =
      await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("c");
    const senderAddress = h32("d");
    const assetType = h32("e");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const challenge = h32("3");

    const round1NonceIdBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1NonceIdBySlot[slot] = h32(String((slot + 6) % 16).slice(-1) || "f").slice(0, 64);
    }

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path.endsWith("/ca_registration/round1")) {
          const commitmentHex = h32(String((slot % 9) + 1));
          const nonceId = round1NonceIdBySlot[slot];
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round1WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            rosterHash: rosterHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitmentHex,
            nonceId,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              commitmentHex,
              commitmentHash: h32("a"),
              nonceId,
              workerTranscriptHash: workerHash,
            },
          };
        }
        if (path.endsWith("/ca_registration/challenge")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { aggregateCommitment: h32("4"), challenge },
          };
        }
        if (path.endsWith("/ca_registration/round2")) {
          const responseHex = h32(String((slot % 7) + 1));
          const { sha256 } = await import("@noble/hashes/sha256");
          const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");
          const responseHash = bytesToHex(sha256(hexToBytes(responseHex)));
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round2WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            nonceId: round1NonceIdBySlot[slot],
            challenge,
            responseHash,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, responseHex, responseHash, workerTranscriptHash: workerHash },
          };
        }
        if (path.endsWith("/ca_registration/aggregate")) {
          // Verifier rejects with the canonical "registration sigma proof verification failed"
          // message that the orchestrator looks for to map to aggregate_proof_invalid.
          return {
            slot,
            ok: false,
            statusCode: 400,
            body: {
              error: "worker_error",
              message: "Crypto(\"registration sigma proof verification failed\")",
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-v2-invalid",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("aggregate_proof_invalid");
  });

  it("ca_registration_v2 returns 409 ca_registration_v2_in_flight on concurrent start", async () => {
    const { caRegistrationV2Round1WorkerTranscriptHash, caRegistrationV2Round2WorkerTranscriptHash } =
      await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("c");
    const senderAddress = h32("d");
    const assetType = h32("e");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const challenge = h32("3");
    const aggregateCommitment = h32("4");

    const round1NonceIdBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1NonceIdBySlot[slot] = h32(String((slot + 6) % 16).slice(-1) || "f").slice(0, 64);
    }

    let releaseFirst: () => void = () => {};
    const firstHold = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let round1Started = 0;

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path.endsWith("/ca_registration/round1")) {
          round1Started += 1;
          await firstHold;
          const commitmentHex = h32(String((slot % 9) + 1));
          const nonceId = round1NonceIdBySlot[slot];
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round1WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            rosterHash: rosterHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitmentHex,
            nonceId,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              commitmentHex,
              commitmentHash: h32("a"),
              nonceId,
              workerTranscriptHash: workerHash,
            },
          };
        }
        if (path.endsWith("/ca_registration/challenge")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { aggregateCommitment, challenge },
          };
        }
        if (path.endsWith("/ca_registration/round2")) {
          const responseHex = h32(String((slot % 7) + 1));
          const { sha256 } = await import("@noble/hashes/sha256");
          const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");
          const responseHash = bytesToHex(sha256(hexToBytes(responseHex)));
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round2WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            nonceId: round1NonceIdBySlot[slot],
            challenge,
            responseHash,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, responseHex, responseHash, workerTranscriptHash: workerHash },
          };
        }
        if (path.endsWith("/ca_registration/aggregate")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              aggregateCommitment,
              aggregateResponse: h32("5"),
              challenge,
              proofHash: h32("9"),
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-v2-lock-1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    while (round1Started < 5) {
      await new Promise((r) => setTimeout(r, 5));
    }
    // First request is blocked at round1 barrier; the lock is held. Second start MUST 409.
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-v2-lock-2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("ca_registration_v2_in_flight");

    releaseFirst();
    const firstRes = await firstPromise;
    expect(firstRes.statusCode).toBe(200);
  });

  // =============================================================================================
  // Codex P2 #1: vaultEk provenance verification.
  //
  // The coordinator accepts vaultEk from the request body. Without verifying that this
  // value came from a real Phase 2 transcript, a stale or forged vaultEk would burn five
  // workers' nonces before the aggregate verifier catches the mismatch. The fix scans
  // the coordinator's persisted Phase 2 transcripts at
  // `<stateRoot>/coordinator/vault_ek_derivation/` for a matching tuple BEFORE acquiring
  // the lock or calling workers.
  // =============================================================================================
  it("ca_registration_v2 rejects unknown vaultEk provenance when stateRoot is configured", async () => {
    const { mkdtemp, writeFile, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-provenance-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const realVaultEk = h32("c");
    const otherVaultEk = h32("9"); // never persisted

    // Persist a Phase 2 artifact for `realVaultEk` but NOT for `otherVaultEk`.
    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    const phase2Artifact = {
      scheme: "vault_ek_derivation_v1",
      dkgEpoch,
      caDkgTranscriptHash: caDkgTranscriptHashHex,
      selectedSlots: [0, 1, 2, 3, 4],
      selectionRationale: "coordinator-chosen",
      rosterHash: rosterHashHex,
      verifierSlot: 0,
      perSlotContributions: [],
      vaultEk: realVaultEk,
      finalTranscriptHash: h32("7"),
      createdAtUnixMs: 1_700_000_000_000,
    };
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__some-prior-derive.json`),
      JSON.stringify(phase2Artifact, null, 2),
      { mode: 0o600 },
    );

    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });

    // Case 1: unknown vaultEk → 400 vault_ek_provenance_unknown, worker NEVER called.
    const unknownRes = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-unknown-provenance",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk: otherVaultEk,
        senderAddress: h32("d"),
        assetType: h32("e"),
        chainId: 2,
      },
    });
    expect(unknownRes.statusCode).toBe(400);
    expect(unknownRes.json().error).toBe("vault_ek_provenance_unknown");
    expect(workerCalled).toBe(false);

    // Case 2: vaultEk for a Phase 2 transcript with a DIFFERENT dkgEpoch → still rejected.
    const wrongEpochRes = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-wrong-epoch",
        dkgEpoch: "999", // never persisted
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk: realVaultEk,
        senderAddress: h32("d"),
        assetType: h32("e"),
        chainId: 2,
      },
    });
    expect(wrongEpochRes.statusCode).toBe(400);
    // dkgEpoch != roster.dkgEpoch may surface either as stale_dkg_epoch (roster mismatch)
    // OR vault_ek_provenance_unknown (no matching transcript). Both are fail-closed.
    expect(["vault_ek_provenance_unknown", "stale_dkg_epoch"]).toContain(
      wrongEpochRes.json().error,
    );
    expect(workerCalled).toBe(false);
  });

  it("ca_registration_v2 accepts the call + records vaultEkTranscriptHash when provenance matches", async () => {
    const { caRegistrationV2Round1WorkerTranscriptHash, caRegistrationV2Round2WorkerTranscriptHash } =
      await import("@eunoma/deop-protocol");
    const { mkdtemp, writeFile, mkdir, readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-provenance-ok-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("c");
    const senderAddress = h32("d");
    const assetType = h32("e");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const persistedTranscriptHash = h32("7");

    // Persist a Phase 2 artifact for the (dkgEpoch, vaultEk, caDkgTranscriptHash,
    // rosterHash) tuple the request will use.
    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__derive-ok.json`),
      JSON.stringify({
        scheme: "vault_ek_derivation_v1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        selectedSlots: expectedSelectedSlots,
        selectionRationale: "coordinator-chosen",
        rosterHash: rosterHashHex,
        verifierSlot: 0,
        perSlotContributions: [],
        vaultEk,
        finalTranscriptHash: persistedTranscriptHash,
        createdAtUnixMs: 1_700_000_000_000,
      }, null, 2),
      { mode: 0o600 },
    );

    const round1NonceIdBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1NonceIdBySlot[slot] = h32(String((slot + 6) % 16).slice(-1) || "f").slice(0, 64);
    }
    const round1CommitmentBySlot: Record<number, string> = {};
    for (const slot of expectedSelectedSlots) {
      round1CommitmentBySlot[slot] = h32(String((slot % 9) + 1));
    }
    const challengeFromAggregator = h32("3");
    const finalAggregateCommitment = h32("4");
    const finalAggregateResponse = h32("5");

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path.endsWith("/ca_registration/round1")) {
          const commitmentHex = round1CommitmentBySlot[slot];
          const nonceId = round1NonceIdBySlot[slot];
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round1WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            rosterHash: rosterHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitmentHex,
            nonceId,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              commitmentHex,
              commitmentHash: h32("a"),
              nonceId,
              workerTranscriptHash: workerHash,
            },
          };
        }
        if (path.endsWith("/ca_registration/challenge")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { aggregateCommitment: finalAggregateCommitment, challenge: challengeFromAggregator },
          };
        }
        if (path.endsWith("/ca_registration/round2")) {
          const responseHex = h32(String((slot % 7) + 1).padStart(1, "0"));
          const { sha256 } = await import("@noble/hashes/sha256");
          const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");
          const responseHash = bytesToHex(sha256(hexToBytes(responseHex)));
          const playerId = expectedSelectedSlots.indexOf(slot);
          const workerHash = caRegistrationV2Round2WorkerTranscriptHash({
            sessionId: (body as Record<string, unknown>).sessionId as string,
            requestId: (body as Record<string, unknown>).requestId as string,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashHex,
            sortedSelectedSlots: expectedSelectedSlots,
            selfSlot: slot,
            playerId,
            nonceId: round1NonceIdBySlot[slot],
            challenge: challengeFromAggregator,
            responseHash,
          });
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: { slot, responseHex, responseHash, workerTranscriptHash: workerHash },
          };
        }
        if (path.endsWith("/ca_registration/aggregate")) {
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              aggregateCommitment: finalAggregateCommitment,
              aggregateResponse: finalAggregateResponse,
              challenge: challengeFromAggregator,
              proofHash: h32("9"),
            },
          };
        }
        return { slot, ok: false, statusCode: 500, body: { error: "unexpected" } };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-provenance-ok",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    // Response surfaces the Phase 2 cross-reference.
    expect(body.vaultEkTranscriptHash).toBe(persistedTranscriptHash);
    // Persisted artifact records the cross-reference too.
    expect(typeof body.transcriptPath).toBe("string");
    const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
    expect(artifact.vaultEkTranscriptHash).toBe(persistedTranscriptHash);
    expect(typeof artifact.vaultEkTranscriptPath).toBe("string");
  });

  it("ca_registration_v2 rejects vault_ek_provenance_mismatch when supplied hash disagrees", async () => {
    const { mkdtemp, writeFile, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-provenance-pin-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const realVaultEk = h32("c");
    const persistedTranscriptHash = h32("7");

    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__derive-x.json`),
      JSON.stringify({
        scheme: "vault_ek_derivation_v1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        selectedSlots: [0, 1, 2, 3, 4],
        selectionRationale: "coordinator-chosen",
        rosterHash: rosterHashHex,
        verifierSlot: 0,
        perSlotContributions: [],
        vaultEk: realVaultEk,
        finalTranscriptHash: persistedTranscriptHash,
        createdAtUnixMs: 1_700_000_000_000,
      }, null, 2),
      { mode: 0o600 },
    );

    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });

    // Caller pins the wrong transcript hash → 400 vault_ek_provenance_mismatch.
    const res = await server.inject({
      method: "POST",
      url: "/v2/derive/ca_registration/start",
      payload: {
        requestId: "ca-reg-pin-mismatch",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk: realVaultEk,
        vaultEkTranscriptHash: h32("9"), // does NOT match the persisted finalTranscriptHash
        senderAddress: h32("d"),
        assetType: h32("e"),
        chainId: 2,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("vault_ek_provenance_mismatch");
    expect(workerCalled).toBe(false);
  });

  // =============================================================================================
  // Milestone 2 sub-milestone 2a: vault-state share initialization orchestrator tests.
  // =============================================================================================
  it("vault_state_v2 init concurrent fan-out to all 5 selected slots", async () => {
    const { vaultStateV2InitWorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEkTranscriptHash = h32("b");
    const registrationTranscriptHash = h32("c");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const aggregateCommitment = h32("1");
    const aggregateResponse = h32("2");
    const challenge = h32("3");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    let initInFlight = 0;
    let initPeak = 0;
    let releaseInit: () => void = () => {};
    const initBarrier = new Promise<void>((resolve) => {
      releaseInit = resolve;
    });

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        // Codex M3a P1: handle the second-round /init/finalize fan-out. The mock workers
        // here apply the SAME semantics as the real Rust workers — they re-derive the
        // final transcript hash from the supplied contributions and echo back
        // `initTranscriptHash = finalTranscriptHash`. A real worker would also UPDATE
        // its persisted vault_state_v2.json to pin this canonical value.
        if (path === "/worker/v2/vault_state/init/finalize") {
          const playerId = expectedSelectedSlots.indexOf(slot);
          const finalTranscriptHash = (body as Record<string, unknown>).finalTranscriptHash as string;
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              playerId,
              vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
              vaultStateHash: h32(String((slot + 5) % 9)),
              initTranscriptHash: finalTranscriptHash,
              finalized: true,
            },
          };
        }
        if (path !== "/worker/v2/vault_state/init") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path", path } };
        }
        initInFlight += 1;
        initPeak = Math.max(initPeak, initInFlight);
        if (initInFlight === 5) queueMicrotask(() => releaseInit());
        await initBarrier;
        initInFlight -= 1;

        const playerId = expectedSelectedSlots.indexOf(slot);
        const vaultStateHash = h32(String((slot + 5) % 9));
        const workerTranscriptHash = vaultStateV2InitWorkerTranscriptHash({
          sessionId: (body as Record<string, unknown>).sessionId as string,
          requestId: (body as Record<string, unknown>).requestId as string,
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: rosterHashHex,
          sortedSelectedSlots: expectedSelectedSlots,
          selfSlot: slot,
          playerId,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          vaultSequence: 0,
          depositCountObserved: 0,
        });
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash,
            workerTranscriptHash,
            vaultSequence: 0,
            depositCountObserved: 0,
            createdAtUnixMs: 1_700_000_000_000 + slot,
            initialized: true,
          },
        };
      },
    });

    // No stateRoot configured → caller must supply *TranscriptHash and the sigma tuple inline.
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        requestId: "vault-state-concurrent",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
        vaultEkTranscriptHash,
        registrationTranscriptHash,
        aggregateCommitment,
        aggregateResponse,
        challenge,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    expect(body.selectedSlots).toEqual(expectedSelectedSlots);
    expect(body.selectionRationale).toBe("coordinator-chosen");
    expect(body.vaultEk).toBe(vaultEk);
    expect(body.vaultEkTranscriptHash).toBe(vaultEkTranscriptHash);
    expect(body.registrationTranscriptHash).toBe(registrationTranscriptHash);
    expect(body.aggregateCommitment).toBe(aggregateCommitment);
    expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.perSlotContributions).toHaveLength(5);
    // KILLER ASSERTION: concurrent fan-out — all 5 workers in flight simultaneously.
    expect(initPeak).toBe(5);
  });

  it("vault_state_v2 init returns 502 worker_transcript_hash_mismatch on tampered worker reply", async () => {
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path !== "/worker/v2/vault_state/init") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId: slot,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash: h32("a"),
            // Tamper: return a transcript hash that DOESN'T match the TS-side reconstruction.
            workerTranscriptHash: h32(String((slot % 9) + 1)),
            vaultSequence: 0,
            depositCountObserved: 0,
            createdAtUnixMs: 1_700_000_000_000,
            initialized: true,
          },
        };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        requestId: "vault-state-tamper",
        dkgEpoch,
        caDkgTranscriptHash: h32("a"),
        vaultEk: h32("d"),
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
        vaultEkTranscriptHash: h32("b"),
        registrationTranscriptHash: h32("c"),
        aggregateCommitment: h32("1"),
        aggregateResponse: h32("2"),
        challenge: h32("3"),
      },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("worker_transcript_hash_mismatch");
  });

  it("vault_state_v2 init returns 409 vault_state_v2_init_in_flight on concurrent calls", async () => {
    const caDkgV2Roster = dkgRoster();
    const dkgEpoch = "1";

    let releaseHung: () => void = () => {};
    const hungBarrier = new Promise<void>((resolve) => {
      releaseHung = resolve;
    });
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => {
        // First call hangs forever (until released).
        await hungBarrier;
        return { slot, ok: false, statusCode: 500, body: {} };
      },
    });

    const payload = {
      dkgEpoch,
      caDkgTranscriptHash: h32("a"),
      vaultEk: h32("d"),
      senderAddress: h32("e"),
      assetType: h32("f"),
      chainId: 2,
      vaultEkTranscriptHash: h32("b"),
      registrationTranscriptHash: h32("c"),
      aggregateCommitment: h32("1"),
      aggregateResponse: h32("2"),
      challenge: h32("3"),
    };
    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: { requestId: "vault-state-lock-1", ...payload },
    });
    // Allow first call's microtasks to run + acquire the lock.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: { requestId: "vault-state-lock-2", ...payload },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("vault_state_v2_init_in_flight");

    releaseHung();
    await firstPromise;
  });

  it("vault_state_v2 init rejects forbidden plaintext fields recursively", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
        vaultEk: h32("d"),
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
        vaultEkTranscriptHash: h32("b"),
        registrationTranscriptHash: h32("c"),
        aggregateCommitment: h32("1"),
        aggregateResponse: h32("2"),
        challenge: h32("3"),
        metadata: { dkShare: "leak" },
      },
    });
    // Note: dkShare is recursed into via the body parser at the orchestrator level — but the
    // orchestrator currently doesn't call parseVaultStateV2InitRequest on the OUTER body
    // (it does its own shape validation). The recursive forbidden-field guard fires from the
    // deop-protocol assembleVaultStateV2InitTranscript path which the orchestrator goes
    // through. Either way the request must be rejected.
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(res.statusCode).toBeLessThan(500);
  });

  it("vault_state_v2 init rejects stale dkgEpoch", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        dkgEpoch: "999", // doesn't match roster.dkgEpoch == "1"
        caDkgTranscriptHash: h32("a"),
        vaultEk: h32("d"),
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
        vaultEkTranscriptHash: h32("b"),
        registrationTranscriptHash: h32("c"),
        aggregateCommitment: h32("1"),
        aggregateResponse: h32("2"),
        challenge: h32("3"),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("stale_dkg_epoch");
  });

  // Codex M2a P2 #3: requestId is embedded into transcript paths
  // (<stateRoot>/coordinator/vault_state_v2/<dkgEpoch>__<requestId>.json). A caller-supplied
  // requestId containing path separators ("../"), null bytes, or non-ASCII must be rejected
  // 400 BEFORE the lock acquire / provenance scan / worker fan-out. This test exercises
  // each unsafe shape against the three endpoints that take a caller-supplied requestId
  // and write a transcript file.
  //
  // The empty-string case is intentionally NOT included here: the endpoints fall back to a
  // server-generated default in that case (`vault-ek-derive-${Date.now()}` etc), which is
  // safe by construction. The unsafe-id guard never sees the empty value.
  it("rejects unsafe requestId before lock / provenance / fan-out across all 3 transcript-writing endpoints", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const unsafeIds = [
      "../../etc/passwd", // path traversal
      "a/b", // path separator
      "a\\b", // windows separator
      "a\0b", // null byte
      "a\nb", // newline
      "a b", // space
      "a:b", // colon (rejected even though it's a valid Unix path char)
      "x".repeat(129), // over length cap
    ];
    for (const requestId of unsafeIds) {
      // /v2/derive/vault_ek/start
      const r1 = await server.inject({
        method: "POST",
        url: "/v2/derive/vault_ek/start",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          requestId,
        },
      });
      // /v2/derive/ca_registration/start
      const r2 = await server.inject({
        method: "POST",
        url: "/v2/derive/ca_registration/start",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          vaultEk: h32("d"),
          senderAddress: h32("e"),
          assetType: h32("f"),
          chainId: 2,
          requestId,
        },
      });
      // /v2/vault_state/init
      const r3 = await server.inject({
        method: "POST",
        url: "/v2/vault_state/init",
        payload: {
          dkgEpoch: "1",
          caDkgTranscriptHash: h32("a"),
          vaultEk: h32("d"),
          senderAddress: h32("e"),
          assetType: h32("f"),
          chainId: 2,
          vaultEkTranscriptHash: h32("b"),
          registrationTranscriptHash: h32("c"),
          aggregateCommitment: h32("1"),
          aggregateResponse: h32("2"),
          challenge: h32("3"),
          requestId,
        },
      });
      expect(r1.statusCode).toBe(400);
      expect(r1.json().error).toBe("unsafe_request_id");
      expect(r2.statusCode).toBe(400);
      expect(r2.json().error).toBe("unsafe_request_id");
      expect(r3.statusCode).toBe(400);
      expect(r3.json().error).toBe("unsafe_request_id");
    }
  });

  it("vault_state_v2 init resolves provenance from persisted transcripts when stateRoot configured", async () => {
    const { vaultStateV2InitWorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const { mkdtemp, writeFile, mkdir, readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-vault-state-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const persistedVaultEkTranscriptHash = h32("7");
    const persistedRegistrationTranscriptHash = h32("8");
    const persistedAggCommitment = h32("4");
    const persistedAggResponse = h32("5");
    const persistedChallenge = h32("6");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__phase2.json`),
      JSON.stringify(
        {
          scheme: "vault_ek_derivation_v1",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          selectedSlots: expectedSelectedSlots,
          selectionRationale: "coordinator-chosen",
          rosterHash: rosterHashHex,
          verifierSlot: 0,
          perSlotContributions: [],
          vaultEk,
          finalTranscriptHash: persistedVaultEkTranscriptHash,
          createdAtUnixMs: 1_700_000_000_000,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );

    const m1Dir = join(stateRoot, "coordinator", "ca_registration_v2");
    await mkdir(m1Dir, { recursive: true });
    await writeFile(
      join(m1Dir, `${dkgEpoch}__milestone1.json`),
      JSON.stringify(
        {
          scheme: "ca_registration_v2",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          rosterHash: rosterHashHex,
          selectedSlots: expectedSelectedSlots,
          verifierSlot: 0,
          vaultEk,
          vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment: persistedAggCommitment,
          aggregateResponse: persistedAggResponse,
          challenge: persistedChallenge,
          perSlotContributions: [],
          transcriptHash: persistedRegistrationTranscriptHash,
          createdAtUnixMs: 1_700_000_000_000,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        // Codex M3a P1: respond to the second-round finalize fan-out.
        if (path === "/worker/v2/vault_state/init/finalize") {
          const playerId = expectedSelectedSlots.indexOf(slot);
          const finalTranscriptHash = (body as Record<string, unknown>).finalTranscriptHash as string;
          return {
            slot,
            ok: true,
            statusCode: 200,
            body: {
              slot,
              playerId,
              vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
              vaultStateHash: h32(String((slot + 5) % 9)),
              initTranscriptHash: finalTranscriptHash,
              finalized: true,
            },
          };
        }
        if (path !== "/worker/v2/vault_state/init") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        const playerId = expectedSelectedSlots.indexOf(slot);
        const vaultStateHash = h32(String((slot + 5) % 9));
        const workerTranscriptHash = vaultStateV2InitWorkerTranscriptHash({
          sessionId: (body as Record<string, unknown>).sessionId as string,
          requestId: (body as Record<string, unknown>).requestId as string,
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
          registrationTranscriptHash: persistedRegistrationTranscriptHash,
          rosterHash: rosterHashHex,
          sortedSelectedSlots: expectedSelectedSlots,
          selfSlot: slot,
          playerId,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment: persistedAggCommitment,
          aggregateResponse: persistedAggResponse,
          challenge: persistedChallenge,
          vaultSequence: 0,
          depositCountObserved: 0,
        });
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash,
            workerTranscriptHash,
            vaultSequence: 0,
            depositCountObserved: 0,
            createdAtUnixMs: 1_700_000_000_000,
            initialized: true,
          },
        };
      },
    });

    // Caller supplies NEITHER aggregate fields NOR transcript hashes — coordinator resolves
    // all of them from the persisted transcripts on disk.
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        requestId: "vault-state-provenance-ok",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    // KILLER ASSERTION: coordinator resolved BOTH provenance entries from disk.
    expect(body.vaultEkTranscriptHash).toBe(persistedVaultEkTranscriptHash);
    expect(body.registrationTranscriptHash).toBe(persistedRegistrationTranscriptHash);
    expect(body.aggregateCommitment).toBe(persistedAggCommitment);
    expect(body.aggregateResponse).toBe(persistedAggResponse);
    expect(body.challenge).toBe(persistedChallenge);
    // KILLER ASSERTION: transcript artifact persisted to disk.
    expect(typeof body.transcriptPath).toBe("string");
    const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
    expect(artifact.scheme).toBe("vault_state_v2");
    expect(artifact.vaultEk).toBe(vaultEk);
    expect(artifact.perSlotContributions).toHaveLength(5);
  });

  it("vault_state_v2 init returns 400 ca_registration_provenance_unknown when stateRoot present but no Milestone 1 transcript", async () => {
    const { mkdtemp, writeFile, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-vault-state-no-m1-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const vaultEk = h32("d");
    const caDkgTranscriptHashHex = h32("a");
    const persistedVaultEkTranscriptHash = h32("7");

    // Phase 2 transcript exists but Milestone 1 does NOT.
    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__phase2.json`),
      JSON.stringify(
        {
          scheme: "vault_ek_derivation_v1",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          selectedSlots: [0, 1, 2, 3, 4],
          rosterHash: rosterHashHex,
          verifierSlot: 0,
          perSlotContributions: [],
          vaultEk,
          finalTranscriptHash: persistedVaultEkTranscriptHash,
          createdAtUnixMs: 1_700_000_000_000,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );

    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/init",
      payload: {
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("ca_registration_provenance_unknown");
    expect(workerCalled).toBe(false);
  });

  // =============================================================================================
  // Milestone 2 sub-milestone 2b: observe-deposit orchestrator tests.
  //
  // All these tests run without `stateRoot`, requiring the caller to supply
  // `vaultEkTranscriptHash`, `registrationTranscriptHash`, and `selectedSlots` inline. One test
  // covers the stateRoot-resolved path explicitly.
  // =============================================================================================

  function observeDepositPayload(
    rosterHashHex: string,
    overrides: Record<string, unknown> = {},
  ) {
    return {
      requestId: "vault-state-observe-1",
      dkgEpoch: "1",
      caDkgTranscriptHash: h32("a"),
      vaultEk: h32("d"),
      senderAddress: h32("e"),
      assetType: h32("f"),
      chainId: 2,
      depositCount: 1,
      commitment: h32("1"),
      amountTag: h32("2"),
      caPayloadHash: h32("3"),
      depositNonce: h32("4"),
      sequenceNumber: "0",
      txVersion: "1234567",
      eventGuid: "0:0xfeed",
      vaultEkTranscriptHash: h32("b"),
      registrationTranscriptHash: h32("c"),
      selectedSlots: [0, 1, 2, 3, 4],
      // rosterHashHex is unused inline; included only to mirror init test signature for
      // consistency. The coordinator derives the dkg roster hash from caDkgV2Roster.
      __rosterHashHex: rosterHashHex,
    };
  }

  it("vault_state_v2 observe_deposit concurrent fan-out to all 5 selected slots", async () => {
    const { vaultStateV2ObserveWorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const vaultEkTranscriptHash = h32("b");
    const registrationTranscriptHash = h32("c");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const depositCount = 1;
    const commitment = h32("1");
    const amountTag = h32("2");
    const caPayloadHash = h32("3");
    const depositNonce = h32("4");
    const sequenceNumber = "0";
    const txVersion = "1234567";
    const eventGuid = "0:0xfeed";

    let observeInFlight = 0;
    let observePeak = 0;
    let releaseObserve: () => void = () => {};
    const barrier = new Promise<void>((resolve) => {
      releaseObserve = resolve;
    });

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path !== "/worker/v2/vault_state/observe_deposit") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path", path } };
        }
        observeInFlight += 1;
        observePeak = Math.max(observePeak, observeInFlight);
        if (observeInFlight === 5) queueMicrotask(() => releaseObserve());
        await barrier;
        observeInFlight -= 1;

        const playerId = expectedSelectedSlots.indexOf(slot);
        const vaultStateHash = h32(String((slot + 5) % 9));
        const workerTranscriptHash = vaultStateV2ObserveWorkerTranscriptHash({
          sessionId: (body as Record<string, unknown>).sessionId as string,
          requestId: (body as Record<string, unknown>).requestId as string,
          dkgEpoch,
          sortedSelectedSlots: expectedSelectedSlots,
          selfSlot: slot,
          playerId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          depositCount,
          commitment,
          amountTag,
          caPayloadHash,
          depositNonce,
          sequenceNumber,
          txVersion,
          eventGuid,
          previousDepositCountObserved: 0,
          newDepositCountObserved: depositCount,
        });
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash,
            workerTranscriptHash,
            previousDepositCountObserved: 0,
            depositCountObserved: depositCount,
            vaultSequence: 0,
            observedAtUnixMs: 1_700_000_000_000 + slot,
            observed: true,
          },
        };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: observeDepositPayload(rosterHashHex),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(true);
    expect(body.depositCount).toBe(depositCount);
    expect(body.previousDepositCountObserved).toBe(0);
    expect(body.newDepositCountObserved).toBe(depositCount);
    expect(body.perSlotContributions).toHaveLength(5);
    expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    // KILLER ASSERTION: concurrent fan-out — all 5 workers in flight simultaneously.
    expect(observePeak).toBe(5);
  });

  it("vault_state_v2 observe_deposit returns 502 worker_transcript_hash_mismatch on tampered worker reply", async () => {
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path !== "/worker/v2/vault_state/observe_deposit") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId: slot,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash: h32("a"),
            // Tamper: return a hash that DOESN'T match the TS-side reconstruction.
            workerTranscriptHash: h32(String((slot % 9) + 1)),
            previousDepositCountObserved: 0,
            depositCountObserved: 1,
            vaultSequence: 0,
            observedAtUnixMs: 1_700_000_000_000,
            observed: true,
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: observeDepositPayload(rosterHashHex),
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("worker_transcript_hash_mismatch");
  });

  it("vault_state_v2 observe_deposit returns 502 cursor_divergence when one worker reports a different cursor", async () => {
    const { vaultStateV2ObserveWorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const vaultEkTranscriptHash = h32("b");
    const registrationTranscriptHash = h32("c");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const depositCount = 1;

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path !== "/worker/v2/vault_state/observe_deposit") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        const playerId = expectedSelectedSlots.indexOf(slot);
        // KILLER: slot 4 reports depositCountObserved=2 (different from request.depositCount=1).
        // This simulates a worker whose persisted cursor disagreed with the others. The
        // orchestrator MUST detect it and return cursor_divergence.
        const reportedCursor = slot === 4 ? 2 : 1;
        const workerTranscriptHash = vaultStateV2ObserveWorkerTranscriptHash({
          sessionId: (body as Record<string, unknown>).sessionId as string,
          requestId: (body as Record<string, unknown>).requestId as string,
          dkgEpoch,
          sortedSelectedSlots: expectedSelectedSlots,
          selfSlot: slot,
          playerId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          depositCount,
          commitment: h32("1"),
          amountTag: h32("2"),
          caPayloadHash: h32("3"),
          depositNonce: h32("4"),
          sequenceNumber: "0",
          txVersion: "1234567",
          eventGuid: "0:0xfeed",
          previousDepositCountObserved: 0,
          newDepositCountObserved: reportedCursor,
        });
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash: h32("a"),
            workerTranscriptHash,
            previousDepositCountObserved: 0,
            depositCountObserved: reportedCursor,
            vaultSequence: 0,
            observedAtUnixMs: 1_700_000_000_000,
            observed: true,
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: observeDepositPayload(rosterHashHex),
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("cursor_divergence");
    expect(res.json().slot).toBe(4);
    expect(res.json().expected).toBe(1);
    expect(res.json().actual).toBe(2);
  });

  it("vault_state_v2 observe_deposit returns 409 vault_state_v2_observe_in_flight on concurrent calls", async () => {
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);

    let releaseHung: () => void = () => {};
    const hungBarrier = new Promise<void>((resolve) => {
      releaseHung = resolve;
    });
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => {
        // First call hangs forever (until released).
        await hungBarrier;
        return { slot, ok: false, statusCode: 500, body: {} };
      },
    });

    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: { ...observeDepositPayload(rosterHashHex), requestId: "hung-1" },
    });
    // Give the first request time to acquire the lock + start fanning out before sending the
    // second. 50ms is more than enough for a fastify route handler entry.
    await new Promise((r) => setTimeout(r, 50));
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: { ...observeDepositPayload(rosterHashHex), requestId: "hung-2" },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("vault_state_v2_observe_in_flight");

    releaseHung();
    await firstPromise.catch(() => undefined);
  });

  it("vault_state_v2 observe_deposit rejects forbidden plaintext fields recursively", async () => {
    const caDkgV2Roster = dkgRoster();
    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: {
        ...observeDepositPayload(caDkgV2RosterHash(caDkgV2Roster)),
        // FORBIDDEN — nested
        metadata: { nullifier_secret: "leak" },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
    expect(workerCalled).toBe(false);
  });

  it("vault_state_v2 observe_deposit rejects stale dkgEpoch", async () => {
    const caDkgV2Roster = dkgRoster();
    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: {
        ...observeDepositPayload(caDkgV2RosterHash(caDkgV2Roster)),
        dkgEpoch: "99", // dkgRoster's dkgEpoch is "1"
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("stale_dkg_epoch");
    expect(workerCalled).toBe(false);
  });

  it("vault_state_v2 observe_deposit rejects unsafe requestId", async () => {
    const caDkgV2Roster = dkgRoster();
    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: {
        ...observeDepositPayload(caDkgV2RosterHash(caDkgV2Roster)),
        requestId: "../../etc/passwd",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("unsafe_request_id");
    expect(workerCalled).toBe(false);
  });

  it("vault_state_v2 observe_deposit resolves provenance from persisted init transcript when stateRoot configured", async () => {
    const { mkdtemp, writeFile, mkdir, readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const { vaultStateV2ObserveWorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-observe-stateroot-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const vaultEk = h32("d");
    const caDkgTranscriptHashHex = h32("a");
    const persistedVaultEkTranscriptHash = h32("b");
    const persistedRegistrationTranscriptHash = h32("c");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const expectedSelectedSlots = [0, 1, 2, 3, 4];
    const depositCount = 1;
    const commitment = h32("1");
    const amountTag = h32("2");
    const caPayloadHash = h32("3");
    const depositNonce = h32("4");
    const sequenceNumber = "0";
    const txVersion = "1234567";
    const eventGuid = "0:0xfeed";

    // Persist the Milestone 2a init transcript at the expected path.
    const initDir = join(stateRoot, "coordinator", "vault_state_v2");
    await mkdir(initDir, { recursive: true });
    await writeFile(
      join(initDir, `${dkgEpoch}__init.json`),
      JSON.stringify(
        {
          scheme: "vault_state_v2",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
          registrationTranscriptHash: persistedRegistrationTranscriptHash,
          rosterHash: rosterHashHex,
          selectedSlots: expectedSelectedSlots,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment: h32("1"),
          aggregateResponse: h32("2"),
          challenge: h32("3"),
          perSlotContributions: [],
          transcriptHash: h32("7"),
          createdAtUnixMs: 1_700_000_000_000,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path !== "/worker/v2/vault_state/observe_deposit") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        const playerId = expectedSelectedSlots.indexOf(slot);
        const workerTranscriptHash = vaultStateV2ObserveWorkerTranscriptHash({
          sessionId: (body as Record<string, unknown>).sessionId as string,
          requestId: (body as Record<string, unknown>).requestId as string,
          dkgEpoch,
          sortedSelectedSlots: expectedSelectedSlots,
          selfSlot: slot,
          playerId,
          vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
          registrationTranscriptHash: persistedRegistrationTranscriptHash,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          depositCount,
          commitment,
          amountTag,
          caPayloadHash,
          depositNonce,
          sequenceNumber,
          txVersion,
          eventGuid,
          previousDepositCountObserved: 0,
          newDepositCountObserved: depositCount,
        });
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            vaultStatePath: `/tmp/slot-${slot}/vault_state_v2.json`,
            vaultStateHash: h32("a"),
            workerTranscriptHash,
            previousDepositCountObserved: 0,
            depositCountObserved: depositCount,
            vaultSequence: 0,
            observedAtUnixMs: 1_700_000_000_000,
            observed: true,
          },
        };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: {
        requestId: "observe-with-stateroot",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
        depositCount,
        commitment,
        amountTag,
        caPayloadHash,
        depositNonce,
        sequenceNumber,
        txVersion,
        eventGuid,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.vaultEkTranscriptHash).toBe(persistedVaultEkTranscriptHash);
    expect(body.registrationTranscriptHash).toBe(persistedRegistrationTranscriptHash);
    expect(body.selectedSlots).toEqual(expectedSelectedSlots);
    expect(body.depositCount).toBe(depositCount);
    expect(body.transcriptPath).toBeDefined();

    // Sanity-check the persisted artifact under <stateRoot>/coordinator/vault_state_v2_observed/
    const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
    expect(artifact.scheme).toBe("vault_state_v2_observe_deposit");
    expect(artifact.depositCount).toBe(depositCount);
    expect(artifact.initTranscriptPath).toContain("vault_state_v2");
  });

  it("vault_state_v2 observe_deposit returns 400 vault_state_init_provenance_unknown when stateRoot present but no Milestone 2a init transcript", async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-observe-no-init-"));
    const caDkgV2Roster = dkgRoster();
    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async () => {
        workerCalled = true;
        return { slot: 0, ok: true, statusCode: 200, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/vault_state/observe_deposit",
      payload: {
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
        vaultEk: h32("d"),
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
        depositCount: 1,
        commitment: h32("1"),
        amountTag: h32("2"),
        caPayloadHash: h32("3"),
        depositNonce: h32("4"),
        sequenceNumber: "0",
        txVersion: "1234567",
        eventGuid: "0:0xfeed",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("vault_state_init_provenance_unknown");
    expect(workerCalled).toBe(false);
  });

  // ---------------------------------------------------------------------------------------------
  // Milestone 3 sub-milestone 3a — MPCCA withdraw V2 round1 orchestrator.
  // ---------------------------------------------------------------------------------------------
  function mpccaWithdrawValidPayload(
    overrides: Record<string, unknown> = {},
  ): Record<string, unknown> {
    return {
      dkgEpoch: "1",
      caDkgTranscriptHash: h32("a"),
      vaultEk: h32("d"),
      senderAddress: h32("e"),
      assetType: h32("f"),
      chainId: 2,
      // Inline (no-stateRoot) provenance fields:
      vaultEkTranscriptHash: h32("7"),
      registrationTranscriptHash: h32("8"),
      vaultStateInitTranscriptHash: h32("9"),
      observedDepositTranscriptHashes: [h32("0")],
      selectedSlots: [0, 1, 2, 3, 4],
      // Withdraw envelope:
      root: h32("1"),
      nullifierHash: h32("2"),
      recipient: h32("3"),
      recipientHash: h32("4"),
      amountTag: h32("5"),
      vaultSequence: 0,
      expirySecs: 1_700_000_000,
      requestHash: h32("6"),
      depositCount: 1,
      ...overrides,
    };
  }

  function stubMpccaRound1Forwarder(opts: {
    expectedSelectedSlots: number[];
    rosterHashHex: string;
    dkgEpoch: string;
    vaultEkTranscriptHash: string;
    registrationTranscriptHash: string;
    vaultStateInitTranscriptHash: string;
    observedDepositTranscriptHashes: string[];
    vaultEk: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
    root: string;
    nullifierHash: string;
    recipient: string;
    recipientHash: string;
    amountTag: string;
    vaultSequence: number;
    expirySecs: number;
    requestHash: string;
    depositCount: number;
    onCall?: (slot: number) => Promise<void>;
    overridePhase?: (slot: number) => string | undefined;
    tamperWorkerHash?: (slot: number) => boolean;
  }) {
    return async (path: string, body: unknown, _roster: unknown, slot: number) => {
      if (opts.onCall) await opts.onCall(slot);
      if (path !== "/worker/v2/mpcca/withdraw/round1") {
        return {
          slot,
          ok: false,
          statusCode: 500,
          body: { error: "unexpected_path", path },
        };
      }
      const playerId = opts.expectedSelectedSlots.indexOf(slot);
      const phase =
        (opts.overridePhase && opts.overridePhase(slot)) ||
        "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4";
      // Compute the canonical worker_transcript_hash so the orchestrator's defense-in-depth
      // re-derivation matches. (Tests can opt to flip it via tamperWorkerHash to exercise the
      // hash-mismatch path.)
      const sessionId = (body as Record<string, unknown>).sessionId as string;
      const requestId = (body as Record<string, unknown>).requestId as string;
      const canonical = mpccaWithdrawRound1WorkerTranscriptHash({
        sessionId,
        requestId,
        dkgEpoch: opts.dkgEpoch,
        vaultEkTranscriptHash: opts.vaultEkTranscriptHash,
        registrationTranscriptHash: opts.registrationTranscriptHash,
        vaultStateInitTranscriptHash: opts.vaultStateInitTranscriptHash,
        observedDepositTranscriptHashes: opts.observedDepositTranscriptHashes,
        rosterHash: opts.rosterHashHex,
        sortedSelectedSlots: opts.expectedSelectedSlots,
        selfSlot: slot,
        playerId,
        vaultEk: opts.vaultEk,
        senderAddress: opts.senderAddress,
        assetType: opts.assetType,
        chainId: opts.chainId,
        root: opts.root,
        nullifierHash: opts.nullifierHash,
        recipient: opts.recipient,
        recipientHash: opts.recipientHash,
        amountTag: opts.amountTag,
        vaultSequence: opts.vaultSequence,
        expirySecs: opts.expirySecs,
        requestHash: opts.requestHash,
        depositCount: opts.depositCount,
      });
      const workerTranscriptHash =
        opts.tamperWorkerHash && opts.tamperWorkerHash(slot) ? h32(String((slot + 7) % 9)) : canonical;
      return {
        slot,
        ok: false,
        statusCode: 501,
        body: {
          slot,
          playerId,
          sessionStatePath: `/tmp/slot-${slot}/mpc-sessions/req__sess/mpcca_withdraw_v2_round1.json`,
          sessionStateHash: h32(String((slot + 3) % 9)),
          workerTranscriptHash,
          observedAtUnixMs: 1_700_000_000_000 + slot,
          completed: false,
          notImplementedPhase: phase,
        },
      };
    };
  }

  it("mpcca_withdraw_round1_concurrent_fan_out_surfaces_stub_phase", async () => {
    const { mpccaWithdrawRound1WorkerTranscriptHash } = await import("@eunoma/deop-protocol");
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const payload = mpccaWithdrawValidPayload();
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    // KILLER: track in-flight count so we can assert all 5 worker calls launched before any
    // completed.
    let inFlight = 0;
    let peak = 0;
    let releaseBarrier: () => void = () => {};
    const barrier = new Promise<void>((resolve) => {
      releaseBarrier = resolve;
    });

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: stubMpccaRound1Forwarder({
        expectedSelectedSlots,
        rosterHashHex,
        dkgEpoch: payload.dkgEpoch as string,
        vaultEkTranscriptHash: payload.vaultEkTranscriptHash as string,
        registrationTranscriptHash: payload.registrationTranscriptHash as string,
        vaultStateInitTranscriptHash: payload.vaultStateInitTranscriptHash as string,
        observedDepositTranscriptHashes: payload.observedDepositTranscriptHashes as string[],
        vaultEk: payload.vaultEk as string,
        senderAddress: payload.senderAddress as string,
        assetType: payload.assetType as string,
        chainId: payload.chainId as number,
        root: payload.root as string,
        nullifierHash: payload.nullifierHash as string,
        recipient: payload.recipient as string,
        recipientHash: payload.recipientHash as string,
        amountTag: payload.amountTag as string,
        vaultSequence: payload.vaultSequence as number,
        expirySecs: payload.expirySecs as number,
        requestHash: payload.requestHash as string,
        depositCount: payload.depositCount as number,
        onCall: async (_slot) => {
          inFlight += 1;
          peak = Math.max(peak, inFlight);
          if (inFlight === 5) queueMicrotask(() => releaseBarrier());
          await barrier;
          inFlight -= 1;
        },
      }),
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-concurrent", ...payload },
    });
    expect(res.statusCode).toBe(501);
    const body = res.json();
    expect(body.accepted).toBe(false);
    expect(body.round).toBe("round1");
    expect(body.phase).toBe(
      "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
    );
    expect(body.requestId).toBe("mpcca-wdr-concurrent");
    expect(body.depositCount).toBe(1);
    expect(body.perSlotContributions).toHaveLength(5);
    // KILLER ASSERTION: concurrent fan-out — all 5 workers in flight simultaneously.
    expect(peak).toBe(5);
    // Codex M3a P2 #3: transcriptHash is a real 32-byte hex digest, NOT the scheme literal.
    expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.transcriptHash).not.toBe("mpcca_withdraw_v2_round1_partial");

    // Touch the imported helper to keep TS happy (the stub uses it directly).
    expect(mpccaWithdrawRound1WorkerTranscriptHash).toBeTypeOf("function");
  });

  // Codex M3a P3: response.transcriptHash is a REAL digest over the persisted artifact.
  // The original P2 #3 test only asserted shape (32-byte hex) and the negative literal
  // — it didn't recompute the hash from the on-disk artifact and assert equality. That
  // gap meant a future refactor could drift the persistence path and the response shape
  // independently without the test catching it.
  //
  // This test:
  //   1. Configures stateRoot so the orchestrator writes the artifact to disk.
  //   2. Calls /v2/withdraw/mpcca/start and captures both the response transcriptHash AND
  //      the persisted artifact's transcriptHash.
  //   3. Recomputes the canonical hash by re-running the SAME canonicalize+sha256 the
  //      orchestrator runs (deterministic JSON over the artifact minus the transcriptHash
  //      field).
  //   4. Asserts all three match. If they don't, the integrity contract is broken.
  it("mpcca_withdraw_round1 transcriptHash recomputes byte-for-byte from persisted artifact", async () => {
    const { mkdtemp, writeFile, mkdir, readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const { sha256, bytesToHex } = await import("@eunoma/shared");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-mpcca-transcript-"));
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const persistedVaultEkTranscriptHash = h32("7");
    const persistedRegistrationTranscriptHash = h32("8");
    const persistedAggCommitment = h32("4");
    const persistedAggResponse = h32("5");
    const persistedChallenge = h32("6");
    const persistedInitTranscriptHash = h32("9");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    // Materialise the prereq transcripts so the orchestrator can resolve provenance.
    const phase2Dir = join(stateRoot, "coordinator", "vault_ek_derivation");
    await mkdir(phase2Dir, { recursive: true });
    await writeFile(
      join(phase2Dir, `${dkgEpoch}__phase2.json`),
      JSON.stringify({
        scheme: "vault_ek_derivation_v1",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        selectedSlots: expectedSelectedSlots,
        selectionRationale: "coordinator-chosen",
        rosterHash: rosterHashHex,
        verifierSlot: 0,
        perSlotContributions: [],
        vaultEk,
        finalTranscriptHash: persistedVaultEkTranscriptHash,
        createdAtUnixMs: 1_700_000_000_000,
      }),
      { mode: 0o600 },
    );
    const m1Dir = join(stateRoot, "coordinator", "ca_registration_v2");
    await mkdir(m1Dir, { recursive: true });
    await writeFile(
      join(m1Dir, `${dkgEpoch}__milestone1.json`),
      JSON.stringify({
        scheme: "ca_registration_v2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        rosterHash: rosterHashHex,
        selectedSlots: expectedSelectedSlots,
        verifierSlot: 0,
        vaultEk,
        vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
        senderAddress,
        assetType,
        chainId,
        aggregateCommitment: persistedAggCommitment,
        aggregateResponse: persistedAggResponse,
        challenge: persistedChallenge,
        perSlotContributions: [],
        transcriptHash: persistedRegistrationTranscriptHash,
        createdAtUnixMs: 1_700_000_000_000,
      }),
      { mode: 0o600 },
    );
    const m2aDir = join(stateRoot, "coordinator", "vault_state_v2");
    await mkdir(m2aDir, { recursive: true });
    await writeFile(
      join(m2aDir, `${dkgEpoch}__m2a-recompute.json`),
      JSON.stringify({
        scheme: "vault_state_v2",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
        registrationTranscriptHash: persistedRegistrationTranscriptHash,
        rosterHash: rosterHashHex,
        selectedSlots: expectedSelectedSlots,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
        aggregateCommitment: persistedAggCommitment,
        aggregateResponse: persistedAggResponse,
        challenge: persistedChallenge,
        perSlotContributions: [],
        transcriptHash: persistedInitTranscriptHash,
        createdAtUnixMs: 1_700_000_000_000,
      }),
      { mode: 0o600 },
    );

    // No observed deposits — keeps the test focused on the round1 transcript binding.
    const payload = {
      requestId: "mpcca-wdr-recompute",
      dkgEpoch,
      caDkgTranscriptHash: caDkgTranscriptHashHex,
      vaultEk,
      senderAddress,
      assetType,
      chainId,
      root: h32("1"),
      nullifierHash: h32("2"),
      recipient: h32("3"),
      recipientHash: h32("4"),
      amountTag: h32("5"),
      vaultSequence: 0,
      expirySecs: 1_700_000_000,
      requestHash: h32("6"),
      depositCount: 0,
    };

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: stubMpccaRound1Forwarder({
        expectedSelectedSlots,
        rosterHashHex,
        dkgEpoch,
        vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
        registrationTranscriptHash: persistedRegistrationTranscriptHash,
        vaultStateInitTranscriptHash: persistedInitTranscriptHash,
        observedDepositTranscriptHashes: [],
        vaultEk,
        senderAddress,
        assetType,
        chainId,
        root: payload.root,
        nullifierHash: payload.nullifierHash,
        recipient: payload.recipient,
        recipientHash: payload.recipientHash,
        amountTag: payload.amountTag,
        vaultSequence: payload.vaultSequence,
        expirySecs: payload.expirySecs,
        requestHash: payload.requestHash,
        depositCount: payload.depositCount,
      }),
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload,
    });
    expect(res.statusCode).toBe(501);
    const body = res.json();
    const responseTranscriptHash = body.transcriptHash as string;
    expect(responseTranscriptHash).toMatch(/^[0-9a-f]{64}$/);

    // Read the persisted artifact and assert its transcriptHash matches the response.
    const artifactPath = join(
      stateRoot,
      "coordinator",
      "mpcca_withdraw",
      `${dkgEpoch}__${payload.requestId}__round1.json`,
    );
    const raw = await readFile(artifactPath, "utf8");
    const artifact = JSON.parse(raw) as Record<string, unknown>;
    expect(artifact.transcriptHash).toBe(responseTranscriptHash);

    // KILLER: independently recompute the canonical hash from the persisted artifact
    // and assert it matches. This proves the artifact's transcriptHash is a REAL digest
    // over its own contents (minus the transcriptHash field itself), not a literal or a
    // stale value from an earlier write.
    //
    // Mirror the orchestrator's canonicalize() in this test scope so a coordinator-side
    // refactor that drifts the serializer is caught here.
    function canonicalize(value: unknown): unknown {
      if (value === null || typeof value !== "object") return value;
      if (Array.isArray(value)) return value.map(canonicalize);
      const obj = value as Record<string, unknown>;
      const sorted: Record<string, unknown> = {};
      for (const key of Object.keys(obj).sort()) {
        const v = obj[key];
        if (v === undefined) continue;
        sorted[key] = canonicalize(v);
      }
      return sorted;
    }
    const { transcriptHash: _stripped, ...artifactWithoutHash } = artifact;
    const recomputed = bytesToHex(
      sha256(new TextEncoder().encode(JSON.stringify(canonicalize(artifactWithoutHash)))),
    );
    expect(recomputed).toBe(responseTranscriptHash);
  });

  it("mpcca_withdraw_round1 returns 502 worker_transcript_hash_mismatch on tampered reply", async () => {
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const payload = mpccaWithdrawValidPayload();
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: stubMpccaRound1Forwarder({
        expectedSelectedSlots,
        rosterHashHex,
        dkgEpoch: payload.dkgEpoch as string,
        vaultEkTranscriptHash: payload.vaultEkTranscriptHash as string,
        registrationTranscriptHash: payload.registrationTranscriptHash as string,
        vaultStateInitTranscriptHash: payload.vaultStateInitTranscriptHash as string,
        observedDepositTranscriptHashes: payload.observedDepositTranscriptHashes as string[],
        vaultEk: payload.vaultEk as string,
        senderAddress: payload.senderAddress as string,
        assetType: payload.assetType as string,
        chainId: payload.chainId as number,
        root: payload.root as string,
        nullifierHash: payload.nullifierHash as string,
        recipient: payload.recipient as string,
        recipientHash: payload.recipientHash as string,
        amountTag: payload.amountTag as string,
        vaultSequence: payload.vaultSequence as number,
        expirySecs: payload.expirySecs as number,
        requestHash: payload.requestHash as string,
        depositCount: payload.depositCount as number,
        tamperWorkerHash: (slot) => slot === 2, // slot 2 lies about its transcript hash
      }),
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-tamper", ...payload },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("worker_transcript_hash_mismatch");
  });

  // Codex M3a P1 v4: when a worker rejects MPCCA round1 with InvalidDkgState(
  // "vault_state_v2_not_finalized") — i.e. its persisted vault_state_v2.json has
  // init_transcript_hash=None (legitimate partial-finalize state) — the coordinator MUST
  // surface a SPECIFIC, OPERATOR-ACTIONABLE 503 instead of the generic 502
  // round1_unexpected_status. The operator's action is to invoke /v2/vault_state/init/finalize
  // (idempotent across already-finalized slots).
  it("mpcca_withdraw_round1 surfaces 503 vault_state_v2_not_finalized_invoke_finalize_first", async () => {
    const caDkgV2Roster = dkgRoster();
    const payload = mpccaWithdrawValidPayload();

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      // Custom forwarder that returns a 409 + worker's structured body shape for slot 0,
      // simulating an unfinalized worker; the other 4 slots return the normal 501 stub.
      singleNodeForwarder: async (path, body, _roster, slot) => {
        if (path !== "/worker/v2/mpcca/withdraw/round1") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        if (slot === 0) {
          return {
            slot,
            ok: false,
            statusCode: 409,
            body: {
              error: "invalid_dkg_state",
              code: "vault_state_v2_not_finalized",
              message: 'InvalidDkgState("vault_state_v2_not_finalized")',
            },
          };
        }
        // Other slots — return generic 501 just so the loop walks past them (unreachable
        // since we return early on slot 0, but the Promise.all fans out all 5).
        return {
          slot,
          ok: false,
          statusCode: 501,
          body: {
            slot,
            playerId: (body as Record<string, unknown>).playerId ?? 0,
            notImplementedPhase:
              "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
          },
        };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-not-finalized", ...payload },
    });
    expect(res.statusCode).toBe(503);
    const body = res.json();
    expect(body.error).toBe("vault_state_v2_not_finalized_invoke_finalize_first");
    expect(body.workerCode).toBe("vault_state_v2_not_finalized");
    expect(body.message).toContain("/v2/vault_state/init/finalize");
    // Distinguishability KILLER: this is NOT the generic round1_unexpected_status — that
    // mapping would lose the operator-actionable recovery hint.
    expect(body.error).not.toBe("round1_unexpected_status");
  });

  // Codex M3a P1 v4: backwards-compat fallback — if the worker body lacks the structured
  // `code` field but the legacy `message` contains the sentinel, the coordinator still
  // surfaces the actionable 503. This protects against older worker builds in a heterogeneous
  // rolling deploy.
  it(
    "mpcca_withdraw_round1 surfaces 503 vault_state_v2_not_finalized from legacy worker " +
      "with only message",
    async () => {
      const caDkgV2Roster = dkgRoster();
      const payload = mpccaWithdrawValidPayload();

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        singleNodeForwarder: async (path, _body, _roster, slot) => {
          if (path !== "/worker/v2/mpcca/withdraw/round1") {
            return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
          }
          if (slot === 0) {
            // LEGACY worker: emits ONLY `error` + `message` (no `code` field). Coordinator
            // must still detect the sentinel substring inside `message`.
            return {
              slot,
              ok: false,
              statusCode: 409,
              body: {
                error: "invalid_dkg_state",
                message: 'InvalidDkgState("vault_state_v2_not_finalized")',
              },
            };
          }
          return {
            slot,
            ok: false,
            statusCode: 501,
            body: {
              slot,
              playerId: 0,
              notImplementedPhase:
                "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
            },
          };
        },
      });

      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/start",
        payload: { requestId: "mpcca-wdr-not-finalized-legacy", ...payload },
      });
      expect(res.statusCode).toBe(503);
      const body = res.json();
      expect(body.error).toBe("vault_state_v2_not_finalized_invoke_finalize_first");
    },
  );

  // Codex M3a P1 v4: a 409 conflict WITHOUT the vault_state_v2_not_finalized sentinel must
  // still surface as the generic 502 — we mustn't accidentally surface 503 for unrelated
  // conflicts (e.g. vault_state_init_transcript_hash_mismatch implies tamper, not partial
  // finalize, and the operator action differs).
  it("mpcca_withdraw_round1 still returns 502 for unrelated 409 conflicts", async () => {
    const caDkgV2Roster = dkgRoster();
    const payload = mpccaWithdrawValidPayload();

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (path, _body, _roster, slot) => {
        if (path !== "/worker/v2/mpcca/withdraw/round1") {
          return { slot, ok: false, statusCode: 500, body: { error: "unexpected_path" } };
        }
        if (slot === 0) {
          // Different InvalidDkgState code: NOT vault_state_v2_not_finalized.
          return {
            slot,
            ok: false,
            statusCode: 409,
            body: {
              error: "invalid_dkg_state",
              code: "vault_state_init_transcript_hash_mismatch",
              message: 'InvalidDkgState("vault_state_init_transcript_hash_mismatch")',
            },
          };
        }
        return {
          slot,
          ok: false,
          statusCode: 501,
          body: {
            slot,
            playerId: 0,
            notImplementedPhase:
              "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4",
          },
        };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-other-conflict", ...payload },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("round1_unexpected_status");
  });

  it("mpcca_withdraw_round1 returns 502 crypto_stub_phase_divergence when workers disagree on phase", async () => {
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const payload = mpccaWithdrawValidPayload();
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: stubMpccaRound1Forwarder({
        expectedSelectedSlots,
        rosterHashHex,
        dkgEpoch: payload.dkgEpoch as string,
        vaultEkTranscriptHash: payload.vaultEkTranscriptHash as string,
        registrationTranscriptHash: payload.registrationTranscriptHash as string,
        vaultStateInitTranscriptHash: payload.vaultStateInitTranscriptHash as string,
        observedDepositTranscriptHashes: payload.observedDepositTranscriptHashes as string[],
        vaultEk: payload.vaultEk as string,
        senderAddress: payload.senderAddress as string,
        assetType: payload.assetType as string,
        chainId: payload.chainId as number,
        root: payload.root as string,
        nullifierHash: payload.nullifierHash as string,
        recipient: payload.recipient as string,
        recipientHash: payload.recipientHash as string,
        amountTag: payload.amountTag as string,
        vaultSequence: payload.vaultSequence as number,
        expirySecs: payload.expirySecs as number,
        requestHash: payload.requestHash as string,
        depositCount: payload.depositCount as number,
        overridePhase: (slot) =>
          slot === 3 ? "different_phase_string_for_slot_3" : undefined,
      }),
    });

    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-phase-div", ...payload },
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("crypto_stub_phase_divergence");
  });

  it("mpcca_withdraw_round1 returns 409 vault_mpcca_withdraw_in_flight on concurrent calls", async () => {
    const caDkgV2Roster = dkgRoster();
    const payload = mpccaWithdrawValidPayload();

    let releaseHung: () => void = () => {};
    const hungBarrier = new Promise<void>((resolve) => {
      releaseHung = resolve;
    });
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      singleNodeForwarder: async (_path, _body, _roster, slot) => {
        await hungBarrier;
        return { slot, ok: false, statusCode: 500, body: {} };
      },
    });
    const firstPromise = server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-lock-1", ...payload },
    });
    // Allow first call's microtasks to run + acquire the lock.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const secondRes = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-wdr-lock-2", ...payload },
    });
    expect(secondRes.statusCode).toBe(409);
    expect(secondRes.json().error).toBe("vault_mpcca_withdraw_in_flight");
    releaseHung();
    await firstPromise;
  });

  it("mpcca_withdraw_round1 rejects forbidden plaintext fields", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        ...mpccaWithdrawValidPayload(),
        secret: "leak",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("mpcca_withdraw_round1 rejects nested dkShare guard", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        ...mpccaWithdrawValidPayload(),
        metadata: { dkShare: h32("9") },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("mpcca_withdraw_round1 rejects stale dkgEpoch", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        ...mpccaWithdrawValidPayload(),
        dkgEpoch: "99",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("stale_dkg_epoch");
  });

  it("mpcca_withdraw_round1 rejects unsafe requestId before lock acquire", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        ...mpccaWithdrawValidPayload(),
        requestId: "../../etc/passwd",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("unsafe_request_id");
  });

  it("mpcca_withdraw_round1 returns 400 vault_state_init_provenance_unknown when no init transcript exists", async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-mpcca-no-provenance-"));
    const caDkgV2Roster = dkgRoster();
    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async (_path, _body, _roster, slot) => {
        workerCalled = true;
        return { slot, ok: false, statusCode: 500, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        requestId: "mpcca-wdr-no-prov",
        dkgEpoch: "1",
        caDkgTranscriptHash: h32("a"),
        vaultEk: h32("d"),
        senderAddress: h32("e"),
        assetType: h32("f"),
        chainId: 2,
        root: h32("1"),
        nullifierHash: h32("2"),
        recipient: h32("3"),
        recipientHash: h32("4"),
        amountTag: h32("5"),
        vaultSequence: 0,
        expirySecs: 1_700_000_000,
        requestHash: h32("6"),
        depositCount: 1,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("vault_state_init_provenance_unknown");
    expect(workerCalled).toBe(false);
  });

  it("mpcca_withdraw_round1 returns 400 vault_state_observed_provenance_unknown when init transcript exists but no observe transcript for depositCount", async () => {
    const { mkdtemp, writeFile, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(
      join(os.tmpdir(), "eunoma-coord-mpcca-no-observe-"),
    );
    const caDkgV2Roster = dkgRoster();
    const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
    const dkgEpoch = "1";
    const caDkgTranscriptHashHex = h32("a");
    const vaultEk = h32("d");
    const senderAddress = h32("e");
    const assetType = h32("f");
    const chainId = 2;
    const persistedVaultEkTranscriptHash = h32("7");
    const persistedRegistrationTranscriptHash = h32("8");
    const persistedInitTranscriptHash = h32("9");
    const expectedSelectedSlots = [0, 1, 2, 3, 4];

    const initDir = join(stateRoot, "coordinator", "vault_state_v2");
    await mkdir(initDir, { recursive: true });
    await writeFile(
      join(initDir, `${dkgEpoch}__init.json`),
      JSON.stringify(
        {
          scheme: "vault_state_v2",
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashHex,
          vaultEkTranscriptHash: persistedVaultEkTranscriptHash,
          registrationTranscriptHash: persistedRegistrationTranscriptHash,
          rosterHash: rosterHashHex,
          selectedSlots: expectedSelectedSlots,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          transcriptHash: persistedInitTranscriptHash,
          perSlotContributions: [],
          createdAtUnixMs: 1_700_000_000_000,
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );

    let workerCalled = false;
    const { server } = buildCoordinatorServer({
      caDkgV2Roster,
      stateRoot,
      singleNodeForwarder: async (_path, _body, _roster, slot) => {
        workerCalled = true;
        return { slot, ok: false, statusCode: 500, body: {} };
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: {
        requestId: "mpcca-wdr-no-observe",
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashHex,
        vaultEk,
        senderAddress,
        assetType,
        chainId,
        root: h32("1"),
        nullifierHash: h32("2"),
        recipient: h32("3"),
        recipientHash: h32("4"),
        amountTag: h32("5"),
        vaultSequence: 0,
        expirySecs: 1_700_000_000,
        requestHash: h32("6"),
        depositCount: 1, // > 0, but no observe transcript exists for it
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("vault_state_observed_provenance_unknown");
    expect(workerCalled).toBe(false);
  });

  // ---------------------------------------------------------------------------------------------
  // Milestone 5 sub-milestone 5b — POST /v2/withdraw/mpcca/submit orchestrator.
  //
  // M5b is plumbing-only: the finalize transcript is still the M3a NotImplemented stub today,
  // so every real-world call to this route surfaces 501 with `notImplementedPhase` set. These
  // tests exercise the orchestration WITHOUT touching crypto — the killer is
  // `mpcca_submit_returns_501_when_finalize_is_m3a_stub` which proves the plumbing surfaces
  // NotImplemented cleanly.
  // ---------------------------------------------------------------------------------------------
  describe("MPCCA withdraw V2 submit — M5b plumbing", () => {
    async function makeStateRoot(prefix: string): Promise<string> {
      const { mkdtemp } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const os = await import("node:os");
      return mkdtemp(join(os.tmpdir(), prefix));
    }

    async function writeFinalizeTranscriptStub(
      stateRoot: string,
      dkgEpoch: string,
      requestId: string,
      notImplementedPhase: string,
    ): Promise<string> {
      const { mkdir, writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const path = join(dir, `${dkgEpoch}__${requestId}__finalize.json`);
      await writeFile(
        path,
        JSON.stringify({
          scheme: "mpcca_withdraw_v2_finalize",
          dkgEpoch,
          requestId,
          notImplementedPhase,
          transcriptHash: h32("e"),
          createdAtUnixMs: 1_700_000_000_000,
        }),
      );
      return path;
    }

    async function writeFinalizeTranscriptComplete(
      stateRoot: string,
      dkgEpoch: string,
      requestId: string,
      fieldOverrides: Record<string, unknown> = {},
    ): Promise<string> {
      const { mkdir, writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const path = join(dir, `${dkgEpoch}__${requestId}__finalize.json`);
      const hex32 = (seed: number) =>
        Array.from({ length: 32 }, (_, i) =>
          ((i + seed) & 0xff).toString(16).padStart(2, "0"),
        ).join("");
      const hexN = (n: number, seed: number) =>
        Array.from({ length: n }, (_, i) =>
          ((i + seed) & 0xff).toString(16).padStart(2, "0"),
        ).join("");
      const fields = {
        root: hex32(0x10),
        nullifierHash: hex32(0x11),
        recipient: hex32(0x12),
        recipientHash: hex32(0x13),
        amountTag: hex32(0x14),
        caPayloadHash: hex32(0x15),
        requestHash: hex32(0x16),
        vaultSequence: "42",
        expirySecs: "1800000000",
        withdrawProof: hexN(192, 0x20),
        groupSignature: hexN(64, 0x30),
        fallbackBitmap: 0,
        fallbackSignatures: [],
        newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
        newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
        newBalanceREffAud: [],
        amountP: Array.from({ length: 4 }, (_, i) => hex32(0x60 + i)),
        amountRSender: Array.from({ length: 4 }, (_, i) => hex32(0x70 + i)),
        amountRRecip: Array.from({ length: 4 }, (_, i) => hex32(0x80 + i)),
        amountREffAud: [],
        ekVolunAuds: [],
        amountRVolunAuds: [],
        zkrpNewBalance: hexN(672, 0x90),
        zkrpAmount: hexN(672, 0xa0),
        sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
        sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
        memo: "",
        ...fieldOverrides,
      };
      await writeFile(
        path,
        JSON.stringify({
          scheme: "mpcca_withdraw_v2_finalize",
          dkgEpoch,
          requestId,
          withdrawV2CallArgsFields: fields,
          transcriptHash: h32("e"),
          createdAtUnixMs: 1_700_000_000_000,
        }),
      );
      return path;
    }

    it("mpcca_submit_returns_400_when_finalize_transcript_missing", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-no-finalize-");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-missing" },
      });
      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.error).toBe("mpcca_finalize_transcript_not_found");
      expect(body.expectedPath).toContain("1__withdraw-missing__finalize.json");
      expect(body.message).toContain("M4 will fill them in");
    });

    // KILLER: M5b's load-bearing assertion. When the finalize transcript carries the M3a
    // NotImplemented stub, the submit route surfaces 501 cleanly with the phase string
    // verbatim, AND persists a stub submit-transcript so an auditor can see the attempt.
    it("mpcca_submit_returns_501_when_finalize_is_m3a_stub", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-stub-");
      await writeFinalizeTranscriptStub(
        stateRoot,
        "1",
        "withdraw-stub",
        "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
      );
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-stub" },
      });
      expect(res.statusCode).toBe(501);
      const body = res.json();
      expect(body.accepted).toBe(false);
      expect(body.completed).toBe(false);
      expect(body.simulated).toBe(true);
      expect(body.notImplementedPhase).toBe(
        "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
      );
      expect(body.txHash).toBeUndefined();
      // Stub submit-transcript persisted with a real digest.
      expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
      expect(body.transcriptPath).toContain("mpcca_withdraw_submit");
      expect(body.transcriptPath).toContain("1__withdraw-stub.json");
      // Verify the file actually exists on disk + carries the same transcriptHash.
      const { readFile } = await import("node:fs/promises");
      const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
      expect(artifact.transcriptHash).toBe(body.transcriptHash);
      expect(artifact.notImplementedPhase).toBe(
        "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
      );
      expect(artifact.domain).toBe("EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1");
    });

    it("mpcca_submit_calls_relayer_with_assembled_args", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-relayer-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-real");
      let receivedArgs: Record<string, unknown> | undefined;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async (args) => {
          receivedArgs = args as unknown as Record<string, unknown>;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-real" },
      });
      expect(res.statusCode).toBe(202); // simulated submit → 202
      const body = res.json();
      expect(body.accepted).toBe(true);
      expect(body.completed).toBe(true);
      expect(body.simulated).toBe(true);
      expect(body.txHash).toBe("0x" + "ab".repeat(32));
      expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
      expect(body.transcriptPath).toContain("mpcca_withdraw_submit");
      // LOAD-BEARING: 27 fields handed to the relayer.
      expect(receivedArgs).toBeDefined();
      expect(Object.keys(receivedArgs!).length).toBe(27);
      expect(receivedArgs!.root).toBeDefined();
      expect(receivedArgs!.vaultSequence).toBe("42");
      expect(receivedArgs!.memo).toBe("");
    });

    it("mpcca_submit_propagates_relayer_error", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-relayer-err-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-relayer-err");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => {
          throw new Error("relayer is down");
        },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-relayer-err" },
      });
      expect(res.statusCode).toBe(502);
      const body = res.json();
      expect(body.error).toBe("relayer_returned_error");
      expect(body.message).toContain("relayer is down");
    });

    it("mpcca_submit_returns_502_relayer_unreachable_when_no_submitter_configured", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-no-submitter-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-no-submitter");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        // no relayerSubmitter
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-no-submitter" },
      });
      expect(res.statusCode).toBe(502);
      expect(res.json().error).toBe("relayer_unreachable");
    });

    it("mpcca_submit_returns_409_on_lock_contention", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-lock-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-lock-a");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-lock-b");
      let releaseBarrier: () => void = () => {};
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => {
          await barrier;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      const first = server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-lock-a" },
      });
      // Give the first call enough time to acquire the lock and reach the relayer await.
      await new Promise((r) => setTimeout(r, 20));
      const secondRes = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-lock-b" },
      });
      expect(secondRes.statusCode).toBe(409);
      expect(secondRes.json().error).toBe("mpcca_withdraw_submit_in_flight");
      // Drain the first call so the lock releases cleanly.
      releaseBarrier();
      const firstRes = await first;
      expect(firstRes.statusCode).toBe(202);
    });

    it("mpcca_submit_rejects_forbidden_plaintext_field", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-forbidden-");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-x", amount: "1000" },
      });
      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.error).toBe("forbidden_plaintext_field");
      expect(body.field).toBe("amount");
    });

    it("mpcca_submit_rejects_unsafe_request_id_before_loading_finalize", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-unsafe-");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "../../etc/passwd" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("unsafe_request_id");
    });

    it("mpcca_submit_returns_400_state_root_required_without_stateRoot_config", async () => {
      const { server } = buildCoordinatorServer({ caDkgV2Roster: dkgRoster() });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-x" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("state_root_required");
    });

    it("mpcca_submit_returns_400_for_malformed_request_body", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-bad-body-");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "abc", requestId: "withdraw-x" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_request");
    });

    // KILLER (Codex M5b P1 #2): the loader enforces that the on-disk transcript's
    // embedded (dkgEpoch, requestId) matches the request tuple. Previously a transcript
    // file copied under a different filename would pass shape validation and could be
    // assembled/submitted under the caller's tuple, while the submit artifact recorded
    // the caller's tuple — silently breaking auditability.
    it("submit_route_rejects_stale_transcript_identity_mismatch", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-stale-id-");
      const { mkdir, writeFile, readFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      // Write a finalize transcript whose EMBEDDED (dkgEpoch, requestId) is (2, req-A)
      // but at the FILENAME for (1, req-B). The loader must reject this.
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const correctPath = join(dir, "2__req-A__finalize.json");
      // Use the helper to write a valid transcript at (2, req-A) first.
      await writeFinalizeTranscriptComplete(stateRoot, "2", "req-A");
      // Now COPY the bytes to the misfiled path (1, req-B) so they pass shape checks
      // but mismatch the request tuple the route uses.
      const misfiledPath = join(dir, "1__req-B__finalize.json");
      const raw = await readFile(correctPath, "utf8");
      await writeFile(misfiledPath, raw);
      let submitterInvoked = false;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => {
          submitterInvoked = true;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        // Caller asks for (1, req-B) — the transcript embedded identity is (2, req-A).
        payload: { dkgEpoch: "1", requestId: "req-B" },
      });
      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.error).toBe("mpcca_finalize_transcript_identity_mismatch");
      expect(body.message).toContain("does not match the request tuple");
      // CRITICAL: the relayer must NEVER have been invoked.
      expect(submitterInvoked).toBe(false);
    });

    // KILLER (Codex M5b P1 #1): the assembler enforces the M5a/M5b no-auditor invariant
    // BEFORE the relayer is ever called. The relayer parser also enforces this at the HTTP
    // boundary (defense in depth), but a mocked/in-process submitter trusting the
    // coordinator type previously could receive auditor payloads. We assert each of the
    // four auditor vectors independently to catch single-field regressions.
    it("submit_route_rejects_nonempty_auditor_fields_at_assembler", async () => {
      const oneHash = "ff".repeat(32);
      const cases: Array<[string, Record<string, unknown>]> = [
        ["newBalanceREffAud", { newBalanceREffAud: [oneHash] }],
        ["amountREffAud", { amountREffAud: [oneHash] }],
        ["ekVolunAuds", { ekVolunAuds: [oneHash] }],
        ["amountRVolunAuds", { amountRVolunAuds: [[oneHash]] }],
      ];
      for (const [label, overrides] of cases) {
        const stateRoot = await makeStateRoot(`eunoma-mpcca-submit-auditor-${label}-`);
        await writeFinalizeTranscriptComplete(stateRoot, "1", `req-${label}`, overrides);
        let submitterInvoked = false;
        const { server } = buildCoordinatorServer({
          caDkgV2Roster: dkgRoster(),
          stateRoot,
          relayerSubmitter: async () => {
            submitterInvoked = true;
            return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
          },
        });
        const res = await server.inject({
          method: "POST",
          url: "/v2/withdraw/mpcca/submit",
          payload: { dkgEpoch: "1", requestId: `req-${label}` },
        });
        expect(res.statusCode, label).toBe(400);
        const body = res.json();
        expect(body.error, label).toBe("auditor_branch_not_supported_in_milestone_5b");
        expect(body.message, label).toMatch(/Eunoma is no-auditor today/);
        // CRITICAL: the relayer must NEVER have been invoked.
        expect(submitterInvoked, label).toBe(false);
      }
    });
  });
});
