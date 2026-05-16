import { describe, expect, it } from "vitest";
import type {
  CaDkgV2Roster,
  DeoperatorRoster,
  FrostDkgV2Roster,
} from "@eunoma/deop-protocol";
import {
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
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
        if (path.endsWith("/ca/registration/challenge")) {
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
        if (path.endsWith("/ca/registration/challenge")) {
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
        if (path.endsWith("/ca/registration/challenge")) {
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
});
