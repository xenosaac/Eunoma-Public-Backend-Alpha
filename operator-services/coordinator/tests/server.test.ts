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

  it("rejects caller-supplied selectedSlots with duplicates", async () => {
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
    expect(res.json().error).toBe("DUPLICATE_SLOT");
  });

  it("rejects caller-supplied selectedSlots with under-quorum count", async () => {
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
    expect(res.json().error).toBe("UNDER_QUORUM");
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
});
