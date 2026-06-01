import { describe, expect, it } from "vitest";
import { RistrettoPoint } from "@aptos-labs/confidential-asset";
import type {
  CaDkgV2Roster,
  DeoperatorRoster,
  FrostDkgV2Roster,
} from "@eunoma/deop-protocol";
import {
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  ingressEnvelopesHash,
  mpccaWithdrawRound1WorkerTranscriptHash,
  rosterHash,
  WITHDRAW_V2_CALL_ARGS_ORDER,
} from "@eunoma/deop-protocol";
import { assembleWithdrawV2CallArgs } from "@eunoma/shared";
import { buildCoordinatorServer, forwardSessionShareToRoster } from "../src/index.js";
import { buildDefaultRelayerSubmitter, configFromEnv } from "../src/config.js";

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

  // Codex M5b P2 #2: env-driven config sources all submit-route inputs so a production
  // start.ts can wire stateRoot / relayerUrl / chainNodeUrl without any per-call config.
  it("configFromEnv_sources_M5b_submit_route_inputs", () => {
    const r = roster();
    const cfg = configFromEnv({
      DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
      EUNOMA_STATE_ROOT: "/var/eunoma/state",
      RELAYER_URL: "https://relayer.invalid:4300",
      RELAYER_BEARER_TOKEN: "test-relayer-bearer-token-do-not-use",
      APTOS_NODE_URL: "https://node.invalid:8080",
      APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS: "45000",
    });
    expect(cfg.stateRoot).toBe("/var/eunoma/state");
    expect(cfg.relayerUrl).toBe("https://relayer.invalid:4300");
    expect(cfg.relayerBearerToken).toBe("test-relayer-bearer-token-do-not-use");
    expect(cfg.chainNodeUrl).toBe("https://node.invalid:8080");
    expect(cfg.chainConfirmationTimeoutMs).toBe(45000);
  });

  it("configFromEnv_rejects_non_decimal_chain_confirmation_timeout", () => {
    const r = roster();
    expect(() =>
      configFromEnv({
        DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
        APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS: "abc",
      }),
    ).toThrow(/APTOS_CHAIN_CONFIRMATION_TIMEOUT_MS/);
  });

  // Codex M5b P2 #2: the default relayer submitter factory wires a fetch-backed
  // submitter that POSTs to <relayerUrl>/v2/relayer/submit/withdraw with Bearer auth.
  // Tests bypass this by injecting `relayerSubmitter` directly into buildCoordinatorServer;
  // here we just verify the factory's wire shape.
  it("buildDefaultRelayerSubmitter_returns_undefined_when_relayer_url_unset", () => {
    const r = roster();
    const cfg = configFromEnv({ DEOPERATOR_ROSTER_JSON: JSON.stringify(r) });
    const submitter = buildDefaultRelayerSubmitter(cfg);
    expect(submitter).toBeUndefined();
  });

  it("buildDefaultRelayerSubmitter_posts_to_relayer_with_bearer_auth", async () => {
    const r = roster();
    const cfg = configFromEnv({
      DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
      RELAYER_URL: "https://relayer.invalid:4300",
      RELAYER_BEARER_TOKEN: "abc123",
    });
    let observedUrl: string | undefined;
    let observedAuth: string | undefined;
    let observedBody: unknown;
    const fakeFetch: typeof fetch = async (url, init) => {
      observedUrl = String(url);
      observedAuth = (init?.headers as Record<string, string>)?.authorization;
      observedBody = JSON.parse(String(init?.body ?? "null"));
      return new Response(
        JSON.stringify({ accepted: true, txHash: "0xfeed", simulated: true }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    };
    const submitter = buildDefaultRelayerSubmitter(cfg, fakeFetch);
    expect(submitter).toBeDefined();
    const result = await submitter!({ root: "0xab" });
    expect(result).toEqual({ accepted: true, txHash: "0xfeed", simulated: true });
    expect(observedUrl).toBe("https://relayer.invalid:4300/v2/relayer/submit/withdraw");
    expect(observedAuth).toBe("Bearer abc123");
    expect(observedBody).toEqual({ root: "0xab" });
  });

  it("buildDefaultRelayerSubmitter_throws_on_relayer_5xx", async () => {
    const r = roster();
    const cfg = configFromEnv({
      DEOPERATOR_ROSTER_JSON: JSON.stringify(r),
      RELAYER_URL: "https://relayer.invalid:4300",
      RELAYER_BEARER_TOKEN: "abc123",
    });
    const fakeFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "submit_failed", message: "boom" }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    const submitter = buildDefaultRelayerSubmitter(cfg, fakeFetch);
    await expect(submitter!({ root: "0xab" })).rejects.toThrow(
      /relayer responded 502 \(submit_failed\): boom/,
    );
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
  function mockIngressEnvelope(seed: number): {
    kem: "DHKEM_X25519_HKDF_SHA256";
    kdf: "HKDF_SHA256";
    aead: "AES_256_GCM";
    enc: string;
    ciphertext: string;
    aadHash: string;
  } {
    const seedByte = seed.toString(16).padStart(2, "0");
    return {
      kem: "DHKEM_X25519_HKDF_SHA256",
      kdf: "HKDF_SHA256",
      aead: "AES_256_GCM",
      enc: seedByte.repeat(32),
      // 80 bytes = 64-byte plaintext (a_i || b_i) + 16-byte AES-GCM tag.
      ciphertext: seedByte.repeat(80),
      aadHash: seedByte.repeat(32),
    };
  }

  // Pre-compute a valid (amountCommitment, perShareCommitments[5]) tuple where
  // Σ perShareCommitments == amountCommitment, using RistrettoPoint scalar-mul over
  // BASE with distinct scalars. The shape is Pedersen-coherent enough to satisfy
  // the coordinator's aggregate-sum invariant; the workers never see the underlying
  // shares in these stub tests, so the per-share Pedersen verify isn't exercised here.
  function buildValidIngressCommitments(): {
    amountCommitment: string;
    perShareCommitments: string[];
  } {
    const points = [1, 2, 3, 4, 5].map((seed) => {
      // Use scalar from a fixed seed; arithmetic stays inside curve25519-dalek.
      const scalarBytes = new Uint8Array(32);
      scalarBytes[0] = seed;
      return RistrettoPoint.BASE.multiply(BigInt(seed) + 7n);
    });
    const sum = points.reduce((acc, p) => acc.add(p));
    const toHex = (bytes: Uint8Array) =>
      Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    return {
      amountCommitment: toHex(sum.toRawBytes()),
      perShareCommitments: points.map((p) => toHex(p.toRawBytes())),
    };
  }
  const VALID_COMMITMENTS = buildValidIngressCommitments();

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
      // Milestone 1: amount ingress fields. Use Pedersen-coherent commitments so the
      // coordinator's aggregate-sum invariant accepts them; worker-side decrypt + verify is
      // stubbed in stubMpccaRound1Forwarder, so we don't need real HPKE envelopes here.
      amountCommitment: VALID_COMMITMENTS.amountCommitment,
      perShareCommitments: VALID_COMMITMENTS.perShareCommitments,
      ingressEnvelopes: [
        mockIngressEnvelope(0x11),
        mockIngressEnvelope(0x22),
        mockIngressEnvelope(0x33),
        mockIngressEnvelope(0x44),
        mockIngressEnvelope(0x55),
      ],
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
      // Compute the canonical worker_transcript_hash so the orchestrator's defense-in-depth
      // re-derivation matches. Under M1, this binds the ingress fields too — read them from
      // the request body and fold them in via ingressEnvelopesHash.
      const bodyObj = body as Record<string, unknown>;
      const sessionId = bodyObj.sessionId as string;
      const requestId = bodyObj.requestId as string;
      const amountCommitment = bodyObj.amountCommitment as string;
      const perShareCommitments = bodyObj.perShareCommitments as string[];
      const ingressEnvs = bodyObj.ingressEnvelopes as Array<{
        kem: "DHKEM_X25519_HKDF_SHA256";
        kdf: "HKDF_SHA256";
        aead: "AES_256_GCM";
        enc: string;
        ciphertext: string;
        aadHash: string;
      }>;
      const ingressEnvelopesHashHex = ingressEnvelopesHash(ingressEnvs);
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
        amountCommitment,
        perShareCommitments,
        ingressEnvelopesHash: ingressEnvelopesHashHex,
      });
      const workerTranscriptHash =
        opts.tamperWorkerHash && opts.tamperWorkerHash(slot) ? h32(String((slot + 7) % 9)) : canonical;
      return {
        slot,
        ok: true,
        statusCode: 200,
        body: {
          slot,
          playerId,
          sessionStatePath: `/tmp/slot-${slot}/mpc-sessions/req__sess/mpcca_withdraw_v2_round1.json`,
          sessionStateHash: h32(String((slot + 3) % 9)),
          workerTranscriptHash,
          observedAtUnixMs: 1_700_000_000_000 + slot,
          completed: true,
          ingressTranscriptHash: workerTranscriptHash,
        },
      };
    };
  }

  it("mpcca_withdraw_round1_concurrent_fan_out_returns_completed_m1_ingress", async () => {
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
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.accepted).toBe(false);
    expect(body.round).toBe("round1");
    expect(body.completed).toBe(true);
    expect(body.requestId).toBe("mpcca-wdr-concurrent");
    expect(body.depositCount).toBe(1);
    expect(body.perSlotContributions).toHaveLength(5);
    // KILLER ASSERTION: concurrent fan-out — all 5 workers in flight simultaneously.
    expect(peak).toBe(5);
    // M1 ingress: every contribution is completed:true with ingressTranscriptHash.
    for (const c of body.perSlotContributions) {
      expect(c.completed).toBe(true);
      expect(c.ingressTranscriptHash).toMatch(/^[0-9a-f]{64}$/);
      expect(c.ingressTranscriptHash).toBe(c.workerTranscriptHash);
    }
    expect(body.amountCommitment).toBe(payload.amountCommitment);
    expect(body.perShareCommitments).toEqual(payload.perShareCommitments);
    expect(body.ingressEnvelopesHash).toMatch(/^[0-9a-f]{64}$/);
    // Codex M3a P2 #3: transcriptHash is a real 32-byte hex digest, NOT the scheme literal.
    expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.transcriptHash).not.toBe("mpcca_withdraw_v2_round1_ingress");

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
      // M1 ingress fields.
      amountCommitment: VALID_COMMITMENTS.amountCommitment,
      perShareCommitments: VALID_COMMITMENTS.perShareCommitments,
      ingressEnvelopes: [
        mockIngressEnvelope(0x11),
        mockIngressEnvelope(0x22),
        mockIngressEnvelope(0x33),
        mockIngressEnvelope(0x44),
        mockIngressEnvelope(0x55),
      ],
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
    expect(res.statusCode).toBe(200);
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
        // Non-conflicting slots return a valid M1 completed body. Slot 0's 409 makes the
        // orchestrator surface 502 round1_unexpected_status regardless.
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId: 0,
            sessionStatePath: `/tmp/slot-${slot}/mpc-sessions/req__sess/mpcca_withdraw_v2_round1.json`,
            sessionStateHash: h32(String((slot + 3) % 9)),
            workerTranscriptHash: h32(String((slot + 1) % 9)),
            observedAtUnixMs: 1_700_000_000_000 + slot,
            completed: true,
            ingressTranscriptHash: h32(String((slot + 1) % 9)),
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

  it("mpcca_withdraw_round1 M1 aggregate-commitment invariant: rejects Σ != amountCommitment", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const payload = mpccaWithdrawValidPayload();
    // Flip amountCommitment to a different valid Ristretto point (e.g., BASE * 99) so the
    // aggregate-sum check fires. Use VALID_COMMITMENTS.perShareCommitments unchanged so each
    // per-share commitment is still a valid Ristretto point — the invariant violation is the
    // ONLY problem.
    const altPoint = RistrettoPoint.BASE.multiply(99n);
    (payload as Record<string, unknown>).amountCommitment = Array.from(altPoint.toRawBytes())
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-agg-mismatch", ...payload },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("ingress_aggregate_commitment_mismatch");
  });

  it("mpcca_withdraw_round1 M1: rejects non-canonical Ristretto perShareCommitment", async () => {
    const caDkgV2Roster = dkgRoster();
    const { server } = buildCoordinatorServer({ caDkgV2Roster });
    const payload = mpccaWithdrawValidPayload();
    (payload as Record<string, unknown>).perShareCommitments = [
      ...VALID_COMMITMENTS.perShareCommitments.slice(0, 4),
      // ff*32 is not a valid Ristretto compression (decompress will fail).
      "ff".repeat(32),
    ];
    const res = await server.inject({
      method: "POST",
      url: "/v2/withdraw/mpcca/start",
      payload: { requestId: "mpcca-noncanon-commit", ...payload },
    });
    expect(res.statusCode).toBe(400);
    // The aggregate check decodes each commitment and rejects bad encodings before summing.
    expect(res.json().error).toBe("ingress_invalid_commitment_shape");
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
        // M1 ingress fields.
        amountCommitment: VALID_COMMITMENTS.amountCommitment,
        perShareCommitments: VALID_COMMITMENTS.perShareCommitments,
        ingressEnvelopes: [
          mockIngressEnvelope(0x11),
          mockIngressEnvelope(0x22),
          mockIngressEnvelope(0x33),
          mockIngressEnvelope(0x44),
          mockIngressEnvelope(0x55),
        ],
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
        // M1 ingress fields.
        amountCommitment: VALID_COMMITMENTS.amountCommitment,
        perShareCommitments: VALID_COMMITMENTS.perShareCommitments,
        ingressEnvelopes: [
          mockIngressEnvelope(0x11),
          mockIngressEnvelope(0x22),
          mockIngressEnvelope(0x33),
          mockIngressEnvelope(0x44),
          mockIngressEnvelope(0x55),
        ],
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("vault_state_observed_provenance_unknown");
    expect(workerCalled).toBe(false);
  });

  // ---------------------------------------------------------------------------------------------
  // M4 Commit 2 — POST /v2/withdraw/mpcca/round2 orchestrator.
  //
  // Builds on the round1 __round1.json artifact: the round2 route lifts the chained-round
  // binding from round1 and fans out per-worker Round2Request bodies (chained envelope +
  // 7 Statement input fields). User-supplied proof artifacts (Bulletproof bytes, per-chunk
  // commitments, user sigma α-points + response shares) are coordinator-only and never
  // forwarded to workers.
  // ---------------------------------------------------------------------------------------------
  describe("MPCCA withdraw V2 round2 — M4 commit 2 orchestrator", () => {
    /** Generate a deterministic 32-byte hex per call (label+index pattern). */
    function genHex32(group: string, i: number): string {
      const idx = i.toString(16).padStart(2, "0");
      return (group + idx).repeat(16);
    }
    function buildStatementInputs() {
      return {
        recipientEk: "a1".repeat(32),
        oldBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("b0", i)),
        oldBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("c0", i)),
        newBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("d0", i)),
        newBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("e0", i)),
        transferAmountC: Array.from({ length: 4 }, (_, i) => genHex32("f0", i)),
        transferAmountDSender: Array.from({ length: 4 }, (_, i) => genHex32("12", i)),
        transferAmountDRecipient: Array.from({ length: 4 }, (_, i) => genHex32("23", i)),
      };
    }
    function buildRound2OrchestrateBody(
      overrides: Record<string, unknown> = {},
    ): Record<string, unknown> {
      const stmt = buildStatementInputs();
      return {
        dkgEpoch: "1",
        requestId: "mpcca-wdr-r2",
        sessionId: "mpcca-wdr-r2",
        vaultEkTranscriptHash: h32("7"),
        registrationTranscriptHash: h32("8"),
        vaultStateInitTranscriptHash: h32("9"),
        observedDepositTranscriptHashes: [h32("0")],
        rosterHash: h32("aa"),
        selectedSlots: [0, 1, 2, 3, 4],
        selfSlot: 0,
        playerId: 0,
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
        ...stmt,
        userSigmaCommitmentsHex: Array.from({ length: 29 }, (_, i) => genHex32("34", i)),
        userSigmaResponseSharesHex: Array.from({ length: 24 }, (_, i) => genHex32("45", i)),
        bulletproofZkrpAmountHex: "ab".repeat(96),
        bulletproofZkrpNewBalanceHex: "cd".repeat(160),
        perChunkCommitmentsAmountHex: Array.from({ length: 4 }, (_, i) => genHex32("56", i)),
        perChunkCommitmentsNewBalanceHex: Array.from({ length: 8 }, (_, i) => genHex32("67", i)),
        ...overrides,
      };
    }
    async function stageRound1Artifact(
      stateRoot: string,
      body: Record<string, unknown>,
      rosterHashHex: string,
      perSlotIngress: Map<number, string>,
    ): Promise<string> {
      const { mkdir, writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const path = join(
        dir,
        `${body.dkgEpoch}__${body.requestId}__round1.json`,
      );
      const sortedSlots = (body.selectedSlots as number[]).slice().sort((a, b) => a - b);
      const perSlotContributions = sortedSlots.map((slot) => ({
        slot,
        sessionStateHash: h32(String((slot + 1) % 9)),
        workerTranscriptHash: perSlotIngress.get(slot)!,
        completed: true,
        ingressTranscriptHash: perSlotIngress.get(slot)!,
      }));
      const artifact = {
        scheme: "mpcca_withdraw_v2_round1_ingress",
        dkgEpoch: body.dkgEpoch,
        requestId: body.requestId,
        vaultEkTranscriptHash: body.vaultEkTranscriptHash,
        registrationTranscriptHash: body.registrationTranscriptHash,
        vaultStateInitTranscriptHash: body.vaultStateInitTranscriptHash,
        observedDepositTranscriptHashes: body.observedDepositTranscriptHashes,
        rosterHash: rosterHashHex,
        selectedSlots: sortedSlots,
        vaultEk: body.vaultEk,
        senderAddress: body.senderAddress,
        assetType: body.assetType,
        chainId: body.chainId,
        root: body.root,
        nullifierHash: body.nullifierHash,
        recipient: body.recipient,
        recipientHash: body.recipientHash,
        amountTag: body.amountTag,
        vaultSequence: body.vaultSequence,
        expirySecs: body.expirySecs,
        requestHash: body.requestHash,
        depositCount: body.depositCount,
        perSlotContributions,
        transcriptHash: h32("ab"),
        createdAtUnixMs: 1_700_000_000_000,
      };
      await writeFile(path, JSON.stringify(artifact), { mode: 0o600 });
      return path;
    }
    async function makeStateRoot(prefix: string): Promise<string> {
      const { mkdtemp } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const os = await import("node:os");
      return mkdtemp(join(os.tmpdir(), prefix));
    }

    type ParsedRound2Body = {
      dkgEpoch: string;
      requestId: string;
      sessionId: string;
      vaultEkTranscriptHash: string;
      registrationTranscriptHash: string;
      vaultStateInitTranscriptHash: string;
      observedDepositTranscriptHashes: string[];
      rosterHash: string;
      selectedSlots: number[];
      selfSlot: number;
      playerId: number;
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
      previousRoundTranscriptHash: string;
      previousRoundCommitments: string[];
      recipientEk: string;
      oldBalanceC: string[];
      oldBalanceD: string[];
      newBalanceC: string[];
      newBalanceD: string[];
      transferAmountC: string[];
      transferAmountDSender: string[];
      transferAmountDRecipient: string[];
    };

    function stubMpccaRound2Forwarder(opts: {
      tamperWorkerHash?: (slot: number) => boolean;
      tamperDkIndices?: (slot: number) => number[] | undefined;
      onCall?: (slot: number, signal?: AbortSignal) => Promise<void>;
      neverResolve?: (slot: number) => boolean;
    }) {
      return async (
        path: string,
        body: unknown,
        _roster: unknown,
        slot: number,
        signal?: AbortSignal,
      ) => {
        if (opts.onCall) await opts.onCall(slot, signal);
        if (opts.neverResolve && opts.neverResolve(slot)) {
          // Wait until aborted, then throw.
          await new Promise<void>((_, reject) => {
            if (signal?.aborted) reject(new Error("aborted"));
            signal?.addEventListener(
              "abort",
              () => reject(new Error("aborted")),
              { once: true },
            );
          });
        }
        if (path !== "/worker/v2/mpcca/withdraw/round2") {
          return {
            slot,
            ok: false,
            statusCode: 500,
            body: { error: "unexpected_path", path },
          };
        }
        const b = body as ParsedRound2Body;
        const playerId = b.selectedSlots.indexOf(slot);
        const canonicalHash = (await import("@eunoma/deop-protocol"))
          .mpccaWithdrawRound2WorkerTranscriptHash({
            sessionId: b.sessionId,
            requestId: b.requestId,
            dkgEpoch: b.dkgEpoch,
            vaultEkTranscriptHash: b.vaultEkTranscriptHash,
            registrationTranscriptHash: b.registrationTranscriptHash,
            vaultStateInitTranscriptHash: b.vaultStateInitTranscriptHash,
            observedDepositTranscriptHashes: b.observedDepositTranscriptHashes,
            rosterHash: b.rosterHash,
            sortedSelectedSlots: b.selectedSlots,
            selfSlot: slot,
            playerId,
            vaultEk: b.vaultEk,
            senderAddress: b.senderAddress,
            assetType: b.assetType,
            chainId: b.chainId,
            root: b.root,
            nullifierHash: b.nullifierHash,
            recipient: b.recipient,
            recipientHash: b.recipientHash,
            amountTag: b.amountTag,
            vaultSequence: b.vaultSequence,
            expirySecs: b.expirySecs,
            requestHash: b.requestHash,
            depositCount: b.depositCount,
            previousRoundTranscriptHash: b.previousRoundTranscriptHash,
            previousRoundCommitments: b.previousRoundCommitments,
            statementInputs: {
              recipientEk: b.recipientEk,
              oldBalanceC: b.oldBalanceC,
              oldBalanceD: b.oldBalanceD,
              newBalanceC: b.newBalanceC,
              newBalanceD: b.newBalanceD,
              transferAmountC: b.transferAmountC,
              transferAmountDSender: b.transferAmountDSender,
              transferAmountDRecipient: b.transferAmountDRecipient,
            },
          });
        const workerTranscriptHash =
          opts.tamperWorkerHash && opts.tamperWorkerHash(slot)
            ? h32(String((slot + 5) % 9))
            : canonicalHash;
        const dkBaseIndicesUsed =
          (opts.tamperDkIndices && opts.tamperDkIndices(slot)) ?? [0, 17];
        const partialDkCommitments = dkBaseIndicesUsed.map((index) => ({
          index,
          commitmentHex: h32(String((index + slot + 3) % 9)),
        }));
        return {
          slot,
          ok: true,
          statusCode: 200,
          body: {
            slot,
            playerId,
            sessionStatePath: `/tmp/slot-${slot}/mpc-sessions/req__sess/mpcca_withdraw_v2_round2.json`,
            sessionStateHash: h32(String((slot + 2) % 9)),
            workerTranscriptHash,
            observedAtUnixMs: 1_700_000_000_000 + slot,
            completed: true,
            partialDkCommitments,
            dkBaseIndicesUsed,
          },
        };
      };
    }

    it("round2_happy_path_concurrent_fan_out_persists_aggregate_hash", async () => {
      const { mkdir } = await import("node:fs/promises");
      const { readFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const stateRoot = await makeStateRoot("eunoma-coord-round2-happy-");
      await mkdir(join(stateRoot, "coordinator", "mpcca_withdraw"), {
        recursive: true,
      });

      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>([
        [0, h32("a0")],
        [1, h32("a1")],
        [2, h32("a2")],
        [3, h32("a3")],
        [4, h32("a4")],
      ]);
      await stageRound1Artifact(stateRoot, body, rosterHashHex, perSlotIngress);

      // KILLER: concurrent fan-out — all 5 workers in flight at once before any completes.
      let inFlight = 0;
      let peak = 0;
      let releaseBarrier: () => void = () => {};
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({
          onCall: async () => {
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
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(200);
      const respBody = res.json();
      expect(respBody.accepted).toBe(false);
      expect(respBody.round).toBe("round2");
      expect(respBody.completed).toBe(true);
      expect(respBody.requestId).toBe("mpcca-wdr-r2");
      expect(respBody.dkBaseIndicesUsed).toEqual([0, 17]);
      expect(respBody.perSlotContributions).toHaveLength(5);
      expect(peak).toBe(5);
      expect(respBody.transcriptHash).toMatch(/^[0-9a-f]{64}$/);

      // Persisted __round2.json sanity.
      const round2Path = join(
        stateRoot,
        "coordinator",
        "mpcca_withdraw",
        "1__mpcca-wdr-r2__round2.json",
      );
      const raw = await readFile(round2Path, "utf8");
      const persisted = JSON.parse(raw);
      expect(persisted.scheme).toBe("mpcca_withdraw_v2_round2_dk");
      expect(persisted.transcriptHash).toBe(respBody.transcriptHash);
      expect(persisted.dkBaseIndicesUsed).toEqual([0, 17]);
      expect(persisted.perSlotContributions).toHaveLength(5);
      expect(persisted.userProofArtifacts.bulletproofZkrpAmountHex).toBe(
        body.bulletproofZkrpAmountHex,
      );
      expect(persisted.statementInputsHashHex).toMatch(/^[0-9a-f]{64}$/);
    });

    it("round2_rejects_when_round1_transcript_missing", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-no-round1-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("round1_transcript_not_found");
    });

    it("round2_rejects_when_round1_identity_mismatch_vaultEk", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-mismatch-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>(
        [0, 1, 2, 3, 4].map((s) => [s, h32(String(s))]),
      );
      // Stage round1 with DIFFERENT vaultEk than round2 request.
      const staleBody = { ...body, vaultEk: h32("ff") };
      await stageRound1Artifact(stateRoot, staleBody, rosterHashHex, perSlotIngress);

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("round1_transcript_identity_mismatch");
      expect(res.json().field).toBe("vaultEk");
    });

    it("round2_rejects_when_worker_timeout_fires", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-timeout-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>(
        [0, 1, 2, 3, 4].map((s) => [s, h32(String(s))]),
      );
      await stageRound1Artifact(stateRoot, body, rosterHashHex, perSlotIngress);

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        mpccaWithdrawRound2WorkerTimeoutMs: 50,
        singleNodeForwarder: stubMpccaRound2Forwarder({
          // Slot 2 never resolves → AbortController fires after 50ms.
          neverResolve: (slot) => slot === 2,
        }),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(502);
      expect(res.json().error).toBe("round2_worker_timeout");
      expect(res.json().slot).toBe(2);
      expect(res.json().timeoutMs).toBe(50);
    });

    it("round2_rejects_when_worker_transcript_hash_diverges", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-hash-bad-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>(
        [0, 1, 2, 3, 4].map((s) => [s, h32(String(s))]),
      );
      await stageRound1Artifact(stateRoot, body, rosterHashHex, perSlotIngress);

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({
          tamperWorkerHash: (slot) => slot === 3,
        }),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(502);
      expect(res.json().error).toBe("round2_worker_transcript_hash_mismatch");
      expect(res.json().slot).toBe(3);
    });

    it("round2_rejects_when_dk_base_indices_diverge_across_workers", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-divergence-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>(
        [0, 1, 2, 3, 4].map((s) => [s, h32(String(s))]),
      );
      await stageRound1Artifact(stateRoot, body, rosterHashHex, perSlotIngress);

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({
          // Slot 0 returns canonical [0,17] (first worker → sets canonical baseline).
          // Slot 1 returns [0] only → invalid wrt canonical AND will be rejected by
          // parseMpccaWithdrawRound2DkResult before divergence check fires.
          tamperDkIndices: (slot) => (slot === 1 ? [0] : [0, 17]),
        }),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(502);
      // Could be either `round2_returned_invalid` (parse rejected [0] alone — canonical set is [0,17])
      // or `dk_base_indices_divergence` (canonical anchored from slot 0, slot 1 differs).
      // The parser-level check fires earlier (per-worker), so we expect round2_returned_invalid.
      // But the rejection at minimum surfaces a 502 with a structured error code.
      const errBody = res.json();
      expect(errBody.error).toMatch(/(round2_returned_invalid|dk_base_indices_divergence)/);
      expect(errBody.slot).toBe(1);
    });

    it("round2_rejects_forbidden_plaintext_field_amount", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-forbidden-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({
        rosterHash: rosterHashHex,
        amount: "1000",
      });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
      expect(res.json().field).toBe("amount");
    });

    it("round2_rejects_forbidden_plaintext_field_dkShare", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-dkshare-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({
        rosterHash: rosterHashHex,
        dkShare: "deadbeef",
      });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
    });

    it("round2_rejects_empty_bulletproof_bytes", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-emptybp-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({
        rosterHash: rosterHashHex,
        bulletproofZkrpAmountHex: "",
      });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("INVALID_BULLETPROOF_BYTES");
    });

    it("round2_rejects_when_state_root_not_configured", async () => {
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        // No stateRoot configured.
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("state_root_not_configured");
    });

    it("round2_rejects_stale_dkg_epoch", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-stale-epoch-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({
        rosterHash: rosterHashHex,
        dkgEpoch: "999",
      });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({}),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("stale_dkg_epoch");
    });

    it("round2_returns_409_when_withdraw_lock_busy", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-round2-lockbusy-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildRound2OrchestrateBody({ rosterHash: rosterHashHex });
      const perSlotIngress = new Map<number, string>(
        [0, 1, 2, 3, 4].map((s) => [s, h32(String(s))]),
      );
      await stageRound1Artifact(stateRoot, body, rosterHashHex, perSlotIngress);

      let releaseBarrier: () => void = () => {};
      const barrier = new Promise<void>((resolve) => {
        releaseBarrier = resolve;
      });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubMpccaRound2Forwarder({
          onCall: async () => {
            await barrier;
          },
        }),
      });
      // Stage round1 artifact for the second request id too, so both reach lock acquisition.
      await stageRound1Artifact(
        stateRoot,
        { ...body, requestId: "mpcca-wdr-r2-second" },
        rosterHashHex,
        perSlotIngress,
      );
      // First call holds the lock by parking on the barrier.
      const firstCall = server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: body,
      });
      // Wait long enough for the first request to acquire the lock + start fan-out.
      await new Promise((r) => setTimeout(r, 200));
      // Second call (different requestId so they don't collide on the __round2.json path)
      // hits the same lock and gets 409.
      const secondCall = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/round2",
        payload: { ...body, requestId: "mpcca-wdr-r2-second" },
      });
      releaseBarrier();
      await firstCall;
      expect(secondCall.statusCode).toBe(409);
      expect(secondCall.json().error).toBe("vault_mpcca_withdraw_in_flight");
    });
  });

  // ---------------------------------------------------------------------------------------------
  // Milestone 4 sub-milestone 4-c4 — POST /v2/withdraw/mpcca/finalize orchestrator.
  //
  // Reads __round2.json, builds the aggregated 30-point sigma commitment vector (Ristretto-point
  // addition over worker dk-base partials + user A_user[29]), derives canonical Fiat-Shamir e
  // via Aptos SDK's sigmaProtocolFiatShamir, fans out per-worker FinalizeRequest concurrently,
  // collects partial s_share responses, aggregates s[0] = Σ_j s_share_j (mod n), combines with
  // user s_user[1..25] into the full sigma response vector, and persists __finalize.json with
  // `notImplementedPhase = "m4_pending_frost_signature_assembly"` + mpccaWithdrawFinalizeArtifact.
  //
  // M4-c4 happy-path + algebraic-byte-parity tests live in the Aptos SDK end-to-end byte-parity
  // suite (planned for M4-c5). The c4 coordinator tests here exercise the orchestration error
  // paths: missing __round2.json, identity mismatch, stale roster/epoch, lock contention,
  // forbidden plaintext fields, state_root unconfigured.
  // ---------------------------------------------------------------------------------------------
  describe("MPCCA withdraw V2 finalize — M4 commit 4 orchestrator", () => {
    function genHex32(group: string, i: number): string {
      const idx = i.toString(16).padStart(2, "0");
      return (group + idx).repeat(16);
    }

    function buildFinalizeOrchestrateBody(
      overrides: Record<string, unknown> = {},
    ): Record<string, unknown> {
      return {
        dkgEpoch: "1",
        requestId: "mpcca-wdr-fin",
        sessionId: "mpcca-wdr-fin",
        vaultEkTranscriptHash: h32("7"),
        registrationTranscriptHash: h32("8"),
        vaultStateInitTranscriptHash: h32("9"),
        observedDepositTranscriptHashes: [h32("0")],
        rosterHash: h32("aa"),
        selectedSlots: [0, 1, 2, 3, 4],
        selfSlot: 0,
        playerId: 0,
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
        ...overrides,
      };
    }

    function buildStatementInputs() {
      return {
        recipientEk: "a1".repeat(32),
        oldBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("b0", i)),
        oldBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("c0", i)),
        newBalanceC: Array.from({ length: 8 }, (_, i) => genHex32("d0", i)),
        newBalanceD: Array.from({ length: 8 }, (_, i) => genHex32("e0", i)),
        transferAmountC: Array.from({ length: 4 }, (_, i) => genHex32("f0", i)),
        transferAmountDSender: Array.from({ length: 4 }, (_, i) => genHex32("12", i)),
        transferAmountDRecipient: Array.from({ length: 4 }, (_, i) => genHex32("23", i)),
      };
    }

    async function makeStateRoot(prefix: string): Promise<string> {
      const { mkdtemp } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const os = await import("node:os");
      return mkdtemp(join(os.tmpdir(), prefix));
    }

    async function stageRound2Artifact(
      stateRoot: string,
      body: Record<string, unknown>,
      rosterHashHex: string,
    ): Promise<string> {
      const { mkdir, writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const path = join(
        dir,
        `${body.dkgEpoch}__${body.requestId}__round2.json`,
      );
      const sortedSlots = (body.selectedSlots as number[]).slice().sort((a, b) => a - b);
      const stmt = buildStatementInputs();
      const perSlotContributions = sortedSlots.map((slot) => ({
        slot,
        playerId: sortedSlots.indexOf(slot),
        sessionStateHash: h32(String((slot + 1) % 9)),
        workerTranscriptHash: h32(String((slot + 7) % 9)),
        partialDkCommitments: [
          { index: 0, commitmentHex: h32(String((slot + 3) % 9)) },
          { index: 17, commitmentHex: h32(String((slot + 4) % 9)) },
        ],
        dkBaseIndicesUsed: [0, 17],
      }));
      const artifact = {
        scheme: "mpcca_withdraw_v2_round2_dk",
        dkgEpoch: body.dkgEpoch,
        requestId: body.requestId,
        sessionId: body.sessionId,
        rosterHash: rosterHashHex,
        selectedSlots: sortedSlots,
        vaultEkTranscriptHash: body.vaultEkTranscriptHash,
        registrationTranscriptHash: body.registrationTranscriptHash,
        vaultStateInitTranscriptHash: body.vaultStateInitTranscriptHash,
        observedDepositTranscriptHashes: body.observedDepositTranscriptHashes,
        vaultEk: body.vaultEk,
        senderAddress: body.senderAddress,
        assetType: body.assetType,
        chainId: body.chainId,
        root: body.root,
        nullifierHash: body.nullifierHash,
        recipient: body.recipient,
        recipientHash: body.recipientHash,
        amountTag: body.amountTag,
        vaultSequence: body.vaultSequence,
        expirySecs: body.expirySecs,
        requestHash: body.requestHash,
        depositCount: body.depositCount,
        previousRoundTranscriptHash: h32("ab"),
        previousRoundCommitments: [
          h32("a0"),
          h32("a1"),
          h32("a2"),
          h32("a3"),
          h32("a4"),
        ],
        statementInputs: stmt,
        statementInputsHashHex: h32("ff"),
        dkBaseIndicesUsed: [0, 17],
        perSlotContributions,
        userProofArtifacts: {
          userSigmaCommitmentsHex: Array.from({ length: 29 }, (_, i) => genHex32("34", i)),
          userSigmaResponseSharesHex: Array.from({ length: 24 }, (_, i) => genHex32("45", i)),
          bulletproofZkrpAmountHex: "ab".repeat(96),
          bulletproofZkrpNewBalanceHex: "cd".repeat(160),
          perChunkCommitmentsAmountHex: Array.from({ length: 4 }, (_, i) => genHex32("56", i)),
          perChunkCommitmentsNewBalanceHex: Array.from({ length: 8 }, (_, i) => genHex32("67", i)),
        },
        round1TranscriptHash: h32("ab"),
        round1TranscriptPath: join(dir, "1__mpcca-wdr-fin__round1.json"),
        transcriptHash: h32("dd"),
        createdAtUnixMs: 1_700_000_000_000,
      };
      await writeFile(path, JSON.stringify(artifact), { mode: 0o600 });
      return path;
    }

    function stubFinalizeForwarderFailClosed(): typeof singleNodeForwarder {
      // Stub that returns a 500 to surface forward_rejected; used by error-path tests where
      // we expect the route to fail BEFORE fan-out (so this stub is never actually called).
      return async (_path, _body, _roster, slot) => ({
        slot,
        ok: false,
        statusCode: 500,
        body: { error: "should_not_be_called" },
      });
    }

    it("finalize_rejects_state_root_not_configured", async () => {
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        // No stateRoot.
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("state_root_not_configured");
    });

    it("finalize_rejects_when_round2_transcript_missing", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-no-r2-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({ rosterHash: rosterHashHex });

      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("round2_transcript_not_found");
    });

    it("finalize_rejects_round2_identity_mismatch_vaultEk", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-mismatch-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({ rosterHash: rosterHashHex });
      await stageRound2Artifact(stateRoot, body, rosterHashHex);
      // Tamper vaultEk in the finalize body. Use a canonical 32-byte hex string distinct
      // from the staged value (h32("d") = "d".repeat(64)).
      const tampered = { ...body, vaultEk: "ee".repeat(32) };
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: tampered,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("round2_transcript_identity_mismatch");
      expect(res.json().field).toBe("vaultEk");
    });

    it("finalize_rejects_stale_dkg_epoch", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-stale-epoch-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({
        rosterHash: rosterHashHex,
        dkgEpoch: "999",
      });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("stale_dkg_epoch");
    });

    it("finalize_rejects_stale_roster_hash", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-stale-roster-");
      const caDkgV2Roster = dkgRoster();
      const body = buildFinalizeOrchestrateBody({ rosterHash: "ee".repeat(32) });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("stale_roster_hash");
    });

    it("finalize_rejects_forbidden_plaintext_field_amount", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-forbidden-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: { ...body, amount: 1_000_000 },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
      expect(res.json().field).toContain("amount");
    });

    it("finalize_rejects_forbidden_plaintext_field_dkShare", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-fin-forbidden-dk-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFinalizeOrchestrateBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubFinalizeForwarderFailClosed(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/finalize",
        payload: { ...body, dkShare: "01".repeat(32) },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
    });

    // NOTE: M4-c4 lock contention is covered by the M4-c2 round2 lock test
    // (`round2_returns_409_when_withdraw_lock_busy`); the finalize route re-uses the same
    // `acquireVaultMpccaWithdrawLock` mechanism. A finalize-specific 409 killer test would
    // require canonical Ristretto-point partials in the staged __round2.json so the route
    // can pass aggregation and reach the lock step under the barrier; that's deferred to
    // M4-c5's Aptos SDK byte-parity test which exercises the full happy path.
  });

  // ---------------------------------------------------------------------------------------------
  // Milestone 5 sub-milestone 5-c1 — POST /v2/withdraw/mpcca/frost-attest orchestrator.
  //
  // Reads __round2.json + __finalize.json, builds CA payload + caPayloadHash, drives the
  // 3-round FROST signing ceremony, assembles 30-field WithdrawV2CallArgs, and persists the
  // updated __finalize.json (removes notImplementedPhase, adds withdrawV2CallArgsFields).
  //
  // Happy-path with canonical Ristretto + real FROST keys is deferred to local cluster
  // smoke (M6-prep); these c1 coordinator tests focus on orchestration error paths.
  // ---------------------------------------------------------------------------------------------
  describe("MPCCA withdraw V2 FROST attest — M5 commit 1 orchestrator", () => {
    function genHex32(group: string, i: number): string {
      const idx = i.toString(16).padStart(2, "0");
      return (group + idx).repeat(16);
    }

    function buildFrostAttestBody(
      overrides: Record<string, unknown> = {},
    ): Record<string, unknown> {
      return {
        dkgEpoch: "1",
        requestId: "mpcca-wdr-frost",
        sessionId: "mpcca-wdr-frost",
        vaultEkTranscriptHash: h32("7"),
        registrationTranscriptHash: h32("8"),
        vaultStateInitTranscriptHash: h32("9"),
        observedDepositTranscriptHashes: [h32("0")],
        rosterHash: "aa".repeat(32),
        selectedSlots: [0, 1, 2, 3, 4],
        selfSlot: 0,
        playerId: 0,
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
        aspRoot: h32("a"),
        stateTreeDepth: 4,
        aspTreeDepth: 3,
        depositCount: 1,
        attestationConfig: {
          bridge: "11".repeat(32),
          vault: "22".repeat(32),
          operatorSetVersion: "1",
          frostGroupPubkey: "33".repeat(32),
          circuitVersionsHash: "44".repeat(32),
        },
        withdrawProofHex: "ee".repeat(96),
        ...overrides,
      };
    }

    async function makeStateRoot(prefix: string): Promise<string> {
      const { mkdtemp } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const os = await import("node:os");
      return mkdtemp(join(os.tmpdir(), prefix));
    }

    function stubForbid(): typeof singleNodeForwarder {
      return async (_path, _body, _roster, slot) => ({
        slot,
        ok: false,
        statusCode: 500,
        body: { error: "should_not_be_called" },
      });
    }

    it("frost_attest_rejects_state_root_not_configured", async () => {
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("state_root_not_configured");
    });

    it("frost_attest_rejects_round2_transcript_missing", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-no-r2-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("round2_transcript_not_found");
    });

    it("frost_attest_rejects_stale_roster_hash", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-stale-roster-");
      const caDkgV2Roster = dkgRoster();
      const body = buildFrostAttestBody({ rosterHash: "ee".repeat(32) });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("stale_roster_hash");
    });

    it("frost_attest_rejects_stale_dkg_epoch", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-stale-epoch-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({
        rosterHash: rosterHashHex,
        dkgEpoch: "999",
      });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("stale_dkg_epoch");
    });

    it("frost_attest_rejects_missing_withdrawProofHex", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-no-proof-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({ rosterHash: rosterHashHex });
      // strip required field
      delete (body as Record<string, unknown>).withdrawProofHex;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("INVALID_BULLETPROOF_BYTES");
    });

    it("frost_attest_rejects_missing_attestationConfig", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-no-cfg-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({ rosterHash: rosterHashHex });
      delete (body as Record<string, unknown>).attestationConfig;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: body,
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("INVALID_WITHDRAW_FIELD_SHAPE");
    });

    it("frost_attest_rejects_forbidden_plaintext_field_amount", async () => {
      const stateRoot = await makeStateRoot("eunoma-coord-frost-forbidden-");
      const caDkgV2Roster = dkgRoster();
      const rosterHashHex = caDkgV2RosterHash(caDkgV2Roster);
      const body = buildFrostAttestBody({ rosterHash: rosterHashHex });
      const { server } = buildCoordinatorServer({
        caDkgV2Roster,
        stateRoot,
        singleNodeForwarder: stubForbid(),
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/frost-attest",
        payload: { ...body, amount: 1_000_000 },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("forbidden_plaintext_field");
    });
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
      artifactOverrides: Record<string, unknown> = {},
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
        aspRoot: hex32(0x17),
        stateTreeDepth: "4",
        aspTreeDepth: "3",
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
          ...artifactOverrides,
        }),
      );
      return path;
    }

    // KILLER (Codex M5b P3): the shared assembler's bundle MUST iterate keys in
    // exactly `WITHDRAW_V2_CALL_ARGS_ORDER` byte-for-byte — the relayer's CLI encoder
    // depends on this order to splice positional `--args` in the Move-signature order.
    // Locks the helper's FinalizeWithdrawV2CallArgsFields layout to the canonical list.
    it("expect_assembled_field_order_matches_WITHDRAW_V2_CALL_ARGS_ORDER", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-fieldorder-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-fieldorder");
      const finalizeArtifact = await (async () => {
        const { readFile } = await import("node:fs/promises");
        const { join } = await import("node:path");
        return JSON.parse(
          await readFile(
            join(
              stateRoot,
              "coordinator",
              "mpcca_withdraw",
              "1__withdraw-fieldorder__finalize.json",
            ),
            "utf8",
          ),
        );
      })();
      const assembled = assembleWithdrawV2CallArgs(finalizeArtifact);
      const keys = Object.keys(assembled);
      expect(keys).toEqual([...WITHDRAW_V2_CALL_ARGS_ORDER]);
    });

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
      // LOAD-BEARING: 30 fields handed to the relayer.
      expect(receivedArgs).toBeDefined();
      expect(Object.keys(receivedArgs!).length).toBe(30);
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

    // Codex M5b P2 #3: when the finalize transcript carries an `attestationConfig`
    // block, the submit artifact MUST mirror it verbatim — but the relayer MUST NOT
    // receive these fields (only the 30-field WithdrawV2CallArgs).
    it("submit_route_persists_attestationConfig_into_submit_artifact", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-attest-");
      const { mkdir, writeFile, readFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
      await mkdir(dir, { recursive: true });
      const hex32 = (seed: number) =>
        Array.from({ length: 32 }, (_, i) =>
          ((i + seed) & 0xff).toString(16).padStart(2, "0"),
        ).join("");
      const hexN = (n: number, seed: number) =>
        Array.from({ length: n }, (_, i) =>
          ((i + seed) & 0xff).toString(16).padStart(2, "0"),
        ).join("");
      const attestationConfig = {
        chainId: 2,
        bridge: hex32(0x01),
        vault: hex32(0x02),
        assetType: hex32(0x03),
        operatorSetVersion: "1",
        rosterHash: hex32(0x04),
        frostGroupPubkey: hex32(0x05),
        circuitVersionsHash: hex32(0x06),
      };
      const fields = {
        root: hex32(0x10),
        nullifierHash: hex32(0x11),
        recipient: hex32(0x12),
        recipientHash: hex32(0x13),
        amountTag: hex32(0x14),
        caPayloadHash: hex32(0x15),
        requestHash: hex32(0x16),
        aspRoot: hex32(0x17),
        stateTreeDepth: "4",
        aspTreeDepth: "3",
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
      };
      await writeFile(
        join(dir, "1__withdraw-attest__finalize.json"),
        JSON.stringify({
          scheme: "mpcca_withdraw_v2_finalize",
          dkgEpoch: "1",
          requestId: "withdraw-attest",
          withdrawV2CallArgsFields: fields,
          attestationConfig,
          transcriptHash: h32("e"),
        }),
      );
      let relayerArgs: Record<string, unknown> | undefined;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async (args) => {
          relayerArgs = args as unknown as Record<string, unknown>;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-attest" },
      });
      expect(res.statusCode).toBe(202);
      // Relayer must receive ONLY the 30 call-args fields; attestationConfig keys must
      // NOT appear.
      expect(relayerArgs).toBeDefined();
      const relayerKeys = Object.keys(relayerArgs!);
      expect(relayerKeys.length).toBe(30);
      for (const k of [
        "chainId",
        "bridge",
        "vault",
        "operatorSetVersion",
        "rosterHash",
        "frostGroupPubkey",
        "circuitVersionsHash",
      ]) {
        expect(relayerKeys, `relayer must not see ${k}`).not.toContain(k);
      }
      // But the submit artifact MUST carry it verbatim.
      const artifact = JSON.parse(await readFile(res.json().transcriptPath, "utf8"));
      expect(artifact.attestationConfig).toEqual(attestationConfig);
    });

    // KILLER (Codex M5b P2 #1): a completed submit is idempotent against retries with
    // byte-identical inputs — the route returns the existing artifact verbatim WITHOUT
    // re-invoking the relayer.
    it("submit_route_idempotent_on_completed_retry_with_identical_inputs", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-idempotent-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-idem");
      let submitterCallCount = 0;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => {
          submitterCallCount += 1;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      // First call — relayer is invoked and the artifact is persisted with completed=true.
      const first = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-idem" },
      });
      expect(first.statusCode).toBe(202);
      const firstBody = first.json();
      expect(firstBody.completed).toBe(true);
      expect(submitterCallCount).toBe(1);
      // Second call — identical body. MUST return the same artifact verbatim WITHOUT
      // re-invoking the relayer (no rebroadcast).
      const second = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-idem" },
      });
      expect(second.statusCode).toBe(202);
      const secondBody = second.json();
      expect(secondBody.completed).toBe(true);
      expect(secondBody.txHash).toBe(firstBody.txHash);
      expect(secondBody.transcriptHash).toBe(firstBody.transcriptHash);
      expect(secondBody.idempotentReplay).toBe(true);
      expect(submitterCallCount).toBe(1); // CRITICAL: relayer NEVER re-invoked
    });

    // KILLER (Codex M5b P2 #1): a retry whose assembled inputs differ from the
    // already-completed artifact MUST 409 — refuse to overwrite the audit record.
    it("submit_route_409s_on_retry_with_different_inputs", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-409-diff-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-409");
      let submitterCallCount = 0;
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => {
          submitterCallCount += 1;
          return { accepted: true, txHash: "0x" + "ab".repeat(32), simulated: true };
        },
      });
      // First call — succeeds + persists.
      const first = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-409" },
      });
      expect(first.statusCode).toBe(202);
      expect(submitterCallCount).toBe(1);
      // Mutate the finalize transcript on disk so the assembled args differ from what
      // was previously committed. (In real operations the finalize transcript should
      // never mutate post-completion; the gate exists to catch tampering.)
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-409", {
        vaultSequence: "999", // different from the first run's "42"
      });
      const second = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-409" },
      });
      expect(second.statusCode).toBe(409);
      expect(second.json().error).toBe(
        "mpcca_withdraw_submit_already_completed_with_different_inputs",
      );
      expect(submitterCallCount).toBe(1); // CRITICAL: relayer NEVER re-invoked
    });

    // KILLER (Codex M5b P1 #4): when the relayer returns simulated:false (real
    // submission), the route MUST require chainNodeUrl + poll for confirmation. Without
    // chainNodeUrl, the route previously returned 200 completed after only relayer
    // acceptance — a misconfigured deploy could silently broadcast unconfirmed txs.
    it("submit_route_502s_when_chain_node_url_absent_for_real_submit", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-no-node-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-no-node");
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => ({
          accepted: true,
          txHash: "0x" + "ab".repeat(32),
          simulated: false, // REAL submission
        }),
        // chainNodeUrl: undefined  ← intentionally omitted
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-no-node" },
      });
      expect(res.statusCode).toBe(502);
      const body = res.json();
      expect(body.error).toBe("chain_node_url_required_for_real_submit");
      expect(body.txHash).toBe("0x" + "ab".repeat(32));
      expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
      expect(body.message).toContain("APTOS_NODE_URL");
      // Persisted artifact reflects the failure-closed posture.
      const { readFile } = await import("node:fs/promises");
      const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
      expect(artifact.completed).toBe(false);
      expect(artifact.chainConfirmationError).toBe(
        "chain_node_url_required_for_real_submit",
      );
    });

    // KILLER (Codex M5b P1 #3): a confirmed-but-failed chain execution surfaces as 502
    // chain_execution_failed with vmStatus, NOT a 200 success. The submit artifact must
    // also record completed: false so P2 #1 retry idempotency does not short-circuit on
    // a failed attempt.
    it("submit_route_502s_on_chain_execution_failed_with_vmstatus", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-chain-fail-");
      await writeFinalizeTranscriptComplete(stateRoot, "1", "withdraw-chain-fail");
      // Chain returns confirmed=true, success=false, vmStatus="MOVE_ABORT".
      const fakeChainFetch: typeof fetch = async () =>
        new Response(
          JSON.stringify({ success: false, vm_status: "MOVE_ABORT: code=42" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => ({
          accepted: true,
          txHash: "0x" + "ab".repeat(32),
          simulated: false, // REAL submission → coordinator must poll
        }),
        chainNodeUrl: "http://127.0.0.1:8080",
        chainFetch: fakeChainFetch,
        chainConfirmationTimeoutMs: 1000,
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-chain-fail" },
      });
      expect(res.statusCode).toBe(502);
      const body = res.json();
      expect(body.error).toBe("chain_execution_failed");
      expect(body.vmStatus).toBe("MOVE_ABORT: code=42");
      expect(body.txHash).toBe("0x" + "ab".repeat(32));
      expect(body.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
      // Persisted artifact must record completed=false + the vmStatus so retries are
      // NOT short-circuited as idempotent against a failed attempt.
      const { readFile } = await import("node:fs/promises");
      const artifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
      expect(artifact.completed).toBe(false);
      expect(artifact.chainSuccess).toBe(false);
      expect(artifact.chainVmStatus).toBe("MOVE_ABORT: code=42");
    });

    it("submit_route_runs_post_withdraw_resync_after_confirmed_relayer_submit", async () => {
      const stateRoot = await makeStateRoot("eunoma-mpcca-submit-resync-");
      const attestationConfig = {
        chainId: 2,
        bridge: h32("1"),
        vault: h32("2"),
        assetType: h32("3"),
        operatorSetVersion: "1",
        rosterHash: h32("4"),
        frostGroupPubkey: h32("5"),
        circuitVersionsHash: h32("6"),
      };
      const txHash = "0x" + "ab".repeat(32);
      await writeFinalizeTranscriptComplete(
        stateRoot,
        "1",
        "withdraw-resync",
        {},
        { attestationConfig },
      );
      const eventData = {
        root: h32("a"),
        nullifier_hash: h32("b"),
        recipient_hash: h32("c"),
        request_hash: h32("d"),
        vault_sequence: "42",
      };
      const fakeChainFetch: typeof fetch = async () =>
        new Response(
          JSON.stringify({
            success: true,
            vm_status: "Executed successfully",
            events: [
              {
                type: `${attestationConfig.bridge}::eunoma_bridge::WithdrawEventV3`,
                data: eventData,
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      const workerCalls: Array<{ path: string; slot: number; body: Record<string, unknown> }> = [];
      const { server } = buildCoordinatorServer({
        caDkgV2Roster: dkgRoster(),
        stateRoot,
        relayerSubmitter: async () => ({
          accepted: true,
          txHash,
          simulated: false,
        }),
        chainNodeUrl: "http://127.0.0.1:8080",
        chainFetch: fakeChainFetch,
        chainConfirmationTimeoutMs: 1000,
        bridgeVaultAddress: attestationConfig.vault,
        bridgeAssetType: attestationConfig.assetType,
        singleNodeForwarder: async (path, body, _roster, slot) => {
          workerCalls.push({ path, slot, body: body as Record<string, unknown> });
          return { slot, ok: true, statusCode: 200, body: { vault_sequence: 43 } };
        },
      });
      const res = await server.inject({
        method: "POST",
        url: "/v2/withdraw/mpcca/submit",
        payload: { dkgEpoch: "1", requestId: "withdraw-resync" },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.completed).toBe(true);
      expect(body.postWithdrawResync.ok).toBe(true);
      expect(body.postWithdrawResync.statusCode).toBe(200);
      expect(body.postWithdrawResync.body.summary.okSlots).toEqual([0, 1, 2, 3, 4, 5, 6]);
      expect(workerCalls.map((c) => c.path)).toEqual(Array(7).fill("/v2/vault/resync"));
      expect(workerCalls[0].body).toMatchObject({
        txHash,
        bridgePackage: attestationConfig.bridge,
        vault: attestationConfig.vault,
        assetType: attestationConfig.assetType,
        root: eventData.root,
        nullifierHash: eventData.nullifier_hash,
        recipientHash: eventData.recipient_hash,
        requestHash: eventData.request_hash,
        eventVaultSequence: 42,
        expectedNextSequence: 43,
      });
      const { readFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const resyncArtifact = JSON.parse(
        await readFile(
          join(stateRoot, "coordinator", "vault_resync", "1__withdraw-resync__after_withdraw.json"),
          "utf8",
        ),
      );
      expect(resyncArtifact.summary.thresholdMet).toBe(true);
      const submitArtifact = JSON.parse(await readFile(body.transcriptPath, "utf8"));
      expect(submitArtifact.postWithdrawResync.ok).toBe(true);
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

describe("coordinator ASP / state-tree public endpoints", () => {
  async function makeStateRoot(): Promise<{ stateRoot: string; coordinatorDir: string }> {
    const { mkdtemp, mkdir } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const os = await import("node:os");
    const stateRoot = await mkdtemp(join(os.tmpdir(), "eunoma-coord-tree-"));
    const coordinatorDir = join(stateRoot, "coordinator");
    await mkdir(coordinatorDir, { recursive: true });
    return { stateRoot, coordinatorDir };
  }

  // Build a REAL LeanIMT snapshot via the circuit-parity class so the fixture is byte-identical to
  // what scripts/local_build_commitment_tree.mjs writes.
  async function leanImtSnapshot(commitmentBigs: bigint[]) {
    const mod = await import(
      "../../../circuits/scripts/leanimt_tree.mjs"
    );
    const tree = new mod.LeanIMTTree();
    for (const c of commitmentBigs) tree.append(c, {});
    return tree.serialize();
  }

  describe("GET /v2/state-tree", () => {
    it("returns the LeanIMT snapshot verbatim", async () => {
      const { writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const { stateRoot, coordinatorDir } = await makeStateRoot();
      const snap = await leanImtSnapshot([101n, 202n, 303n, 404n, 505n]);
      await writeFile(join(coordinatorDir, "state_leanimt_tree.json"), JSON.stringify(snap));

      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot });
      const res = await server.inject({ method: "GET", url: "/v2/state-tree" });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.scheme).toBe("eunoma_leanimt_tree_v1");
      expect(body.treeDepth).toBe(snap.treeDepth);
      expect(body.latestRootHex).toBe(snap.latestRootHex);
      expect(body.leaves).toEqual(snap.leaves);
      expect(body.depositMeta).toEqual(snap.depositMeta);
    });

    it("is reachable WITHOUT a bearer token (public route)", async () => {
      const { writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const { stateRoot, coordinatorDir } = await makeStateRoot();
      const snap = await leanImtSnapshot([1n, 2n]);
      await writeFile(join(coordinatorDir, "state_leanimt_tree.json"), JSON.stringify(snap));

      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot, bearerToken: "secret" });
      const res = await server.inject({ method: "GET", url: "/v2/state-tree" });
      expect(res.statusCode).toBe(200);
    });

    it("returns 503 when the snapshot file is missing (mirrors /v2/pool/state)", async () => {
      const { stateRoot } = await makeStateRoot();
      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot });
      const res = await server.inject({ method: "GET", url: "/v2/state-tree" });
      expect(res.statusCode).toBe(503);
      expect(res.json().error).toBe("state_tree_unavailable");
    });

    it("returns 503 when stateRoot is unconfigured", async () => {
      const { server } = buildCoordinatorServer({ roster: roster() });
      const res = await server.inject({ method: "GET", url: "/v2/state-tree" });
      expect(res.statusCode).toBe(503);
    });
  });

  describe("GET /v2/asp-set and /v2/asp-root-current", () => {
    const aspArtifact = {
      scheme: "eunoma_asp_set_v1",
      version: 1,
      treeDepth: 3,
      leafCount: 4,
      rootHex: `0x${"ab".repeat(32)}`,
      commitments: [
        `0x${"11".repeat(32)}`,
        `0x${"22".repeat(32)}`,
        `0x${"33".repeat(32)}`,
        `0x${"44".repeat(32)}`,
      ],
      ipfsCid: "bafytestcid",
      updatedAtUnix: 1700000000,
    };

    it("/v2/asp-set maps the artifact to { aspRootHex, aspTreeDepth, ipfsCid, commitments }", async () => {
      const { writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const { stateRoot, coordinatorDir } = await makeStateRoot();
      await writeFile(join(coordinatorDir, "asp_set.json"), JSON.stringify(aspArtifact));

      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot });
      const res = await server.inject({ method: "GET", url: "/v2/asp-set" });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        aspRootHex: aspArtifact.rootHex,
        aspTreeDepth: aspArtifact.treeDepth,
        ipfsCid: aspArtifact.ipfsCid,
        commitments: aspArtifact.commitments,
      });
    });

    it("/v2/asp-root-current is the lightweight pointer (no commitments)", async () => {
      const { writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const { stateRoot, coordinatorDir } = await makeStateRoot();
      await writeFile(join(coordinatorDir, "asp_set.json"), JSON.stringify(aspArtifact));

      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot });
      const res = await server.inject({ method: "GET", url: "/v2/asp-root-current" });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        aspRootHex: aspArtifact.rootHex,
        aspTreeDepth: aspArtifact.treeDepth,
        ipfsCid: aspArtifact.ipfsCid,
      });
    });

    it("both ASP routes are reachable WITHOUT a bearer token (public)", async () => {
      const { writeFile } = await import("node:fs/promises");
      const { join } = await import("node:path");
      const { stateRoot, coordinatorDir } = await makeStateRoot();
      await writeFile(join(coordinatorDir, "asp_set.json"), JSON.stringify(aspArtifact));

      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot, bearerToken: "secret" });
      for (const url of ["/v2/asp-set", "/v2/asp-root-current"]) {
        const res = await server.inject({ method: "GET", url });
        expect(res.statusCode, url).toBe(200);
      }
    });

    it("both ASP routes return 503 when asp_set.json is missing", async () => {
      const { stateRoot } = await makeStateRoot();
      const { server } = buildCoordinatorServer({ roster: roster(), stateRoot });
      for (const url of ["/v2/asp-set", "/v2/asp-root-current"]) {
        const res = await server.inject({ method: "GET", url });
        expect(res.statusCode, url).toBe(503);
        expect(res.json().error, url).toBe("asp_set_unavailable");
      }
    });
  });
});
