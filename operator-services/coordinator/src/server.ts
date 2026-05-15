import Fastify, { type FastifyInstance } from "fastify";
import {
  DEOPERATOR_COUNT,
  ForbiddenPlaintextFieldError,
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  parseCaRegistrationAggregateRequest,
  parseCaRegistrationAggregateResult,
  parseCaRegistrationChallengeRequest,
  parseCaRegistrationChallengeResult,
  parseCaRegistrationNonceCommitRequest,
  parseCaRegistrationNonceCommitResult,
  parseCaRegistrationPartialRequest,
  parseCaRegistrationPartialResult,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  parseDkgRoundRequest,
  parseDkgRoundResult,
  parseMpccaRoundRequest,
  parseMpccaRoundResult,
  parseSessionShareEnvelope,
  rosterHash,
  UnderQuorumError,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
  type FrostRound1Broadcast,
  type FrostRound2Envelope,
  type SessionShareEnvelope,
} from "@eunoma/deop-protocol";
import { sha256, bytesToHex } from "@eunoma/shared";
import { HttpError, requireBearer } from "@eunoma/shared";
import { InMemoryCoordinatorStore, type CoordinatorStore } from "./store.js";

export interface ProxyForwardResult {
  slot: number;
  ok: boolean;
  statusCode?: number;
  error?: string;
  body?: unknown;
}

export type SessionShareForwarder = (
  envelope: SessionShareEnvelope,
  roster: DeoperatorRoster,
) => Promise<ProxyForwardResult[]>;

export type SingleNodeForwarder = (
  path: string,
  body: unknown,
  roster: RoutableRoster,
  slot: number,
) => Promise<ProxyForwardResult>;

export interface RoutableRoster {
  nodes: Array<{ slot: number; endpoint: string }>;
}

export interface CoordinatorServerOptions {
  roster?: DeoperatorRoster;
  caDkgV2Roster?: CaDkgV2Roster;
  frostDkgV2Roster?: FrostDkgV2Roster;
  bearerToken?: string;
  nodeBearerTokens?: Record<string, string>;
  store?: CoordinatorStore;
  forwarder?: SessionShareForwarder;
  singleNodeForwarder?: SingleNodeForwarder;
}

export function buildCoordinatorServer(
  opts: CoordinatorServerOptions,
): { server: FastifyInstance; store: CoordinatorStore } {
  if (opts.roster) validateRoster(opts.roster);
  if (opts.caDkgV2Roster) validateCaDkgV2Roster(opts.caDkgV2Roster);
  if (opts.frostDkgV2Roster) validateFrostDkgV2Roster(opts.frostDkgV2Roster);
  if (!opts.roster && !opts.caDkgV2Roster) {
    throw new Error("coordinator requires DEOPERATOR_ROSTER_JSON or CA_DKG_V2_ROSTER_JSON");
  }
  const store = opts.store ?? new InMemoryCoordinatorStore();
  const server = Fastify({ logger: false });
  const currentRosterHash = opts.roster ? rosterHash(opts.roster) : undefined;
  const currentCaDkgV2RosterHash = opts.caDkgV2Roster ? caDkgV2RosterHash(opts.caDkgV2Roster) : undefined;
  const currentFrostDkgV2RosterHash = opts.frostDkgV2Roster
    ? frostDkgV2RosterHash(opts.frostDkgV2Roster)
    : undefined;
  const forwarder = opts.forwarder ?? forwardSessionShareToRoster(opts.nodeBearerTokens ?? {});
  const singleNodeForwarder =
    opts.singleNodeForwarder ?? forwardToRosterNode(opts.nodeBearerTokens ?? {});

  server.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code });
    }
    return reply.code(500).send({ error: "internal_error" });
  });

  server.addHook("onRequest", async (req) => {
    if (req.method === "GET" && (req.url === "/v2/roster" || req.url === "/v2/health")) {
      return;
    }
    requireBearer(req.headers.authorization, opts.bearerToken);
  });

  server.get("/v2/health", async () => ({
    ok: true,
    threshold: opts.roster?.threshold ?? opts.caDkgV2Roster?.threshold,
    rosterHash: currentRosterHash,
    caDkgV2RosterHash: currentCaDkgV2RosterHash,
  }));

  server.get("/v2/roster", async () =>
    opts.roster
      ? {
          ...opts.roster,
          rosterHash: currentRosterHash,
        }
      : {
          caDkgV2Roster: opts.caDkgV2Roster,
          caDkgV2RosterHash: currentCaDkgV2RosterHash,
        },
  );

  server.get("/v2/status/:requestId", async (req) => {
    const params = req.params as { requestId: string };
    return store.getStatus(params.requestId);
  });

  server.post("/v2/dkg/ca/v2/start", async (req, reply) => {
    try {
      const raw = (req.body ?? {}) as Record<string, unknown>;
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);
      const requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `ca-dkg-v2-${Date.now()}`;
      const sessionId =
        typeof raw.sessionId === "string" && raw.sessionId.length > 0
          ? raw.sessionId
          : `${dkgRoster.operatorSetVersion}:${dkgRoster.dkgEpoch}:${dkgRosterHash}`;
      const participantSlots = Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => slot);
      const baseBody = {
        requestId,
        sessionId,
        operatorSetVersion: dkgRoster.operatorSetVersion,
        dkgEpoch: dkgRoster.dkgEpoch,
        rosterHash: dkgRosterHash,
        threshold: dkgRoster.threshold,
        participantSlots,
        caDkgScheme: "ca_dkg_v2",
      };

      const round1Results = [];
      for (const node of dkgRoster.nodes) {
        const forwarded = await singleNodeForwarder(
          "/deop/v2/dkg/ca/round1",
          { ...baseBody, slot: node.slot, commitments: [], encryptedShares: [], caDkgV2Roster: dkgRoster },
          dkgRoster,
          node.slot,
        );
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "round1", forwarded });
        }
        const result = parseDkgRoundResult(forwarded.body);
        if (!result.dealerBroadcast || !result.encryptedShares || result.encryptedShares.length !== DEOPERATOR_COUNT) {
          throw new Error(`round1 slot ${node.slot} did not return a complete dealer artifact`);
        }
        await store.recordPartialArtifact({
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          slot: result.slot,
          artifactKind: "dkg-ca-round",
          artifactHash: result.artifactHash,
          transcriptHash: result.transcriptHash,
        });
        round1Results.push(result);
      }

      const dealerBroadcasts = round1Results.map((result) => result.dealerBroadcast!);
      const allEncryptedShares = round1Results.flatMap((result) => result.encryptedShares ?? []);
      const round2Results = [];
      for (const node of dkgRoster.nodes) {
        const encryptedShares = allEncryptedShares.filter((share) => share.toSlot === node.slot);
        if (encryptedShares.length !== DEOPERATOR_COUNT) {
          throw new Error(`round2 slot ${node.slot} does not have 7 encrypted shares`);
        }
        const forwarded = await singleNodeForwarder(
          "/deop/v2/dkg/ca/round2",
          {
            ...baseBody,
            slot: node.slot,
            commitments: [],
            dealerBroadcasts,
            encryptedShares,
          },
          dkgRoster,
          node.slot,
        );
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "round2", forwarded });
        }
        const result = parseDkgRoundResult(forwarded.body);
        await store.recordPartialArtifact({
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          slot: result.slot,
          artifactKind: "dkg-ca-round",
          artifactHash: result.artifactHash,
          transcriptHash: result.transcriptHash,
        });
        if (result.complaints && result.complaints.length > 0) {
          await store.markAborted(requestId);
          return reply.code(409).send({
            accepted: false,
            round: "round2",
            slot: result.slot,
            complaints: result.complaints,
            abortEvidenceHash: result.abortEvidenceHash,
          });
        }
        round2Results.push(result);
      }

      const caDkgTranscriptHash = round2Results[0]?.transcriptHash;
      if (!caDkgTranscriptHash || !round2Results.every((result) => result.transcriptHash === caDkgTranscriptHash)) {
        throw new Error("round2 workers produced inconsistent CA DKG transcript hashes");
      }

      const finalizeResults = [];
      for (const node of dkgRoster.nodes) {
        const forwarded = await singleNodeForwarder(
          "/deop/v2/dkg/ca/finalize",
          {
            ...baseBody,
            slot: node.slot,
            transcriptHash: caDkgTranscriptHash,
            commitments: [],
            encryptedShares: [],
          },
          dkgRoster,
          node.slot,
        );
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "finalize", forwarded });
        }
        const result = parseDkgRoundResult(forwarded.body);
        await store.recordPartialArtifact({
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          slot: result.slot,
          artifactKind: "dkg-ca-round",
          artifactHash: result.artifactHash,
          transcriptHash: result.transcriptHash,
        });
        finalizeResults.push(result);
      }

      await store.markComplete(requestId);
      return reply.code(200).send({
        accepted: true,
        requestId,
        sessionId,
        caDkgV2RosterHash: dkgRosterHash,
        caDkgTranscriptHash,
        workerArtifactHashes: finalizeResults.map((result) => ({
          slot: result.slot,
          artifactHash: result.artifactHash,
          caDkgShareHash: result.caDkgShareHash,
        })),
      });
    } catch (err) {
      const maybeRequestId = ((req.body ?? {}) as Record<string, unknown>).requestId;
      await store.markAborted(typeof maybeRequestId === "string" ? maybeRequestId : "ca-dkg-v2-unknown");
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/dkg/frost/v2/start", async (req, reply) => {
    try {
      const raw = (req.body ?? {}) as Record<string, unknown>;
      const dkgRoster = raw.frostDkgV2Roster
        ? parseFrostDkgV2Roster(raw.frostDkgV2Roster)
        : requireFrostDkgV2Roster(opts.frostDkgV2Roster);
      validateFrostDkgV2Roster(dkgRoster);
      const dkgRosterHash = frostDkgV2RosterHash(dkgRoster);
      const requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `frost-dkg-v2-${Date.now()}`;
      const sessionId =
        typeof raw.sessionId === "string" && raw.sessionId.length > 0
          ? raw.sessionId
          : `${dkgRoster.operatorSetVersion}:${dkgRoster.dkgEpoch}:${dkgRosterHash}`;
      const participantSlots = Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => slot);
      const baseBody = {
        requestId,
        sessionId,
        protocol: "frost" as const,
        operatorSetVersion: dkgRoster.operatorSetVersion,
        dkgEpoch: dkgRoster.dkgEpoch,
        threshold: dkgRoster.threshold,
        participantSlots,
        frostDkgV2RosterHash: dkgRosterHash,
      };

      const recordFrost = async (slot: number, artifactHash: string, transcriptHash: string) => {
        await store.recordPartialArtifact({
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          slot,
          artifactKind: "dkg-frost-round",
          artifactHash,
          transcriptHash,
        });
      };

      const round1Results = await Promise.all(
        dkgRoster.nodes.map((node) =>
          singleNodeForwarder(
            "/deop/v2/dkg/frost/round1",
            {
              ...baseBody,
              round: "round1",
              slot: node.slot,
              commitments: [],
              encryptedShares: [],
              frostDkgV2Roster: dkgRoster,
            },
            dkgRoster,
            node.slot,
          ),
        ),
      );
      for (const forwarded of round1Results) {
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "round1", forwarded });
        }
      }
      const round1Parsed = round1Results.map((forwarded) => parseDkgRoundResult(forwarded.body));
      const round1Broadcasts: FrostRound1Broadcast[] = round1Parsed.map((result) => {
        const broadcast = result.frostRound1Broadcast;
        if (!broadcast) {
          throw new Error(`round1 slot ${result.slot} did not return a frostRound1Broadcast`);
        }
        return broadcast;
      });
      for (const result of round1Parsed) {
        await recordFrost(result.slot, result.artifactHash, result.transcriptHash);
      }

      const round2SendResults = await Promise.all(
        dkgRoster.nodes.map((node) =>
          singleNodeForwarder(
            "/deop/v2/dkg/frost/round2_send",
            {
              ...baseBody,
              round: "round2_send",
              slot: node.slot,
              commitments: [],
              encryptedShares: [],
              frostRound1Broadcasts: round1Broadcasts,
            },
            dkgRoster,
            node.slot,
          ),
        ),
      );
      for (const forwarded of round2SendResults) {
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "round2_send", forwarded });
        }
      }
      const round2SendParsed = round2SendResults.map((forwarded) =>
        parseDkgRoundResult(forwarded.body),
      );
      const allEnvelopes: FrostRound2Envelope[] = round2SendParsed.flatMap((result) => {
        const envelopes = result.frostRound2Envelopes ?? [];
        if (envelopes.length !== DEOPERATOR_COUNT - 1) {
          throw new Error(
            `round2_send slot ${result.slot} returned ${envelopes.length} envelopes (expected ${
              DEOPERATOR_COUNT - 1
            })`,
          );
        }
        return envelopes;
      });
      for (const result of round2SendParsed) {
        await recordFrost(result.slot, result.artifactHash, result.transcriptHash);
      }

      const envelopesByReceiver = new Map<number, FrostRound2Envelope[]>();
      for (const env of allEnvelopes) {
        const bucket = envelopesByReceiver.get(env.toSlot) ?? [];
        bucket.push(env);
        envelopesByReceiver.set(env.toSlot, bucket);
      }

      const round2ReceiveResults = await Promise.all(
        dkgRoster.nodes.map((node) => {
          const inbound = envelopesByReceiver.get(node.slot) ?? [];
          if (inbound.length !== DEOPERATOR_COUNT - 1) {
            throw new Error(
              `round2_receive slot ${node.slot} expected ${
                DEOPERATOR_COUNT - 1
              } inbound envelopes, got ${inbound.length}`,
            );
          }
          return singleNodeForwarder(
            "/deop/v2/dkg/frost/round2_receive",
            {
              ...baseBody,
              round: "round2_receive",
              slot: node.slot,
              commitments: [],
              encryptedShares: [],
              frostRound1Broadcasts: round1Broadcasts,
              frostRound2Envelopes: inbound,
            },
            dkgRoster,
            node.slot,
          );
        }),
      );
      for (const forwarded of round2ReceiveResults) {
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "round2_receive", forwarded });
        }
      }
      const round2ReceiveParsed = round2ReceiveResults.map((forwarded) =>
        parseDkgRoundResult(forwarded.body),
      );
      for (const result of round2ReceiveParsed) {
        if (result.complaints && result.complaints.length > 0) {
          await store.markAborted(requestId);
          return reply.code(409).send({
            accepted: false,
            round: "round2_receive",
            slot: result.slot,
            complaints: result.complaints,
            abortEvidenceHash: result.abortEvidenceHash,
          });
        }
      }
      for (const result of round2ReceiveParsed) {
        await recordFrost(result.slot, result.artifactHash, result.transcriptHash);
      }

      const sortedTranscripts = [...round2ReceiveParsed.map((r) => r.transcriptHash)].sort();
      const dkgTranscriptHash = bytesToHex(
        sha256(new TextEncoder().encode(sortedTranscripts.join(""))),
      );

      const finalizeResults = await Promise.all(
        dkgRoster.nodes.map((node) =>
          singleNodeForwarder(
            "/deop/v2/dkg/frost/finalize",
            {
              ...baseBody,
              round: "finalize",
              slot: node.slot,
              commitments: [],
              encryptedShares: [],
              transcriptHash: dkgTranscriptHash,
            },
            dkgRoster,
            node.slot,
          ),
        ),
      );
      for (const forwarded of finalizeResults) {
        if (!forwarded.ok || !forwarded.body) {
          await store.markAborted(requestId);
          return reply.code(502).send({ accepted: false, round: "finalize", forwarded });
        }
      }
      const finalizeParsed = finalizeResults.map((forwarded) => parseDkgRoundResult(forwarded.body));
      for (const result of finalizeParsed) {
        await recordFrost(result.slot, result.artifactHash, result.transcriptHash);
      }
      const firstGroupKey = finalizeParsed[0]?.groupPublicKey;
      if (!firstGroupKey) {
        throw new Error("finalize did not return a groupPublicKey");
      }
      for (const result of finalizeParsed) {
        if (result.groupPublicKey !== firstGroupKey) {
          throw new Error("finalize workers produced inconsistent groupPublicKey values");
        }
      }

      await store.markComplete(requestId);
      return reply.code(200).send({
        accepted: true,
        requestId,
        sessionId,
        operatorSetVersion: dkgRoster.operatorSetVersion,
        dkgEpoch: dkgRoster.dkgEpoch,
        frostDkgV2RosterHash: dkgRosterHash,
        dkgTranscriptHash,
        groupPublicKey: firstGroupKey,
        workerArtifactHashes: finalizeParsed.map((result) => ({
          slot: result.slot,
          artifactHash: result.artifactHash,
          frostKeyPackageHash: result.frostKeyPackageHash,
          frostPublicPackageHash: result.frostPublicPackageHash,
          frostVerifyingShare: result.frostVerifyingShare,
        })),
      });
    } catch (err) {
      const maybeRequestId = ((req.body ?? {}) as Record<string, unknown>).requestId;
      await store.markAborted(typeof maybeRequestId === "string" ? maybeRequestId : "frost-dkg-v2-unknown");
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/session-share", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const body = parseSessionShareEnvelope(req.body);
      if (body.rosterHash.replace(/^0x/i, "").toLowerCase() !== currentRosterHash) {
        throw new Error("roster hash mismatch");
      }
      await store.recordSessionShare(body);
      const forwarded = await forwarder(body, roster);
      return reply.code(202).send({
        accepted: true,
        requestId: body.requestId,
        forwarded,
      });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/dkg/:protocol/:round", async (req, reply) => {
    try {
      const params = req.params as { protocol: string; round: string };
      const body = parseDkgRoundRequest({
        ...(req.body as Record<string, unknown>),
        protocol: params.protocol,
        round: params.round,
      });
      const isFrost = body.protocol === "frost";
      const isCaDkgV2 = !isFrost && (body.caDkgScheme === "ca_dkg_v2" || body.caDkgV2Roster !== undefined);
      const targetRoster: RoutableRoster = isFrost
        ? requireFrostDkgV2Roster(opts.frostDkgV2Roster)
        : isCaDkgV2
          ? requireCaDkgV2Roster(opts.caDkgV2Roster)
          : requireRoster(opts.roster);
      if (isFrost) {
        const expectedHash = currentFrostDkgV2RosterHash;
        const claimedHash = body.frostDkgV2RosterHash?.replace(/^0x/i, "").toLowerCase();
        if (expectedHash && claimedHash && claimedHash !== expectedHash) {
          throw new Error("FROST DKG V2 roster hash mismatch");
        }
      } else {
        const expectedHash = isCaDkgV2 ? currentCaDkgV2RosterHash : currentRosterHash;
        if (body.rosterHash.replace(/^0x/i, "").toLowerCase() !== expectedHash) {
          throw new Error("roster hash mismatch");
        }
      }
      const forwarded = await singleNodeForwarder(
        `/deop/v2/dkg/${body.protocol}/${body.round}`,
        body,
        targetRoster,
        body.slot,
      );
      if (forwarded.ok && forwarded.body) {
        const result = parseDkgRoundResult(forwarded.body);
        const recordedRosterHash = isFrost
          ? body.frostDkgV2RosterHash ?? body.rosterHash
          : body.rosterHash;
        await store.recordPartialArtifact({
          requestId: result.requestId,
          sessionId: result.sessionId,
          rosterHash: recordedRosterHash,
          slot: result.slot,
          artifactKind: result.protocol === "ca" ? "dkg-ca-round" : "dkg-frost-round",
          artifactHash: result.artifactHash,
          transcriptHash: result.transcriptHash,
        });
      }
      return reply.code(forwarded.ok ? 202 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/mpcca/:protocol/:round", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const params = req.params as { protocol: string; round: string };
      const body = parseMpccaRoundRequest({
        ...(req.body as Record<string, unknown>),
        protocol: params.protocol,
        round: params.round,
      });
      if (body.rosterHash.replace(/^0x/i, "").toLowerCase() !== currentRosterHash) {
        throw new Error("roster hash mismatch");
      }
      const forwarded = await singleNodeForwarder(
        `/deop/v2/mpcca/${body.protocol}/${body.round}`,
        body,
        roster,
        body.slot,
      );
      if (forwarded.ok && forwarded.body) {
        const result = parseMpccaRoundResult(forwarded.body);
        await store.recordPartialArtifact({
          requestId: result.requestId,
          sessionId: result.sessionId,
          rosterHash: body.rosterHash,
          slot: result.slot,
          artifactKind: "mpcca-withdraw-round",
          artifactHash: result.artifactHash,
          transcriptHash: result.transcriptHash,
        });
      }
      return reply.code(forwarded.ok ? 202 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/ca/registration/:slot/nonce-commit", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const slot = slotParam((req.params as { slot: string }).slot);
      const body = parseCaRegistrationNonceCommitRequest(req.body);
      const forwarded = await singleNodeForwarder(
        "/deop/v2/ca/registration/nonce-commit",
        body,
        roster,
        slot,
      );
      if (forwarded.ok && forwarded.body) {
        forwarded.body = parseCaRegistrationNonceCommitResult(forwarded.body);
      }
      return reply.code(forwarded.ok ? 200 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/ca/registration/:slot/challenge", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const slot = slotParam((req.params as { slot: string }).slot);
      const body = parseCaRegistrationChallengeRequest(req.body);
      assertRosterVaultEk(body.vaultEk, roster.vaultEk);
      const forwarded = await singleNodeForwarder(
        "/deop/v2/ca/registration/challenge",
        body,
        roster,
        slot,
      );
      if (forwarded.ok && forwarded.body) {
        forwarded.body = parseCaRegistrationChallengeResult(forwarded.body);
      }
      return reply.code(forwarded.ok ? 200 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/ca/registration/:slot/partial", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const slot = slotParam((req.params as { slot: string }).slot);
      const body = parseCaRegistrationPartialRequest(req.body);
      const forwarded = await singleNodeForwarder(
        "/deop/v2/ca/registration/partial",
        body,
        roster,
        slot,
      );
      if (forwarded.ok && forwarded.body) {
        forwarded.body = parseCaRegistrationPartialResult(forwarded.body);
      }
      return reply.code(forwarded.ok ? 200 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  server.post("/v2/proxy/ca/registration/:slot/aggregate", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const slot = slotParam((req.params as { slot: string }).slot);
      const body = parseCaRegistrationAggregateRequest(req.body);
      assertRosterVaultEk(body.vaultEk, roster.vaultEk);
      const forwarded = await singleNodeForwarder(
        "/deop/v2/ca/registration/aggregate",
        body,
        roster,
        slot,
      );
      if (forwarded.ok && forwarded.body) {
        const result = parseCaRegistrationAggregateResult(forwarded.body);
        forwarded.body = result;
        await store.recordPartialArtifact({
          requestId: `ca-registration:${body.senderAddress}:${body.assetType}`,
          sessionId: `${body.chainId}:${body.senderAddress}:${body.assetType}`,
          rosterHash: currentRosterHash,
          slot,
          artifactKind: "ca-registration",
          artifactHash: result.proof_hash,
          transcriptHash: result.transcript_hash,
        });
      }
      return reply.code(forwarded.ok ? 200 : 502).send({ accepted: forwarded.ok, forwarded });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof UnderQuorumError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  return { server, store };
}

export function forwardSessionShareToRoster(
  bearerTokens: Record<string, string> = {},
): SessionShareForwarder {
  return async (envelope, roster) => {
    const results: ProxyForwardResult[] = [];
    for (const node of roster.nodes) {
      const nodeEnvelope = {
        ...envelope,
        envelopes: envelope.envelopes.filter((item) => item.slot === node.slot),
      };
      if (nodeEnvelope.envelopes.length === 0) {
        results.push({ slot: node.slot, ok: false, error: "missing_envelope_for_slot" });
        continue;
      }
      try {
        const token = bearerTokens[String(node.slot)];
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (token) headers.authorization = `Bearer ${token}`;
        const res = await fetch(new URL("/deop/v2/session-share", node.endpoint), {
          method: "POST",
          headers,
          body: JSON.stringify(nodeEnvelope),
        });
        results.push({ slot: node.slot, ok: res.ok, statusCode: res.status });
      } catch (err) {
        results.push({
          slot: node.slot,
          ok: false,
          error: err instanceof Error ? err.message : "unknown",
        });
      }
    }
    return results;
  };
}

export function forwardToRosterNode(
  bearerTokens: Record<string, string> = {},
): SingleNodeForwarder {
  return async (path, body, roster, slot) => {
    const node = roster.nodes.find((item) => item.slot === slot);
    if (!node) return { slot, ok: false, error: "unknown_slot" };
    try {
      const token = bearerTokens[String(slot)];
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token) headers.authorization = `Bearer ${token}`;
      const res = await fetch(new URL(path, node.endpoint), {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      let responseBody: unknown;
      try {
        responseBody = await res.json();
      } catch {
        responseBody = undefined;
      }
      return { slot, ok: res.ok, statusCode: res.status, body: responseBody };
    } catch (err) {
      return {
        slot,
        ok: false,
        error: err instanceof Error ? err.message : "unknown",
      };
    }
  };
}

function slotParam(value: string): number {
  const slot = Number.parseInt(value, 10);
  if (!Number.isInteger(slot) || String(slot) !== value || slot < 0 || slot >= DEOPERATOR_COUNT) {
    throw new Error("slot must be a deoperator slot");
  }
  return slot;
}

function requireRoster(roster: DeoperatorRoster | undefined): DeoperatorRoster {
  if (!roster) throw new Error("DEOPERATOR_ROSTER_JSON is required for this route");
  return roster;
}

function requireCaDkgV2Roster(roster: CaDkgV2Roster | undefined): CaDkgV2Roster {
  if (!roster) throw new Error("CA_DKG_V2_ROSTER_JSON is required for CA DKG V2");
  return roster;
}

function requireFrostDkgV2Roster(roster: FrostDkgV2Roster | undefined): FrostDkgV2Roster {
  if (!roster) throw new Error("FROST_DKG_V2_ROSTER_JSON is required for FROST DKG V2");
  return roster;
}

function assertRosterVaultEk(actual: string, expected: string): void {
  if (actual.replace(/^0x/i, "").toLowerCase() !== expected.replace(/^0x/i, "").toLowerCase()) {
    throw new Error("vaultEk mismatch");
  }
}
