import Fastify, { type FastifyInstance } from "fastify";
import {
  assembleVaultEkTranscript,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  ForbiddenPlaintextFieldError,
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  lagrangeCoefficientsAtZero,
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
  parseVaultEkContributions,
  rosterHash,
  scalarHexFromBigint,
  UnderQuorumError,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  VaultEkDerivationError,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
  type FrostRound1Broadcast,
  type FrostRound2Envelope,
  type SessionShareEnvelope,
  type VaultEkContribution,
} from "@eunoma/deop-protocol";
import { sha256, bytesToHex } from "@eunoma/shared";
import { HttpError, requireBearer } from "@eunoma/shared";
import { mkdir, rename, writeFile, chmod } from "node:fs/promises";
import { dirname, join } from "node:path";
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
  stateRoot?: string;
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

  // Process-wide async lock for /v2/derive/vault_ek/start. The current MASCOT runtime uses a
  // fixed port range (EUNOMA_MPC_PARTY_PORT_BASE + slot), so two concurrent derivations would
  // collide on peer ports. Phase 2 ships single-session-at-a-time semantics: the lock is
  // acquired before any worker dispatch and released in finally. If a new derivation arrives
  // while one is in flight, it gets HTTP 409 `vault_ek_derivation_in_flight` quickly (~100ms
  // wait). Concurrent support is out of scope (plan §"Concurrent vault_ek derivations").
  let vaultEkInFlight: Promise<unknown> | null = null;
  const vaultEkLockAcquireTimeoutMs = 100;
  async function acquireVaultEkDerivationLock(): Promise<{ release: () => void } | "busy"> {
    const start = Date.now();
    while (vaultEkInFlight !== null) {
      if (Date.now() - start > vaultEkLockAcquireTimeoutMs) {
        return "busy";
      }
      // Wait for the current holder to settle; ignore its outcome (we only care that the
      // lock slot is free). If the holder rejects, vaultEkInFlight has already been cleared
      // by the holder's finally.
      try {
        await Promise.race([
          vaultEkInFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // The holder failed; loop iteration will re-check vaultEkInFlight.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    vaultEkInFlight = held;
    return {
      release: () => {
        vaultEkInFlight = null;
        resolveHeld();
      },
    };
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

  server.post("/v2/derive/vault_ek/start", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);

      const dkgEpoch = typeof raw.dkgEpoch === "string" && raw.dkgEpoch.length > 0
        ? raw.dkgEpoch
        : undefined;
      if (!dkgEpoch || !/^[0-9]+$/.test(dkgEpoch)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "dkgEpoch must be a non-empty decimal string",
        });
      }
      if (dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          message: `request.dkgEpoch ${dkgEpoch} does not match caDkgV2Roster.dkgEpoch ${dkgRoster.dkgEpoch}`,
        });
      }
      const caDkgTranscriptHashInput = raw.caDkgTranscriptHash;
      if (typeof caDkgTranscriptHashInput !== "string" || caDkgTranscriptHashInput.length === 0) {
        return reply.code(400).send({
          error: "no_ca_dkg_v2_record_for_dkg_epoch",
          message:
            "caDkgTranscriptHash is required for /v2/derive/vault_ek/start; supply the value from the CA DKG V2 artifact",
        });
      }

      requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `vault-ek-derive-${Date.now()}`;
      if (raw.selectedSlots !== undefined) {
        return reply.code(400).send({
          error: "selected_slots_not_overridable",
          message:
            "selectedSlots is coordinator-chosen; do not supply in request body. " +
            "If Phase 2 needs failover, add a separate admin-gated endpoint.",
        });
      }
      const selectedSlots = lowestEligibleSlots(dkgRoster, DEOPERATOR_THRESHOLD);
      const sortedSelectedSlots = [...selectedSlots].sort((a, b) => a - b);
      const selectionRationale = "coordinator-chosen" as const;

      // Phase 2: compute Lagrange coefficients (public) and peer addresses (deterministic
      // from S + EUNOMA_MPC_PARTY_PORT_BASE) for the per-party MASCOT fan-out.
      const lambdas = lagrangeCoefficientsAtZero(sortedSelectedSlots);
      const lagrangeCoefficients = lambdas.map(scalarHexFromBigint);
      const portBase = Number(process.env.EUNOMA_MPC_PARTY_PORT_BASE ?? 14000);
      // Codex P1 #2: peer addresses MUST be derived from per-slot host (via dkgRoster.nodes
      // endpoint), not a hardcoded 127.0.0.1. Real deoperators on separate hosts would
      // otherwise connect back to themselves instead of peers. Fail closed for prod when
      // the host can't be derived; allow 127.0.0.1 fallback only under EUNOMA_LOCAL_CLUSTER=1.
      const allowLocalClusterFallback = process.env.EUNOMA_LOCAL_CLUSTER === "1";
      const peerAddresses = sortedSelectedSlots.map((slot) =>
        resolveMpcPeerAddress(dkgRoster, slot, portBase, allowLocalClusterFallback),
      );
      const sessionId = requestId;

      // Acquire the single-session lock before issuing any worker calls. Without this guard
      // two concurrent /v2/derive/vault_ek/start requests would collide on MASCOT ports.
      const lock = await acquireVaultEkDerivationLock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "vault_ek_derivation_in_flight",
          requestId,
          message:
            "another vault_ek derivation is in progress; retry shortly. Concurrent " +
            "vault_ek derivations are out of scope in Phase 2 (per plan).",
        });
      }
      try {
      // Codex P1 #4 round0: fan out round0 FIRST. Each worker generates r_i, commits
      // h_r_i locally, and returns h_r_i. The coordinator collects all 5, broadcasts them
      // in round1 as `allHRoundZero`. Each worker verifies its own h_r_i matches what
      // the coordinator broadcast — the binding closes the post-m bias attack.
      //
      // Round0 is pure local state (no MASCOT subprocess), so it's fast (~ms per worker).
      // Fan out concurrently for the same reason round1 does, and short-circuit on any
      // non-200 since round0 failure means we can't proceed.
      const round0Bodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashInput,
        rosterHash: dkgRosterHash,
        selectedSlots: sortedSelectedSlots,
        selfSlot: slot,
        requestId: requestId!,
        sessionId,
        playerId: ordinalIndex,
        peerAddresses,
        lagrangeCoefficients,
      }));
      const round0Results = await Promise.all(
        sortedSelectedSlots.map((slot, ordinalIndex) =>
          singleNodeForwarder(
            "/worker/v2/derive/vault_ek/round0",
            round0Bodies[ordinalIndex],
            dkgRoster,
            slot,
          ).then(
            (value) => ({ kind: "value" as const, slot, value }),
            (reason) => ({ kind: "rejected" as const, slot, reason }),
          ),
        ),
      );
      const allHRoundZero: string[] = new Array(DEOPERATOR_THRESHOLD).fill("");
      for (let i = 0; i < round0Results.length; i += 1) {
        const res = round0Results[i];
        if (res.kind === "rejected") {
          return reply.code(502).send({
            error: "round0_forward_rejected",
            slot: res.slot,
            requestId,
            reason: res.reason instanceof Error ? res.reason.message : String(res.reason),
          });
        }
        if (
          res.value.statusCode === 503 &&
          res.value.body &&
          typeof res.value.body === "object" &&
          (res.value.body as Record<string, unknown>).error === "mpc_inverse_unavailable"
        ) {
          // round0 doesn't run MASCOT so this is unusual, but propagate it cleanly.
          return reply
            .code(503)
            .send({ error: "mpc_inverse_unavailable", slot: res.slot, requestId });
        }
        if (!res.value.ok || !res.value.body) {
          return reply.code(502).send({
            error: "round0_forward_failed",
            slot: res.slot,
            statusCode: res.value.statusCode,
            requestId,
          });
        }
        const body = res.value.body as Record<string, unknown>;
        const hR = typeof body.hR === "string" ? body.hR : undefined;
        if (!hR) {
          return reply.code(502).send({
            error: "round0_returned_incomplete",
            slot: res.slot,
            requestId,
          });
        }
        allHRoundZero[i] = hR;
      }

      // Concurrent fan-out — each worker spawns its own MASCOT party and blocks waiting
      // for peers, so sequential await would deadlock (plan §"Coordinator delta").
      //
      // Codex P2 #8: when ANY worker returns 503 mpc_inverse_unavailable, return 503
      // immediately rather than waiting for the others to finish (MASCOT peers will block
      // until their TLS timeout — typically 60s — because the 503-returning party never
      // connects). We race the per-slot promises: the first 503-detector resolution wins,
      // otherwise wait for all to settle.
      //
      // Codex P2 #8 regression fix: with the 503 short-circuit, the OTHER in-flight
      // workers may still be running on fixed MASCOT ports. Holding the lock until those
      // siblings settle prevents a new derivation from colliding with their port state.
      // We use AbortController to cancel sibling fetches as soon as the 503 wins (so the
      // worker-side handlers return quickly on the next syscall) but still await
      // `Promise.allSettled` so the lock is held until each fetch has resolved.
      const round1Promises = sortedSelectedSlots.map((slot, ordinalIndex) =>
        singleNodeForwarder(
          "/worker/v2/derive/vault_ek/round1",
          {
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashInput,
            rosterHash: dkgRosterHash,
            selectedSlots: sortedSelectedSlots,
            selfSlot: slot,
            requestId,
            sessionId,
            playerId: ordinalIndex,
            peerAddresses,
            lagrangeCoefficients,
            allHRoundZero,
          },
          dkgRoster,
          slot,
        ).then(
          (value) => ({ kind: "value" as const, slot, value }),
          (reason) => ({ kind: "rejected" as const, slot, reason }),
        ),
      );
      type Resolved =
        | { kind: "value"; slot: number; value: ProxyForwardResult }
        | { kind: "rejected"; slot: number; reason: unknown };
      const detector: Promise<Resolved | "all_done"> = Promise.race(
        round1Promises.map((p) =>
          p.then((res) => {
            if (
              res.kind === "value" &&
              res.value.statusCode === 503 &&
              res.value.body &&
              typeof res.value.body === "object" &&
              (res.value.body as Record<string, unknown>).error === "mpc_inverse_unavailable"
            ) {
              return res; // 503 winner
            }
            // Not a 503; emit a sentinel that loses the race vs a real 503 by deferring.
            return new Promise<Resolved | "all_done">((resolve) => {
              // Wait for the all-settled outcome to resolve all_done — but only if no
              // promise has emitted 503 yet. Achieved via a separate `Promise.all`.
              void Promise.all(round1Promises).then(() => resolve("all_done"));
            });
          }),
        ),
      );
      const winner = await detector;
      if (winner !== "all_done" && winner.kind === "value") {
        // Codex P2 #8 regression: send 503 NOW (UX win — caller doesn't wait for the
        // hung MASCOT siblings), but DO NOT return from the handler until all sibling
        // fetches have settled. The `finally` block below releases the lock — keeping
        // the handler alive through `allSettled` means the lock is held until the
        // siblings either complete or hit their EUNOMA_MPC_TIMEOUT_SECS-bounded MASCOT
        // timeout (default 60s).
        const winningSlot = winner.slot;
        await reply
          .code(503)
          .send({ error: "mpc_inverse_unavailable", slot: winningSlot, requestId });
        // Wait for siblings to settle — keeps the lock held.
        await Promise.allSettled(round1Promises);
        return reply;
      }
      // No 503 short-circuit; collect all results.
      const settledList: Resolved[] = await Promise.all(round1Promises);
      const roundResults: Array<{ slot: number; body: Record<string, unknown> }> = [];
      for (const res of settledList) {
        if (res.kind === "rejected") {
          return reply.code(502).send({
            error: "round1_forward_rejected",
            slot: res.slot,
            requestId,
            reason: res.reason instanceof Error ? res.reason.message : String(res.reason),
          });
        }
        const forwarded = res.value;
        if (
          forwarded.statusCode === 503 &&
          forwarded.body &&
          typeof forwarded.body === "object" &&
          (forwarded.body as Record<string, unknown>).error === "mpc_inverse_unavailable"
        ) {
          // Belt-and-suspenders: if the detector somehow missed a 503, catch it here.
          return reply
            .code(503)
            .send({ error: "mpc_inverse_unavailable", slot: res.slot, requestId });
        }
        if (!forwarded.ok || !forwarded.body) {
          return reply.code(502).send({
            error: "round1_forward_failed",
            slot: res.slot,
            statusCode: forwarded.statusCode,
            requestId,
          });
        }
        roundResults.push({ slot: res.slot, body: forwarded.body as Record<string, unknown> });
      }

      const contributions: VaultEkContribution[] = parseVaultEkContributions(
        roundResults.map((item) => item.body),
      );

      // Codex P1 #4: all 5 workers MUST report the same MPC-opened m (MAC-checked by
      // MASCOT). Reject 400 if any disagrees — the verifier worker will catch it too, but
      // failing here gives a more specific error code and avoids paying the verify call.
      if (contributions.length > 0) {
        const expectedM = contributions[0].mpcOpenM.toLowerCase();
        for (const c of contributions) {
          if (c.mpcOpenM.toLowerCase() !== expectedM) {
            return reply.code(400).send({
              error: "mpc_open_m_disagreement",
              slot: c.slot,
              requestId,
              message: `worker at slot ${c.slot} reported mpcOpenM that disagrees with slot ${contributions[0].slot}`,
            });
          }
        }
      }

      const transcript = assembleVaultEkTranscript({
        dkgEpoch,
        caDkgTranscriptHash: caDkgTranscriptHashInput,
        selectedSlots,
        rosterHash: dkgRosterHash,
        contributions,
        allHRoundZero,
        roster: dkgRoster,
      });

      const verifierSlot = selectedSlots[0];
      const verifyForwarded = await singleNodeForwarder(
        "/worker/v2/derive/vault_ek/verify",
        {
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          selectedSlots,
          contributions: transcript.contributions,
          allHRoundZero,
        },
        dkgRoster,
        verifierSlot,
      );
      if (
        verifyForwarded.statusCode === 503 &&
        verifyForwarded.body &&
        typeof verifyForwarded.body === "object" &&
        (verifyForwarded.body as Record<string, unknown>).error === "mpc_inverse_unavailable"
      ) {
        return reply
          .code(503)
          .send({ error: "mpc_inverse_unavailable", slot: verifierSlot, requestId });
      }
      if (!verifyForwarded.ok || !verifyForwarded.body) {
        return reply.code(502).send({
          error: "verify_forward_failed",
          slot: verifierSlot,
          statusCode: verifyForwarded.statusCode,
          requestId,
        });
      }
      const verifyBody = verifyForwarded.body as Record<string, unknown>;
      const vaultEk = typeof verifyBody.vaultEk === "string" ? verifyBody.vaultEk : undefined;
      const finalTranscriptHash =
        typeof verifyBody.finalTranscriptHash === "string"
          ? verifyBody.finalTranscriptHash
          : undefined;
      if (!vaultEk || !finalTranscriptHash) {
        return reply.code(502).send({
          error: "verify_returned_incomplete",
          slot: verifierSlot,
          requestId,
        });
      }

      const transcriptArtifact = {
        scheme: "vault_ek_derivation_v1" as const,
        dkgEpoch,
        caDkgTranscriptHash: transcript.caDkgTranscriptHash,
        selectedSlots,
        selectionRationale,
        rosterHash: dkgRosterHash,
        verifierSlot,
        perSlotContributions: transcript.contributions,
        // Codex P1 #4 round0: persist the round0 commit vector in the on-disk artifact
        // so audit trails record the pre-MPC h_r_i commitments alongside the final
        // contributions. Replay verification reconstructs the worker hashes from this.
        allHRoundZero,
        vaultEk,
        finalTranscriptHash,
        createdAtUnixMs: Date.now(),
      };

      let transcriptPath: string | undefined;
      if (opts.stateRoot) {
        const dir = join(opts.stateRoot, "coordinator", "vault_ek_derivation");
        transcriptPath = join(dir, `${dkgEpoch}__${requestId}.json`);
        await writeTranscriptArtifactAtomic(transcriptPath, transcriptArtifact);
      }
      await store.recordPartialArtifact({
        requestId,
        sessionId: requestId,
        rosterHash: dkgRosterHash,
        slot: verifierSlot,
        artifactKind: "vault-ek-derivation",
        artifactHash: finalTranscriptHash,
        transcriptHash: finalTranscriptHash,
      });
      await store.markComplete(requestId);

      return reply.code(200).send({
        accepted: true,
        requestId,
        dkgEpoch,
        rosterHash: dkgRosterHash,
        selectedSlots,
        selectionRationale,
        verifierSlot,
        vaultEk,
        finalTranscriptHash,
        transcriptHash: finalTranscriptHash,
        transcriptPath,
      });
      } finally {
        // Always release the in-flight lock — even on early returns above (Fastify treats a
        // `return reply` as the response value, but the JS code path still falls through to
        // finally).
        lock.release();
      }
    } catch (err) {
      if (requestId) await store.markAborted(requestId);
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof VaultEkDerivationError) {
        return reply.code(400).send({ error: err.code, message: err.message });
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

function lowestEligibleSlots(roster: CaDkgV2Roster, n: number): number[] {
  return roster.nodes
    .map((node) => node.slot)
    .sort((a, b) => a - b)
    .slice(0, n);
}

/**
 * Resolve the MASCOT peer `host:port` for `slot`. The port is always `portBase + slot`. The
 * host is extracted from the roster node's `endpoint` URL (e.g. `http://10.0.0.5:8080` →
 * `10.0.0.5`). If the endpoint is unparseable AND `EUNOMA_LOCAL_CLUSTER=1`, fall back to
 * `127.0.0.1`. Otherwise throw — production must never silently send all peers to localhost.
 */
function resolveMpcPeerAddress(
  roster: CaDkgV2Roster,
  slot: number,
  portBase: number,
  allowLocalClusterFallback: boolean,
): string {
  const node = roster.nodes.find((entry) => entry.slot === slot);
  if (!node) {
    throw new Error(`vault_ek peer resolution: no roster node for slot ${slot}`);
  }
  let host: string | undefined;
  try {
    const parsed = new URL(node.endpoint);
    host = parsed.hostname;
  } catch {
    host = undefined;
  }
  if (!host || host.length === 0) {
    if (allowLocalClusterFallback) {
      host = "127.0.0.1";
    } else {
      throw new Error(
        `vault_ek peer resolution: roster slot ${slot} endpoint ${node.endpoint} has no parseable hostname; ` +
          `set EUNOMA_LOCAL_CLUSTER=1 to allow the 127.0.0.1 fallback`,
      );
    }
  }
  return `${host}:${portBase + slot}`;
}

async function writeTranscriptArtifactAtomic(
  path: string,
  value: unknown,
): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, path);
}
