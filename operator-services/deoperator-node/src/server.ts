import Fastify, { type FastifyInstance } from "fastify";
import { CryptoWorkerUnavailableError, type CryptoWorker } from "@eunoma/crypto-worker-client";
import {
  ForbiddenPlaintextFieldError,
  assertNoForbiddenPlaintextFields,
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  parseAbortEvidenceRequest,
  parseAttestationPartialRequest,
  parseCaRegistrationAggregateRequest,
  parseCaRegistrationAggregateResult,
  parseCaRegistrationChallengeRequest,
  parseCaRegistrationChallengeResult,
  parseCaRegistrationNonceCommitRequest,
  parseCaRegistrationNonceCommitResult,
  parseCaRegistrationPartialRequest,
  parseCaRegistrationPartialResult,
  parseDepositBindRequest,
  parseDkgRoundRequest,
  parseMpccaRoundRequest,
  parseSessionShareEnvelope,
  parseWithdrawCAPayloadRequest,
  rosterHash,
  UnderQuorumError,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
} from "@eunoma/deop-protocol";
import { HttpError, requireBearer } from "@eunoma/shared";
import {
  InMemoryDeoperatorNodeStore,
  type DeoperatorNodeStore,
} from "./store.js";

export interface DeoperatorNodeServerOptions {
  slot: number;
  nodeId: string;
  roster?: DeoperatorRoster;
  caDkgV2Roster?: CaDkgV2Roster;
  frostDkgV2Roster?: FrostDkgV2Roster;
  cryptoWorker: CryptoWorker;
  bearerToken?: string;
  store?: DeoperatorNodeStore;
  /**
   * Phase 2: URL of the local crypto worker for the vault_ek derive proxy routes
   * (`/worker/v2/derive/vault_ek/{round1,verify}`). The coordinator hits the deop-node by
   * `node.endpoint`; this option lets the deop-node forward those calls to its local worker.
   * Falls back to `CRYPTO_WORKER_URL` env at start when not supplied.
   */
  cryptoWorkerUrl?: string;
}

export function buildDeoperatorNodeServer(
  opts: DeoperatorNodeServerOptions,
): { server: FastifyInstance; store: DeoperatorNodeStore } {
  if (opts.roster) validateRoster(opts.roster);
  if (opts.caDkgV2Roster) validateCaDkgV2Roster(opts.caDkgV2Roster);
  if (opts.frostDkgV2Roster) validateFrostDkgV2Roster(opts.frostDkgV2Roster);
  if (!opts.roster && !opts.caDkgV2Roster) {
    throw new Error("node requires DEOPERATOR_ROSTER_JSON or CA_DKG_V2_ROSTER_JSON");
  }
  const store = opts.store ?? new InMemoryDeoperatorNodeStore();
  const server = Fastify({ logger: false });
  const expectedRosterHash = opts.roster ? rosterHash(opts.roster) : undefined;
  const expectedCaDkgV2RosterHash = opts.caDkgV2Roster ? caDkgV2RosterHash(opts.caDkgV2Roster) : undefined;
  const expectedFrostDkgV2RosterHash = opts.frostDkgV2Roster
    ? frostDkgV2RosterHash(opts.frostDkgV2Roster)
    : undefined;

  server.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code });
    }
    return reply.code(500).send({ error: "internal_error" });
  });

  server.addHook("onRequest", async (req) => {
    if (req.url === "/deop/v2/health") return;
    requireBearer(req.headers.authorization, opts.bearerToken);
  });

  server.get("/deop/v2/health", async () => ({
    ok: true,
    slot: opts.slot,
    nodeId: opts.nodeId,
    threshold: opts.roster?.threshold ?? opts.caDkgV2Roster?.threshold,
    rosterHash: expectedRosterHash,
    caDkgV2RosterHash: expectedCaDkgV2RosterHash,
  }));

  server.get("/deop/v2/status/:requestId", async (req) => {
    const params = req.params as { requestId: string };
    return store.status(params.requestId);
  });

  server.post("/deop/v2/session-share", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseSessionShareEnvelope(req.body);
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      assertEnvelopeForSlot(body, opts.slot);
      const result = await opts.cryptoWorker.acceptSessionShare(body);
      await store.putSessionShare({ ...body, transcriptHash: result.transcriptHash });
      return reply.code(202).send({ accepted: true, slot: opts.slot, transcriptHash: result.transcriptHash });
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/dkg/:protocol/:round", async (req, reply) => {
    try {
      const params = req.params as { protocol: string; round: string };
      const body = parseDkgRoundRequest({
        ...(req.body as Record<string, unknown>),
        protocol: params.protocol,
        round: params.round,
      });
      const isFrost = body.protocol === "frost";
      const isCaDkgV2 = !isFrost && (body.caDkgScheme === "ca_dkg_v2" || body.caDkgV2Roster !== undefined);
      if (isFrost) {
        if (body.frostDkgV2RosterHash && expectedFrostDkgV2RosterHash) {
          assertRoster(body.frostDkgV2RosterHash, expectedFrostDkgV2RosterHash);
        }
      } else if (isCaDkgV2) {
        assertRoster(body.rosterHash, requireHash(expectedCaDkgV2RosterHash));
      } else {
        requireRoster(opts.roster);
        assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      }
      assertSlot(body.slot, opts.slot);
      const result = await opts.cryptoWorker.runDkgRound(body);
      await store.putDkgRoundArtifact(result);
      return reply.code(202).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/mpcca/:protocol/:round", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const params = req.params as { protocol: string; round: string };
      const body = parseMpccaRoundRequest({
        ...(req.body as Record<string, unknown>),
        protocol: params.protocol,
        round: params.round,
      });
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      assertSlot(body.slot, opts.slot);
      const result = await opts.cryptoWorker.runMpccaRound(body);
      await store.putMpccaRoundArtifact(result);
      return reply.code(202).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/ca/registration/nonce-commit", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseCaRegistrationNonceCommitRequest(req.body);
      const result = parseCaRegistrationNonceCommitResult(
        await opts.cryptoWorker.caRegistrationNonceCommit(body),
      );
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/ca/registration/challenge", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const body = parseCaRegistrationChallengeRequest(req.body);
      assertRosterVaultEk(body.vaultEk, roster.vaultEk);
      const result = parseCaRegistrationChallengeResult(
        await opts.cryptoWorker.caRegistrationChallenge(body),
      );
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/ca/registration/partial", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseCaRegistrationPartialRequest(req.body);
      const result = parseCaRegistrationPartialResult(
        await opts.cryptoWorker.caRegistrationPartial(body),
      );
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/ca/registration/aggregate", async (req, reply) => {
    try {
      const roster = requireRoster(opts.roster);
      const body = parseCaRegistrationAggregateRequest(req.body);
      assertRosterVaultEk(body.vaultEk, roster.vaultEk);
      const result = parseCaRegistrationAggregateResult(
        await opts.cryptoWorker.caRegistrationAggregate(body),
      );
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/deposit/bind", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseDepositBindRequest(req.body);
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      const result = await opts.cryptoWorker.bindDeposit(body);
      await store.putDepositBindShare(result);
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/withdraw/ca-payload", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseWithdrawCAPayloadRequest(req.body);
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      const result = await opts.cryptoWorker.buildWithdrawCAPayload(body);
      await store.putWithdrawPayloadShare(result);
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/attestation/partial", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseAttestationPartialRequest(req.body);
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      const result = await opts.cryptoWorker.partialAttestation(body);
      await store.putAttestationShare(result);
      return reply.code(200).send(result);
    } catch (err) {
      return sendError(reply, err);
    }
  });

  server.post("/deop/v2/abort-evidence", async (req, reply) => {
    try {
      requireRoster(opts.roster);
      const body = parseAbortEvidenceRequest(req.body);
      assertRoster(body.rosterHash, requireHash(expectedRosterHash));
      await store.putAbortEvidence(body);
      return reply.code(202).send({ accepted: true, slot: opts.slot });
    } catch (err) {
      return sendError(reply, err);
    }
  });

  // Phase 2 / Milestone 1: passthrough routes for the vault_ek derive HTTP fan-out AND the
  // V2 CA registration sigma fan-out. The coordinator hits `node.endpoint` (the deop-node),
  // and the deop-node forwards to its local crypto worker. This sits in between because we
  // keep worker URLs private to each node + we want the deop-node's bearer-auth hook to apply.
  //
  // Codex P1 #5: BEFORE forwarding, validate `rosterHash` matches the configured
  // CA_DKG_V2_ROSTER_JSON and (for round1) `selfSlot` matches this node's slot. Otherwise
  // a stale or wrong-roster request can reach MP-SPDZ or persist a malformed nonce file.
  const forwardToWorker = async (
    path:
      | "/worker/v2/derive/vault_ek/round0"
      | "/worker/v2/derive/vault_ek/round1"
      | "/worker/v2/derive/vault_ek/verify"
      | "/worker/v2/derive/ca_registration/round1"
      | "/worker/v2/derive/ca_registration/round2"
      | "/worker/v2/derive/ca_registration/challenge"
      | "/worker/v2/derive/ca_registration/verify"
      | "/worker/v2/derive/ca_registration/aggregate",
    body: unknown,
    reply: { code: (s: number) => { send: (body: unknown) => unknown } },
  ) => {
    if (!opts.cryptoWorkerUrl) {
      return reply.code(503).send({ error: "crypto_worker_unavailable" });
    }
    try {
      const res = await fetch(new URL(path, opts.cryptoWorkerUrl), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      let parsed: unknown;
      try {
        parsed = await res.json();
      } catch {
        parsed = {};
      }
      return reply.code(res.status).send(parsed);
    } catch (err) {
      return reply.code(502).send({
        error: "worker_forward_failed",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  };
  // Codex P1 #4 round0: pre-MPC commitment passthrough. Mirrors round1's roster + slot
  // assertion pattern; without it a stale-roster or wrong-slot request could persist
  // a round0 commitment under this node's state_dir.
  //
  // Codex P1 #3 (audit): every V2 worker passthrough runs `assertNoForbiddenPlaintextFields`
  // on the request body BEFORE forwarding. Skipping the parser at this boundary would
  // let extra fields named `dkShare`, `blindShare`, `secret`, `nullifier`, etc. flow to
  // the worker — violating the TS/API plaintext invariant even if the worker itself
  // ignores them.
  server.post("/worker/v2/derive/vault_ek/round0", async (req, reply) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
      const rosterHashClaim = typeof body.rosterHash === "string" ? body.rosterHash : "";
      assertRoster(rosterHashClaim, requireHash(expectedCaDkgV2RosterHash));
      const selfSlot = body.selfSlot;
      if (typeof selfSlot !== "number") {
        throw new Error("selfSlot must be a number");
      }
      assertSlot(selfSlot, opts.slot);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/vault_ek/round0", req.body, reply);
  });
  server.post("/worker/v2/derive/vault_ek/round1", async (req, reply) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
      const rosterHashClaim = typeof body.rosterHash === "string" ? body.rosterHash : "";
      assertRoster(rosterHashClaim, requireHash(expectedCaDkgV2RosterHash));
      const selfSlot = body.selfSlot;
      if (typeof selfSlot !== "number") {
        throw new Error("selfSlot must be a number");
      }
      assertSlot(selfSlot, opts.slot);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/vault_ek/round1", req.body, reply);
  });
  server.post("/worker/v2/derive/vault_ek/verify", async (req, reply) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
      const rosterHashClaim = typeof body.rosterHash === "string" ? body.rosterHash : "";
      assertRoster(rosterHashClaim, requireHash(expectedCaDkgV2RosterHash));
      // /verify body has no `selfSlot` — coordinator picks the verifier; trust the
      // roster-hash gate to bind the request to our configured roster.
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/vault_ek/verify", req.body, reply);
  });

  // Milestone 1: V2 threshold CA registration passthroughs. Mirror the vault_ek
  // round0/round1 pattern — assert rosterHash + (for round1/round2) selfSlot before
  // forwarding so a stale-roster or wrong-slot request can't persist a nonce file under
  // this node's state_dir. Codex P1 #3: every route also runs
  // `assertNoForbiddenPlaintextFields(body)` BEFORE forwarding — without it, extra
  // fields named `dkShare`, `blindShare`, `secret`, etc. would slip past the
  // TS/API boundary, even on the share-independent /challenge, /verify, /aggregate
  // routes.
  server.post("/worker/v2/derive/ca_registration/round1", async (req, reply) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
      const rosterHashClaim = typeof body.rosterHash === "string" ? body.rosterHash : "";
      assertRoster(rosterHashClaim, requireHash(expectedCaDkgV2RosterHash));
      const selfSlot = body.selfSlot;
      if (typeof selfSlot !== "number") {
        throw new Error("selfSlot must be a number");
      }
      assertSlot(selfSlot, opts.slot);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/ca_registration/round1", req.body, reply);
  });
  server.post("/worker/v2/derive/ca_registration/round2", async (req, reply) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
      const rosterHashClaim = typeof body.rosterHash === "string" ? body.rosterHash : "";
      assertRoster(rosterHashClaim, requireHash(expectedCaDkgV2RosterHash));
      const selfSlot = body.selfSlot;
      if (typeof selfSlot !== "number") {
        throw new Error("selfSlot must be a number");
      }
      assertSlot(selfSlot, opts.slot);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/ca_registration/round2", req.body, reply);
  });
  server.post("/worker/v2/derive/ca_registration/challenge", async (req, reply) => {
    // Codex P1 #2: V2 interim aggregator passthrough. Share-independent public compute
    // over published round1 commitments; coordinator targets the verifier slot. No
    // selfSlot binding — same shape as /verify and /aggregate. Replaces the V1
    // `/worker/v2/ca/registration/challenge` route that this deop-node never
    // allowlisted.
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/ca_registration/challenge", req.body, reply);
  });
  server.post("/worker/v2/derive/ca_registration/verify", async (req, reply) => {
    // /verify body has no selfSlot — coordinator picks the verifier. The roster-hash
    // gate binds it to our configured roster.
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/ca_registration/verify", req.body, reply);
  });
  server.post("/worker/v2/derive/ca_registration/aggregate", async (req, reply) => {
    // /aggregate is share-independent public compute over already-published commitments
    // + responses. No selfSlot binding required — the coordinator targets the verifier
    // slot. Forward directly to the local worker.
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      assertNoForbiddenPlaintextFields(body);
    } catch (err) {
      return sendError(reply, err);
    }
    return forwardToWorker("/worker/v2/derive/ca_registration/aggregate", req.body, reply);
  });

  return { server, store };
}

function assertEnvelopeForSlot(
  body: ReturnType<typeof parseSessionShareEnvelope>,
  slot: number,
): void {
  if (!body.envelopes.some((envelope) => envelope.slot === slot)) {
    throw new Error(`missing encrypted share envelope for slot ${slot}`);
  }
}

function assertRoster(actual: string, expected: string): void {
  if (actual.replace(/^0x/i, "").toLowerCase() !== expected) {
    throw new Error("roster hash mismatch");
  }
}

function requireHash(hash: string | undefined): string {
  if (!hash) throw new Error("roster hash is not configured for this route");
  return hash;
}

function requireRoster(roster: DeoperatorRoster | undefined): DeoperatorRoster {
  if (!roster) throw new Error("DEOPERATOR_ROSTER_JSON is required for this route");
  return roster;
}

function assertRosterVaultEk(actual: string, expected: string): void {
  if (actual.replace(/^0x/i, "").toLowerCase() !== expected.replace(/^0x/i, "").toLowerCase()) {
    throw new Error("vaultEk mismatch");
  }
}

function assertSlot(actual: number, expected: number): void {
  if (actual !== expected) {
    throw new Error(`slot mismatch: expected ${expected}`);
  }
}

function sendError(reply: { code: (statusCode: number) => { send: (body: unknown) => unknown } }, err: unknown): unknown {
  if (err instanceof ForbiddenPlaintextFieldError) {
    return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
  }
  if (err instanceof UnderQuorumError) {
    return reply.code(400).send({ error: err.code, message: err.message });
  }
  if (err instanceof CryptoWorkerUnavailableError) {
    return reply.code(503).send({ error: "crypto_worker_unavailable" });
  }
  return reply.code(400).send({
    error: "invalid_request",
    message: err instanceof Error ? err.message : "unknown",
  });
}
