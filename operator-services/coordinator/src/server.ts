import Fastify, { type FastifyInstance } from "fastify";
import {
  assembleCaRegistrationV2Transcript,
  assembleVaultEkTranscript,
  assembleVaultStateV2InitTranscript,
  assembleVaultStateV2ObserveDepositTranscript,
  CaRegistrationV2Error,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1,
  ForbiddenPlaintextFieldError,
  MpccaWithdrawSubmitError,
  MpccaWithdrawV2Error,
  caDkgV2RosterHash,
  caRegistrationV2Round1WorkerTranscriptHash,
  caRegistrationV2Round2WorkerTranscriptHash,
  frostDkgV2RosterHash,
  lagrangeCoefficientsAtZero,
  mpccaWithdrawRound1WorkerTranscriptHash,
  parseCaRegistrationAggregateRequest,
  parseCaRegistrationAggregateResult,
  parseCaRegistrationChallengeRequest,
  parseCaRegistrationChallengeResult,
  parseCaRegistrationNonceCommitRequest,
  parseCaRegistrationNonceCommitResult,
  parseCaRegistrationPartialRequest,
  parseCaRegistrationPartialResult,
  parseCaRegistrationV2Round1Response,
  parseCaRegistrationV2Round2Response,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  parseDkgRoundRequest,
  parseDkgRoundResult,
  parseMpccaRoundRequest,
  parseMpccaRoundResult,
  parseMpccaWithdrawRound1Response,
  parseMpccaWithdrawSubmitRequest,
  parseObserveDepositResponse,
  parseSessionShareEnvelope,
  parseVaultEkContributions,
  parseVaultStateV2InitFinalizeResponse,
  parseVaultStateV2InitResponse,
  rosterHash,
  scalarHexFromBigint,
  UnderQuorumError,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
  VaultEkDerivationError,
  VaultStateV2InitError,
  VaultStateV2ObserveDepositError,
  vaultStateV2InitWorkerTranscriptHash,
  vaultStateV2ObserveWorkerTranscriptHash,
  type CaDkgV2Roster,
  type CaRegistrationV2Contribution,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
  type FrostRound1Broadcast,
  type FrostRound2Envelope,
  type MpccaWithdrawRound1Contribution,
  type ObserveDepositContribution,
  type SessionShareEnvelope,
  type VaultEkContribution,
  type VaultStateV2InitContribution,
} from "@eunoma/deop-protocol";
import { sha256, bytesToHex } from "@eunoma/shared";
import { HttpError, requireBearer } from "@eunoma/shared";
import {
  assembleWithdrawV2CallArgs,
  isNotImplementedPhasePassthrough,
  loadMpccaFinalizeTranscript,
  mpccaFinalizeTranscriptPath,
  waitForTx,
  type WithdrawV2CallArgsShape,
} from "@eunoma/shared";
import { assertNoForbiddenPlaintextFields } from "@eunoma/deop-protocol";
import { mkdir, rename, writeFile, chmod, readdir, readFile, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { InMemoryCoordinatorStore, type CoordinatorStore } from "./store.js";

/**
 * Codex M2a P2 #3: safe-id sanitiser for caller-supplied identifiers that the coordinator
 * embeds in filesystem paths.
 *
 * The Rust worker rejects unsafe ids before writing its own files (see
 * `mpc_spdz_adapter::is_safe_id`), but the COORDINATOR should not depend on worker success
 * for its own filesystem hygiene. A worker that returns matching public hashes can let a
 * caller-controlled `requestId` containing path separators (e.g. `../../etc/passwd`) or
 * null bytes influence where the coordinator writes its transcript artifact.
 *
 * Allowed: ASCII alphanumeric plus `.`, `_`, `-`. Length: 1..=128 bytes. Anything else —
 * `/`, `\`, `..`, null bytes, control chars, non-ASCII — is rejected.
 *
 * Mirrors the worker's `is_safe_id` byte-for-byte, with a length cap added (the worker
 * doesn't impose a length cap because its callers already cap the size of POSTed JSON,
 * but the coordinator builds these names directly into paths and we want a hard ceiling
 * to prevent `requestId = "a" * 1e9` blowing up the file system).
 */
const SAFE_ID_MAX_LEN = 128;
export function isSafeId(s: string): boolean {
  if (typeof s !== "string") return false;
  if (s.length === 0 || s.length > SAFE_ID_MAX_LEN) return false;
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    const isDigit = code >= 0x30 && code <= 0x39;
    const isLower = code >= 0x61 && code <= 0x7a;
    const isUpper = code >= 0x41 && code <= 0x5a;
    const isPunct = code === 0x2e || code === 0x5f || code === 0x2d; // . _ -
    if (!(isDigit || isLower || isUpper || isPunct)) return false;
  }
  return true;
}

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

/**
 * Milestone 5b — injectable relayer submitter for POST /v2/withdraw/mpcca/submit.
 *
 * The coordinator's submit route does NOT speak HTTP to the relayer directly in tests; the
 * test injects a `relayerSubmitter` that captures the assembled WithdrawV2CallArgs body and
 * returns a deterministic result. In production, configFromEnv wires up a fetch-backed
 * implementation pointing at RELAYER_URL with RELAYER_BEARER_TOKEN.
 *
 * The submitter returns the relayer's reply shape — `accepted`, `txHash`, `simulated`. Any
 * thrown error (relayer 5xx, network failure) is surfaced by the route as 502.
 */
export type RelayerWithdrawSubmitter = (
  args: WithdrawV2CallArgsShape,
) => Promise<{ accepted: boolean; txHash: string; simulated: boolean }>;

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
  /**
   * Milestone 5b: optional relayer submitter for POST /v2/withdraw/mpcca/submit. If absent,
   * the route returns 502 relayer_unreachable when invoked. Tests inject mocks.
   */
  relayerSubmitter?: RelayerWithdrawSubmitter;
  /**
   * Milestone 5b: Aptos fullnode URL for waitForTx polling. If absent, the route SKIPS chain
   * confirmation (simulated submits) and returns `completed: true, simulated: true` directly
   * after the relayer accepts.
   */
  chainNodeUrl?: string;
  /**
   * Milestone 5b: injectable fetch for waitForTx. Tests use this to feed deterministic
   * chain-confirmation responses without standing up a real Aptos node.
   */
  chainFetch?: typeof fetch;
  /**
   * Milestone 5b: timeout for waitForTx polling (default 30s).
   */
  chainConfirmationTimeoutMs?: number;
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

  // Milestone 1: separate session lock for /v2/derive/ca_registration/start. We keep it
  // distinct from the vault_ek lock because CA registration does NOT spawn MASCOT
  // subprocesses (no fixed-port collision) — concurrent CA registrations are safe
  // independent of in-flight vault_ek derivations. But we still want single-session-at-a-
  // time semantics inside the CA registration surface itself so two concurrent registrations
  // under the same vault_ek can't interleave round1/round2 files on the same workers.
  let caRegistrationV2InFlight: Promise<unknown> | null = null;
  const caRegistrationV2LockAcquireTimeoutMs = 100;
  async function acquireCaRegistrationV2Lock(): Promise<{ release: () => void } | "busy"> {
    const start = Date.now();
    while (caRegistrationV2InFlight !== null) {
      if (Date.now() - start > caRegistrationV2LockAcquireTimeoutMs) {
        return "busy";
      }
      try {
        await Promise.race([
          caRegistrationV2InFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // Holder failed; loop re-checks.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    caRegistrationV2InFlight = held;
    return {
      release: () => {
        caRegistrationV2InFlight = null;
        resolveHeld();
      },
    };
  }

  // Milestone 2a: separate session lock for /v2/vault_state/init. We keep it distinct from the
  // vault_ek and ca_registration locks: a fresh init under the same (vaultEk, registration)
  // pair against a different roster subset is a coordinator state-mutation we want serialized,
  // but it doesn't block in-flight derivations. The vault-state init writes to per-worker
  // `state_dir/vault_state_v2.json`; two concurrent initialisations for the SAME vault would
  // both write the same file, which is fine on the disk side (worker checks for byte-identical
  // contents) but produces ambiguous coordinator transcripts unless one wins. Single-session-
  // at-a-time semantics mirror the other V2 surfaces.
  let vaultStateV2InitInFlight: Promise<unknown> | null = null;
  const vaultStateV2InitLockAcquireTimeoutMs = 100;
  async function acquireVaultStateV2InitLock(): Promise<{ release: () => void } | "busy"> {
    const start = Date.now();
    while (vaultStateV2InitInFlight !== null) {
      if (Date.now() - start > vaultStateV2InitLockAcquireTimeoutMs) {
        return "busy";
      }
      try {
        await Promise.race([
          vaultStateV2InitInFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // Holder failed; loop re-checks.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    vaultStateV2InitInFlight = held;
    return {
      release: () => {
        vaultStateV2InitInFlight = null;
        resolveHeld();
      },
    };
  }

  // Milestone 2b: separate session lock for /v2/vault_state/observe_deposit. We keep it
  // distinct from the init lock because the observer + initializer are different operator
  // workflows that can run concurrently against each other. But TWO concurrent observe calls
  // for the SAME vault would race on the worker's cursor: both could pass `deposit_count > existing`
  // (strict), both could write the same new cursor, both could persist artifacts under DIFFERENT
  // requestIds. The serialization keeps the cursor monotonic across the orchestrator surface,
  // mirroring the strict monotonicity check on the worker itself.
  let vaultStateV2ObserveInFlight: Promise<unknown> | null = null;
  const vaultStateV2ObserveLockAcquireTimeoutMs = 100;
  async function acquireVaultStateV2ObserveLock(): Promise<{ release: () => void } | "busy"> {
    const start = Date.now();
    while (vaultStateV2ObserveInFlight !== null) {
      if (Date.now() - start > vaultStateV2ObserveLockAcquireTimeoutMs) {
        return "busy";
      }
      try {
        await Promise.race([
          vaultStateV2ObserveInFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // Holder failed; loop re-checks.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    vaultStateV2ObserveInFlight = held;
    return {
      release: () => {
        vaultStateV2ObserveInFlight = null;
        resolveHeld();
      },
    };
  }

  // Milestone 3a: separate session lock for /v2/withdraw/mpcca/start. The MPCCA withdraw is a
  // multi-round state machine that mutates per-worker session state files at every round; a
  // concurrent in-flight withdraw against the SAME vault would race on the round-N session
  // file paths (which are keyed by requestId + sessionId, both caller-supplied). Lock keeps
  // single-session-at-a-time semantics across the entire 4-round transaction.
  let vaultMpccaWithdrawInFlight: Promise<unknown> | null = null;
  const vaultMpccaWithdrawLockAcquireTimeoutMs = 100;
  async function acquireVaultMpccaWithdrawLock(): Promise<{ release: () => void } | "busy"> {
    const start = Date.now();
    while (vaultMpccaWithdrawInFlight !== null) {
      if (Date.now() - start > vaultMpccaWithdrawLockAcquireTimeoutMs) {
        return "busy";
      }
      try {
        await Promise.race([
          vaultMpccaWithdrawInFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // Holder failed; loop re-checks.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    vaultMpccaWithdrawInFlight = held;
    return {
      release: () => {
        vaultMpccaWithdrawInFlight = null;
        resolveHeld();
      },
    };
  }

  // Milestone 5b: separate session lock for /v2/withdraw/mpcca/submit. We keep it distinct
  // from the round1 lock because the two routes operate on different artifacts (round1 lock
  // protects the 4-round state machine; submit lock protects the chain-submission pipeline +
  // the persisted submit-transcript artifact). A submit concurrent with a withdraw start is
  // SAFE — they're disjoint phases — but two concurrent submits for the same (dkgEpoch,
  // requestId) would race on the persisted artifact path.
  let vaultMpccaWithdrawSubmitInFlight: Promise<unknown> | null = null;
  const vaultMpccaWithdrawSubmitLockAcquireTimeoutMs = 100;
  async function acquireVaultMpccaWithdrawSubmitLock(): Promise<
    { release: () => void } | "busy"
  > {
    const start = Date.now();
    while (vaultMpccaWithdrawSubmitInFlight !== null) {
      if (Date.now() - start > vaultMpccaWithdrawSubmitLockAcquireTimeoutMs) {
        return "busy";
      }
      try {
        await Promise.race([
          vaultMpccaWithdrawSubmitInFlight,
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      } catch {
        // Holder failed; loop re-checks.
      }
    }
    let resolveHeld: (value: void) => void = () => {};
    const held = new Promise<void>((resolve) => {
      resolveHeld = resolve;
    });
    vaultMpccaWithdrawSubmitInFlight = held;
    return {
      release: () => {
        vaultMpccaWithdrawSubmitInFlight = null;
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
      // Codex M2a P2 #3: sanitise caller-supplied requestId BEFORE acquiring any lock,
      // touching the provenance scan, or constructing any FS path. Reject with 400 so
      // the caller knows the requestId was the problem (NOT a 500 / silent rejection).
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }
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

  // =============================================================================================
  // Milestone 1: V2 threshold CA registration sigma orchestrator.
  //
  // Flow:
  //   1. Validate request body + roster + selectedSlots (lowest-5 by default; selectedSlots
  //      override allowed for failover/recovery — strict 5-of-7 over current CA DKG V2 roster).
  //   2. Acquire CA-registration-specific session lock; 409 on contention.
  //   3. Round1 fan-out (Promise.all over 5 selected slots):
  //      POST /worker/v2/derive/ca_registration/round1 to each slot's deop-node.
  //      Each worker draws r_i, persists nonce file (0o600), returns
  //      `(commitmentHex, commitmentHash, nonceId, workerTranscriptHash)`.
  //   4. Aggregate-commitments + challenge: hit the verifier-slot worker's
  //      `/worker/v2/derive/ca_registration/challenge` route — share-independent public
  //      compute that returns `(aggregateCommitment, challenge)` only. We need the
  //      challenge BEFORE round2; the full `/aggregate` route also runs verify, which
  //      requires responses we don't have yet. Then round2 fan-out, then the FINAL
  //      aggregate-and-verify call. (Codex P1 #2: this used to call the V1
  //      `/worker/v2/ca/registration/challenge` route, which was not in the deop-node
  //      allowlist — fixed by adding a V2-shaped `/worker/v2/derive/ca_registration/challenge`
  //      route on the worker + deop-node passthrough.)
  //   5. Round2 fan-out with the challenge → 5 responses.
  //   6. Final aggregate-and-verify via `/worker/v2/derive/ca_registration/aggregate` (does
  //      Lagrange on commitments + responses + Fiat-Shamir challenge + verify in one shot).
  //   7. Persist transcript artifact under `state_root/coordinator/ca_registration_v2/`
  //      atomically with mode 0o600.
  //   8. Return `{ requestId, dkgEpoch, vaultEk, aggregateCommitment, aggregateResponse,
  //      challenge, transcriptHash, transcriptPath }`.
  //
  // Failure modes (per acceptance criteria):
  //   - 409 ca_registration_v2_in_flight (lock contention)
  //   - 400 forbidden_plaintext_field / under_quorum / duplicate_slot / etc.
  //   - 502 round1_forward_failed / round2_forward_failed / aggregate_forward_failed
  //   - 502 aggregate_proof_invalid (verify equation fails — public algebra disagreement)
  // =============================================================================================
  server.post("/v2/derive/ca_registration/start", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);

      const dkgEpoch =
        typeof raw.dkgEpoch === "string" && raw.dkgEpoch.length > 0 ? raw.dkgEpoch : undefined;
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
            "caDkgTranscriptHash is required; supply the value from the CA DKG V2 artifact",
        });
      }
      const vaultEk = raw.vaultEk;
      if (typeof vaultEk !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(vaultEk)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultEk must be a 32-byte hex string (Phase 2-derived public point)",
        });
      }
      const senderAddress = raw.senderAddress;
      if (
        typeof senderAddress !== "string" ||
        !/^(0x)?[0-9a-fA-F]{64}$/.test(senderAddress)
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "senderAddress must be a 32-byte hex string",
        });
      }
      const assetType = raw.assetType;
      if (typeof assetType !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(assetType)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "assetType must be a 32-byte hex string",
        });
      }
      const chainIdRaw = raw.chainId;
      if (
        !Number.isInteger(chainIdRaw) ||
        (chainIdRaw as number) < 0 ||
        (chainIdRaw as number) > 255
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "chainId must be a u8",
        });
      }
      const chainId = chainIdRaw as number;

      requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `ca-registration-v2-${Date.now()}`;
      // Codex M2a P2 #3: sanitise caller-supplied requestId BEFORE acquiring any lock,
      // touching the provenance scan, or constructing any FS path.
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }

      // Slot selection: either caller-supplied (validated against current roster) or
      // coordinator-chosen lowest 5. Both shapes feed the same downstream pipeline.
      let selectedSlots: number[];
      let selectionRationale: "caller-supplied" | "coordinator-chosen";
      if (raw.selectedSlots !== undefined) {
        if (
          !Array.isArray(raw.selectedSlots) ||
          raw.selectedSlots.length !== DEOPERATOR_THRESHOLD
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
          });
        }
        const seen = new Set<number>();
        const arr: number[] = [];
        for (const slot of raw.selectedSlots) {
          if (
            !Number.isInteger(slot) ||
            (slot as number) < 0 ||
            (slot as number) >= DEOPERATOR_COUNT
          ) {
            return reply.code(400).send({
              error: "invalid_request",
              message: `selectedSlots entry ${slot} out of range`,
            });
          }
          if (seen.has(slot as number)) {
            return reply.code(400).send({
              error: "duplicate_slot",
              message: `duplicate selectedSlots entry ${slot}`,
            });
          }
          seen.add(slot as number);
          arr.push(slot as number);
        }
        const rosterSlots = new Set(dkgRoster.nodes.map((node) => node.slot));
        for (const slot of arr) {
          if (!rosterSlots.has(slot)) {
            return reply.code(400).send({
              error: "unknown_slot",
              message: `selectedSlots entry ${slot} is not in caDkgV2Roster`,
            });
          }
        }
        selectedSlots = arr;
        selectionRationale = "caller-supplied";
      } else {
        selectedSlots = lowestEligibleSlots(dkgRoster, DEOPERATOR_THRESHOLD);
        selectionRationale = "coordinator-chosen";
      }
      const sortedSelectedSlots = [...selectedSlots].sort((a, b) => a - b);
      const sessionId = requestId;

      // Codex P2 #1: verify vaultEk provenance BEFORE acquiring the session lock and
      // BEFORE fanning out to workers. A stale/forged vaultEk would otherwise burn five
      // workers' nonces and only fail at the aggregate check. We require an opt-in
      // `vaultEkTranscriptHash` in the request body for the strongest binding; when not
      // supplied, we scan the coordinator's persisted Phase 2 transcripts at
      // `<stateRoot>/coordinator/vault_ek_derivation/` for a matching
      // (dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash) tuple. When `stateRoot` is
      // not configured (test/dev mode without persistence) we skip the check — same as
      // Phase 2 itself, which only persists transcripts under stateRoot.
      const claimedVaultEkTranscriptHash =
        typeof raw.vaultEkTranscriptHash === "string" && raw.vaultEkTranscriptHash.length > 0
          ? raw.vaultEkTranscriptHash
          : undefined;
      let vaultEkTranscriptHash: string | undefined;
      let vaultEkTranscriptPath: string | undefined;
      if (opts.stateRoot) {
        const provenance = await findVaultEkProvenance(opts.stateRoot, {
          dkgEpoch,
          vaultEk,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
        });
        if (!provenance) {
          return reply.code(400).send({
            error: "vault_ek_provenance_unknown",
            requestId,
            message:
              "no persisted Phase 2 vault_ek_derivation transcript matches the supplied " +
              "(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash). Run /v2/derive/vault_ek/start " +
              "first or supply a vaultEk that the coordinator produced.",
          });
        }
        // If the caller pinned a specific transcript hash, the persisted match must agree.
        if (
          claimedVaultEkTranscriptHash &&
          claimedVaultEkTranscriptHash.replace(/^0x/i, "").toLowerCase() !==
            provenance.vaultEkTranscriptHash.replace(/^0x/i, "").toLowerCase()
        ) {
          return reply.code(400).send({
            error: "vault_ek_provenance_mismatch",
            requestId,
            message:
              "vaultEkTranscriptHash supplied in the request does not match the persisted " +
              "Phase 2 transcript that produced this vaultEk",
            expected: provenance.vaultEkTranscriptHash,
            received: claimedVaultEkTranscriptHash,
          });
        }
        vaultEkTranscriptHash = provenance.vaultEkTranscriptHash;
        vaultEkTranscriptPath = provenance.transcriptPath;
      } else if (claimedVaultEkTranscriptHash) {
        // No stateRoot persistence but the caller still pinned a hash — accept it
        // verbatim (test/dev paths). Production deployments always configure stateRoot.
        vaultEkTranscriptHash = claimedVaultEkTranscriptHash;
      }

      const lock = await acquireCaRegistrationV2Lock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "ca_registration_v2_in_flight",
          requestId,
          message: "another ca_registration_v2 session is in progress; retry shortly",
        });
      }

      try {
        // ---------- Round 1: nonce-commit fan-out (concurrent) ----------
        const round1Bodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
        }));
        const round1Forwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/derive/ca_registration/round1",
              round1Bodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        const round1ResponsesBySlot = new Map<number, ReturnType<typeof parseCaRegistrationV2Round1Response>>();
        for (const res of round1Forwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "round1_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (!res.value.ok || !res.value.body) {
            return reply.code(502).send({
              error: "round1_forward_failed",
              slot: res.slot,
              statusCode: res.value.statusCode,
              body: res.value.body,
              requestId,
            });
          }
          let parsed;
          try {
            parsed = parseCaRegistrationV2Round1Response(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "round1_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          // Defense in depth: cross-check worker_transcript_hash matches our TS-side reconstruction.
          const expectedWorkerHash = caRegistrationV2Round1WorkerTranscriptHash({
            sessionId,
            requestId: requestId!,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashInput,
            rosterHash: dkgRosterHash,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitmentHex: parsed.commitmentHex,
            nonceId: parsed.nonceId,
          });
          if (parsed.workerTranscriptHash !== expectedWorkerHash) {
            return reply.code(502).send({
              error: "round1_worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedWorkerHash,
              actual: parsed.workerTranscriptHash,
            });
          }
          round1ResponsesBySlot.set(res.slot, parsed);
        }

        // ---------- Compute aggregate commitment + challenge ----------
        // Codex P1 #2: the coordinator was calling `/worker/v2/ca/registration/challenge`
        // (a V1 route) but the deop-node only allowlists `/worker/v2/derive/*` paths, so
        // every production V2 session stalled before round2 with a 404. Fix: call the new
        // V2 interim aggregator `/worker/v2/derive/ca_registration/challenge`, which lives
        // under the same prefix the deop-node already passes through. Share-independent
        // public compute over published commitments — identical math as the V1 helper,
        // just exposed under the V2 path.
        const verifierSlot = sortedSelectedSlots[0];
        const commitmentsForAggregate = sortedSelectedSlots.map((slot) => ({
          slot,
          commitment: round1ResponsesBySlot.get(slot)!.commitmentHex,
        }));
        const challengeForwarded = await singleNodeForwarder(
          "/worker/v2/derive/ca_registration/challenge",
          {
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitments: commitmentsForAggregate,
          },
          dkgRoster,
          verifierSlot,
        );
        if (!challengeForwarded.ok || !challengeForwarded.body) {
          return reply.code(502).send({
            error: "challenge_forward_failed",
            slot: verifierSlot,
            statusCode: challengeForwarded.statusCode,
            body: challengeForwarded.body,
            requestId,
          });
        }
        const challengeBody = challengeForwarded.body as Record<string, unknown>;
        const aggregateCommitmentInterim =
          typeof challengeBody.aggregateCommitment === "string"
            ? challengeBody.aggregateCommitment
            : undefined;
        const challenge =
          typeof challengeBody.challenge === "string" ? challengeBody.challenge : undefined;
        if (!aggregateCommitmentInterim || !challenge) {
          return reply.code(502).send({
            error: "challenge_returned_incomplete",
            slot: verifierSlot,
            requestId,
          });
        }

        // ---------- Round 2: partial-response fan-out (concurrent) ----------
        const round2Bodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          nonceId: round1ResponsesBySlot.get(slot)!.nonceId,
          challenge,
        }));
        const round2Forwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/derive/ca_registration/round2",
              round2Bodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        const round2ResponsesBySlot = new Map<number, ReturnType<typeof parseCaRegistrationV2Round2Response>>();
        for (const res of round2Forwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "round2_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (!res.value.ok || !res.value.body) {
            return reply.code(502).send({
              error: "round2_forward_failed",
              slot: res.slot,
              statusCode: res.value.statusCode,
              body: res.value.body,
              requestId,
            });
          }
          let parsed;
          try {
            parsed = parseCaRegistrationV2Round2Response(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "round2_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          const expectedWorkerHash = caRegistrationV2Round2WorkerTranscriptHash({
            sessionId,
            requestId: requestId!,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashInput,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            nonceId: round1ResponsesBySlot.get(res.slot)!.nonceId,
            challenge,
            responseHash: parsed.responseHash,
          });
          if (parsed.workerTranscriptHash !== expectedWorkerHash) {
            return reply.code(502).send({
              error: "round2_worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedWorkerHash,
              actual: parsed.workerTranscriptHash,
            });
          }
          round2ResponsesBySlot.set(res.slot, parsed);
        }

        // ---------- Final aggregate + verify ----------
        const responsesForAggregate = sortedSelectedSlots.map((slot) => ({
          slot,
          response: round2ResponsesBySlot.get(slot)!.responseHex,
        }));
        const aggregateForwarded = await singleNodeForwarder(
          "/worker/v2/derive/ca_registration/aggregate",
          {
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            commitments: commitmentsForAggregate,
            responses: responsesForAggregate,
          },
          dkgRoster,
          verifierSlot,
        );
        if (!aggregateForwarded.ok || !aggregateForwarded.body) {
          // The worker returns a non-200 specifically on `verify_registration_proof`
          // failure (the public equation didn't hold). Map this to 502
          // aggregate_proof_invalid for the operator-runbook contract.
          const body = aggregateForwarded.body as Record<string, unknown> | undefined;
          if (
            body &&
            typeof body.message === "string" &&
            body.message.includes("registration sigma proof verification failed")
          ) {
            return reply.code(502).send({
              error: "aggregate_proof_invalid",
              slot: verifierSlot,
              requestId,
              message: body.message,
            });
          }
          return reply.code(502).send({
            error: "aggregate_forward_failed",
            slot: verifierSlot,
            statusCode: aggregateForwarded.statusCode,
            body: aggregateForwarded.body,
            requestId,
          });
        }
        const aggregateBody = aggregateForwarded.body as Record<string, unknown>;
        const aggregateCommitment =
          typeof aggregateBody.aggregateCommitment === "string"
            ? aggregateBody.aggregateCommitment
            : undefined;
        const aggregateResponse =
          typeof aggregateBody.aggregateResponse === "string"
            ? aggregateBody.aggregateResponse
            : undefined;
        const aggregateChallenge =
          typeof aggregateBody.challenge === "string" ? aggregateBody.challenge : undefined;
        if (!aggregateCommitment || !aggregateResponse || !aggregateChallenge) {
          return reply.code(502).send({
            error: "aggregate_returned_incomplete",
            slot: verifierSlot,
            requestId,
          });
        }
        // Cross-check: aggregate commitment + challenge from round-2-prep must match the
        // values from the final aggregate call. If they differ, the verifier worker
        // disagreed with itself between calls — fail closed.
        if (
          aggregateCommitment.toLowerCase() !== aggregateCommitmentInterim.toLowerCase()
        ) {
          return reply.code(502).send({
            error: "aggregate_commitment_mismatch_between_calls",
            requestId,
            interim: aggregateCommitmentInterim,
            final: aggregateCommitment,
          });
        }
        if (aggregateChallenge.toLowerCase() !== challenge.toLowerCase()) {
          return reply.code(502).send({
            error: "challenge_mismatch_between_calls",
            requestId,
            interim: challenge,
            final: aggregateChallenge,
          });
        }

        // ---------- Build + persist transcript artifact ----------
        const perSlotContributions: CaRegistrationV2Contribution[] = sortedSelectedSlots.map(
          (slot) => ({
            slot,
            commitmentHex: round1ResponsesBySlot.get(slot)!.commitmentHex,
            responseHex: round2ResponsesBySlot.get(slot)!.responseHex,
            workerRound1TranscriptHash: round1ResponsesBySlot.get(slot)!.workerTranscriptHash,
            workerRound2TranscriptHash: round2ResponsesBySlot.get(slot)!.workerTranscriptHash,
          }),
        );
        const transcript = assembleCaRegistrationV2Transcript({
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          verifierSlot,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          perSlotContributions,
        });
        const transcriptArtifact = {
          ...transcript,
          selectionRationale,
          requestId,
          // Codex P2 #1: cross-reference the Phase 2 transcript that produced this
          // vaultEk. Auditors can replay-verify by reading this hash + opening
          // `<stateRoot>/coordinator/vault_ek_derivation/*.json` for the matching artifact.
          vaultEkTranscriptHash,
          vaultEkTranscriptPath,
          createdAtUnixMs: Date.now(),
        };

        let transcriptPath: string | undefined;
        if (opts.stateRoot) {
          const dir = join(opts.stateRoot, "coordinator", "ca_registration_v2");
          transcriptPath = join(dir, `${dkgEpoch}__${requestId}.json`);
          await writeTranscriptArtifactAtomic(transcriptPath, transcriptArtifact);
        }
        await store.recordPartialArtifact({
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          slot: verifierSlot,
          artifactKind: "ca-registration",
          artifactHash: transcript.transcriptHash,
          transcriptHash: transcript.transcriptHash,
        });
        await store.markComplete(requestId);

        return reply.code(200).send({
          accepted: true,
          requestId,
          dkgEpoch,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selectionRationale,
          verifierSlot,
          vaultEk,
          vaultEkTranscriptHash,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          transcriptHash: transcript.transcriptHash,
          transcriptPath,
        });
      } finally {
        lock.release();
      }
    } catch (err) {
      if (requestId) await store.markAborted(requestId);
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof CaRegistrationV2Error) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // =============================================================================================
  // Milestone 2 sub-milestone 2a: vault-state share initialization orchestrator.
  //
  // Flow:
  //   1. Parse + validate request body (forbidden-field guard, decimal dkgEpoch, hex shape).
  //   2. Look up Phase 2 transcript by (dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash). If
  //      stateRoot is configured and no match → 400 vault_ek_provenance_unknown (mirrors the
  //      Milestone 1 check; same operator runbook).
  //   3. Look up Milestone 1 ca_registration_v2 transcript by (dkgEpoch, vaultEk, rosterHash,
  //      caDkgTranscriptHash). If stateRoot is configured and no match → 400
  //      ca_registration_provenance_unknown. Extract `aggregateCommitment`, `aggregateResponse`,
  //      `challenge`, `transcriptHash` so the caller doesn't have to pass them (the coordinator
  //      already produced them).
  //   4. Acquire session lock (409 vault_state_v2_init_in_flight on contention).
  //   5. Fan-out `/worker/v2/vault_state/init` to all 5 selectedSlots concurrently. Cross-check
  //      each worker's `workerTranscriptHash` against the TS-side reconstruction.
  //   6. Assemble + persist the transcript artifact at
  //      `state_root/coordinator/vault_state_v2/<dkgEpoch>__<requestId>.json` (atomic 0o600).
  //   7. Return { accepted, requestId, dkgEpoch, vaultEk, vaultEkTranscriptHash,
  //      registrationTranscriptHash, perSlotContributions, transcriptHash, transcriptPath }.
  //
  // Failure modes:
  //   - 400 forbidden_plaintext_field / under_quorum / duplicate_slot / unknown_slot
  //   - 400 vault_ek_provenance_unknown / ca_registration_provenance_unknown
  //   - 400 vault_ek_provenance_mismatch / ca_registration_provenance_mismatch
  //   - 409 vault_state_v2_init_in_flight (lock contention)
  //   - 502 init_forward_rejected / init_forward_failed / init_returned_invalid
  //   - 502 worker_transcript_hash_mismatch
  // =============================================================================================
  server.post("/v2/vault_state/init", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // Forbidden-plaintext-field guard runs FIRST on the raw body. Catches any extra fields
      // named secret/blind/dkShare/nullifier/etc. before any downstream code touches them.
      // Mirrors the ca_registration_v2 orchestrator pattern.
      assertNoForbiddenPlaintextFields(raw);
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);

      const dkgEpoch =
        typeof raw.dkgEpoch === "string" && raw.dkgEpoch.length > 0 ? raw.dkgEpoch : undefined;
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
            "caDkgTranscriptHash is required; supply the value from the CA DKG V2 artifact",
        });
      }
      const vaultEk = raw.vaultEk;
      if (typeof vaultEk !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(vaultEk)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultEk must be a 32-byte hex string (Phase 2-derived public point)",
        });
      }
      const senderAddress = raw.senderAddress;
      if (
        typeof senderAddress !== "string" ||
        !/^(0x)?[0-9a-fA-F]{64}$/.test(senderAddress)
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "senderAddress must be a 32-byte hex string",
        });
      }
      const assetType = raw.assetType;
      if (typeof assetType !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(assetType)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "assetType must be a 32-byte hex string",
        });
      }
      const chainIdRaw = raw.chainId;
      if (
        !Number.isInteger(chainIdRaw) ||
        (chainIdRaw as number) < 0 ||
        (chainIdRaw as number) > 255
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "chainId must be a u8",
        });
      }
      const chainId = chainIdRaw as number;

      requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `vault-state-v2-${Date.now()}`;
      // Codex M2a P2 #3: sanitise caller-supplied requestId BEFORE acquiring any lock,
      // touching the provenance scan, or constructing any FS path.
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }

      // Slot selection: same shape as ca_registration_v2. Default to lowest-5; caller may
      // override for failover/recovery. Note that in production the Milestone 1 transcript
      // already pins the selectedSlots that ran the sigma — if the operator wants the SAME
      // 5-of-7 to hold per-worker state (best practice), they should pass that subset here.
      // We don't enforce equality though: a vault can legitimately be served by a 5-of-7
      // subset different from the one that ran the registration sigma, as long as the new
      // subset's workers all hold valid ca_dkg_share_v2 entries.
      let selectedSlots: number[];
      let selectionRationale: "caller-supplied" | "coordinator-chosen";
      if (raw.selectedSlots !== undefined) {
        if (
          !Array.isArray(raw.selectedSlots) ||
          raw.selectedSlots.length !== DEOPERATOR_THRESHOLD
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `selectedSlots must have ${DEOPERATOR_THRESHOLD} entries`,
          });
        }
        const seen = new Set<number>();
        const arr: number[] = [];
        for (const slot of raw.selectedSlots) {
          if (
            !Number.isInteger(slot) ||
            (slot as number) < 0 ||
            (slot as number) >= DEOPERATOR_COUNT
          ) {
            return reply.code(400).send({
              error: "invalid_request",
              message: `selectedSlots entry ${slot} out of range`,
            });
          }
          if (seen.has(slot as number)) {
            return reply.code(400).send({
              error: "duplicate_slot",
              message: `duplicate selectedSlots entry ${slot}`,
            });
          }
          seen.add(slot as number);
          arr.push(slot as number);
        }
        const rosterSlots = new Set(dkgRoster.nodes.map((node) => node.slot));
        for (const slot of arr) {
          if (!rosterSlots.has(slot)) {
            return reply.code(400).send({
              error: "unknown_slot",
              message: `selectedSlots entry ${slot} is not in caDkgV2Roster`,
            });
          }
        }
        selectedSlots = arr;
        selectionRationale = "caller-supplied";
      } else {
        selectedSlots = lowestEligibleSlots(dkgRoster, DEOPERATOR_THRESHOLD);
        selectionRationale = "coordinator-chosen";
      }
      const sortedSelectedSlots = [...selectedSlots].sort((a, b) => a - b);
      const sessionId = requestId;

      // Provenance: cross-reference both Phase 2 (vault_ek) and Milestone 1 (registration)
      // transcripts BEFORE acquiring the lock or fanning out. A bad request fails closed at
      // ~2 disk reads.
      const claimedVaultEkTranscriptHash =
        typeof raw.vaultEkTranscriptHash === "string" && raw.vaultEkTranscriptHash.length > 0
          ? raw.vaultEkTranscriptHash
          : undefined;
      let vaultEkTranscriptHash: string | undefined;
      let vaultEkTranscriptPath: string | undefined;
      if (opts.stateRoot) {
        const provenance = await findVaultEkProvenance(opts.stateRoot, {
          dkgEpoch,
          vaultEk,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
        });
        if (!provenance) {
          return reply.code(400).send({
            error: "vault_ek_provenance_unknown",
            requestId,
            message:
              "no persisted Phase 2 vault_ek_derivation transcript matches the supplied " +
              "(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash). Run /v2/derive/vault_ek/start " +
              "first or supply a vaultEk that the coordinator produced.",
          });
        }
        if (
          claimedVaultEkTranscriptHash &&
          claimedVaultEkTranscriptHash.replace(/^0x/i, "").toLowerCase() !==
            provenance.vaultEkTranscriptHash.replace(/^0x/i, "").toLowerCase()
        ) {
          return reply.code(400).send({
            error: "vault_ek_provenance_mismatch",
            requestId,
            message:
              "vaultEkTranscriptHash supplied in the request does not match the persisted " +
              "Phase 2 transcript that produced this vaultEk",
            expected: provenance.vaultEkTranscriptHash,
            received: claimedVaultEkTranscriptHash,
          });
        }
        vaultEkTranscriptHash = provenance.vaultEkTranscriptHash;
        vaultEkTranscriptPath = provenance.transcriptPath;
      } else if (claimedVaultEkTranscriptHash) {
        vaultEkTranscriptHash = claimedVaultEkTranscriptHash;
      }

      // Milestone 1 (CA registration) provenance. Same shape as Phase 2 — scan
      // `<stateRoot>/coordinator/ca_registration_v2/` for a transcript whose
      // (dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType,
      // chainId) tuple matches. The matched transcript supplies the sigma tuple
      // (aggregateCommitment, aggregateResponse, challenge) we forward to every worker.
      const claimedRegistrationTranscriptHash =
        typeof raw.registrationTranscriptHash === "string" &&
        raw.registrationTranscriptHash.length > 0
          ? raw.registrationTranscriptHash
          : undefined;
      let registrationTranscriptHash: string | undefined;
      let registrationTranscriptPath: string | undefined;
      let aggregateCommitment: string | undefined;
      let aggregateResponse: string | undefined;
      let challenge: string | undefined;
      let registrationVerifierSlot: number | undefined;
      if (opts.stateRoot) {
        const provenance = await findCaRegistrationV2Provenance(opts.stateRoot, {
          dkgEpoch,
          vaultEk,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          senderAddress,
          assetType,
          chainId,
        });
        if (!provenance) {
          return reply.code(400).send({
            error: "ca_registration_provenance_unknown",
            requestId,
            message:
              "no persisted Milestone 1 ca_registration_v2 transcript matches the supplied " +
              "(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType, chainId). " +
              "Run /v2/derive/ca_registration/start first.",
          });
        }
        if (
          claimedRegistrationTranscriptHash &&
          claimedRegistrationTranscriptHash.replace(/^0x/i, "").toLowerCase() !==
            provenance.registrationTranscriptHash.replace(/^0x/i, "").toLowerCase()
        ) {
          return reply.code(400).send({
            error: "ca_registration_provenance_mismatch",
            requestId,
            message:
              "registrationTranscriptHash supplied in the request does not match the persisted " +
              "Milestone 1 transcript",
            expected: provenance.registrationTranscriptHash,
            received: claimedRegistrationTranscriptHash,
          });
        }
        registrationTranscriptHash = provenance.registrationTranscriptHash;
        registrationTranscriptPath = provenance.transcriptPath;
        aggregateCommitment = provenance.aggregateCommitment;
        aggregateResponse = provenance.aggregateResponse;
        challenge = provenance.challenge;
        registrationVerifierSlot = provenance.verifierSlot;
      } else {
        // No stateRoot — caller MUST supply the sigma tuple inline. Same shape as Phase 2
        // dev/test fallback.
        if (
          typeof raw.aggregateCommitment !== "string" ||
          typeof raw.aggregateResponse !== "string" ||
          typeof raw.challenge !== "string" ||
          !claimedRegistrationTranscriptHash
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message:
              "stateRoot is not configured; caller must supply aggregateCommitment, aggregateResponse, " +
              "challenge, and registrationTranscriptHash inline",
          });
        }
        aggregateCommitment = raw.aggregateCommitment;
        aggregateResponse = raw.aggregateResponse;
        challenge = raw.challenge;
        registrationTranscriptHash = claimedRegistrationTranscriptHash;
      }
      if (!vaultEkTranscriptHash || !registrationTranscriptHash) {
        return reply.code(400).send({
          error: "invalid_request",
          message:
            "vaultEkTranscriptHash and registrationTranscriptHash are required (supply " +
            "inline OR configure stateRoot to derive them from persisted transcripts)",
        });
      }
      if (!aggregateCommitment || !aggregateResponse || !challenge) {
        return reply.code(400).send({
          error: "invalid_request",
          message:
            "aggregateCommitment, aggregateResponse, and challenge are required (supply " +
            "inline OR configure stateRoot to derive them from the Milestone 1 transcript)",
        });
      }

      const lock = await acquireVaultStateV2InitLock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "vault_state_v2_init_in_flight",
          requestId,
          message: "another vault_state_v2 init session is in progress; retry shortly",
        });
      }

      try {
        // Fan out to all 5 selected slots concurrently. Each worker writes
        // `state_dir/vault_state_v2.json` and returns
        // (slot, playerId, vaultStatePath, vaultStateHash, workerTranscriptHash,
        //  vaultSequence, depositCountObserved, createdAtUnixMs, initialized).
        const initBodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
        }));
        const forwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/vault_state/init",
              initBodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        const responsesBySlot = new Map<number, ReturnType<typeof parseVaultStateV2InitResponse>>();
        for (const res of forwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "init_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (!res.value.ok || !res.value.body) {
            return reply.code(502).send({
              error: "init_forward_failed",
              slot: res.slot,
              statusCode: res.value.statusCode,
              body: res.value.body,
              requestId,
            });
          }
          let parsed;
          try {
            parsed = parseVaultStateV2InitResponse(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "init_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          // Defense in depth: re-derive the worker transcript hash from public inputs and
          // assert byte-equality with the worker's claim. Cuts off the "wrong slot replied"
          // and "tampered transcript" paths even if a deop-node was tricked.
          const expectedWorkerHash = vaultStateV2InitWorkerTranscriptHash({
            sessionId,
            requestId: requestId!,
            dkgEpoch,
            caDkgTranscriptHash: caDkgTranscriptHashInput,
            vaultEkTranscriptHash,
            registrationTranscriptHash,
            rosterHash: dkgRosterHash,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            aggregateCommitment,
            aggregateResponse,
            challenge,
            vaultSequence: parsed.vaultSequence,
            depositCountObserved: parsed.depositCountObserved,
          });
          if (parsed.workerTranscriptHash !== expectedWorkerHash) {
            return reply.code(502).send({
              error: "worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedWorkerHash,
              actual: parsed.workerTranscriptHash,
            });
          }
          if (parsed.slot !== res.slot) {
            return reply.code(502).send({
              error: "init_returned_invalid",
              slot: res.slot,
              requestId,
              message: `worker returned slot ${parsed.slot} for selfSlot ${res.slot}`,
            });
          }
          responsesBySlot.set(res.slot, parsed);
        }

        const perSlotContributions: VaultStateV2InitContribution[] = sortedSelectedSlots.map(
          (slot) => {
            const r = responsesBySlot.get(slot)!;
            return {
              slot,
              vaultStateHash: r.vaultStateHash,
              workerTranscriptHash: r.workerTranscriptHash,
              vaultSequence: r.vaultSequence,
              depositCountObserved: r.depositCountObserved,
              initialized: r.initialized,
            };
          },
        );
        const transcript = assembleVaultStateV2InitTranscript({
          dkgEpoch,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          perSlotContributions,
        });
        // ===================================================================================
        // Codex M3a P1 (regression fix) — vault_state_v2 init finalize fan-out.
        //
        // The first fan-out collected per-slot init contributions. Each worker persisted
        // its OWN per-slot worker_transcript_hash as init_transcript_hash. But the
        // canonical value the MPCCA withdraw round1 binds against — and that the
        // coordinator's request body carries — is the FINAL transcript hash
        // (EUNOMA_VAULT_STATE_V2_FINAL_V1 domain over public inputs + sorted
        // contributions), computed by assembleVaultStateV2InitTranscript above.
        //
        // We MUST now fan out a finalize round so every worker re-derives the same final
        // hash, asserts byte-equality, and UPDATES its persisted init_transcript_hash to
        // the canonical value. Without this round, every coordinator-orchestrated MPCCA
        // withdraw will fail closed with vault_state_init_transcript_hash_mismatch even
        // though all upstream provenance gates passed.
        //
        // The finalize round is fail-closed: if ANY of the 5 workers rejects the finalize
        // call, we tear down with init_finalize_failed (502) and the init itself is treated
        // as not-yet-canonical. The store.markComplete call only runs after the finalize
        // round succeeds across all 5 workers.
        const finalizeBodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          perSlotContributions,
          finalTranscriptHash: transcript.transcriptHash,
        }));
        const finalizeForwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/vault_state/init/finalize",
              finalizeBodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        for (const res of finalizeForwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "init_finalize_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (!res.value.ok || !res.value.body) {
            return reply.code(502).send({
              error: "init_finalize_forward_failed",
              slot: res.slot,
              statusCode: res.value.statusCode,
              body: res.value.body,
              requestId,
            });
          }
          let parsedFinalize;
          try {
            parsedFinalize = parseVaultStateV2InitFinalizeResponse(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "init_finalize_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          // Defense in depth: worker's claimed `initTranscriptHash` MUST equal the
          // coordinator's computed final hash. A divergence here means the worker either
          // (a) didn't run the local re-derivation (impossible by worker code path), or
          // (b) the deop-node tampered the response on its way back.
          if (
            parsedFinalize.initTranscriptHash.replace(/^0x/i, "").toLowerCase() !==
            transcript.transcriptHash.replace(/^0x/i, "").toLowerCase()
          ) {
            return reply.code(502).send({
              error: "init_finalize_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: transcript.transcriptHash,
              actual: parsedFinalize.initTranscriptHash,
            });
          }
          if (parsedFinalize.slot !== res.slot) {
            return reply.code(502).send({
              error: "init_finalize_returned_invalid",
              slot: res.slot,
              requestId,
              message: `worker returned slot ${parsedFinalize.slot} for selfSlot ${res.slot}`,
            });
          }
        }
        const transcriptArtifact = {
          ...transcript,
          selectionRationale,
          requestId,
          vaultEkTranscriptPath,
          registrationTranscriptPath,
          registrationVerifierSlot,
          createdAtUnixMs: Date.now(),
        };

        let transcriptPath: string | undefined;
        if (opts.stateRoot) {
          const dir = join(opts.stateRoot, "coordinator", "vault_state_v2");
          transcriptPath = join(dir, `${dkgEpoch}__${requestId}.json`);
          await writeTranscriptArtifactAtomic(transcriptPath, transcriptArtifact);
        }
        // Persist per-slot rows in the coordinator's partial-artifact log. Same shape as
        // ca_registration and vault_ek — auditors can query
        // /v2/status/<requestId> after the call.
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          await store.recordPartialArtifact({
            requestId,
            sessionId,
            rosterHash: dkgRosterHash,
            slot,
            artifactKind: "vault-state-v2-init",
            artifactHash: r.vaultStateHash,
            transcriptHash: r.workerTranscriptHash,
          });
        }
        await store.markComplete(requestId);

        return reply.code(200).send({
          accepted: true,
          requestId,
          dkgEpoch,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selectionRationale,
          vaultEk,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          senderAddress,
          assetType,
          chainId,
          aggregateCommitment,
          aggregateResponse,
          challenge,
          perSlotContributions,
          transcriptHash: transcript.transcriptHash,
          transcriptPath,
        });
      } finally {
        lock.release();
      }
    } catch (err) {
      if (requestId) await store.markAborted(requestId);
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof VaultStateV2InitError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // =============================================================================================
  // Milestone 2 sub-milestone 2b: confirmed-deposit observer orchestrator.
  //
  // Flow:
  //   1. Forbidden-field guard on the raw body (catches extra amount*/blind*/secret*/dk*/share*/
  //      nullifier* fields before any downstream code touches them).
  //   2. Sanitize requestId via isSafeId before any FS path construction.
  //   3. Parse the 14 required fields: dkgEpoch, caDkgTranscriptHash (used to look up the
  //      Milestone 2a init transcript), vaultEk, senderAddress, assetType, chainId, depositCount
  //      (positive u64 the observer derives as sequenceNumber+1), commitment, amountTag,
  //      caPayloadHash, depositNonce, sequenceNumber, txVersion, eventGuid.
  //   4. Provenance gate: scan <stateRoot>/coordinator/vault_state_v2/ for the matching
  //      Milestone 2a init transcript (which itself binds Phase 2 + Milestone 1 transcripts).
  //      Extract selectedSlots + vaultEkTranscriptHash + registrationTranscriptHash from it. If
  //      not found → 400 vault_state_init_provenance_unknown.
  //   5. Acquire the observe lock (409 vault_state_v2_observe_in_flight on contention).
  //   6. Fan-out POST /worker/v2/vault_state/observe_deposit to all 5 selectedSlots concurrently.
  //   7. For each response: parseObserveDepositResponse, re-derive expectedWorkerHash via
  //      vaultStateV2ObserveWorkerTranscriptHash, byte-equality assert → 502
  //      worker_transcript_hash_mismatch.
  //   8. Cursor consistency: every worker's `depositCountObserved` MUST equal req.depositCount.
  //      Otherwise → 502 cursor_divergence.
  //   9. assemble + persist ObserveDepositTranscript at
  //      <stateRoot>/coordinator/vault_state_v2_observed/<dkgEpoch>__<depositCount>__<requestId>.json
  //      (atomic 0o600).
  //   10. Return { accepted, requestId, dkgEpoch, depositCount, vaultEk, perSlotContributions,
  //       transcriptHash, transcriptPath }.
  //
  // Failure modes:
  //   - 400 forbidden_plaintext_field / unsafe_request_id / under_quorum / duplicate_slot / unknown_slot
  //   - 400 invalid_request (malformed body)
  //   - 400 vault_state_init_provenance_unknown
  //   - 400 stale_dkg_epoch / stale_deposit_count
  //   - 409 vault_state_v2_observe_in_flight
  //   - 502 observe_forward_rejected / observe_forward_failed / observe_returned_invalid
  //   - 502 worker_transcript_hash_mismatch
  //   - 502 cursor_divergence
  // =============================================================================================
  server.post("/v2/vault_state/observe_deposit", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // Codex M2b P1 — forbidden-plaintext-field guard runs FIRST on the raw body.
      assertNoForbiddenPlaintextFields(raw);
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);

      const dkgEpoch =
        typeof raw.dkgEpoch === "string" && raw.dkgEpoch.length > 0 ? raw.dkgEpoch : undefined;
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
          error: "invalid_request",
          message:
            "caDkgTranscriptHash is required; supply the value from the CA DKG V2 artifact",
        });
      }
      const vaultEk = raw.vaultEk;
      if (typeof vaultEk !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(vaultEk)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultEk must be a 32-byte hex string",
        });
      }
      const senderAddress = raw.senderAddress;
      if (
        typeof senderAddress !== "string" ||
        !/^(0x)?[0-9a-fA-F]{64}$/.test(senderAddress)
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "senderAddress must be a 32-byte hex string",
        });
      }
      const assetType = raw.assetType;
      if (typeof assetType !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(assetType)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "assetType must be a 32-byte hex string",
        });
      }
      const chainIdRaw = raw.chainId;
      if (
        !Number.isInteger(chainIdRaw) ||
        (chainIdRaw as number) < 0 ||
        (chainIdRaw as number) > 255
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "chainId must be a u8",
        });
      }
      const chainId = chainIdRaw as number;
      const depositCountRaw = raw.depositCount;
      if (
        !Number.isInteger(depositCountRaw) ||
        (depositCountRaw as number) < 1
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "depositCount must be a positive integer (= sequenceNumber + 1)",
        });
      }
      const depositCount = depositCountRaw as number;
      const commitmentField = raw.commitment;
      const amountTagField = raw.amountTag;
      const caPayloadHashField = raw.caPayloadHash;
      const depositNonceField = raw.depositNonce;
      for (const [name, value] of [
        ["commitment", commitmentField],
        ["amountTag", amountTagField],
        ["caPayloadHash", caPayloadHashField],
        ["depositNonce", depositNonceField],
      ] as const) {
        if (typeof value !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(value)) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `${name} must be a 32-byte hex string`,
          });
        }
      }
      const commitment = commitmentField as string;
      const amountTag = amountTagField as string;
      const caPayloadHash = caPayloadHashField as string;
      const depositNonce = depositNonceField as string;
      const sequenceNumber = raw.sequenceNumber;
      const txVersion = raw.txVersion;
      const eventGuid = raw.eventGuid;
      if (typeof sequenceNumber !== "string" || !/^[0-9]+$/.test(sequenceNumber)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "sequenceNumber must be a non-empty decimal string",
        });
      }
      if (typeof txVersion !== "string" || !/^[0-9]+$/.test(txVersion)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "txVersion must be a non-empty decimal string",
        });
      }
      if (typeof eventGuid !== "string" || eventGuid.length === 0 || eventGuid.length > 256) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "eventGuid must be a non-empty string up to 256 chars",
        });
      }

      requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `vault-state-observe-${Date.now()}`;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }
      const sessionId = requestId;

      // Provenance gate: look up the Milestone 2a init transcript so we can lift the
      // (selectedSlots, vaultEkTranscriptHash, registrationTranscriptHash) without trusting
      // the caller's body. The init transcript itself binds Phase 2 + Milestone 1, so a
      // matching init transcript implies the entire chain of derivation prerequisites is in
      // place. No-stateRoot mode (dev/test) requires the caller to supply these inline.
      const claimedVaultEkTranscriptHash =
        typeof raw.vaultEkTranscriptHash === "string" && raw.vaultEkTranscriptHash.length > 0
          ? raw.vaultEkTranscriptHash
          : undefined;
      const claimedRegistrationTranscriptHash =
        typeof raw.registrationTranscriptHash === "string" &&
        raw.registrationTranscriptHash.length > 0
          ? raw.registrationTranscriptHash
          : undefined;
      const claimedSelectedSlots = Array.isArray(raw.selectedSlots)
        ? (raw.selectedSlots as unknown[])
        : undefined;
      let vaultEkTranscriptHash: string | undefined;
      let registrationTranscriptHash: string | undefined;
      let selectedSlots: number[] | undefined;
      let initTranscriptPath: string | undefined;
      if (opts.stateRoot) {
        const provenance = await findVaultStateV2InitProvenance(opts.stateRoot, {
          dkgEpoch,
          vaultEk,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          senderAddress,
          assetType,
          chainId,
        });
        if (!provenance) {
          return reply.code(400).send({
            error: "vault_state_init_provenance_unknown",
            requestId,
            message:
              "no persisted Milestone 2a vault_state_v2 init transcript matches the supplied " +
              "(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType, chainId). " +
              "Run /v2/vault_state/init first.",
          });
        }
        vaultEkTranscriptHash = provenance.vaultEkTranscriptHash;
        registrationTranscriptHash = provenance.registrationTranscriptHash;
        selectedSlots = provenance.selectedSlots;
        initTranscriptPath = provenance.transcriptPath;
      } else {
        if (
          !claimedVaultEkTranscriptHash ||
          !claimedRegistrationTranscriptHash ||
          !claimedSelectedSlots ||
          claimedSelectedSlots.length !== DEOPERATOR_THRESHOLD
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message:
              "stateRoot is not configured; caller must supply vaultEkTranscriptHash, " +
              "registrationTranscriptHash, and selectedSlots inline",
          });
        }
        const arr: number[] = [];
        const seen = new Set<number>();
        for (const slot of claimedSelectedSlots) {
          if (
            !Number.isInteger(slot) ||
            (slot as number) < 0 ||
            (slot as number) >= DEOPERATOR_COUNT
          ) {
            return reply.code(400).send({
              error: "invalid_request",
              message: `selectedSlots entry ${slot} out of range`,
            });
          }
          if (seen.has(slot as number)) {
            return reply.code(400).send({
              error: "duplicate_slot",
              message: `duplicate selectedSlots entry ${slot}`,
            });
          }
          seen.add(slot as number);
          arr.push(slot as number);
        }
        vaultEkTranscriptHash = claimedVaultEkTranscriptHash;
        registrationTranscriptHash = claimedRegistrationTranscriptHash;
        selectedSlots = arr;
      }
      if (!vaultEkTranscriptHash || !registrationTranscriptHash || !selectedSlots) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "internal: provenance fields unresolved",
        });
      }
      const sortedSelectedSlots = [...selectedSlots].sort((a, b) => a - b);

      const lock = await acquireVaultStateV2ObserveLock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "vault_state_v2_observe_in_flight",
          requestId,
          message:
            "another vault_state_v2 observe_deposit session is in progress; retry shortly",
        });
      }

      try {
        // Bound the observer-claimed `previousDepositCountObserved` to `depositCount - 1`. The
        // worker's strict-monotonicity check enforces this too, but capturing the convention
        // here lets the transcript hash bind a single canonical cursor delta per call.
        const previousDepositCountObserved = depositCount - 1;
        const newDepositCountObserved = depositCount;

        const observeBodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
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
          previousDepositCountObserved,
          newDepositCountObserved,
        }));

        // Concurrent fan-out (KILLER): all 5 worker calls launched before any completes. The
        // strict cursor-monotonicity check on the worker means concurrent in-flight observes
        // at the SAME cursor MUST not both succeed — but a coordinator-side serialisation
        // already prevents two observe calls from being in flight at once anyway.
        const forwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/vault_state/observe_deposit",
              observeBodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        const responsesBySlot = new Map<
          number,
          ReturnType<typeof parseObserveDepositResponse>
        >();
        for (const res of forwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "observe_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (!res.value.ok || !res.value.body) {
            return reply.code(502).send({
              error: "observe_forward_failed",
              slot: res.slot,
              statusCode: res.value.statusCode,
              body: res.value.body,
              requestId,
            });
          }
          let parsed;
          try {
            parsed = parseObserveDepositResponse(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "observe_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          // Defense in depth: re-derive the worker transcript hash from public inputs and
          // assert byte-equality with the worker's claim. Catches a deop-node tricked into
          // proxying a tampered response.
          const expectedWorkerHash = vaultStateV2ObserveWorkerTranscriptHash({
            sessionId,
            requestId: requestId!,
            dkgEpoch,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
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
            previousDepositCountObserved: parsed.previousDepositCountObserved,
            newDepositCountObserved: parsed.depositCountObserved,
          });
          if (parsed.workerTranscriptHash !== expectedWorkerHash) {
            return reply.code(502).send({
              error: "worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedWorkerHash,
              actual: parsed.workerTranscriptHash,
            });
          }
          if (parsed.slot !== res.slot) {
            return reply.code(502).send({
              error: "observe_returned_invalid",
              slot: res.slot,
              requestId,
              message: `worker returned slot ${parsed.slot} for selfSlot ${res.slot}`,
            });
          }
          responsesBySlot.set(res.slot, parsed);
        }

        // Cursor consistency: every worker MUST report depositCountObserved == request.depositCount.
        // If any worker reports a different cursor (e.g. one was already at depositCount, or
        // observed a different one), the orchestrator cannot proceed — that worker's state
        // disagrees with the others. Operator runbook: investigate per-slot vault_state_v2.json
        // and re-run after manual reconciliation.
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          if (r.depositCountObserved !== depositCount) {
            return reply.code(502).send({
              error: "cursor_divergence",
              slot,
              requestId,
              expected: depositCount,
              actual: r.depositCountObserved,
              message:
                "worker reported depositCountObserved that does not match request.depositCount",
            });
          }
        }

        const perSlotContributions: ObserveDepositContribution[] = sortedSelectedSlots.map(
          (slot) => {
            const r = responsesBySlot.get(slot)!;
            return {
              slot,
              vaultStateHash: r.vaultStateHash,
              workerTranscriptHash: r.workerTranscriptHash,
              previousDepositCountObserved: r.previousDepositCountObserved,
              depositCountObserved: r.depositCountObserved,
              vaultSequence: r.vaultSequence,
            };
          },
        );
        const transcript = assembleVaultStateV2ObserveDepositTranscript({
          dkgEpoch,
          requestId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
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
          previousDepositCountObserved,
          newDepositCountObserved,
          perSlotContributions,
        });
        const transcriptArtifact = {
          ...transcript,
          initTranscriptPath,
          observedAtUnixMs: Date.now(),
        };

        let transcriptPath: string | undefined;
        if (opts.stateRoot) {
          const dir = join(opts.stateRoot, "coordinator", "vault_state_v2_observed");
          transcriptPath = join(
            dir,
            `${dkgEpoch}__${depositCount}__${requestId}.json`,
          );
          await writeTranscriptArtifactAtomic(transcriptPath, transcriptArtifact);
        }
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          await store.recordPartialArtifact({
            requestId,
            sessionId,
            rosterHash: dkgRosterHash,
            slot,
            artifactKind: "vault-state-v2-observe-deposit",
            artifactHash: r.vaultStateHash,
            transcriptHash: r.workerTranscriptHash,
          });
        }
        await store.markComplete(requestId);

        return reply.code(200).send({
          accepted: true,
          requestId,
          dkgEpoch,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          vaultEk,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
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
          previousDepositCountObserved,
          newDepositCountObserved,
          perSlotContributions,
          transcriptHash: transcript.transcriptHash,
          transcriptPath,
        });
      } finally {
        lock.release();
      }
    } catch (err) {
      if (requestId) await store.markAborted(requestId);
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof VaultStateV2ObserveDepositError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // =================================================================================================
  // Milestone 3 sub-milestone 3a — MPCCA withdraw V2 round1 fan-out orchestrator.
  //
  // POST /v2/withdraw/mpcca/start kicks off the 4-round MPCCA withdraw state machine. In 3a we
  // ONLY ship round1 — round2/prove/finalize routes are passthrough'd to the worker which surfaces
  // a 501 NotImplemented stub. The coordinator's round1 fan-out IS load-bearing: it does the
  // double-provenance gate (init transcript + observed deposits), acquires the single-session-at-
  // a-time lock, fans out concurrently to all 5 selected slots, and asserts every worker's
  // returned worker_transcript_hash matches the TS-side reconstruction.
  //
  // Wire shape:
  //   1. Forbidden-field guard runs FIRST on the raw body.
  //   2. Parse + shape-validate all withdraw envelope fields (root, nullifierHash, recipient,
  //      recipientHash, amountTag, vaultSequence, expirySecs, requestHash, depositCount).
  //   3. isSafeId(requestId) before any FS path construction.
  //   4. Provenance gate 1: findVaultStateV2InitProvenance for (dkgEpoch, vaultEk, caDkgTranscript,
  //      rosterHash, sender, asset, chainId) → lifts (selectedSlots, vaultEkTranscriptHash,
  //      registrationTranscriptHash, vaultStateInitTranscriptHash). 400 vault_state_init_provenance_unknown.
  //   5. Provenance gate 2: findVaultStateV2ObservedProvenance for the supplied depositCount →
  //      lifts the observed-deposit transcript hash for that cursor. 400
  //      vault_state_observed_provenance_unknown if missing.
  //   6. Acquire vaultMpccaWithdrawInFlight lock. 409 vault_mpcca_withdraw_in_flight on contention.
  //   7. Build 5 round1 request bodies (one per sorted selectedSlot with playerId set).
  //   8. Promise.all concurrent fan-out singleNodeForwarder("/worker/v2/mpcca/withdraw/round1",
  //      body, roster, slot).
  //   9. **Expected: all 5 return 501 NotImplemented** with the milestone 3a stub body. Parse each
  //      response; assert phase string matches across all 5 → 502 crypto_stub_phase_divergence if
  //      any disagree.
  //  10. Assemble + persist a partial transcript artifact at
  //      state_root/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__round1.json (atomic 0o600).
  //  11. Return 501 { accepted: false, requestId, dkgEpoch, depositCount, round: "round1", phase,
  //      transcriptHash, transcriptPath, perSlotContributions[] }.
  // =================================================================================================
  server.post("/v2/withdraw/mpcca/start", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // 1. Forbidden-plaintext-field guard FIRST.
      assertNoForbiddenPlaintextFields(raw);
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);

      // 2. Validate every required field.
      const dkgEpoch =
        typeof raw.dkgEpoch === "string" && raw.dkgEpoch.length > 0 ? raw.dkgEpoch : undefined;
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
          error: "invalid_request",
          message: "caDkgTranscriptHash is required",
        });
      }
      const vaultEk = raw.vaultEk;
      if (typeof vaultEk !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(vaultEk)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultEk must be a 32-byte hex string",
        });
      }
      const senderAddress = raw.senderAddress;
      if (
        typeof senderAddress !== "string" ||
        !/^(0x)?[0-9a-fA-F]{64}$/.test(senderAddress)
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "senderAddress must be a 32-byte hex string",
        });
      }
      const assetType = raw.assetType;
      if (typeof assetType !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(assetType)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "assetType must be a 32-byte hex string",
        });
      }
      const chainIdRaw = raw.chainId;
      if (
        !Number.isInteger(chainIdRaw) ||
        (chainIdRaw as number) < 0 ||
        (chainIdRaw as number) > 255
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "chainId must be a u8",
        });
      }
      const chainId = chainIdRaw as number;
      // Withdraw envelope fields — all 32-byte hex, with the integer counters.
      const withdrawHexFields = [
        "root",
        "nullifierHash",
        "recipient",
        "recipientHash",
        "amountTag",
        "requestHash",
      ] as const;
      const withdrawHex: Record<(typeof withdrawHexFields)[number], string> = {} as never;
      for (const name of withdrawHexFields) {
        const v = raw[name];
        if (typeof v !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(v)) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `${name} must be a 32-byte hex string`,
          });
        }
        withdrawHex[name] = v;
      }
      const vaultSequenceRaw = raw.vaultSequence;
      if (!Number.isInteger(vaultSequenceRaw) || (vaultSequenceRaw as number) < 0) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultSequence must be a non-negative integer",
        });
      }
      const vaultSequence = vaultSequenceRaw as number;
      const expirySecsRaw = raw.expirySecs;
      if (!Number.isInteger(expirySecsRaw) || (expirySecsRaw as number) < 0) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "expirySecs must be a non-negative integer",
        });
      }
      const expirySecs = expirySecsRaw as number;
      const depositCountRaw = raw.depositCount;
      if (!Number.isInteger(depositCountRaw) || (depositCountRaw as number) < 0) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "depositCount must be a non-negative integer",
        });
      }
      const depositCount = depositCountRaw as number;

      // 3. Sanitise caller-supplied requestId BEFORE acquiring any lock or touching the FS.
      requestId =
        typeof raw.requestId === "string" && raw.requestId.length > 0
          ? raw.requestId
          : `mpcca-withdraw-${Date.now()}`;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }
      const sessionId = requestId;

      // 4. Provenance gate 1 — Milestone 2a vault_state_v2 init transcript MUST match.
      // The init transcript itself binds Phase 2 + Milestone 1, so a matching init transcript
      // implies the entire prereq chain is in place.
      const claimedSelectedSlots = Array.isArray(raw.selectedSlots)
        ? (raw.selectedSlots as unknown[])
        : undefined;
      const claimedVaultEkTranscriptHash =
        typeof raw.vaultEkTranscriptHash === "string" && raw.vaultEkTranscriptHash.length > 0
          ? raw.vaultEkTranscriptHash
          : undefined;
      const claimedRegistrationTranscriptHash =
        typeof raw.registrationTranscriptHash === "string" &&
        raw.registrationTranscriptHash.length > 0
          ? raw.registrationTranscriptHash
          : undefined;
      const claimedVaultStateInitTranscriptHash =
        typeof raw.vaultStateInitTranscriptHash === "string" &&
        raw.vaultStateInitTranscriptHash.length > 0
          ? raw.vaultStateInitTranscriptHash
          : undefined;
      let selectedSlots: number[] | undefined;
      let vaultEkTranscriptHash: string | undefined;
      let registrationTranscriptHash: string | undefined;
      let vaultStateInitTranscriptHash: string | undefined;
      let vaultStateInitTranscriptPath: string | undefined;
      if (opts.stateRoot) {
        const initProvenance = await findVaultStateV2InitWithTranscriptHash(opts.stateRoot, {
          dkgEpoch,
          vaultEk,
          caDkgTranscriptHash: caDkgTranscriptHashInput,
          rosterHash: dkgRosterHash,
          senderAddress,
          assetType,
          chainId,
        });
        if (!initProvenance) {
          return reply.code(400).send({
            error: "vault_state_init_provenance_unknown",
            requestId,
            message:
              "no persisted Milestone 2a vault_state_v2 init transcript matches the supplied " +
              "(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType, " +
              "chainId). Run /v2/vault_state/init first.",
          });
        }
        selectedSlots = initProvenance.selectedSlots;
        vaultEkTranscriptHash = initProvenance.vaultEkTranscriptHash;
        registrationTranscriptHash = initProvenance.registrationTranscriptHash;
        vaultStateInitTranscriptHash = initProvenance.transcriptHash;
        vaultStateInitTranscriptPath = initProvenance.transcriptPath;
      } else {
        if (
          !claimedSelectedSlots ||
          claimedSelectedSlots.length !== DEOPERATOR_THRESHOLD ||
          !claimedVaultEkTranscriptHash ||
          !claimedRegistrationTranscriptHash ||
          !claimedVaultStateInitTranscriptHash
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message:
              "stateRoot is not configured; caller must supply selectedSlots, " +
              "vaultEkTranscriptHash, registrationTranscriptHash, and " +
              "vaultStateInitTranscriptHash inline",
          });
        }
        const arr: number[] = [];
        const seen = new Set<number>();
        for (const slot of claimedSelectedSlots) {
          if (
            !Number.isInteger(slot) ||
            (slot as number) < 0 ||
            (slot as number) >= DEOPERATOR_COUNT
          ) {
            return reply.code(400).send({
              error: "invalid_request",
              message: `selectedSlots entry ${slot} out of range`,
            });
          }
          if (seen.has(slot as number)) {
            return reply.code(400).send({
              error: "duplicate_slot",
              message: `duplicate selectedSlots entry ${slot}`,
            });
          }
          seen.add(slot as number);
          arr.push(slot as number);
        }
        selectedSlots = arr;
        vaultEkTranscriptHash = claimedVaultEkTranscriptHash;
        registrationTranscriptHash = claimedRegistrationTranscriptHash;
        vaultStateInitTranscriptHash = claimedVaultStateInitTranscriptHash;
      }
      if (
        !selectedSlots ||
        !vaultEkTranscriptHash ||
        !registrationTranscriptHash ||
        !vaultStateInitTranscriptHash
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "internal: provenance fields unresolved",
        });
      }
      const sortedSelectedSlots = [...selectedSlots].sort((a, b) => a - b);

      // 5. Provenance gate 2 — Milestone 2b observed-deposit transcripts. Scan
      // <stateRoot>/coordinator/vault_state_v2_observed/ for an artifact at the supplied
      // depositCount whose tuple matches; lift its `transcriptHash` field. Multiple
      // observe-deposit calls may have run; we want the one at the supplied cursor.
      const claimedObservedDepositTranscriptHashes = Array.isArray(
        raw.observedDepositTranscriptHashes,
      )
        ? (raw.observedDepositTranscriptHashes as unknown[])
        : undefined;
      let observedDepositTranscriptHashes: string[] | undefined;
      if (opts.stateRoot && depositCount > 0) {
        const observedProvenance = await findVaultStateV2ObservedProvenance(opts.stateRoot, {
          dkgEpoch,
          depositCount,
          vaultEk,
          rosterHash: dkgRosterHash,
          senderAddress,
          assetType,
          chainId,
        });
        if (!observedProvenance) {
          return reply.code(400).send({
            error: "vault_state_observed_provenance_unknown",
            requestId,
            depositCount,
            message:
              "no persisted Milestone 2b observe_deposit transcript matches the supplied " +
              "(dkgEpoch, depositCount, vaultEk, rosterHash, senderAddress, assetType, " +
              "chainId). Run /v2/vault_state/observe_deposit first.",
          });
        }
        observedDepositTranscriptHashes = observedProvenance.observedDepositTranscriptHashes;
      } else if (depositCount === 0) {
        // depositCount=0 means "no observed deposits yet" — empty observed list is valid.
        observedDepositTranscriptHashes = [];
      } else {
        // No stateRoot — caller supplies the observed list inline.
        if (!claimedObservedDepositTranscriptHashes) {
          return reply.code(400).send({
            error: "invalid_request",
            message:
              "stateRoot is not configured; caller must supply observedDepositTranscriptHashes inline",
          });
        }
        const arr: string[] = [];
        for (const h of claimedObservedDepositTranscriptHashes) {
          if (typeof h !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(h)) {
            return reply.code(400).send({
              error: "invalid_request",
              message: "every observedDepositTranscriptHashes entry must be 32-byte hex",
            });
          }
          arr.push(h);
        }
        observedDepositTranscriptHashes = arr;
      }
      if (!observedDepositTranscriptHashes) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "internal: observedDepositTranscriptHashes unresolved",
        });
      }

      // Codex M3a P2 #1 v2 (ordering regression fix): build the parallel cursor mapping
      // for the worker's strict-monotonic-ordering enforcement. The worker rejects any
      // mismatch between observedDepositTranscriptHashes[i] and depositCount = i+1 with
      // observed_deposit_cursors_*. We build [1, 2, …, depositCount] in cursor order
      // since `findVaultStateV2ObservedProvenance` already sorts ascending by cursor.
      const observedDepositCursors: number[] = [];
      for (let c = 1; c <= depositCount; c += 1) {
        observedDepositCursors.push(c);
      }
      if (observedDepositCursors.length !== observedDepositTranscriptHashes.length) {
        return reply.code(400).send({
          error: "invalid_request",
          message:
            `internal: observedDepositCursors length ${observedDepositCursors.length} ` +
            `does not match observedDepositTranscriptHashes length ${observedDepositTranscriptHashes.length}`,
        });
      }

      // 6. Acquire the lock.
      const lock = await acquireVaultMpccaWithdrawLock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "vault_mpcca_withdraw_in_flight",
          requestId,
          message:
            "another MPCCA withdraw session is in progress; retry shortly",
        });
      }

      try {
        // 7. Build 5 round1 request bodies. Each slot gets the same payload modulo selfSlot
        // and playerId.
        const round1Bodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch,
          requestId: requestId!,
          sessionId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          vaultStateInitTranscriptHash,
          observedDepositTranscriptHashes,
          // Codex M3a P2 #1 v2: parallel cursor mapping for worker ordering enforcement.
          // Must be [1, 2, …, depositCount] in index order — the worker rejects any
          // other shape with observed_deposit_cursors_*.
          observedDepositCursors,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          root: withdrawHex.root,
          nullifierHash: withdrawHex.nullifierHash,
          recipient: withdrawHex.recipient,
          recipientHash: withdrawHex.recipientHash,
          amountTag: withdrawHex.amountTag,
          vaultSequence,
          expirySecs,
          requestHash: withdrawHex.requestHash,
          depositCount,
        }));

        // 8. KILLER: concurrent fan-out — all 5 worker calls launched before any completes.
        const forwarded = await Promise.all(
          sortedSelectedSlots.map((slot, ordinalIndex) =>
            singleNodeForwarder(
              "/worker/v2/mpcca/withdraw/round1",
              round1Bodies[ordinalIndex],
              dkgRoster,
              slot,
            ).then(
              (value) => ({ kind: "value" as const, slot, value }),
              (reason) => ({ kind: "rejected" as const, slot, reason }),
            ),
          ),
        );
        // 9. Parse + assert phase agreement.
        const responsesBySlot = new Map<
          number,
          ReturnType<typeof parseMpccaWithdrawRound1Response>
        >();
        const phasesObserved = new Set<string>();
        for (const res of forwarded) {
          if (res.kind === "rejected") {
            return reply.code(502).send({
              error: "round1_forward_rejected",
              slot: res.slot,
              requestId,
              reason:
                res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          // Milestone 3a expectation: every worker returns 501 + a stub body. Anything else
          // means either the worker accepted and ran (which is wrong under 3a) or it failed
          // with a different error (which means the public binding fence kicked in for that
          // slot and not the others — the orchestrator must surface that).
          if (res.value.statusCode !== 501) {
            // Codex M3a P1 v4: surface the SPECIFIC, OPERATOR-ACTIONABLE 409 the worker
            // emits when its persisted `init_transcript_hash` is None — meaning the cluster
            // is in the legitimate partial-finalize state and the operator should invoke
            // `/v2/vault_state/init/finalize` (idempotent across already-finalized slots).
            // Mapping this to a generic 502 round1_unexpected_status loses the recovery
            // hint; the coordinator's caller needs to know to run finalize, not to
            // investigate tamper.
            //
            // Worker emits body shape (post-v4): `{ "code": "vault_state_v2_not_finalized",
            // "error": "invalid_dkg_state", "message": "..." }`. We accept either a top-
            // level `code` field (preferred) or the legacy `message` containing the
            // sentinel substring (backwards compat with worker builds that predate the
            // structured `code` field).
            const body = res.value.body as
              | Record<string, unknown>
              | undefined
              | null;
            const workerCode =
              typeof body?.code === "string" ? body.code : undefined;
            const workerMessage =
              typeof body?.message === "string" ? body.message : undefined;
            const notFinalized =
              workerCode === "vault_state_v2_not_finalized" ||
              (workerMessage !== undefined &&
                workerMessage.includes("vault_state_v2_not_finalized"));
            if (res.value.statusCode === 409 && notFinalized) {
              return reply.code(503).send({
                error: "vault_state_v2_not_finalized_invoke_finalize_first",
                slot: res.slot,
                requestId,
                statusCode: res.value.statusCode,
                workerCode: workerCode ?? "vault_state_v2_not_finalized",
                message:
                  "worker rejected MPCCA round1 because its persisted init_transcript_hash " +
                  "is None — invoke POST /v2/vault_state/init/finalize on the cluster (idempotent " +
                  "across already-finalized slots) before retrying the withdraw. Do not auto-retry: " +
                  "the operator must observe finalize converged to a single canonical hash before " +
                  "the next MPCCA round1 attempt.",
              });
            }
            return reply.code(502).send({
              error: "round1_unexpected_status",
              slot: res.slot,
              requestId,
              statusCode: res.value.statusCode,
              body: res.value.body,
              message:
                "milestone 3a stub expected to return 501 NotImplemented; received different status",
            });
          }
          if (!res.value.body) {
            return reply.code(502).send({
              error: "round1_empty_body",
              slot: res.slot,
              requestId,
            });
          }
          let parsed;
          try {
            parsed = parseMpccaWithdrawRound1Response(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "round1_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          phasesObserved.add(parsed.notImplementedPhase);
          // Defense in depth: re-derive the worker transcript hash from public inputs and
          // assert byte-equality.
          const expectedWorkerHash = mpccaWithdrawRound1WorkerTranscriptHash({
            sessionId,
            requestId: requestId!,
            dkgEpoch,
            vaultEkTranscriptHash,
            registrationTranscriptHash,
            vaultStateInitTranscriptHash,
            observedDepositTranscriptHashes,
            rosterHash: dkgRosterHash,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            vaultEk,
            senderAddress,
            assetType,
            chainId,
            root: withdrawHex.root,
            nullifierHash: withdrawHex.nullifierHash,
            recipient: withdrawHex.recipient,
            recipientHash: withdrawHex.recipientHash,
            amountTag: withdrawHex.amountTag,
            vaultSequence,
            expirySecs,
            requestHash: withdrawHex.requestHash,
            depositCount,
          });
          if (parsed.workerTranscriptHash !== expectedWorkerHash) {
            return reply.code(502).send({
              error: "worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedWorkerHash,
              actual: parsed.workerTranscriptHash,
            });
          }
          if (parsed.slot !== res.slot) {
            return reply.code(502).send({
              error: "round1_returned_invalid",
              slot: res.slot,
              requestId,
              message: `worker returned slot ${parsed.slot} for selfSlot ${res.slot}`,
            });
          }
          responsesBySlot.set(res.slot, parsed);
        }
        // Phase divergence: all 5 workers MUST return the same phase string. If not, the
        // milestone 3a stub got out of sync across workers (or one was tampered).
        if (phasesObserved.size !== 1) {
          return reply.code(502).send({
            error: "crypto_stub_phase_divergence",
            requestId,
            phasesObserved: [...phasesObserved],
            message:
              "milestone 3a stub returned divergent notImplementedPhase strings across the 5 workers",
          });
        }
        const phase = [...phasesObserved][0];

        // 10. Persist a partial round-1 transcript artifact.
        const perSlotContributions: MpccaWithdrawRound1Contribution[] = sortedSelectedSlots.map(
          (slot) => {
            const r = responsesBySlot.get(slot)!;
            return {
              slot,
              sessionStateHash: r.sessionStateHash,
              workerTranscriptHash: r.workerTranscriptHash,
              completed: false as const,
              notImplementedPhase: r.notImplementedPhase,
              roundCommitment: r.roundCommitment,
            };
          },
        );
        // Codex M3a P2 #3: build the artifact with a real `transcriptHash` digest. Pre-fix
        // the field was set to the scheme literal `"mpcca_withdraw_v2_round1_partial"`, so
        // recovery/audit clients could not pin the persisted artifact by the returned hash.
        // We sha256(canonicalize(artifact-without-transcriptHash)) and embed the digest into
        // the artifact, so a later reader can recompute the same hash and verify integrity.
        const round1ArtifactWithoutHash = {
          scheme: "mpcca_withdraw_v2_round1_partial" as const,
          dkgEpoch,
          requestId,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          vaultStateInitTranscriptHash,
          vaultStateInitTranscriptPath,
          observedDepositTranscriptHashes,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          vaultEk,
          senderAddress,
          assetType,
          chainId,
          root: withdrawHex.root,
          nullifierHash: withdrawHex.nullifierHash,
          recipient: withdrawHex.recipient,
          recipientHash: withdrawHex.recipientHash,
          amountTag: withdrawHex.amountTag,
          vaultSequence,
          expirySecs,
          requestHash: withdrawHex.requestHash,
          depositCount,
          notImplementedPhase: phase,
          perSlotContributions,
          createdAtUnixMs: Date.now(),
        };
        const round1TranscriptHash = bytesToHex(
          sha256(new TextEncoder().encode(canonicalJsonStringify(round1ArtifactWithoutHash))),
        );
        const round1TranscriptArtifact = {
          ...round1ArtifactWithoutHash,
          transcriptHash: round1TranscriptHash,
        };
        let transcriptPath: string | undefined;
        if (opts.stateRoot) {
          const dir = join(opts.stateRoot, "coordinator", "mpcca_withdraw");
          transcriptPath = join(dir, `${dkgEpoch}__${requestId}__round1.json`);
          await writeTranscriptArtifactAtomic(transcriptPath, round1TranscriptArtifact);
        }
        // Persist per-slot rows in the partial-artifact log (same shape as other rounds).
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          await store.recordPartialArtifact({
            requestId,
            sessionId,
            rosterHash: dkgRosterHash,
            slot,
            artifactKind: "mpcca-withdraw-v2-round1",
            artifactHash: r.sessionStateHash,
            transcriptHash: r.workerTranscriptHash,
          });
        }
        // We do NOT call store.markComplete — the withdraw is mid-flight (3a only ships
        // round1). Milestone 4 will mark complete at finalize.

        // 11. Return 501 with the partial round-1 outputs. The accept flag is false because
        // the withdraw is NOT done — milestone 4 will fill in round2/prove/finalize.
        return reply.code(501).send({
          accepted: false,
          requestId,
          dkgEpoch,
          depositCount,
          round: "round1",
          phase,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          vaultEk,
          vaultEkTranscriptHash,
          registrationTranscriptHash,
          vaultStateInitTranscriptHash,
          observedDepositTranscriptHashes,
          senderAddress,
          assetType,
          chainId,
          root: withdrawHex.root,
          nullifierHash: withdrawHex.nullifierHash,
          recipient: withdrawHex.recipient,
          recipientHash: withdrawHex.recipientHash,
          amountTag: withdrawHex.amountTag,
          vaultSequence,
          expirySecs,
          requestHash: withdrawHex.requestHash,
          perSlotContributions,
          transcriptHash: round1TranscriptHash,
          transcriptPath,
          message:
            "milestone 3a stub: round1 public binding succeeded across all 5 workers; round2/" +
            "prove/finalize crypto deferred to milestone 4",
        });
      } finally {
        lock.release();
      }
    } catch (err) {
      if (requestId) await store.markAborted(requestId);
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof MpccaWithdrawV2Error) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // =================================================================================================
  // Milestone 5 sub-milestone 5b — MPCCA withdraw V2 chain-submit orchestrator.
  //
  // POST /v2/withdraw/mpcca/submit reads the finalize transcript that M4e will write at
  //   <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json,
  // assembles the 27-field WithdrawV2CallArgs from it, hands them to the relayer, and polls for
  // chain confirmation.
  //
  // 5b is PLUMBING-ONLY — the finalize transcript is still the M3a NotImplemented stub today, so
  // every real-world call to this route surfaces 501 with `notImplementedPhase` set. The route is
  // wired so that when M4d/M4e ship the actual finalize crypto + populate the on-disk artifact,
  // NO new orchestration plumbing is needed.
  //
  // Wire shape:
  //   1. Forbidden-plaintext-field guard FIRST on the raw body.
  //   2. parseMpccaWithdrawSubmitRequest — { dkgEpoch, requestId, [relayerOverrides] }.
  //   3. isSafeId(requestId) before any FS path construction.
  //   4. Acquire vaultMpccaWithdrawSubmitInFlight lock. 409 mpcca_withdraw_submit_in_flight on
  //      contention.
  //   5. loadMpccaFinalizeTranscript(stateRoot, dkgEpoch, requestId). Null → 400
  //      mpcca_finalize_transcript_not_found with an actionable message.
  //   6. assembleWithdrawV2CallArgs(finalize). If returns { notImplementedPhase } → persist the
  //      submit-transcript stub artifact + return 501 with the phase string.
  //   7. Otherwise: invoke the injected relayerSubmitter with the assembled 27-field bundle.
  //      Captures (txHash, simulated).
  //   8. If chainNodeUrl is configured AND the result is not simulated, waitForTx until
  //      confirmed or timeout. On timeout → 502 chain_confirmation_timeout.
  //   9. Persist the submit-transcript artifact at
  //      <stateRoot>/coordinator/mpcca_withdraw_submit/<dkgEpoch>__<requestId>.json.
  //  10. Return 200 (real success), 202 (simulated success), or 501 (M3a stub).
  // =================================================================================================
  server.post("/v2/withdraw/mpcca/submit", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    try {
      // 1. Forbidden-plaintext-field guard FIRST.
      assertNoForbiddenPlaintextFields(raw);
      // 2. Parse + shape-validate.
      const parsed = parseMpccaWithdrawSubmitRequest(raw);
      // 3. isSafeId(requestId) before any FS path construction.
      if (!isSafeId(parsed.requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds this into " +
            "filesystem paths",
        });
      }
      if (!opts.stateRoot) {
        // Plumbing precondition: the submit route is stateRoot-only because the finalize
        // transcript is the load-bearing source of truth. Without stateRoot there's nothing
        // to read.
        return reply.code(400).send({
          error: "state_root_required",
          message:
            "POST /v2/withdraw/mpcca/submit requires stateRoot — the finalize transcript is " +
            "loaded from disk; configure EUNOMA_STATE_ROOT or pass stateRoot to buildCoordinatorServer",
        });
      }
      // 4. Acquire submit lock.
      const lock = await acquireVaultMpccaWithdrawSubmitLock();
      if (lock === "busy") {
        return reply.code(409).send({
          error: "mpcca_withdraw_submit_in_flight",
          requestId: parsed.requestId,
          message: "another MPCCA withdraw submit is in progress for this coordinator; retry shortly",
        });
      }
      try {
        // 5. Load the finalize transcript.
        const finalize = await loadMpccaFinalizeTranscript(
          opts.stateRoot,
          parsed.dkgEpoch,
          parsed.requestId,
        );
        if (!finalize) {
          return reply.code(400).send({
            error: "mpcca_finalize_transcript_not_found",
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            expectedPath: mpccaFinalizeTranscriptPath(
              opts.stateRoot,
              parsed.dkgEpoch,
              parsed.requestId,
            ),
            message:
              "invoke /v2/withdraw/mpcca/start first; ensure all 4 rounds completed (currently " +
              "rounds 2/prove/finalize return 501 — M4 will fill them in)",
          });
        }
        // 6. Assemble. Either get the 27-field bundle or the NotImplemented passthrough.
        let assembleResult: WithdrawV2CallArgsShape | { notImplementedPhase: string };
        try {
          assembleResult = assembleWithdrawV2CallArgs(finalize);
        } catch (err) {
          return reply.code(500).send({
            error: "withdraw_v2_call_args_assembly_failed",
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            message: err instanceof Error ? err.message : "unknown",
          });
        }

        // Persistence helper. Used by all three outcome paths so the audit log captures both
        // the stub case AND the real-submission case.
        const submitTranscriptDir = join(
          opts.stateRoot,
          "coordinator",
          "mpcca_withdraw_submit",
        );
        const submitTranscriptPath = join(
          submitTranscriptDir,
          `${parsed.dkgEpoch}__${parsed.requestId}.json`,
        );
        async function persistSubmitTranscript(payload: Record<string, unknown>): Promise<string> {
          const artifactWithoutHash = {
            scheme: "mpcca_withdraw_submit_v2" as const,
            domain: EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1,
            dkgEpoch: parsed.dkgEpoch,
            requestId: parsed.requestId,
            finalizeTranscriptPath: mpccaFinalizeTranscriptPath(
              opts.stateRoot!,
              parsed.dkgEpoch,
              parsed.requestId,
            ),
            finalizeTranscriptHash: finalize!.transcriptHash,
            createdAtUnixMs: Date.now(),
            ...payload,
          };
          const transcriptHash = bytesToHex(
            sha256(new TextEncoder().encode(canonicalJsonStringify(artifactWithoutHash))),
          );
          await writeTranscriptArtifactAtomic(submitTranscriptPath, {
            ...artifactWithoutHash,
            transcriptHash,
          });
          return transcriptHash;
        }

        if (isNotImplementedPhasePassthrough(assembleResult)) {
          // 6a. M3a/M4 stub passthrough — finalize transcript still carries a NotImplemented
          // phase. Persist the stub submit-transcript so an auditor can see the attempt + the
          // phase that blocked it.
          const phase = assembleResult.notImplementedPhase;
          const transcriptHash = await persistSubmitTranscript({
            completed: false,
            simulated: true,
            notImplementedPhase: phase,
          });
          return reply.code(501).send({
            accepted: false,
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            simulated: true,
            completed: false,
            notImplementedPhase: phase,
            transcriptHash,
            transcriptPath: submitTranscriptPath,
            message:
              `MPCCA withdraw finalize transcript is still on the NotImplemented stub: ${phase}. ` +
              "M4d/M4e will fill in the real finalize crypto. The submit route plumbing is in " +
              "place; no new orchestration work is needed when M4 lands.",
          });
        }

        // 7. Real assembly succeeded. Hand to the relayer.
        if (!opts.relayerSubmitter) {
          return reply.code(502).send({
            error: "relayer_unreachable",
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            message:
              "coordinator has no relayer submitter configured; set RELAYER_URL + " +
              "RELAYER_BEARER_TOKEN in the environment or inject `relayerSubmitter` for tests",
          });
        }
        let relayerResult: Awaited<ReturnType<RelayerWithdrawSubmitter>>;
        try {
          relayerResult = await opts.relayerSubmitter(assembleResult);
        } catch (err) {
          return reply.code(502).send({
            error: "relayer_returned_error",
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            message: err instanceof Error ? err.message : "unknown",
          });
        }
        // 8. Poll for chain confirmation. We poll only if (a) it's NOT a simulated submit
        // (simulated submits never make it on-chain) AND (b) a chainNodeUrl is configured.
        let confirmation: { confirmed: boolean; success?: boolean; vmStatus?: string } | null =
          null;
        if (!relayerResult.simulated && opts.chainNodeUrl) {
          try {
            confirmation = await waitForTx(opts.chainNodeUrl, relayerResult.txHash, {
              timeoutMs: opts.chainConfirmationTimeoutMs,
              fetchImpl: opts.chainFetch,
            });
          } catch (err) {
            // waitForTx threw — either a 5xx from the chain node or unexpected transport
            // failure. Surface as 502 chain_confirmation_timeout so the operator sees the
            // exact failure mode.
            const transcriptHash = await persistSubmitTranscript({
              completed: false,
              simulated: false,
              txHash: relayerResult.txHash,
              chainConfirmationError: err instanceof Error ? err.message : "unknown",
            });
            return reply.code(502).send({
              error: "chain_confirmation_timeout",
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              txHash: relayerResult.txHash,
              transcriptHash,
              transcriptPath: submitTranscriptPath,
              message:
                `chain confirmation polling failed: ${err instanceof Error ? err.message : "unknown"}`,
            });
          }
          if (!confirmation.confirmed) {
            const transcriptHash = await persistSubmitTranscript({
              completed: false,
              simulated: false,
              txHash: relayerResult.txHash,
              chainConfirmationError: "timeout",
            });
            return reply.code(502).send({
              error: "chain_confirmation_timeout",
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              txHash: relayerResult.txHash,
              transcriptHash,
              transcriptPath: submitTranscriptPath,
              message: `tx ${relayerResult.txHash} did not confirm within ${opts.chainConfirmationTimeoutMs ?? 30_000}ms`,
            });
          }
        }
        // 9. Persist the success submit-transcript artifact.
        const submitTranscriptHash = await persistSubmitTranscript({
          completed: true,
          simulated: relayerResult.simulated,
          txHash: relayerResult.txHash,
          ...(confirmation
            ? {
                chainSuccess: confirmation.success,
                chainVmStatus: confirmation.vmStatus,
              }
            : {}),
        });
        // 10. Return — 200 for real-chain confirmation, 202 for simulated.
        const statusCode = relayerResult.simulated ? 202 : 200;
        return reply.code(statusCode).send({
          accepted: relayerResult.accepted,
          requestId: parsed.requestId,
          dkgEpoch: parsed.dkgEpoch,
          txHash: relayerResult.txHash,
          simulated: relayerResult.simulated,
          completed: true,
          transcriptHash: submitTranscriptHash,
          transcriptPath: submitTranscriptPath,
        });
      } finally {
        lock.release();
      }
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof MpccaWithdrawSubmitError) {
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

/**
 * Codex M3a P2 #3: deterministic JSON serializer that sorts object keys recursively. Used
 * to compute integrity hashes over coordinator artifacts where a later reader must be able
 * to recompute the EXACT same hash. Standard JSON.stringify preserves insertion order, which
 * is fine when the artifact's keys are always emitted in the same order — but if a future
 * refactor reorders the object literal, the hash would drift silently. Sorting keys gives
 * a stable serialization tied only to the (key,value) set.
 *
 * Behaviour:
 *   - Plain objects: keys sorted lexicographically (locale-independent UTF-16 order).
 *   - Arrays: order preserved (semantic order is load-bearing — observed transcript order,
 *     per-slot contributions, etc.).
 *   - Primitives: passed through to JSON.stringify.
 *   - `undefined` properties: dropped (matches JSON.stringify semantics).
 *
 * NOT a full JCS implementation; sufficient for the artifact shapes we hash here.
 */
function canonicalJsonStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return value.map((v) => canonicalize(v));
  }
  const obj = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key];
    if (v === undefined) continue;
    sorted[key] = canonicalize(v);
  }
  return sorted;
}

async function writeTranscriptArtifactAtomic(
  path: string,
  value: unknown,
): Promise<void> {
  // Codex M2a P2 #2: write to <path>.tmp.<pid>.<random> with flag 'wx' (O_EXCL +
  // O_CREAT, fails if path exists), fsync via writeFile's flag chain isn't possible in
  // Node's fs/promises — but the create_new + rename is the load-bearing atomicity
  // guarantee: rename(2) on the same FS is atomic and the tmp name is unguessable, so
  // a concurrent writer can't clobber an in-progress write.
  // Loop on AlreadyExists with a fresh random suffix. 16 attempts is far more than
  // enough — collisions on 8 random bytes + pid + ms are astronomically unlikely.
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const body = `${JSON.stringify(value, null, 2)}\n`;
  const MAX_ATTEMPTS = 16;
  let lastErr: unknown;
  for (let i = 0; i < MAX_ATTEMPTS; i += 1) {
    const suffix = randomBytes(8).toString("hex");
    const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${suffix}`;
    try {
      await writeFile(tmp, body, { mode: 0o600, flag: "wx" });
      await chmod(tmp, 0o600);
      try {
        await rename(tmp, path);
        return;
      } catch (renameErr) {
        // best-effort cleanup of the tmp we created
        await unlink(tmp).catch(() => undefined);
        throw renameErr;
      }
    } catch (err) {
      if (
        err instanceof Error &&
        (err as NodeJS.ErrnoException).code === "EEXIST"
      ) {
        // tmp suffix collided; retry
        lastErr = err;
        continue;
      }
      throw err;
    }
  }
  throw new Error(
    `writeTranscriptArtifactAtomic: exhausted ${MAX_ATTEMPTS} tmp-suffix retries for ${path}: ${lastErr}`,
  );
}

/**
 * Codex P2 #1 — verify `vaultEk` provenance.
 *
 * The coordinator's /v2/derive/ca_registration/start accepts vaultEk from the request body.
 * If we don't check that the value came from a real Phase 2 transcript, a stale or
 * malicious vaultEk burns all selected workers' nonces before the aggregate verifier
 * catches the mismatch. Worse, an attacker who can read the worker's round1 commitment
 * could try to predict which (vaultEk, dkgEpoch, caDkgTranscriptHash, rosterHash) tuple
 * the coordinator would accept and grief the system.
 *
 * Fix: scan the coordinator's persisted Phase 2 transcripts at
 * `<stateRoot>/coordinator/vault_ek_derivation/` for an artifact whose
 * `(dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash)` matches the supplied tuple. If
 * none found, return 400 `vault_ek_provenance_unknown` and skip the worker fan-out.
 * If found, return the artifact's `finalTranscriptHash` so the registration transcript
 * can cross-reference its source.
 *
 * Bounds the attack to "burning the coordinator's transcript dir" — since the coordinator
 * itself produced those transcripts (each behind the vault_ek_derivation lock), an
 * attacker cannot fabricate them without first running a successful Phase 2 derive.
 */
async function findVaultEkProvenance(
  stateRoot: string,
  expected: {
    dkgEpoch: string;
    vaultEk: string;
    caDkgTranscriptHash: string;
    rosterHash: string;
  },
): Promise<{ vaultEkTranscriptHash: string; transcriptPath: string } | undefined> {
  const dir = join(stateRoot, "coordinator", "vault_ek_derivation");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    // No directory → no transcripts → no provenance. Caller maps to 400.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  const lowerVaultEk = expected.vaultEk.replace(/^0x/i, "").toLowerCase();
  const lowerCaDkg = expected.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase();
  const lowerRoster = expected.rosterHash.replace(/^0x/i, "").toLowerCase();
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    // Cheap optimization: file name is `<dkgEpoch>__<requestId>.json` so we can skip
    // transcripts for the wrong epoch without parsing JSON. Mismatches across the rest
    // of the tuple still need a JSON read.
    const epochPrefix = `${expected.dkgEpoch}__`;
    if (!entry.startsWith(epochPrefix)) continue;
    const transcriptPath = join(dir, entry);
    let raw: string;
    try {
      raw = await readFile(transcriptPath, "utf8");
    } catch {
      continue;
    }
    let artifact: Record<string, unknown>;
    try {
      artifact = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (artifact.scheme !== "vault_ek_derivation_v1") continue;
    if (typeof artifact.dkgEpoch !== "string" || artifact.dkgEpoch !== expected.dkgEpoch) continue;
    if (typeof artifact.vaultEk !== "string") continue;
    if (typeof artifact.caDkgTranscriptHash !== "string") continue;
    if (typeof artifact.rosterHash !== "string") continue;
    if (typeof artifact.finalTranscriptHash !== "string") continue;
    if (artifact.vaultEk.replace(/^0x/i, "").toLowerCase() !== lowerVaultEk) continue;
    if (artifact.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase() !== lowerCaDkg) continue;
    if (artifact.rosterHash.replace(/^0x/i, "").toLowerCase() !== lowerRoster) continue;
    return {
      vaultEkTranscriptHash: artifact.finalTranscriptHash,
      transcriptPath,
    };
  }
  return undefined;
}

/**
 * Milestone 2a — verify Milestone 1 (CA registration sigma) provenance.
 *
 * Mirrors `findVaultEkProvenance`. Scans `<stateRoot>/coordinator/ca_registration_v2/` for an
 * artifact whose (dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType,
 * chainId) tuple matches the supplied tuple. Returns the persisted sigma tuple
 * (aggregateCommitment, aggregateResponse, challenge) + the final transcriptHash so the
 * coordinator can forward all five fields to each worker without trusting the caller's body.
 *
 * Bounds the attack surface to "burning the coordinator's transcript dir": since the coordinator
 * itself produced those transcripts (each behind the ca_registration_v2 lock), an attacker
 * cannot fabricate them without first running a successful Milestone 1 sigma.
 */
async function findCaRegistrationV2Provenance(
  stateRoot: string,
  expected: {
    dkgEpoch: string;
    vaultEk: string;
    caDkgTranscriptHash: string;
    rosterHash: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
  },
): Promise<
  | {
      registrationTranscriptHash: string;
      transcriptPath: string;
      aggregateCommitment: string;
      aggregateResponse: string;
      challenge: string;
      verifierSlot: number | undefined;
    }
  | undefined
> {
  const dir = join(stateRoot, "coordinator", "ca_registration_v2");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  const lowerVaultEk = expected.vaultEk.replace(/^0x/i, "").toLowerCase();
  const lowerCaDkg = expected.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase();
  const lowerRoster = expected.rosterHash.replace(/^0x/i, "").toLowerCase();
  const lowerSender = expected.senderAddress.replace(/^0x/i, "").toLowerCase();
  const lowerAsset = expected.assetType.replace(/^0x/i, "").toLowerCase();
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const epochPrefix = `${expected.dkgEpoch}__`;
    if (!entry.startsWith(epochPrefix)) continue;
    const transcriptPath = join(dir, entry);
    let raw: string;
    try {
      raw = await readFile(transcriptPath, "utf8");
    } catch {
      continue;
    }
    let artifact: Record<string, unknown>;
    try {
      artifact = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (artifact.scheme !== "ca_registration_v2") continue;
    if (typeof artifact.dkgEpoch !== "string" || artifact.dkgEpoch !== expected.dkgEpoch) continue;
    if (typeof artifact.vaultEk !== "string") continue;
    if (typeof artifact.caDkgTranscriptHash !== "string") continue;
    if (typeof artifact.rosterHash !== "string") continue;
    if (typeof artifact.transcriptHash !== "string") continue;
    if (typeof artifact.senderAddress !== "string") continue;
    if (typeof artifact.assetType !== "string") continue;
    if (typeof artifact.aggregateCommitment !== "string") continue;
    if (typeof artifact.aggregateResponse !== "string") continue;
    if (typeof artifact.challenge !== "string") continue;
    if (typeof artifact.chainId !== "number") continue;
    if (artifact.vaultEk.replace(/^0x/i, "").toLowerCase() !== lowerVaultEk) continue;
    if (artifact.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase() !== lowerCaDkg) continue;
    if (artifact.rosterHash.replace(/^0x/i, "").toLowerCase() !== lowerRoster) continue;
    if (artifact.senderAddress.replace(/^0x/i, "").toLowerCase() !== lowerSender) continue;
    if (artifact.assetType.replace(/^0x/i, "").toLowerCase() !== lowerAsset) continue;
    if (artifact.chainId !== expected.chainId) continue;
    const verifierSlot =
      typeof artifact.verifierSlot === "number" ? artifact.verifierSlot : undefined;
    return {
      registrationTranscriptHash: artifact.transcriptHash,
      transcriptPath,
      aggregateCommitment: artifact.aggregateCommitment,
      aggregateResponse: artifact.aggregateResponse,
      challenge: artifact.challenge,
      verifierSlot,
    };
  }
  return undefined;
}

/**
 * Milestone 2b — verify Milestone 2a (vault_state_v2 init) provenance.
 *
 * Mirrors `findCaRegistrationV2Provenance`. Scans `<stateRoot>/coordinator/vault_state_v2/` for
 * an artifact whose (dkgEpoch, vaultEk, caDkgTranscriptHash, rosterHash, senderAddress, assetType,
 * chainId) tuple matches. Returns the persisted (vaultEkTranscriptHash, registrationTranscriptHash,
 * selectedSlots) so the observe-deposit orchestrator can fan out without re-trusting the caller.
 *
 * The init transcript itself binds Phase 2 + Milestone 1 provenance, so a matching init
 * transcript implies the entire chain of prerequisites is in place. We don't re-scan Phase 2
 * + Milestone 1 here — the init orchestrator already did, and an attacker would need to
 * fabricate a matching init transcript (gated by the init lock + atomic write).
 */
async function findVaultStateV2InitProvenance(
  stateRoot: string,
  expected: {
    dkgEpoch: string;
    vaultEk: string;
    caDkgTranscriptHash: string;
    rosterHash: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
  },
): Promise<
  | {
      vaultEkTranscriptHash: string;
      registrationTranscriptHash: string;
      selectedSlots: number[];
      transcriptPath: string;
    }
  | undefined
> {
  const dir = join(stateRoot, "coordinator", "vault_state_v2");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  const lowerVaultEk = expected.vaultEk.replace(/^0x/i, "").toLowerCase();
  const lowerCaDkg = expected.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase();
  const lowerRoster = expected.rosterHash.replace(/^0x/i, "").toLowerCase();
  const lowerSender = expected.senderAddress.replace(/^0x/i, "").toLowerCase();
  const lowerAsset = expected.assetType.replace(/^0x/i, "").toLowerCase();
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const epochPrefix = `${expected.dkgEpoch}__`;
    if (!entry.startsWith(epochPrefix)) continue;
    const transcriptPath = join(dir, entry);
    let raw: string;
    try {
      raw = await readFile(transcriptPath, "utf8");
    } catch {
      continue;
    }
    let artifact: Record<string, unknown>;
    try {
      artifact = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (artifact.scheme !== "vault_state_v2") continue;
    if (typeof artifact.dkgEpoch !== "string" || artifact.dkgEpoch !== expected.dkgEpoch) continue;
    if (typeof artifact.vaultEk !== "string") continue;
    if (typeof artifact.caDkgTranscriptHash !== "string") continue;
    if (typeof artifact.rosterHash !== "string") continue;
    if (typeof artifact.vaultEkTranscriptHash !== "string") continue;
    if (typeof artifact.registrationTranscriptHash !== "string") continue;
    if (typeof artifact.senderAddress !== "string") continue;
    if (typeof artifact.assetType !== "string") continue;
    if (typeof artifact.chainId !== "number") continue;
    if (!Array.isArray(artifact.selectedSlots)) continue;
    if (artifact.vaultEk.replace(/^0x/i, "").toLowerCase() !== lowerVaultEk) continue;
    if (artifact.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase() !== lowerCaDkg) continue;
    if (artifact.rosterHash.replace(/^0x/i, "").toLowerCase() !== lowerRoster) continue;
    if (artifact.senderAddress.replace(/^0x/i, "").toLowerCase() !== lowerSender) continue;
    if (artifact.assetType.replace(/^0x/i, "").toLowerCase() !== lowerAsset) continue;
    if (artifact.chainId !== expected.chainId) continue;
    const selectedSlots: number[] = [];
    for (const slot of artifact.selectedSlots) {
      if (
        !Number.isInteger(slot) ||
        (slot as number) < 0 ||
        (slot as number) >= DEOPERATOR_COUNT
      ) {
        // malformed init transcript; skip
        continue;
      }
      selectedSlots.push(slot as number);
    }
    if (selectedSlots.length !== DEOPERATOR_THRESHOLD) continue;
    return {
      vaultEkTranscriptHash: artifact.vaultEkTranscriptHash,
      registrationTranscriptHash: artifact.registrationTranscriptHash,
      selectedSlots,
      transcriptPath,
    };
  }
  return undefined;
}

/**
 * Milestone 3a — extended version of findVaultStateV2InitProvenance that ALSO lifts the
 * persisted init transcript's `transcriptHash` field (so the MPCCA withdraw orchestrator can
 * pin the init transcript hash into every per-slot round1 request body). The lift is necessary
 * because the worker's provenance gate cross-references this value, and the orchestrator MUST
 * use the SAME value the persisted artifact carries — not the request body's claim.
 *
 * Returns:
 *   { vaultEkTranscriptHash, registrationTranscriptHash, selectedSlots, transcriptPath,
 *     transcriptHash }
 * where `transcriptHash` is the init artifact's final transcript hash. Returns undefined if no
 * matching transcript is found.
 */
async function findVaultStateV2InitWithTranscriptHash(
  stateRoot: string,
  expected: {
    dkgEpoch: string;
    vaultEk: string;
    caDkgTranscriptHash: string;
    rosterHash: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
  },
): Promise<
  | {
      vaultEkTranscriptHash: string;
      registrationTranscriptHash: string;
      selectedSlots: number[];
      transcriptPath: string;
      transcriptHash: string;
    }
  | undefined
> {
  const dir = join(stateRoot, "coordinator", "vault_state_v2");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  const lowerVaultEk = expected.vaultEk.replace(/^0x/i, "").toLowerCase();
  const lowerCaDkg = expected.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase();
  const lowerRoster = expected.rosterHash.replace(/^0x/i, "").toLowerCase();
  const lowerSender = expected.senderAddress.replace(/^0x/i, "").toLowerCase();
  const lowerAsset = expected.assetType.replace(/^0x/i, "").toLowerCase();
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const epochPrefix = `${expected.dkgEpoch}__`;
    if (!entry.startsWith(epochPrefix)) continue;
    const transcriptPath = join(dir, entry);
    let raw: string;
    try {
      raw = await readFile(transcriptPath, "utf8");
    } catch {
      continue;
    }
    let artifact: Record<string, unknown>;
    try {
      artifact = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (artifact.scheme !== "vault_state_v2") continue;
    if (typeof artifact.dkgEpoch !== "string" || artifact.dkgEpoch !== expected.dkgEpoch) continue;
    if (typeof artifact.vaultEk !== "string") continue;
    if (typeof artifact.caDkgTranscriptHash !== "string") continue;
    if (typeof artifact.rosterHash !== "string") continue;
    if (typeof artifact.vaultEkTranscriptHash !== "string") continue;
    if (typeof artifact.registrationTranscriptHash !== "string") continue;
    if (typeof artifact.transcriptHash !== "string") continue;
    if (typeof artifact.senderAddress !== "string") continue;
    if (typeof artifact.assetType !== "string") continue;
    if (typeof artifact.chainId !== "number") continue;
    if (!Array.isArray(artifact.selectedSlots)) continue;
    if (artifact.vaultEk.replace(/^0x/i, "").toLowerCase() !== lowerVaultEk) continue;
    if (artifact.caDkgTranscriptHash.replace(/^0x/i, "").toLowerCase() !== lowerCaDkg) continue;
    if (artifact.rosterHash.replace(/^0x/i, "").toLowerCase() !== lowerRoster) continue;
    if (artifact.senderAddress.replace(/^0x/i, "").toLowerCase() !== lowerSender) continue;
    if (artifact.assetType.replace(/^0x/i, "").toLowerCase() !== lowerAsset) continue;
    if (artifact.chainId !== expected.chainId) continue;
    const selectedSlots: number[] = [];
    for (const slot of artifact.selectedSlots) {
      if (
        !Number.isInteger(slot) ||
        (slot as number) < 0 ||
        (slot as number) >= DEOPERATOR_COUNT
      ) {
        continue;
      }
      selectedSlots.push(slot as number);
    }
    if (selectedSlots.length !== DEOPERATOR_THRESHOLD) continue;
    return {
      vaultEkTranscriptHash: artifact.vaultEkTranscriptHash,
      registrationTranscriptHash: artifact.registrationTranscriptHash,
      selectedSlots,
      transcriptPath,
      transcriptHash: artifact.transcriptHash,
    };
  }
  return undefined;
}

/**
 * Milestone 3a — verify Milestone 2b observe_deposit provenance for a given depositCount.
 *
 * Codex M3a P2 #1: collect the FULL ORDERED VECTOR of observed-deposit transcripts from
 * depositCount=1 to depositCount=N. The MPCCA withdraw transcript binds this ordering so the
 * milestone 4 crypto can prove "every confirmed deposit through cursor N has been observed
 * by 5-of-7 workers in the canonical order". A single-element vector (the pre-fix shape)
 * gave the appearance of provenance but couldn't catch an out-of-order or skipped cursor.
 *
 * Scans `<stateRoot>/coordinator/vault_state_v2_observed/` for every artifact whose
 * (dkgEpoch, vaultEk, rosterHash, senderAddress, assetType, chainId) tuple matches and
 * whose depositCount is in `1..=N`. Returns the transcripts sorted ascending by depositCount,
 * with a uniqueness check that every cursor 1..=N appears exactly once. Missing cursors →
 * undefined.
 *
 * P3 residual: this scan is O(directory size). For high-deposit-count vaults the directory
 * grows linearly; production hardening could index by `(dkgEpoch, depositCount)` first.
 */
async function findVaultStateV2ObservedProvenance(
  stateRoot: string,
  expected: {
    dkgEpoch: string;
    depositCount: number;
    vaultEk: string;
    rosterHash: string;
    senderAddress: string;
    assetType: string;
    chainId: number;
  },
): Promise<
  | {
      observedDepositTranscriptHashes: string[];
      transcriptPaths: string[];
    }
  | undefined
> {
  if (expected.depositCount < 1) return undefined;
  const dir = join(stateRoot, "coordinator", "vault_state_v2_observed");
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  const lowerVaultEk = expected.vaultEk.replace(/^0x/i, "").toLowerCase();
  const lowerRoster = expected.rosterHash.replace(/^0x/i, "").toLowerCase();
  const lowerSender = expected.senderAddress.replace(/^0x/i, "").toLowerCase();
  const lowerAsset = expected.assetType.replace(/^0x/i, "").toLowerCase();
  // Index matching artifacts by cursor. First-wins for retries at the same cursor (multiple
  // observe-deposit calls can target the same cursor; we accept the first artifact present
  // for that slot).
  const byCursor = new Map<number, { transcriptHash: string; transcriptPath: string }>();
  const epochPrefix = `${expected.dkgEpoch}__`;
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    if (!entry.startsWith(epochPrefix)) continue;
    const transcriptPath = join(dir, entry);
    let raw: string;
    try {
      raw = await readFile(transcriptPath, "utf8");
    } catch {
      continue;
    }
    let artifact: Record<string, unknown>;
    try {
      artifact = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (artifact.scheme !== "vault_state_v2_observe_deposit") continue;
    if (typeof artifact.dkgEpoch !== "string" || artifact.dkgEpoch !== expected.dkgEpoch) continue;
    if (typeof artifact.vaultEk !== "string") continue;
    if (typeof artifact.rosterHash !== "string") continue;
    if (typeof artifact.senderAddress !== "string") continue;
    if (typeof artifact.assetType !== "string") continue;
    if (typeof artifact.chainId !== "number") continue;
    if (typeof artifact.depositCount !== "number") continue;
    if (typeof artifact.transcriptHash !== "string") continue;
    if (artifact.vaultEk.replace(/^0x/i, "").toLowerCase() !== lowerVaultEk) continue;
    if (artifact.rosterHash.replace(/^0x/i, "").toLowerCase() !== lowerRoster) continue;
    if (artifact.senderAddress.replace(/^0x/i, "").toLowerCase() !== lowerSender) continue;
    if (artifact.assetType.replace(/^0x/i, "").toLowerCase() !== lowerAsset) continue;
    if (artifact.chainId !== expected.chainId) continue;
    const cursor = artifact.depositCount;
    if (cursor < 1 || cursor > expected.depositCount) continue;
    // First-wins (in directory iteration order); retries at the same cursor are coalesced.
    if (!byCursor.has(cursor)) {
      byCursor.set(cursor, { transcriptHash: artifact.transcriptHash, transcriptPath });
    }
  }
  // Strict completeness gate: every cursor 1..=N must be present.
  const orderedHashes: string[] = [];
  const orderedPaths: string[] = [];
  for (let c = 1; c <= expected.depositCount; c += 1) {
    const entry = byCursor.get(c);
    if (!entry) return undefined;
    orderedHashes.push(entry.transcriptHash);
    orderedPaths.push(entry.transcriptPath);
  }
  // Uniqueness: each transcriptHash must be distinct (defense in depth — catches a coordinator
  // that's been tricked into reusing the same artifact for two different cursors).
  const seen = new Set<string>();
  for (const h of orderedHashes) {
    const norm = h.replace(/^0x/i, "").toLowerCase();
    if (seen.has(norm)) return undefined;
    seen.add(norm);
  }
  return {
    observedDepositTranscriptHashes: orderedHashes,
    transcriptPaths: orderedPaths,
  };
}
