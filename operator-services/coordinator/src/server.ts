import Fastify, { type FastifyInstance } from "fastify";
import {
  assembleCaRegistrationV2Transcript,
  assembleVaultEkTranscript,
  assembleVaultStateV2InitTranscript,
  assembleVaultStateV2ObserveDepositTranscript,
  CaRegistrationV2Error,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  DepositFrostAttestError,
  EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1,
  ForbiddenPlaintextFieldError,
  MpccaWithdrawSubmitError,
  MpccaWithdrawV2Error,
  caDkgV2RosterHash,
  caRegistrationV2Round1WorkerTranscriptHash,
  caRegistrationV2Round2WorkerTranscriptHash,
  frostDkgV2RosterHash,
  ingressEnvelopesHash,
  lagrangeCoefficientsAtZero,
  mpccaWithdrawFinalizeAggregateHash,
  mpccaWithdrawFinalizeAggregatedCommitmentsHash,
  mpccaWithdrawFinalizeDeriveChallenge,
  mpccaWithdrawFinalizeWorkerTranscriptHash,
  mpccaWithdrawRound1WorkerTranscriptHash,
  mpccaWithdrawRound2AggregateHash,
  mpccaWithdrawRound2StatementInputsHash,
  mpccaWithdrawRound2WorkerTranscriptHash,
  DK_BASE_INDICES_CANONICAL,
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
  buildCaPayloadFromFinalizeArtifact,
  caPayloadHashRawToFrV2,
  caPayloadHashRawV2,
  bcsEncodeDepositAttestationV2,
  bcsEncodeWithdrawAttestationV2,
  depositAttestationTranscriptHash,
  parseDepositFrostAttestRequest,
  parseFrostAggregateSignatureResponse,
  parseFrostNonceCommitmentResponse,
  parseFrostPartialSignatureResponse,
  parseMpccaWithdrawFinalizeDkResult,
  parseMpccaWithdrawFinalizeOrchestrateRequest,
  parseMpccaWithdrawFrostAttestStartRequest,
  parseMpccaWithdrawRound1Response,
  parseMpccaWithdrawRound2DkResult,
  parseMpccaWithdrawRound2OrchestrateRequest,
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
  type DepositFrostAttestArtifact,
  type DepositFrostAttestRequest,
  type FrostDkgV2Roster,
  type FrostRound1Broadcast,
  type FrostRound2Envelope,
  type MpccaWithdrawFinalizeDkResult,
  type MpccaWithdrawFinalizeOrchestrateRequest,
  type MpccaWithdrawFrostAttestStartRequest,
  type MpccaWithdrawRound1Contribution,
  type MpccaWithdrawRound2DkPartial,
  type MpccaWithdrawRound2DkResult,
  type MpccaWithdrawRound2OrchestrateRequest,
  type MpccaWithdrawRound2StatementInputFields,
  type ObserveDepositContribution,
  type SessionShareEnvelope,
  type VaultEkContribution,
  type VaultStateV2InitContribution,
} from "@eunoma/deop-protocol";
import { aggregateRistrettoCommitments, sha256, bytesToHex } from "@eunoma/shared";
import { HttpError, requireBearer } from "@eunoma/shared";
import {
  assembleWithdrawV2CallArgs,
  isNotImplementedPhasePassthrough,
  loadMpccaFinalizeTranscript,
  mpccaFinalizeTranscriptPath,
  waitForTx,
  WithdrawSubmitAssemblyError,
  type MpccaWithdrawFinalizeArtifact,
  type WithdrawV2CallArgsShape,
} from "@eunoma/shared";
import { assertNoForbiddenPlaintextFields } from "@eunoma/deop-protocol";
import {
  mkdir,
  rename,
  writeFile,
  chmod,
  readdir,
  readFile,
  unlink,
  link,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { InMemoryCoordinatorStore, type CoordinatorStore } from "./store.js";
import { registerBalanceDecryptRoute } from "./routes/balance_decrypt.js";
import { registerVaultResyncRoute } from "./routes/vault_resync.js";
import { registerNormalizeSigmaS0Route } from "./routes/normalize_sigma_s0.js";
import { triggerBridgeMaintenance } from "./bridge_maintenance_pipeline.js";

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

/**
 * Validated public ASP-set artifact shape (subset the coordinator serves). Written by
 * scripts/local_run_asp_cycle.mjs (makeAspSetArtifact). Public commitments only — no secrets.
 */
interface AspSetArtifact {
  rootHex: string;
  treeDepth: number;
  ipfsCid?: string | null;
  commitments: string[];
}

/**
 * Read + validate <stateRoot>/coordinator/asp_set.json. Returns the artifact, or null when
 * stateRoot is unconfigured / the file is missing / unreadable / malformed (callers map null
 * to a 503, mirroring /v2/pool/state's missing-tree behavior).
 */
async function readAspSetArtifact(stateRoot: string | undefined): Promise<AspSetArtifact | null> {
  if (!stateRoot) return null;
  const aspPath = join(stateRoot, "coordinator", "asp_set.json");
  let raw: {
    rootHex?: unknown;
    treeDepth?: unknown;
    ipfsCid?: unknown;
    commitments?: unknown;
  };
  try {
    raw = JSON.parse(await readFile(aspPath, "utf8")) as typeof raw;
  } catch {
    return null;
  }
  if (
    typeof raw.rootHex !== "string" ||
    typeof raw.treeDepth !== "number" ||
    !Array.isArray(raw.commitments) ||
    !raw.commitments.every((c) => typeof c === "string")
  ) {
    return null;
  }
  return {
    rootHex: raw.rootHex,
    treeDepth: raw.treeDepth,
    ipfsCid: typeof raw.ipfsCid === "string" ? raw.ipfsCid : null,
    commitments: raw.commitments as string[],
  };
}

function normalizeEventAddr(value: string | undefined): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const stripped = value.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{1,64}$/.test(stripped)) return null;
  return stripped.padStart(64, "0");
}

function normalizeEventHex(value: unknown, key: string): string {
  if (typeof value !== "string") {
    throw new Error(`withdraw_resync_event_${key}_missing`);
  }
  const stripped = value.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(stripped)) {
    throw new Error(`withdraw_resync_event_${key}_bad_hex`);
  }
  return stripped;
}

function parseWithdrawEventForSubmitResync(tx: unknown, bridgePackage: string) {
  const wantBridge = normalizeEventAddr(bridgePackage);
  if (!wantBridge) throw new Error("withdraw_resync_bad_bridge_package");
  if (tx === null || typeof tx !== "object" || Array.isArray(tx)) {
    throw new Error("withdraw_resync_tx_must_be_object");
  }
  const txObj = tx as Record<string, unknown>;
  const events = Array.isArray(txObj.events) ? txObj.events : null;
  if (!events) throw new Error("withdraw_resync_tx_events_missing");

  for (const event of events) {
    if (event === null || typeof event !== "object" || Array.isArray(event)) continue;
    const rec = event as Record<string, unknown>;
    const type = typeof rec.type === "string" ? rec.type : "";
    const [addr, moduleName, eventName] = type.split("::");
    if (
      normalizeEventAddr(addr) !== wantBridge ||
      moduleName !== "eunoma_bridge" ||
      (eventName !== "WithdrawEventV2" && eventName !== "WithdrawEventV3")
    ) {
      continue;
    }
    const data = rec.data;
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("withdraw_resync_event_missing_data");
    }
    const body = data as Record<string, unknown>;
    const seqRaw = body.vault_sequence;
    const eventVaultSequence =
      typeof seqRaw === "string" ? Number(seqRaw) : typeof seqRaw === "number" ? seqRaw : NaN;
    if (!Number.isSafeInteger(eventVaultSequence) || eventVaultSequence < 0) {
      throw new Error("withdraw_resync_event_bad_vault_sequence");
    }
    return {
      root: normalizeEventHex(body.root, "root"),
      nullifierHash: normalizeEventHex(body.nullifier_hash, "nullifier_hash"),
      recipientHash: normalizeEventHex(body.recipient_hash, "recipient_hash"),
      requestHash: normalizeEventHex(body.request_hash, "request_hash"),
      eventVaultSequence,
    };
  }

  throw new Error("withdraw_resync_event_not_found");
}

async function fetchAptosTransactionByHash(
  nodeUrl: string,
  txHash: string,
  fetchImpl: typeof fetch = fetch,
): Promise<unknown> {
  const url = new URL(`/v1/transactions/by_hash/${txHash}`, nodeUrl).toString();
  const res = await fetchImpl(url);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`withdraw_resync_tx_fetch_failed:${res.status}:${text.slice(0, 160)}`);
  }
  return res.json();
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
  /**
   * M4 Commit 2 — optional `AbortSignal` to bound the per-worker request. The default
   * `forwardToRosterNode` passes the signal to `fetch`; injected test forwarders may
   * ignore the signal (existing call sites don't pass one, so backwards compatibility
   * is preserved).
   */
  signal?: AbortSignal,
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
   * CP3 deposit-delegate submitter for POST /v2/deposit/delegate-submit. Forwards the assembled
   * DepositV3DelegateArgs to the relayer's /v3/relayer/submit/deposit (prepare + step2a; step2b
   * stays user-signed). If absent, the route returns 502. Built via
   * buildDefaultDepositRelayerSubmitter; tests inject mocks.
   */
  depositRelayerSubmitter?: (
    args: unknown,
  ) => Promise<{ accepted: boolean; txHashes: string[]; simulated: boolean }>;
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
  /**
   * M4 Commit 2 — per-worker `AbortController` timeout for the round2 fan-out. Default 30s.
   * When the timeout fires, the underlying `fetch` is aborted and the coordinator surfaces
   * a `round2_worker_timeout` 502 for the slow slot.
   */
  mpccaWithdrawRound2WorkerTimeoutMs?: number;
  /** M4 commit 4 — per-worker AbortController timeout for the finalize fan-out. Default 30s. */
  mpccaWithdrawFinalizeWorkerTimeoutMs?: number;
  /**
   * M10-l (codex iter-6 P1-13): bridge vault address. `/v2/balance/decrypt`
   * rejects requests whose `vaultAddress` doesn't match this configured value.
   * Without this gate, a caller with the coordinator bearer can target any
   * confidential balance under the same DKG.
   */
  bridgeVaultAddress?: string;
  /**
   * M10-l (codex iter-6 P1-13): bridge confidential-asset type tag. Same
   * rationale as `bridgeVaultAddress` — narrows the threshold-decrypt surface
   * to a single (vault, asset) pair.
   */
  bridgeAssetType?: string;
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
    if (
      req.method === "GET" &&
      (req.url === "/v2/roster" ||
        req.url === "/v2/health" ||
        req.url === "/v2/pool/state" ||
        req.url === "/v2/state-tree" ||
        req.url === "/v2/asp-set" ||
        req.url === "/v2/asp-root-current")
    ) {
      return;
    }
    requireBearer(req.headers.authorization, opts.bearerToken);
  });

  server.get("/v2/health", async () => {
    const submitEnabled = process.env.RELAYER_SUBMIT_ENABLED === "1";
    const relayerConfigured = Boolean(process.env.RELAYER_URL);
    return {
      ok: true,
      simulationReady: true,
      submitEnabled,
      liveSubmitReady: submitEnabled && relayerConfigured,
      threshold: opts.roster?.threshold ?? opts.caDkgV2Roster?.threshold,
      rosterHash: currentRosterHash,
      caDkgV2RosterHash: currentCaDkgV2RosterHash,
    };
  });

  // The browser verifies the roster against the on-chain DeoperatorConfigV2.roster_hash, which
  // commits to the CaDkgV2Roster (the real DKG HPKE keys). The DeoperatorRoster carries fixture
  // HPKE keys (different digest), so prefer the CaDkgV2Roster here whenever it is configured —
  // otherwise the client recompute won't match chain and shares encrypt to keys nodes can't open.
  server.get("/v2/roster", async () =>
    opts.caDkgV2Roster
      ? {
          caDkgV2Roster: opts.caDkgV2Roster,
          caDkgV2RosterHash: currentCaDkgV2RosterHash,
        }
      : {
          ...opts.roster,
          rosterHash: currentRosterHash,
        },
  );

  // Public pool state for the browser withdraw flow: the ASP-era dynamic-depth LeanIMT state tree
  // maintained off-chain at <stateRoot>/coordinator/state_leanimt_tree.json. Its latestRootHex is the
  // root recorded on-chain and the root the 12-public withdraw/ragequit circuits prove against. The
  // older fixed-depth commitment_tree_v2.json is retained as a build artifact, but must not be served
  // as current_finalized_root here. Safety is enforced on-chain — a withdraw is only accepted if its
  // root is in BridgeVault.known_roots and the proof includes the note's commitment — so this data is
  // non-authoritative (liveness only).
  server.get("/v2/pool/state", async (_req, reply) => {
    if (!opts.stateRoot) {
      return reply.code(503).send({ error: "pool_state_unavailable" });
    }
    const treePath = join(opts.stateRoot, "coordinator", "state_leanimt_tree.json");
    let tree: { scheme?: unknown; latestRootHex?: unknown; leafCount?: unknown; leaves?: unknown };
    try {
      tree = JSON.parse(await readFile(treePath, "utf8")) as typeof tree;
    } catch {
      return reply.code(503).send({ error: "pool_state_unavailable" });
    }
    const root = tree.latestRootHex;
    const leaves = tree.leaves;
    const leafCount = tree.leafCount;
    if (
      tree.scheme !== "eunoma_leanimt_tree_v1" ||
      typeof root !== "string" ||
      !Array.isArray(leaves) ||
      (typeof leafCount !== "number" && typeof leafCount !== "string")
    ) {
      return reply.code(503).send({ error: "pool_state_malformed" });
    }
    return {
      current_finalized_root: root,
      pending_next_index: String(leafCount),
      commitments: leaves,
    };
  });

  // Dynamic-depth LeanIMT STATE tree snapshot for the browser withdraw flow. This is the tree the
  // withdraw circuit verifies state inclusion against (the recorded on-chain state root is this
  // snapshot's latestRootHex — see ops/scripts/refresh_known_root_cycle.sh). Served verbatim from
  // <stateRoot>/coordinator/state_leanimt_tree.json. Same liveness-only / non-authoritative
  // posture as /v2/pool/state: safety is enforced on-chain (root ∈ known_roots + proof binds the
  // note's commitment). Mirrors /v2/pool/state's 503-on-missing behavior.
  server.get("/v2/state-tree", async (_req, reply) => {
    if (!opts.stateRoot) {
      return reply.code(503).send({ error: "state_tree_unavailable" });
    }
    const treePath = join(opts.stateRoot, "coordinator", "state_leanimt_tree.json");
    let snap: {
      scheme?: unknown;
      treeDepth?: unknown;
      leaves?: unknown;
      depositMeta?: unknown;
      latestRootHex?: unknown;
    };
    try {
      snap = JSON.parse(await readFile(treePath, "utf8")) as typeof snap;
    } catch {
      return reply.code(503).send({ error: "state_tree_unavailable" });
    }
    if (
      snap.scheme !== "eunoma_leanimt_tree_v1" ||
      typeof snap.latestRootHex !== "string" ||
      typeof snap.treeDepth !== "number" ||
      !Array.isArray(snap.leaves) ||
      !Array.isArray(snap.depositMeta)
    ) {
      return reply.code(503).send({ error: "state_tree_malformed" });
    }
    return {
      scheme: snap.scheme,
      treeDepth: snap.treeDepth,
      leaves: snap.leaves,
      depositMeta: snap.depositMeta,
      latestRootHex: snap.latestRootHex,
    };
  });

  // The PUBLIC ASP (Association Set Provider) approved-commitment set + its LeanIMT root. The
  // browser pulls this to build the second (ASP) inclusion proof for a curated private withdraw.
  // Written by scripts/local_run_asp_cycle.mjs (makeAspSetArtifact) to
  // <stateRoot>/coordinator/asp_set.json. Public commitments only — no secrets.
  // Mirrors /v2/pool/state's 503-on-missing behavior.
  server.get("/v2/asp-set", async (_req, reply) => {
    const artifact = await readAspSetArtifact(opts.stateRoot);
    if (!artifact) {
      return reply.code(503).send({ error: "asp_set_unavailable" });
    }
    return {
      aspRootHex: artifact.rootHex,
      aspTreeDepth: artifact.treeDepth,
      ipfsCid: artifact.ipfsCid ?? null,
      commitments: artifact.commitments,
    };
  });

  // Lightweight ASP root pointer (no commitment list) from the same asp_set.json — for clients
  // that only need to know which ASP root/CID is current. Mirrors /v2/pool/state's 503-on-missing.
  server.get("/v2/asp-root-current", async (_req, reply) => {
    const artifact = await readAspSetArtifact(opts.stateRoot);
    if (!artifact) {
      return reply.code(503).send({ error: "asp_set_unavailable" });
    }
    return {
      aspRootHex: artifact.rootHex,
      aspTreeDepth: artifact.treeDepth,
      ipfsCid: artifact.ipfsCid ?? null,
    };
  });

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
      const depositTxHashRaw = raw.depositTxHash;
      let depositTxHash: string | undefined;
      if (depositTxHashRaw !== undefined) {
        if (
          typeof depositTxHashRaw !== "string" ||
          !/^0x[0-9a-fA-F]{64}$/.test(depositTxHashRaw)
        ) {
          return reply.code(400).send({
            error: "invalid_request",
            message: "depositTxHash must be 0x + 64 hex chars when supplied",
          });
        }
        depositTxHash = depositTxHashRaw.toLowerCase();
      }
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

        // NORMALIZE plan (2026-05-27) — event-driven pipeline fan-out. Run the
        // refresh_known_root_cycle.sh wrapper after the HTTP response has flushed, so
        // the observe-deposit caller is not delayed by rollover/normalize/root work.
        // Coalesce-on-contention is handled inside the trigger.
        reply.raw.once("finish", () => {
          triggerBridgeMaintenance({
            repoRoot: process.env.EUNOMA_REPO_ROOT || process.cwd(),
            logger: req.log,
            extraDepositTxHashes: depositTxHash ? [depositTxHash] : undefined,
          });
        });

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

      // Milestone 1 — Threshold ElGamal Amount Ingress validation. User-supplied fields:
      // - amountCommitment: 32-byte hex compressed Ristretto.
      // - perShareCommitments[5]: per-slot Pedersen commitments.
      // - ingressEnvelopes[5]: HPKE envelopes per sorted-selectedSlot.
      // The aggregate-commitment invariant (Σ perShareCommitments == amountCommitment) is
      // deferred to defense-in-depth in the M1 wire-completion commit; each worker recomputes
      // G·a_j + H·b_j and compares to its slot's perShareCommitment, which is the per-share
      // binding the coordinator must propagate intact.
      const rawAmountCommitment = raw.amountCommitment;
      if (typeof rawAmountCommitment !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(rawAmountCommitment)) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "amountCommitment must be a 32-byte hex string (compressed Ristretto)",
        });
      }
      const amountCommitment = rawAmountCommitment;
      const rawPerShareCommitments = raw.perShareCommitments;
      if (!Array.isArray(rawPerShareCommitments) || rawPerShareCommitments.length !== DEOPERATOR_THRESHOLD) {
        return reply.code(400).send({
          error: "ingress_commitment_count_mismatch",
          message: `perShareCommitments must have exactly ${DEOPERATOR_THRESHOLD} entries`,
        });
      }
      const perShareCommitments: string[] = [];
      for (let i = 0; i < rawPerShareCommitments.length; i += 1) {
        const c = rawPerShareCommitments[i];
        if (typeof c !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(c)) {
          return reply.code(400).send({
            error: "ingress_invalid_commitment_shape",
            message: `perShareCommitments[${i}] must be 32-byte hex (compressed Ristretto)`,
          });
        }
        perShareCommitments.push(c);
      }
      const rawIngressEnvelopes = raw.ingressEnvelopes;
      if (!Array.isArray(rawIngressEnvelopes) || rawIngressEnvelopes.length !== DEOPERATOR_THRESHOLD) {
        return reply.code(400).send({
          error: "ingress_envelope_count_mismatch",
          message: `ingressEnvelopes must have exactly ${DEOPERATOR_THRESHOLD} entries`,
        });
      }
      const ingressEnvelopes = rawIngressEnvelopes.map((entry, i) => {
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          throw new Error(`ingressEnvelopes[${i}] must be an HpkeEnvelope object`);
        }
        const obj = entry as Record<string, unknown>;
        if (obj.kem !== "DHKEM_X25519_HKDF_SHA256") {
          throw new Error(`ingressEnvelopes[${i}].kem must be DHKEM_X25519_HKDF_SHA256`);
        }
        if (obj.kdf !== "HKDF_SHA256") {
          throw new Error(`ingressEnvelopes[${i}].kdf must be HKDF_SHA256`);
        }
        if (obj.aead !== "AES_256_GCM") {
          throw new Error(`ingressEnvelopes[${i}].aead must be AES_256_GCM`);
        }
        if (typeof obj.enc !== "string" || obj.enc.length === 0) {
          throw new Error(`ingressEnvelopes[${i}].enc must be a non-empty hex string`);
        }
        if (typeof obj.ciphertext !== "string" || obj.ciphertext.length === 0) {
          throw new Error(`ingressEnvelopes[${i}].ciphertext must be a non-empty hex string`);
        }
        if (typeof obj.aadHash !== "string" || obj.aadHash.length === 0) {
          throw new Error(`ingressEnvelopes[${i}].aadHash must be a non-empty hex string`);
        }
        return {
          kem: "DHKEM_X25519_HKDF_SHA256" as const,
          kdf: "HKDF_SHA256" as const,
          aead: "AES_256_GCM" as const,
          enc: obj.enc as string,
          ciphertext: obj.ciphertext as string,
          aadHash: obj.aadHash as string,
        };
      });
      // Pre-compute the ingress envelopes hash so every transcript-hash recompute uses the
      // exact same bytes the workers will fold into their per-slot worker_transcript_hash.
      const computedIngressEnvelopesHash = ingressEnvelopesHash(ingressEnvelopes);

      // Coordinator-side defense-in-depth: assert Σ perShareCommitments == amountCommitment
      // BEFORE fan-out, so a malicious user can't drift the aggregate from what the workers
      // will commit to. The per-share Pedersen verify in each worker catches mismatches
      // between (a_j, b_j) and perShareCommitments[j]; THIS check catches a user that submits
      // a misleading amountCommitment relative to the actually-distributed shares.
      try {
        const aggregateSum = await aggregateRistrettoCommitments(perShareCommitments);
        if (aggregateSum.toLowerCase() !== amountCommitment.replace(/^0x/i, "").toLowerCase()) {
          return reply.code(400).send({
            error: "ingress_aggregate_commitment_mismatch",
            message: `Σ perShareCommitments does not equal amountCommitment (aggregateSum=${aggregateSum}, claimed=${amountCommitment})`,
          });
        }
      } catch (err) {
        return reply.code(400).send({
          error: "ingress_invalid_commitment_shape",
          message: err instanceof Error ? err.message : "unknown",
        });
      }

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
        // and playerId. M1: every body carries the M1 ingress envelope set; each worker opens
        // ONLY its own envelope (envelopes[playerId]) on its side.
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
          // M1 ingress fields — passed unchanged to every worker.
          amountCommitment,
          perShareCommitments,
          ingressEnvelopes,
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
          // Milestone 1 expectation: every worker returns 200 with completed:true. Anything
          // else means either the worker rejected the ingress (per-share commitment mismatch,
          // zero share, HPKE failure, etc.) or it failed with a public-binding error (provenance
          // gate kicked in for that slot and not the others).
          if (res.value.statusCode !== 200) {
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
                "Milestone 1 expected worker to return 200 with completed:true; received different status",
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
          // Defense in depth: re-derive the worker transcript hash from public inputs and
          // assert byte-equality. Under M1, the round1 hash binds the 3 ingress fields too.
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
            amountCommitment,
            perShareCommitments,
            ingressEnvelopesHash: computedIngressEnvelopesHash,
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
        // Under M1, every worker returns completed:true with ingressTranscriptHash; phase
        // divergence is no longer a concept for round1. ingressTranscriptHash agreement was
        // already enforced inside parseMpccaWithdrawRound1Response (it must equal
        // workerTranscriptHash) and via the expectedWorkerHash equality check above.

        // 10. Persist a completed round-1 (ingress) transcript artifact.
        const perSlotContributions: MpccaWithdrawRound1Contribution[] = sortedSelectedSlots.map(
          (slot) => {
            const r = responsesBySlot.get(slot)!;
            return {
              slot,
              sessionStateHash: r.sessionStateHash,
              workerTranscriptHash: r.workerTranscriptHash,
              completed: true as const,
              ingressTranscriptHash: r.ingressTranscriptHash,
            };
          },
        );
        // Codex M3a P2 #3: build the artifact with a real `transcriptHash` digest. Pre-fix
        // the field was set to the scheme literal `"mpcca_withdraw_v2_round1_partial"`, so
        // recovery/audit clients could not pin the persisted artifact by the returned hash.
        // We sha256(canonicalize(artifact-without-transcriptHash)) and embed the digest into
        // the artifact, so a later reader can recompute the same hash and verify integrity.
        const round1ArtifactWithoutHash = {
          scheme: "mpcca_withdraw_v2_round1_ingress" as const,
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
          // M1 public binding — the envelope bodies are NOT persisted in this coordinator
          // artifact (envelope bodies live worker-side, HPKE-encrypted-at-rest); only the
          // public commitments and the envelopes-hash are persisted for audit.
          amountCommitment,
          perShareCommitments,
          ingressEnvelopesHash: computedIngressEnvelopesHash,
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

        // 11. Return 200 with the completed M1 ingress round1 outputs. The accept flag stays
        // false because the OVERALL withdraw is mid-flight — M4 will fill in round2/prove/finalize.
        return reply.code(200).send({
          accepted: false,
          requestId,
          dkgEpoch,
          depositCount,
          round: "round1",
          completed: true,
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
          amountCommitment,
          perShareCommitments,
          ingressEnvelopesHash: computedIngressEnvelopesHash,
          perSlotContributions,
          transcriptHash: round1TranscriptHash,
          transcriptPath,
          message:
            "Milestone 1 ingress: amount/blind shares received and validated by all 5 workers; " +
            "round2/prove/finalize crypto deferred to milestone 4",
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
  // M4 Commit 2 — MPCCA withdraw V2 round2 fan-out orchestrator.
  //
  // POST /v2/withdraw/mpcca/round2 takes the user's Aptos CA TransferV1 Statement input fields +
  // pre-computed user-side sigma artifacts + Bulletproof bytes, lifts the public chained-round
  // binding from the persisted `__round1.json` artifact, and fans out the per-worker Round2Request
  // (chained envelope + Statement inputs only — user sigma artifacts NEVER cross the worker
  // boundary). Workers contribute the dk-component partial commitments at canonical BASE_DK_SET
  // positions `[0, 17]` (programmatically derived by each worker, never trusted from the wire).
  //
  // Privacy contract: workers see only the Statement inputs (public chain ciphertexts +
  // recipient_ek). The user's Bulletproof bytes / per-chunk commitments / sigma α-points /
  // response shares stay coordinator-side and are persisted echoed into `__round2.json` for
  // commit 4 (finalize) to consume.
  //
  // Wire shape:
  //   1. Forbidden-plaintext-field guard on the raw body.
  //   2. `parseMpccaWithdrawRound2OrchestrateRequest` — strict shape validation.
  //   3. `isSafeId(requestId)` before any FS path construction.
  //   4. Load `__round1.json` for `(dkgEpoch, requestId)` from the persisted M1 ingress
  //      artifact. Verify every identity field matches the round2 body. 400
  //      `round1_transcript_not_found` if absent; 400 `round1_transcript_identity_mismatch`
  //      if any field drifts.
  //   5. Acquire `vaultMpccaWithdrawInFlight` (re-used from M3a; ensures only one withdraw
  //      session at a time). 409 `vault_mpcca_withdraw_in_flight` on contention.
  //   6. Build per-worker `Round2Request` body: chained-round envelope (with
  //      `previousRoundTranscriptHash` = round1.transcriptHash and
  //      `previousRoundCommitments[i]` = round1.perSlotContributions[i].ingressTranscriptHash)
  //      plus the 7 Statement input fields. Critically, user-supplied proof artifacts
  //      (Bulletproof bytes, user sigma commitments, etc.) are NOT forwarded — they stay
  //      coordinator-side.
  //   7. `Promise.all` fan-out with per-worker `AbortController` timeout (default 30s, configurable
  //      via `mpccaWithdrawRound2WorkerTimeoutMs`). A worker timeout surfaces 502
  //      `round2_worker_timeout` for that slot.
  //   8. Collect 5 `Round2DkResult` artifacts. Validate:
  //      a. Every slot in `sortedSelectedSlots` returned a body (under-quorum / duplicate /
  //         unknown slot all surface 502).
  //      b. Each worker's `workerTranscriptHash` byte-equals the coordinator's recompute
  //         via `mpccaWithdrawRound2WorkerTranscriptHash` (binds round1 chain + Statement).
  //      c. Every worker's `dkBaseIndicesUsed` equals the canonical `[0, 17]`. Cross-worker
  //         divergence surfaces 502 `dk_base_indices_divergence`.
  //   9. Compute deterministic `round2AggregateHash` via `mpccaWithdrawRound2AggregateHash`.
  //  10. Persist `__round2.json` at
  //      `<stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__round2.json` (atomic
  //      0o600). The persisted shape includes the user's proof artifacts so commit 4 (finalize)
  //      can read them without re-asking the user.
  //  11. Return 200 with deterministic `transcriptHash` (= `round2AggregateHash`),
  //      `previousRoundTranscriptHash` (= round1.transcriptHash), per-slot dk partials.
  // =================================================================================================
  const mpccaWithdrawRound2WorkerTimeoutMs =
    opts.mpccaWithdrawRound2WorkerTimeoutMs ?? 30_000;
  server.post("/v2/withdraw/mpcca/round2", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // 1+2. Forbidden-plaintext-field guard + parse.
      let parsed: MpccaWithdrawRound2OrchestrateRequest;
      try {
        parsed = parseMpccaWithdrawRound2OrchestrateRequest(raw);
      } catch (err) {
        if (err instanceof ForbiddenPlaintextFieldError) {
          return reply
            .code(400)
            .send({ error: "forbidden_plaintext_field", field: err.path });
        }
        if (err instanceof MpccaWithdrawV2Error) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        return reply.code(400).send({
          error: "invalid_request",
          message: err instanceof Error ? err.message : "unknown",
        });
      }
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);
      if (parsed.rosterHash !== dkgRosterHash) {
        return reply.code(400).send({
          error: "stale_roster_hash",
          requestId: parsed.requestId,
          message: `rosterHash mismatch (request=${parsed.rosterHash}, roster=${dkgRosterHash})`,
        });
      }
      if (parsed.dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          requestId: parsed.requestId,
          message: `dkgEpoch mismatch (request=${parsed.dkgEpoch}, roster=${dkgRoster.dkgEpoch})`,
        });
      }
      // 3. Sanitize requestId BEFORE any FS path construction.
      requestId = parsed.requestId;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds it into FS paths",
        });
      }
      const sortedSelectedSlots = [...parsed.selectedSlots].sort((a, b) => a - b);

      // 4. Load __round1.json artifact. We need stateRoot to find it; if not configured
      // and this is an inline test scenario, we can fall back to caller-supplied
      // previousRoundTranscriptHash + previousRoundCommitments — but the production wire
      // expects stateRoot to be set and the round1 artifact to be on disk.
      if (!opts.stateRoot) {
        return reply.code(400).send({
          error: "state_root_not_configured",
          requestId,
          message:
            "MPCCA withdraw round2 requires stateRoot to be configured so the round1 transcript " +
            "can be read from disk. Configure EUNOMA_STATE_ROOT or run via /v2/withdraw/mpcca/start " +
            "with stateRoot before round2.",
        });
      }
      const round1ArtifactPath = join(
        opts.stateRoot,
        "coordinator",
        "mpcca_withdraw",
        `${parsed.dkgEpoch}__${requestId}__round1.json`,
      );
      let round1Artifact: Record<string, unknown>;
      try {
        const raw1 = await readFile(round1ArtifactPath, "utf8");
        round1Artifact = JSON.parse(raw1) as Record<string, unknown>;
      } catch (err) {
        return reply.code(400).send({
          error: "round1_transcript_not_found",
          requestId,
          path: round1ArtifactPath,
          message:
            err instanceof Error ? err.message : "unable to read round1 artifact",
        });
      }
      const round1IdentityMismatch = compareRound2IdentityWithRound1(
        parsed,
        round1Artifact,
        sortedSelectedSlots,
      );
      if (round1IdentityMismatch) {
        return reply.code(400).send({
          error: "round1_transcript_identity_mismatch",
          requestId,
          field: round1IdentityMismatch.field,
          round1Value: round1IdentityMismatch.round1Value,
          requestValue: round1IdentityMismatch.requestValue,
        });
      }
      const round1TranscriptHash = (round1Artifact.transcriptHash as string).replace(
        /^0x/i,
        "",
      );
      const round1PerSlot = round1Artifact.perSlotContributions as Array<{
        slot: number;
        ingressTranscriptHash: string;
      }>;
      // previousRoundCommitments[i] = ingressTranscriptHash of slot sortedSelectedSlots[i].
      const previousRoundCommitments: string[] = [];
      for (const slot of sortedSelectedSlots) {
        const entry = round1PerSlot.find((c) => c.slot === slot);
        if (!entry) {
          return reply.code(400).send({
            error: "round1_transcript_identity_mismatch",
            requestId,
            field: "perSlotContributions",
            message: `round1 artifact missing slot ${slot}`,
          });
        }
        previousRoundCommitments.push(
          entry.ingressTranscriptHash.replace(/^0x/i, ""),
        );
      }

      // 5. Acquire MPCCA withdraw lock.
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
        const statementInputs: MpccaWithdrawRound2StatementInputFields = {
          recipientEk: parsed.recipientEk,
          oldBalanceC: parsed.oldBalanceC,
          oldBalanceD: parsed.oldBalanceD,
          newBalanceC: parsed.newBalanceC,
          newBalanceD: parsed.newBalanceD,
          transferAmountC: parsed.transferAmountC,
          transferAmountDSender: parsed.transferAmountDSender,
          transferAmountDRecipient: parsed.transferAmountDRecipient,
        };
        // 6. Build per-worker round2 request bodies.
        const sessionId = parsed.sessionId;
        const round2Bodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch: parsed.dkgEpoch,
          requestId: requestId!,
          sessionId,
          vaultEkTranscriptHash: parsed.vaultEkTranscriptHash,
          registrationTranscriptHash: parsed.registrationTranscriptHash,
          vaultStateInitTranscriptHash: parsed.vaultStateInitTranscriptHash,
          observedDepositTranscriptHashes: parsed.observedDepositTranscriptHashes,
          // Parallel cursor mapping for the worker's strict-monotonic-ordering enforcement.
          // The worker rejects `observed_deposit_cursors length 0 does not match deposit_count`
          // when this is absent. Must be [1, 2, …, depositCount] in cursor order.
          observedDepositCursors:
            parsed.observedDepositCursors && parsed.observedDepositCursors.length > 0
              ? parsed.observedDepositCursors
              : Array.from({ length: parsed.depositCount }, (_, i) => i + 1),
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk: parsed.vaultEk,
          senderAddress: parsed.senderAddress,
          assetType: parsed.assetType,
          chainId: parsed.chainId,
          root: parsed.root,
          nullifierHash: parsed.nullifierHash,
          recipient: parsed.recipient,
          recipientHash: parsed.recipientHash,
          amountTag: parsed.amountTag,
          vaultSequence: parsed.vaultSequence,
          expirySecs: parsed.expirySecs,
          requestHash: parsed.requestHash,
          depositCount: parsed.depositCount,
          previousRoundTranscriptHash: round1TranscriptHash,
          previousRoundCommitments,
          // Statement input fields — workers consume these to reconstruct the public
          // Aptos CA TransferV1 Statement and derive BASE_DK_SET via psi_transfer.
          recipientEk: statementInputs.recipientEk,
          oldBalanceC: statementInputs.oldBalanceC,
          oldBalanceD: statementInputs.oldBalanceD,
          newBalanceC: statementInputs.newBalanceC,
          newBalanceD: statementInputs.newBalanceD,
          transferAmountC: statementInputs.transferAmountC,
          transferAmountDSender: statementInputs.transferAmountDSender,
          transferAmountDRecipient: statementInputs.transferAmountDRecipient,
        }));

        // 7. Concurrent fan-out with AbortController timeouts.
        const fanoutPromises = sortedSelectedSlots.map((slot, ordinalIndex) => {
          const controller = new AbortController();
          const timer = setTimeout(
            () => controller.abort(),
            mpccaWithdrawRound2WorkerTimeoutMs,
          );
          return singleNodeForwarder(
            "/worker/v2/mpcca/withdraw/round2",
            round2Bodies[ordinalIndex],
            dkgRoster,
            slot,
            controller.signal,
          )
            .then(
              (value) => ({
                kind: "value" as const,
                slot,
                value,
                aborted: controller.signal.aborted,
              }),
              (reason) => ({
                kind: "rejected" as const,
                slot,
                reason,
                aborted: controller.signal.aborted,
              }),
            )
            .finally(() => clearTimeout(timer));
        });
        const forwarded = await Promise.all(fanoutPromises);

        // 8. Parse + cross-check.
        const responsesBySlot = new Map<number, MpccaWithdrawRound2DkResult>();
        const seenSlots = new Set<number>();
        let canonicalDkIndices: number[] | null = null;
        for (const res of forwarded) {
          if (seenSlots.has(res.slot)) {
            return reply.code(502).send({
              error: "round2_duplicate_slot",
              slot: res.slot,
              requestId,
            });
          }
          seenSlots.add(res.slot);
          if (res.kind === "rejected") {
            // AbortController triggered → worker_timeout 502. Else generic forward_rejected.
            if (res.aborted) {
              return reply.code(502).send({
                error: "round2_worker_timeout",
                slot: res.slot,
                requestId,
                timeoutMs: mpccaWithdrawRound2WorkerTimeoutMs,
              });
            }
            return reply.code(502).send({
              error: "round2_forward_rejected",
              slot: res.slot,
              requestId,
              reason: res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (res.aborted) {
            // Some forwarders may resolve with an error result instead of throwing on abort.
            return reply.code(502).send({
              error: "round2_worker_timeout",
              slot: res.slot,
              requestId,
              timeoutMs: mpccaWithdrawRound2WorkerTimeoutMs,
            });
          }
          if (res.value.statusCode !== 200) {
            return reply.code(502).send({
              error: "round2_unexpected_status",
              slot: res.slot,
              requestId,
              statusCode: res.value.statusCode,
              body: res.value.body,
            });
          }
          if (!res.value.body) {
            return reply.code(502).send({
              error: "round2_empty_body",
              slot: res.slot,
              requestId,
            });
          }
          let dkResult: MpccaWithdrawRound2DkResult;
          try {
            dkResult = parseMpccaWithdrawRound2DkResult(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "round2_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          if (dkResult.slot !== res.slot) {
            return reply.code(502).send({
              error: "round2_slot_drift",
              slot: res.slot,
              requestId,
              returnedSlot: dkResult.slot,
            });
          }
          if (dkResult.playerId !== sortedSelectedSlots.indexOf(res.slot)) {
            return reply.code(502).send({
              error: "round2_player_id_drift",
              slot: res.slot,
              requestId,
              returnedPlayerId: dkResult.playerId,
            });
          }
          // Coordinator recomputes the round2 worker_transcript_hash from public inputs
          // (chained binding + Statement input fields). Cross-check binds the worker to
          // the canonical body.
          const expectedHash = mpccaWithdrawRound2WorkerTranscriptHash({
            sessionId,
            requestId,
            dkgEpoch: parsed.dkgEpoch,
            vaultEkTranscriptHash: parsed.vaultEkTranscriptHash,
            registrationTranscriptHash: parsed.registrationTranscriptHash,
            vaultStateInitTranscriptHash: parsed.vaultStateInitTranscriptHash,
            observedDepositTranscriptHashes: parsed.observedDepositTranscriptHashes,
            rosterHash: dkgRosterHash,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            vaultEk: parsed.vaultEk,
            senderAddress: parsed.senderAddress,
            assetType: parsed.assetType,
            chainId: parsed.chainId,
            root: parsed.root,
            nullifierHash: parsed.nullifierHash,
            recipient: parsed.recipient,
            recipientHash: parsed.recipientHash,
            amountTag: parsed.amountTag,
            vaultSequence: parsed.vaultSequence,
            expirySecs: parsed.expirySecs,
            requestHash: parsed.requestHash,
            depositCount: parsed.depositCount,
            previousRoundTranscriptHash: round1TranscriptHash,
            previousRoundCommitments,
            statementInputs,
          });
          if (dkResult.workerTranscriptHash !== expectedHash) {
            return reply.code(502).send({
              error: "round2_worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedHash,
              actual: dkResult.workerTranscriptHash,
            });
          }
          // Cross-worker dk_base_indices_used agreement: all 5 workers must report the
          // SAME canonical set (= `[0, 17]` for Aptos CA TransferV1). A divergence means
          // one worker mis-derived BASE_DK_SET — abort the round.
          const sortedDkIndices = [...dkResult.dkBaseIndicesUsed].sort((a, b) => a - b);
          if (canonicalDkIndices === null) {
            canonicalDkIndices = sortedDkIndices;
          } else if (
            canonicalDkIndices.length !== sortedDkIndices.length ||
            canonicalDkIndices.some((v, i) => v !== sortedDkIndices[i])
          ) {
            return reply.code(502).send({
              error: "dk_base_indices_divergence",
              slot: res.slot,
              requestId,
              expected: canonicalDkIndices,
              actual: sortedDkIndices,
            });
          }
          responsesBySlot.set(res.slot, dkResult);
        }
        // Quorum check: every selected slot must have responded.
        if (responsesBySlot.size !== DEOPERATOR_THRESHOLD) {
          return reply.code(502).send({
            error: "round2_under_quorum",
            requestId,
            received: responsesBySlot.size,
            expected: DEOPERATOR_THRESHOLD,
          });
        }
        // Verify canonical BASE_DK_SET. Defense-in-depth — each parse already restricts
        // entries to `DK_BASE_INDICES_CANONICAL`, but a future refactor that broadens the
        // canonical set must still fail closed if the runtime indices drift.
        const expectedCanonical = [...DK_BASE_INDICES_CANONICAL].sort((a, b) => a - b);
        if (
          !canonicalDkIndices ||
          canonicalDkIndices.length !== expectedCanonical.length ||
          canonicalDkIndices.some((v, i) => v !== expectedCanonical[i])
        ) {
          return reply.code(502).send({
            error: "dk_base_indices_unexpected",
            requestId,
            expected: expectedCanonical,
            actual: canonicalDkIndices ?? [],
          });
        }

        // 9. Compute deterministic round2 aggregate hash.
        const perSlotContributionsOrdered = sortedSelectedSlots.map((slot) => {
          const r = responsesBySlot.get(slot)!;
          return {
            slot,
            playerId: r.playerId,
            sessionStateHash: r.sessionStateHash,
            workerTranscriptHash: r.workerTranscriptHash,
            partialDkCommitments: r.partialDkCommitments,
            dkBaseIndicesUsed: r.dkBaseIndicesUsed,
          };
        });
        const round2AggregateHash = mpccaWithdrawRound2AggregateHash({
          statementInputs,
          dkBaseIndicesUsed: canonicalDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
        });
        const statementInputsHashHex =
          mpccaWithdrawRound2StatementInputsHash(statementInputs);

        // 10. Persist __round2.json with public-only artifacts. User-supplied proof
        // artifacts (Bulletproof bytes + per-chunk commitments + user sigma commitments
        // + user sigma response shares) are echoed-back so commit 4 (finalize) can
        // consume them without re-asking the user. All entries are public crypto outputs
        // — no plaintext witness component appears here.
        const round2ArtifactWithoutHash = {
          scheme: "mpcca_withdraw_v2_round2_dk" as const,
          dkgEpoch: parsed.dkgEpoch,
          requestId,
          sessionId,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          vaultEkTranscriptHash: parsed.vaultEkTranscriptHash,
          registrationTranscriptHash: parsed.registrationTranscriptHash,
          vaultStateInitTranscriptHash: parsed.vaultStateInitTranscriptHash,
          observedDepositTranscriptHashes: parsed.observedDepositTranscriptHashes,
          vaultEk: parsed.vaultEk,
          senderAddress: parsed.senderAddress,
          assetType: parsed.assetType,
          chainId: parsed.chainId,
          root: parsed.root,
          nullifierHash: parsed.nullifierHash,
          recipient: parsed.recipient,
          recipientHash: parsed.recipientHash,
          amountTag: parsed.amountTag,
          vaultSequence: parsed.vaultSequence,
          expirySecs: parsed.expirySecs,
          requestHash: parsed.requestHash,
          depositCount: parsed.depositCount,
          previousRoundTranscriptHash: round1TranscriptHash,
          previousRoundCommitments,
          statementInputs,
          statementInputsHashHex,
          dkBaseIndicesUsed: canonicalDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
          // User-supplied proof artifacts (echo-back). Commit 4 (finalize coord) consumes them.
          userProofArtifacts: {
            userSigmaCommitmentsHex: parsed.userSigmaCommitmentsHex,
            userSigmaResponseSharesHex: parsed.userSigmaResponseSharesHex,
            bulletproofZkrpAmountHex: parsed.bulletproofZkrpAmountHex,
            bulletproofZkrpNewBalanceHex: parsed.bulletproofZkrpNewBalanceHex,
            perChunkCommitmentsAmountHex: parsed.perChunkCommitmentsAmountHex,
            perChunkCommitmentsNewBalanceHex: parsed.perChunkCommitmentsNewBalanceHex,
          },
          round1TranscriptHash,
          round1TranscriptPath: round1ArtifactPath,
          createdAtUnixMs: Date.now(),
        };
        const round2TranscriptArtifact = {
          ...round2ArtifactWithoutHash,
          transcriptHash: round2AggregateHash,
        };
        const round2TranscriptPath = join(
          opts.stateRoot,
          "coordinator",
          "mpcca_withdraw",
          `${parsed.dkgEpoch}__${requestId}__round2.json`,
        );
        await writeTranscriptArtifactAtomic(
          round2TranscriptPath,
          round2TranscriptArtifact,
        );
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          await store.recordPartialArtifact({
            requestId,
            sessionId,
            rosterHash: dkgRosterHash,
            slot,
            artifactKind: "mpcca-withdraw-v2-round2-dk",
            artifactHash: r.sessionStateHash,
            transcriptHash: r.workerTranscriptHash,
          });
        }

        // 11. Return 200 with deterministic round2 transcriptHash + per-slot dk partials.
        return reply.code(200).send({
          accepted: false,
          requestId,
          dkgEpoch: parsed.dkgEpoch,
          round: "round2",
          completed: true,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          dkBaseIndicesUsed: canonicalDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
          previousRoundTranscriptHash: round1TranscriptHash,
          statementInputsHashHex,
          transcriptHash: round2AggregateHash,
          transcriptPath: round2TranscriptPath,
          message:
            "M4 commit 2 round2 dk-component fan-out complete; commit 3 (finalize worker) " +
            "consumes the per-slot α-share via at-rest envelopes, commit 4 (finalize coord) " +
            "aggregates s[0] + assembles WithdrawV2CallArgs.",
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
  // Milestone 4 sub-milestone 4-c4 — MPCCA withdraw V2 finalize orchestrator.
  //
  // POST /v2/withdraw/mpcca/finalize reads the persisted __round2.json artifact (built by
  // M4-c2), aggregates the worker dk-base partials with the user-supplied A_user[29] into the
  // full 30-point sigma commitment vector, computes the canonical Aptos CA TransferV1
  // Fiat-Shamir challenge `e`, fans out the per-worker FinalizeRequest to all 5 selected
  // slots, collects the 5 partial dk response shares s_share_j = α_share_j[0] + e·(λ_j·dk_share_j),
  // aggregates s[0] = Σ_j s_share_j, combines with the user-supplied s_user[1..25] to assemble
  // the full 25-scalar sigma response vector, and persists __finalize.json. The 27-field
  // WithdrawV2CallArgs assembly is deferred to M5 (it needs the FROST attestation), so this
  // route writes a finalize transcript with `notImplementedPhase =
  // "m4_pending_frost_signature_assembly"` and the MPCCA-finalize artifact populated.
  //
  // Privacy contract: workers see only Statement inputs + aggregated A + challenge e. The
  // user's Bulletproof bytes / per-chunk commitments / sigma α-points / response shares stay
  // coordinator-side and are echoed-back from __round2.json into __finalize.json for M5.
  //
  // Wire shape:
  //   1. Forbidden-plaintext-field guard on the raw body.
  //   2. parseMpccaWithdrawFinalizeOrchestrateRequest — base identity only.
  //   3. isSafeId(requestId) before any FS path construction.
  //   4. Load __round2.json for (dkgEpoch, requestId). 400 round2_transcript_not_found if
  //      absent.
  //   5. compareFinalizeIdentityWithRound2 — every identity field MUST match the round2 artifact.
  //   6. Acquire vaultMpccaWithdrawInFlight (re-used from M3a; only one withdraw session
  //      at a time). 409 vault_mpcca_withdraw_in_flight on contention.
  //   7. Build aggregated 30-point sigma commitment vector A_full:
  //        A_full[0] = Σ_j round2.perSlotContributions[j].partialDkCommitments[index=0]
  //        A_full[17] = userSigmaCommitmentsHex[16]
  //                    + Σ_j round2.perSlotContributions[j].partialDkCommitments[index=17]
  //        A_full[i] = userSigmaCommitmentsHex[i-1] for i ∈ [1..30) \ {17}
  //      (Ristretto point addition mod curve order; uses @aptos-labs/confidential-asset's
  //      RistrettoPoint.)
  //   8. Compute Fiat-Shamir challenge e via mpccaWithdrawFinalizeDeriveChallenge (Aptos
  //      SDK's sigmaProtocolFiatShamir over BCS-encoded inputs). Byte-canonical with the
  //      Move-side verifier + each worker's local re-derivation.
  //   9. Build per-worker FinalizeRequest body: chained envelope (previousRoundTranscriptHash
  //      = round2AggregateHash; previousRoundCommitments[i] = round2 per-slot worker
  //      transcript hash) + Statement inputs + aggregated A + e. The Statement inputs +
  //      aggregated A + e are byte-identical across workers.
  //  10. Promise.all fan-out with per-worker AbortController timeout (default 30s,
  //      configurable via mpccaWithdrawFinalizeWorkerTimeoutMs). 502 finalize_worker_timeout
  //      on per-slot abort.
  //  11. Collect 5 FinalizeDkResult artifacts. Validate:
  //        a. Each slot in sortedSelectedSlots returned a body.
  //        b. Each worker's workerTranscriptHash byte-equals the coordinator's recompute via
  //           mpccaWithdrawFinalizeWorkerTranscriptHash.
  //        c. Every worker's dkBaseIndicesUsed equals the canonical [0, 17]. Cross-worker
  //           divergence surfaces 502 dk_base_indices_divergence.
  //  12. Aggregate s[0] = Σ_j partialResponseDkHex_j (scalar addition mod ed25519 order).
  //  13. Combine with user s_user[1..25] (from __round2.json's userSigmaResponseSharesHex)
  //      to form the full 25-scalar sigma response vector.
  //  14. Compute deterministic finalize aggregate hash via mpccaWithdrawFinalizeAggregateHash.
  //  15. Persist __finalize.json at
  //      <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json with
  //      `notImplementedPhase = "m4_pending_frost_signature_assembly"` and
  //      `mpccaWithdrawFinalizeArtifact` populated (so the M5 FROST attestation pass can
  //      complete the 27-field WithdrawV2CallArgs without re-running MPCCA).
  //  16. Return 200 with deterministic transcriptHash (= finalize aggregate hash), per-slot
  //      partial responses, aggregated A, e.
  // =================================================================================================
  const mpccaWithdrawFinalizeWorkerTimeoutMs =
    opts.mpccaWithdrawFinalizeWorkerTimeoutMs ?? 30_000;
  server.post("/v2/withdraw/mpcca/finalize", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // 1+2. Forbidden-plaintext-field guard + parse.
      let parsed: MpccaWithdrawFinalizeOrchestrateRequest;
      try {
        parsed = parseMpccaWithdrawFinalizeOrchestrateRequest(raw);
      } catch (err) {
        if (err instanceof ForbiddenPlaintextFieldError) {
          return reply
            .code(400)
            .send({ error: "forbidden_plaintext_field", field: err.path });
        }
        if (err instanceof MpccaWithdrawV2Error) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        return reply.code(400).send({
          error: "invalid_request",
          message: err instanceof Error ? err.message : "unknown",
        });
      }
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);
      if (parsed.rosterHash !== dkgRosterHash) {
        return reply.code(400).send({
          error: "stale_roster_hash",
          requestId: parsed.requestId,
          message: `rosterHash mismatch (request=${parsed.rosterHash}, roster=${dkgRosterHash})`,
        });
      }
      if (parsed.dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          requestId: parsed.requestId,
          message: `dkgEpoch mismatch (request=${parsed.dkgEpoch}, roster=${dkgRoster.dkgEpoch})`,
        });
      }
      // 3. Sanitize requestId BEFORE FS path construction.
      requestId = parsed.requestId;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds it into FS paths",
        });
      }
      const sortedSelectedSlots = [...parsed.selectedSlots].sort((a, b) => a - b);

      // 4. Read __round2.json artifact.
      if (!opts.stateRoot) {
        return reply.code(400).send({
          error: "state_root_not_configured",
          requestId,
          message:
            "MPCCA withdraw finalize requires stateRoot to be configured so __round2.json " +
            "can be read from disk.",
        });
      }
      const round2ArtifactPath = join(
        opts.stateRoot,
        "coordinator",
        "mpcca_withdraw",
        `${parsed.dkgEpoch}__${requestId}__round2.json`,
      );
      let round2Artifact: Record<string, unknown>;
      try {
        const raw2 = await readFile(round2ArtifactPath, "utf8");
        round2Artifact = JSON.parse(raw2) as Record<string, unknown>;
      } catch (err) {
        return reply.code(400).send({
          error: "round2_transcript_not_found",
          requestId,
          path: round2ArtifactPath,
          message:
            err instanceof Error ? err.message : "unable to read round2 artifact",
        });
      }
      const round2IdentityMismatch = compareFinalizeIdentityWithRound2(
        parsed,
        round2Artifact,
        sortedSelectedSlots,
      );
      if (round2IdentityMismatch) {
        return reply.code(400).send({
          error: "round2_transcript_identity_mismatch",
          requestId,
          field: round2IdentityMismatch.field,
          round2Value: round2IdentityMismatch.round2Value,
          requestValue: round2IdentityMismatch.requestValue,
        });
      }
      // Extract round2 artifact fields needed for the finalize fan-out.
      const round2AggregateHash = (round2Artifact.transcriptHash as string).replace(
        /^0x/i,
        "",
      );
      const statementInputs = round2Artifact.statementInputs as MpccaWithdrawRound2StatementInputFields;
      const statementInputsHashHex = round2Artifact.statementInputsHashHex as string;
      const round2PerSlot = round2Artifact.perSlotContributions as Array<{
        slot: number;
        playerId: number;
        sessionStateHash: string;
        workerTranscriptHash: string;
        partialDkCommitments: MpccaWithdrawRound2DkPartial[];
        dkBaseIndicesUsed: number[];
      }>;
      const userProof = round2Artifact.userProofArtifacts as {
        userSigmaCommitmentsHex: string[];
        userSigmaResponseSharesHex: string[];
        bulletproofZkrpAmountHex: string;
        bulletproofZkrpNewBalanceHex: string;
        perChunkCommitmentsAmountHex: string[];
        perChunkCommitmentsNewBalanceHex: string[];
      };
      const canonicalDkIndices = round2Artifact.dkBaseIndicesUsed as number[];
      // previousRoundCommitments[i] = round2 per-slot workerTranscriptHash of slot
      // sortedSelectedSlots[i].
      const previousRoundCommitments: string[] = [];
      for (const slot of sortedSelectedSlots) {
        const entry = round2PerSlot.find((c) => c.slot === slot);
        if (!entry) {
          return reply.code(400).send({
            error: "round2_transcript_identity_mismatch",
            requestId,
            field: "perSlotContributions",
            message: `round2 artifact missing slot ${slot}`,
          });
        }
        previousRoundCommitments.push(entry.workerTranscriptHash.replace(/^0x/i, ""));
      }

      // 5. Acquire MPCCA withdraw lock.
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
        // 7. Build aggregated 30-point A_full vector.
        //    A_full[0]   = Σ_j worker_partial_j[index=0]            (purely worker)
        //    A_full[17]  = userSigmaCommitmentsHex[16]
        //                + Σ_j worker_partial_j[index=17]           (worker + user)
        //    A_full[i]   = userSigmaCommitmentsHex[i-1]              (purely user) for i ∉ {0,17}
        //
        // user supplies 29 entries covering positions [1..29] (i.e. 30 positions minus {0}).
        // At position 17 the user contributes the NON-dk component; workers contribute the
        // dk component; the coordinator sums.
        const aggregatedSigmaCommitmentsHex: string[] = new Array(30);
        // Compute per-index worker sums via aggregateRistrettoCommitments.
        const workerSumByIndex = new Map<number, string>();
        for (const idx of canonicalDkIndices) {
          const partialsHex: string[] = [];
          for (const slot of sortedSelectedSlots) {
            const entry = round2PerSlot.find((c) => c.slot === slot);
            if (!entry) continue;
            const partial = entry.partialDkCommitments.find((p) => p.index === idx);
            if (!partial) {
              return reply.code(502).send({
                error: "round2_partial_missing",
                requestId,
                slot,
                index: idx,
                message: `slot ${slot} missing partial_dk at index ${idx}`,
              });
            }
            partialsHex.push(partial.commitmentHex);
          }
          let workerSum: string;
          try {
            workerSum = await aggregateRistrettoCommitments(partialsHex);
          } catch (err) {
            return reply.code(502).send({
              error: "round2_partial_aggregation_failed",
              requestId,
              index: idx,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          workerSumByIndex.set(idx, workerSum);
        }

        // Fill A_full[i] from worker sum (i ∈ canonicalDkIndices) + user contribution
        // (i ∉ {0}). The user-supplied vector has 29 entries at positions [1..29] (skipping
        // position 0). Position 17 sums BOTH contributions.
        if (userProof.userSigmaCommitmentsHex.length !== 29) {
          return reply.code(502).send({
            error: "round2_user_sigma_commitments_length_invalid",
            requestId,
            actual: userProof.userSigmaCommitmentsHex.length,
            expected: 29,
          });
        }
        for (let i = 0; i < 30; i += 1) {
          if (i === 0) {
            // Pure worker contribution.
            const ws = workerSumByIndex.get(0);
            if (!ws) {
              return reply.code(500).send({
                error: "round2_worker_sum_missing_at_0",
                requestId,
              });
            }
            aggregatedSigmaCommitmentsHex[i] = ws;
          } else if (canonicalDkIndices.includes(i)) {
            // Shared: user-supplied non-dk part at position i, plus worker sum.
            const userPart = userProof.userSigmaCommitmentsHex[i - 1];
            const workerPart = workerSumByIndex.get(i);
            if (!workerPart || !userPart) {
              return reply.code(500).send({
                error: "round2_shared_position_missing",
                requestId,
                index: i,
              });
            }
            try {
              aggregatedSigmaCommitmentsHex[i] = await aggregateRistrettoCommitments([
                userPart,
                workerPart,
              ]);
            } catch (err) {
              return reply.code(502).send({
                error: "round2_shared_position_aggregation_failed",
                requestId,
                index: i,
                message: err instanceof Error ? err.message : "unknown",
              });
            }
          } else {
            // Pure user contribution.
            aggregatedSigmaCommitmentsHex[i] = userProof.userSigmaCommitmentsHex[i - 1];
          }
        }

        // 8. Compute canonical Fiat-Shamir e via Aptos SDK.
        let challengeHex: string;
        try {
          challengeHex = await mpccaWithdrawFinalizeDeriveChallenge({
            vaultEkHex: parsed.vaultEk,
            statementInputs,
            senderAddressHex: parsed.senderAddress,
            recipientAddressHex: parsed.recipient,
            assetTypeHex: parsed.assetType,
            chainId: parsed.chainId,
            aggregatedSigmaCommitmentsHex,
          });
        } catch (err) {
          return reply.code(500).send({
            error: "finalize_challenge_derivation_failed",
            requestId,
            message: err instanceof Error ? err.message : "unknown",
          });
        }

        // 9. Build per-worker FinalizeRequest body.
        const sessionId = parsed.sessionId;
        const finalizeBodies = sortedSelectedSlots.map((slot, ordinalIndex) => ({
          dkgEpoch: parsed.dkgEpoch,
          requestId: requestId!,
          sessionId,
          vaultEkTranscriptHash: parsed.vaultEkTranscriptHash,
          registrationTranscriptHash: parsed.registrationTranscriptHash,
          vaultStateInitTranscriptHash: parsed.vaultStateInitTranscriptHash,
          observedDepositTranscriptHashes: parsed.observedDepositTranscriptHashes,
          // Parallel cursor mapping for the worker's strict-monotonic-ordering enforcement.
          // The worker rejects `observed_deposit_cursors length 0 does not match deposit_count`
          // when this is absent. Must be [1, 2, …, depositCount] in cursor order.
          observedDepositCursors:
            parsed.observedDepositCursors && parsed.observedDepositCursors.length > 0
              ? parsed.observedDepositCursors
              : Array.from({ length: parsed.depositCount }, (_, i) => i + 1),
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          selfSlot: slot,
          playerId: ordinalIndex,
          vaultEk: parsed.vaultEk,
          senderAddress: parsed.senderAddress,
          assetType: parsed.assetType,
          chainId: parsed.chainId,
          root: parsed.root,
          nullifierHash: parsed.nullifierHash,
          recipient: parsed.recipient,
          recipientHash: parsed.recipientHash,
          amountTag: parsed.amountTag,
          vaultSequence: parsed.vaultSequence,
          expirySecs: parsed.expirySecs,
          requestHash: parsed.requestHash,
          depositCount: parsed.depositCount,
          // previousRoundTranscriptHash = round2 PER-SLOT workerTranscriptHash for this slot
          // (NOT the round2 aggregate hash). This is INTENTIONAL: the Rust M4-c3 worker checks
          // `round2_state.worker_transcript_hash == previous_round_transcript_hash` as a load-
          // bearing per-slot binding — each worker verifies the finalize call is tied to the
          // exact round2 contribution it produced. Sending the aggregate hash would break
          // every legitimate finalize call (the aggregate is not stored worker-side; the
          // worker has no way to verify against it). Defense-in-depth on round2-aggregation
          // is provided separately by the coordinator's own aggregate hash + the per-slot
          // statement_inputs_hash cross-check (which catches Statement-input drift).
          //
          // M4-c2 round2 used the aggregate-hash pattern (round2.previousRoundTranscriptHash =
          // round1.transcriptHash), but the round2 worker doesn't STORE round1's transcript
          // hash — it only folds the supplied value into its chained binding. M4-c3 raised the
          // bar by persisting the per-slot worker_transcript_hash in Round2StateFile and
          // adding the equality gate at finalize. Switching back to the aggregate-hash pattern
          // would silently drop that gate.
          previousRoundTranscriptHash:
            round2PerSlot.find((c) => c.slot === slot)!.workerTranscriptHash,
          previousRoundCommitments,
          recipientEk: statementInputs.recipientEk,
          oldBalanceC: statementInputs.oldBalanceC,
          oldBalanceD: statementInputs.oldBalanceD,
          newBalanceC: statementInputs.newBalanceC,
          newBalanceD: statementInputs.newBalanceD,
          transferAmountC: statementInputs.transferAmountC,
          transferAmountDSender: statementInputs.transferAmountDSender,
          transferAmountDRecipient: statementInputs.transferAmountDRecipient,
          // The Rust FinalizeRequest struct (crypto-worker-rust::mpcca_withdraw_v2)
          // uses serde(rename_all = "camelCase") on fields aggregated_sigma_commitments
          // and challenge_hex, which serialize to aggregatedSigmaCommitments and
          // challengeHex. The coordinator was previously sending
          // aggregatedSigmaCommitmentsHex which fails Axum body extraction (422).
          aggregatedSigmaCommitments: aggregatedSigmaCommitmentsHex,
          challengeHex,
        }));

        // 10. Concurrent fan-out with AbortController timeouts.
        const fanoutPromises = sortedSelectedSlots.map((slot, ordinalIndex) => {
          const controller = new AbortController();
          const timer = setTimeout(
            () => controller.abort(),
            mpccaWithdrawFinalizeWorkerTimeoutMs,
          );
          return singleNodeForwarder(
            "/worker/v2/mpcca/withdraw/finalize",
            finalizeBodies[ordinalIndex],
            dkgRoster,
            slot,
            controller.signal,
          )
            .then(
              (value) => ({
                kind: "value" as const,
                slot,
                value,
                aborted: controller.signal.aborted,
              }),
              (reason) => ({
                kind: "rejected" as const,
                slot,
                reason,
                aborted: controller.signal.aborted,
              }),
            )
            .finally(() => clearTimeout(timer));
        });
        const forwarded = await Promise.all(fanoutPromises);

        // 11. Parse + cross-check.
        const responsesBySlot = new Map<number, MpccaWithdrawFinalizeDkResult>();
        const seenSlots = new Set<number>();
        let canonicalFinalizeDkIndices: number[] | null = null;
        for (const res of forwarded) {
          if (seenSlots.has(res.slot)) {
            return reply.code(502).send({
              error: "finalize_duplicate_slot",
              slot: res.slot,
              requestId,
            });
          }
          seenSlots.add(res.slot);
          if (res.kind === "rejected") {
            if (res.aborted) {
              return reply.code(502).send({
                error: "finalize_worker_timeout",
                slot: res.slot,
                requestId,
                timeoutMs: mpccaWithdrawFinalizeWorkerTimeoutMs,
              });
            }
            return reply.code(502).send({
              error: "finalize_forward_rejected",
              slot: res.slot,
              requestId,
              reason: res.reason instanceof Error ? res.reason.message : String(res.reason),
            });
          }
          if (res.aborted) {
            return reply.code(502).send({
              error: "finalize_worker_timeout",
              slot: res.slot,
              requestId,
              timeoutMs: mpccaWithdrawFinalizeWorkerTimeoutMs,
            });
          }
          if (res.value.statusCode !== 200) {
            return reply.code(502).send({
              error: "finalize_unexpected_status",
              slot: res.slot,
              requestId,
              statusCode: res.value.statusCode,
              body: res.value.body,
            });
          }
          if (!res.value.body) {
            return reply.code(502).send({
              error: "finalize_empty_body",
              slot: res.slot,
              requestId,
            });
          }
          let dkResult: MpccaWithdrawFinalizeDkResult;
          try {
            dkResult = parseMpccaWithdrawFinalizeDkResult(res.value.body);
          } catch (err) {
            return reply.code(502).send({
              error: "finalize_returned_invalid",
              slot: res.slot,
              requestId,
              message: err instanceof Error ? err.message : "unknown",
            });
          }
          if (dkResult.slot !== res.slot) {
            return reply.code(502).send({
              error: "finalize_slot_drift",
              slot: res.slot,
              requestId,
              returnedSlot: dkResult.slot,
            });
          }
          if (dkResult.playerId !== sortedSelectedSlots.indexOf(res.slot)) {
            return reply.code(502).send({
              error: "finalize_player_id_drift",
              slot: res.slot,
              requestId,
              returnedPlayerId: dkResult.playerId,
            });
          }
          const expectedHash = mpccaWithdrawFinalizeWorkerTranscriptHash({
            sessionId,
            requestId,
            dkgEpoch: parsed.dkgEpoch,
            vaultEkTranscriptHash: parsed.vaultEkTranscriptHash,
            registrationTranscriptHash: parsed.registrationTranscriptHash,
            vaultStateInitTranscriptHash: parsed.vaultStateInitTranscriptHash,
            observedDepositTranscriptHashes: parsed.observedDepositTranscriptHashes,
            rosterHash: dkgRosterHash,
            sortedSelectedSlots,
            selfSlot: res.slot,
            playerId: sortedSelectedSlots.indexOf(res.slot),
            vaultEk: parsed.vaultEk,
            senderAddress: parsed.senderAddress,
            assetType: parsed.assetType,
            chainId: parsed.chainId,
            root: parsed.root,
            nullifierHash: parsed.nullifierHash,
            recipient: parsed.recipient,
            recipientHash: parsed.recipientHash,
            amountTag: parsed.amountTag,
            vaultSequence: parsed.vaultSequence,
            expirySecs: parsed.expirySecs,
            requestHash: parsed.requestHash,
            depositCount: parsed.depositCount,
            previousRoundTranscriptHash: finalizeBodies[sortedSelectedSlots.indexOf(res.slot)]
              .previousRoundTranscriptHash,
            previousRoundCommitments,
            statementInputs,
            aggregatedSigmaCommitmentsHex,
            challengeHex,
          });
          if (dkResult.workerTranscriptHash !== expectedHash) {
            return reply.code(502).send({
              error: "finalize_worker_transcript_hash_mismatch",
              slot: res.slot,
              requestId,
              expected: expectedHash,
              actual: dkResult.workerTranscriptHash,
            });
          }
          const sortedDkIndices = [...dkResult.dkBaseIndicesUsed].sort((a, b) => a - b);
          if (canonicalFinalizeDkIndices === null) {
            canonicalFinalizeDkIndices = sortedDkIndices;
          } else if (
            canonicalFinalizeDkIndices.length !== sortedDkIndices.length ||
            canonicalFinalizeDkIndices.some((v, i) => v !== sortedDkIndices[i])
          ) {
            return reply.code(502).send({
              error: "dk_base_indices_divergence",
              slot: res.slot,
              requestId,
              expected: canonicalFinalizeDkIndices,
              actual: sortedDkIndices,
            });
          }
          responsesBySlot.set(res.slot, dkResult);
        }
        if (responsesBySlot.size !== DEOPERATOR_THRESHOLD) {
          return reply.code(502).send({
            error: "finalize_under_quorum",
            requestId,
            received: responsesBySlot.size,
            expected: DEOPERATOR_THRESHOLD,
          });
        }
        // Verify canonical BASE_DK_SET.
        const expectedCanonical = [...DK_BASE_INDICES_CANONICAL].sort((a, b) => a - b);
        if (
          !canonicalFinalizeDkIndices ||
          canonicalFinalizeDkIndices.length !== expectedCanonical.length ||
          canonicalFinalizeDkIndices.some((v, i) => v !== expectedCanonical[i])
        ) {
          return reply.code(502).send({
            error: "dk_base_indices_unexpected",
            requestId,
            expected: expectedCanonical,
            actual: canonicalFinalizeDkIndices ?? [],
          });
        }

        // 12. Aggregate s[0] = Σ_j partialResponseDkHex_j (scalar addition mod n).
        const sZero = await aggregateScalarsModN(
          sortedSelectedSlots.map((slot) => responsesBySlot.get(slot)!.partialResponseDkHex),
        );

        // 13. Combine with user-supplied s_user[1..25] (24 scalars) → full 25-vector.
        if (userProof.userSigmaResponseSharesHex.length !== 24) {
          return reply.code(502).send({
            error: "round2_user_sigma_response_shares_length_invalid",
            requestId,
            actual: userProof.userSigmaResponseSharesHex.length,
            expected: 24,
          });
        }
        const sigmaResponseHex = [sZero, ...userProof.userSigmaResponseSharesHex];

        // 14. Compute deterministic finalize aggregate hash.
        const perSlotContributionsOrdered = sortedSelectedSlots.map((slot) => {
          const r = responsesBySlot.get(slot)!;
          return {
            slot,
            workerTranscriptHash: r.workerTranscriptHash,
            partialResponseDkHex: r.partialResponseDkHex,
          };
        });
        const finalizeAggregateHash = mpccaWithdrawFinalizeAggregateHash({
          statementInputs,
          aggregatedSigmaCommitmentsHex,
          challengeHex,
          dkBaseIndicesUsed: canonicalFinalizeDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
        });

        // 15. Persist __finalize.json with the MPCCA-finalize artifact populated.
        // notImplementedPhase signals to the M5b submit route that FROST attestation +
        // 27-field WithdrawV2CallArgs assembly is still pending.
        const mpccaWithdrawFinalizeArtifact: MpccaWithdrawFinalizeArtifact = {
          aggregatedSigmaCommitmentsHex,
          challengeHex,
          sigmaResponseHex,
          perChunkCommitmentsAmountHex: userProof.perChunkCommitmentsAmountHex,
          perChunkCommitmentsNewBalanceHex: userProof.perChunkCommitmentsNewBalanceHex,
          bulletproofZkrpAmountHex: userProof.bulletproofZkrpAmountHex,
          bulletproofZkrpNewBalanceHex: userProof.bulletproofZkrpNewBalanceHex,
          dkBaseIndicesUsed: canonicalFinalizeDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
          aggregateHash: finalizeAggregateHash,
        };
        const finalizeTranscriptArtifact = {
          scheme: "mpcca_withdraw_v2_finalize" as const,
          dkgEpoch: parsed.dkgEpoch,
          requestId,
          notImplementedPhase: "m4_pending_frost_signature_assembly",
          mpccaWithdrawFinalizeArtifact,
          transcriptHash: finalizeAggregateHash,
          createdAtUnixMs: Date.now(),
        };
        const finalizeTranscriptPath = join(
          opts.stateRoot,
          "coordinator",
          "mpcca_withdraw",
          `${parsed.dkgEpoch}__${requestId}__finalize.json`,
        );
        await writeTranscriptArtifactAtomic(
          finalizeTranscriptPath,
          finalizeTranscriptArtifact,
        );
        for (const slot of sortedSelectedSlots) {
          const r = responsesBySlot.get(slot)!;
          await store.recordPartialArtifact({
            requestId,
            sessionId,
            rosterHash: dkgRosterHash,
            slot,
            artifactKind: "mpcca-withdraw-v2-finalize",
            artifactHash: r.sessionStateHash,
            transcriptHash: r.workerTranscriptHash,
          });
        }

        // Compute caPayloadHash here (identical inputs to the M5 frost-attest pass) so the
        // browser MPCCA withdraw driver can assemble its Groth16 proof — whose ca_payload_hash
        // public input must byte-match the on-chain WithdrawV2CallArgs — BEFORE calling
        // frost-attest (which carries that proof in its request body). The frost-attest pass
        // recomputes the same value from the persisted artifacts; this is idempotent.
        const finalizeCaPayload = buildCaPayloadFromFinalizeArtifact({
          recipientAddressHex: parsed.recipient,
          assetTypeHex: parsed.assetType,
          statementInputs: {
            recipientEk: statementInputs.recipientEk,
            oldBalanceC: statementInputs.oldBalanceC,
            oldBalanceD: statementInputs.oldBalanceD,
            newBalanceC: statementInputs.newBalanceC,
            newBalanceD: statementInputs.newBalanceD,
            transferAmountC: statementInputs.transferAmountC,
            transferAmountDSender: statementInputs.transferAmountDSender,
            transferAmountDRecipient: statementInputs.transferAmountDRecipient,
          },
          mpccaArtifact: {
            aggregatedSigmaCommitmentsHex,
            sigmaResponseHex,
            bulletproofZkrpAmountHex: userProof.bulletproofZkrpAmountHex,
            bulletproofZkrpNewBalanceHex: userProof.bulletproofZkrpNewBalanceHex,
          },
          memoHex: "",
        });
        const finalizeCaPayloadHashRaw = caPayloadHashRawV2(finalizeCaPayload);
        const finalizeCaPayloadHashFr = caPayloadHashRawToFrV2(finalizeCaPayloadHashRaw);

        // 16. Return 200 with the finalize transcript hash + per-slot contributions.
        return reply.code(200).send({
          accepted: false,
          requestId,
          dkgEpoch: parsed.dkgEpoch,
          round: "finalize",
          completed: true,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          dkBaseIndicesUsed: canonicalFinalizeDkIndices,
          perSlotContributions: perSlotContributionsOrdered,
          previousRoundTranscriptHash: round2AggregateHash,
          statementInputsHashHex,
          transcriptHash: finalizeAggregateHash,
          aggregatedSigmaCommitmentsHash:
            mpccaWithdrawFinalizeAggregatedCommitmentsHash(aggregatedSigmaCommitmentsHex),
          challengeHex,
          sigmaResponseHex,
          caPayloadHashRaw: finalizeCaPayloadHashRaw,
          caPayloadHashFr: finalizeCaPayloadHashFr,
          transcriptPath: finalizeTranscriptPath,
          notImplementedPhase: "m4_pending_frost_signature_assembly",
          message:
            "M4 commit 4 MPCCA finalize complete; M5 FROST attestation pass consumes " +
            "mpccaWithdrawFinalizeArtifact + signs caPayloadHash to assemble the 27-field " +
            "WithdrawV2CallArgs.",
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
  // Milestone 5 sub-milestone 5-c1 — MPCCA withdraw V2 FROST attestation orchestrator.
  //
  // POST /v2/withdraw/mpcca/frost-attest reads the persisted __round2.json + __finalize.json
  // artifacts, builds the canonical Aptos CA TransferV1 payload via
  // `buildCaPayloadFromFinalizeArtifact`, computes the caPayloadHash (raw via
  // keccak256-over-BCS, then Fr-safe form via the canonical 32-byte-low-bit-clear), builds
  // the `WithdrawAttestationV2Message`, BCS-encodes it, then drives the 3-round FROST
  // signing ceremony across the 5 selected slots:
  //   Phase A — fan out POST /worker/v2/frost/sign/nonce-commit; collect commitments.
  //   Phase B — fan out POST /worker/v2/frost/sign/partial with (commitments[5],
  //             messageBytes); collect signature shares.
  //   Phase C — call POST /worker/v2/frost/sign/aggregate on slot[0] with
  //             (commitments[5], signatureShares[5], messageBytes); receive the FROST
  //             groupSignature.
  //
  // Then assembles the 27-field withdrawV2CallArgsFields (the M5b submit route consumes
  // this shape) and persists the updated __finalize.json (removes
  // `notImplementedPhase = "m4_pending_frost_signature_assembly"`, adds
  // `withdrawV2CallArgsFields` and `attestationConfig`, keeps `mpccaWithdrawFinalizeArtifact`
  // for audit forensics).
  //
  // Privacy contract: messageBytes is the public BCS-encoded WithdrawAttestationV2Message;
  // workers see only Statement-bound CA-payload-bound public chain identity. No plaintext
  // witness component crosses the worker boundary.
  //
  // Wire shape:
  //   1. Forbidden-plaintext-field guard FIRST on raw body.
  //   2. parseMpccaWithdrawFrostAttestStartRequest — base identity + attestationConfig +
  //      withdrawProofHex (user-supplied Groth16) + optional memoHex.
  //   3. isSafeId(requestId).
  //   4. Roster + epoch validation.
  //   5. Load __round2.json (Statement + userProofArtifacts) + __finalize.json
  //      (mpccaWithdrawFinalizeArtifact).
  //   6. Acquire vaultMpccaWithdrawInFlight lock (re-used from M3a; 409 on contention).
  //   7. Build CA payload + caPayloadHash (raw + Fr-safe).
  //   8. Build WithdrawAttestationV2Message + BCS-encode.
  //   9. Phase A: nonce-commit fan-out with AbortController timeouts (default 30s).
  //  10. Phase B: partial-sign fan-out with AbortController timeouts.
  //  11. Phase C: aggregate on slot[0].
  //  12. Assemble 27-field withdrawV2CallArgsFields.
  //  13. Persist updated __finalize.json (atomic replace).
  //  14. Return 200 with caPayloadHash + groupSignature + withdrawV2CallArgsFields.
  // =================================================================================================
  const mpccaWithdrawFrostAttestWorkerTimeoutMs =
    opts.mpccaWithdrawFinalizeWorkerTimeoutMs ?? 30_000;
  server.post("/v2/withdraw/mpcca/frost-attest", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // 1+2. Forbidden-plaintext-field guard + parse.
      let parsed: MpccaWithdrawFrostAttestStartRequest;
      try {
        parsed = parseMpccaWithdrawFrostAttestStartRequest(raw);
      } catch (err) {
        if (err instanceof ForbiddenPlaintextFieldError) {
          return reply
            .code(400)
            .send({ error: "forbidden_plaintext_field", field: err.path });
        }
        if (err instanceof MpccaWithdrawV2Error) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        return reply.code(400).send({
          error: "invalid_request",
          message: err instanceof Error ? err.message : "unknown",
        });
      }
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);
      if (parsed.rosterHash !== dkgRosterHash) {
        return reply.code(400).send({
          error: "stale_roster_hash",
          requestId: parsed.requestId,
          message: `rosterHash mismatch (request=${parsed.rosterHash}, roster=${dkgRosterHash})`,
        });
      }
      if (parsed.dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          requestId: parsed.requestId,
          message: `dkgEpoch mismatch (request=${parsed.dkgEpoch}, roster=${dkgRoster.dkgEpoch})`,
        });
      }
      // 3. Sanitize requestId BEFORE FS path construction.
      requestId = parsed.requestId;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds it into FS paths",
        });
      }

      // 4. Read __round2.json + __finalize.json artifacts.
      if (!opts.stateRoot) {
        return reply.code(400).send({
          error: "state_root_not_configured",
          requestId,
          message:
            "MPCCA withdraw FROST attest requires stateRoot to be configured so __round2.json " +
            "+ __finalize.json can be read from disk.",
        });
      }
      const round2ArtifactPath = join(
        opts.stateRoot,
        "coordinator",
        "mpcca_withdraw",
        `${parsed.dkgEpoch}__${requestId}__round2.json`,
      );
      let round2Artifact: Record<string, unknown>;
      try {
        round2Artifact = JSON.parse(
          await readFile(round2ArtifactPath, "utf8"),
        ) as Record<string, unknown>;
      } catch (err) {
        return reply.code(400).send({
          error: "round2_transcript_not_found",
          requestId,
          path: round2ArtifactPath,
          message: err instanceof Error ? err.message : "unable to read round2 artifact",
        });
      }
      // Codex M5-c1 P1 #1 + #10: coordinator-selected quorum comes from the PERSISTED
      // __round2.json artifact, NOT the user-supplied body. A caller that submitted a
      // different selectedSlots set than the original round2 ceremony would have its
      // quorum swapped out from under it. Identity fields (vaultEk, recipient, etc.) are
      // cross-checked below via compareFinalizeIdentityWithRound2.
      const round2SelectedSlots = round2Artifact.selectedSlots;
      if (!Array.isArray(round2SelectedSlots) || round2SelectedSlots.length !== DEOPERATOR_THRESHOLD) {
        return reply.code(400).send({
          error: "round2_transcript_selected_slots_missing",
          requestId,
          message: `__round2.json must carry selectedSlots[${DEOPERATOR_THRESHOLD}]; got ${round2SelectedSlots ? (round2SelectedSlots as unknown[]).length : "<missing>"}`,
        });
      }
      const sortedSelectedSlots = [...(round2SelectedSlots as number[])].sort((a, b) => a - b);
      // Defense-in-depth: cross-check the user-supplied selectedSlots against the persisted
      // value. A divergence means the caller is trying to swap quorum mid-flight; fail closed.
      const callerSorted = [...parsed.selectedSlots].sort((a, b) => a - b);
      if (
        callerSorted.length !== sortedSelectedSlots.length ||
        callerSorted.some((v, i) => v !== sortedSelectedSlots[i])
      ) {
        return reply.code(400).send({
          error: "frost_attest_caller_quorum_mismatch",
          requestId,
          callerSelectedSlots: callerSorted,
          round2SelectedSlots: sortedSelectedSlots,
          message:
            "caller-supplied selectedSlots differs from the persisted __round2.json quorum; " +
            "coordinator only signs over the original round2 quorum",
        });
      }

      // Codex M5-c1 P1 #10: cross-check ALL identity fields (vaultEk, recipient, asset_type,
      // root, nullifierHash, ...) against the persisted __round2.json BEFORE driving FROST
      // signing. A caller that hijacks a requestId but supplies different identity fields
      // could induce workers to sign over a different message than the round2 ceremony bound.
      // Re-uses the M4-c4 compareFinalizeIdentityWithRound2 helper which walks 18 identity
      // fields + selectedSlots + observedDepositTranscriptHashes + statementInputs +
      // userProofArtifacts.
      // At frost-attest: requestHash legitimately differs from round2 (placeholder vs the
      // real ca_payload_hash-derived value). Skip that single field; all other identity
      // bindings remain enforced.
      const identityMismatch = compareFinalizeIdentityWithRound2(
        parsed,
        round2Artifact,
        sortedSelectedSlots,
        { allowRequestHashUpdate: true },
      );
      if (identityMismatch) {
        return reply.code(400).send({
          error: "round2_transcript_identity_mismatch",
          requestId,
          field: identityMismatch.field,
          round2Value: identityMismatch.round2Value,
          requestValue: identityMismatch.requestValue,
        });
      }
      const finalizeArtifactPath = join(
        opts.stateRoot,
        "coordinator",
        "mpcca_withdraw",
        `${parsed.dkgEpoch}__${requestId}__finalize.json`,
      );
      let finalizeArtifact: Record<string, unknown>;
      try {
        finalizeArtifact = JSON.parse(
          await readFile(finalizeArtifactPath, "utf8"),
        ) as Record<string, unknown>;
      } catch (err) {
        return reply.code(400).send({
          error: "finalize_transcript_not_found",
          requestId,
          path: finalizeArtifactPath,
          message: err instanceof Error ? err.message : "unable to read finalize artifact",
        });
      }
      const mpccaArtifact = finalizeArtifact.mpccaWithdrawFinalizeArtifact as
        | Record<string, unknown>
        | undefined;
      if (!mpccaArtifact || typeof mpccaArtifact !== "object") {
        return reply.code(400).send({
          error: "finalize_artifact_missing",
          requestId,
          message:
            "__finalize.json is missing mpccaWithdrawFinalizeArtifact; the M4-c4 finalize " +
            "route must run first",
        });
      }
      const statementInputs = round2Artifact.statementInputs as Record<string, unknown>;
      if (!statementInputs || typeof statementInputs !== "object") {
        return reply.code(400).send({
          error: "round2_statement_inputs_missing",
          requestId,
        });
      }

      // 5. Acquire MPCCA withdraw lock.
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
        // 7. Build CA payload + caPayloadHash.
        const caPayload = buildCaPayloadFromFinalizeArtifact({
          recipientAddressHex: parsed.recipient,
          assetTypeHex: parsed.assetType,
          statementInputs: {
            recipientEk: statementInputs.recipientEk as string,
            oldBalanceC: statementInputs.oldBalanceC as string[],
            oldBalanceD: statementInputs.oldBalanceD as string[],
            newBalanceC: statementInputs.newBalanceC as string[],
            newBalanceD: statementInputs.newBalanceD as string[],
            transferAmountC: statementInputs.transferAmountC as string[],
            transferAmountDSender: statementInputs.transferAmountDSender as string[],
            transferAmountDRecipient: statementInputs.transferAmountDRecipient as string[],
          },
          mpccaArtifact: {
            aggregatedSigmaCommitmentsHex:
              mpccaArtifact.aggregatedSigmaCommitmentsHex as string[],
            sigmaResponseHex: mpccaArtifact.sigmaResponseHex as string[],
            bulletproofZkrpAmountHex: mpccaArtifact.bulletproofZkrpAmountHex as string,
            bulletproofZkrpNewBalanceHex:
              mpccaArtifact.bulletproofZkrpNewBalanceHex as string,
          },
          memoHex: parsed.memoHex,
        });
        const caPayloadHashRaw = caPayloadHashRawV2(caPayload);
        const caPayloadHashFr = caPayloadHashRawToFrV2(caPayloadHashRaw);

        // 8. Build + BCS-encode WithdrawAttestationV2Message.
        const attestationMessage = {
          chainId: parsed.chainId,
          bridge: parsed.attestationConfig.bridge,
          vault: parsed.attestationConfig.vault,
          assetType: parsed.assetType,
          operatorSetVersion: parsed.attestationConfig.operatorSetVersion,
          dkgEpoch: parsed.dkgEpoch,
          rosterHash: dkgRosterHash,
          frostGroupPubkey: parsed.attestationConfig.frostGroupPubkey,
          root: parsed.root,
          nullifierHash: parsed.nullifierHash,
          recipient: parsed.recipient,
          recipientHash: parsed.recipientHash,
          amountTag: parsed.amountTag,
          caPayloadHash: caPayloadHashFr,
          requestHash: parsed.requestHash,
          vaultSequence: String(parsed.vaultSequence),
          expirySecs: String(parsed.expirySecs),
          circuitVersionsHash: parsed.attestationConfig.circuitVersionsHash,
        };
        const messageBytes = bcsEncodeWithdrawAttestationV2(attestationMessage);
        const messageHex = bytesToHex(messageBytes);

        // 9. Phase A — fan out nonce-commit.
        const nonceCommitPromises = sortedSelectedSlots.map((slot) => {
          const controller = new AbortController();
          const timer = setTimeout(
            () => controller.abort(),
            mpccaWithdrawFrostAttestWorkerTimeoutMs,
          );
          return singleNodeForwarder(
            "/worker/v2/frost/sign/nonce-commit",
            { requestId },
            dkgRoster,
            slot,
            controller.signal,
          )
            .then(
              (value) => ({
                kind: "value" as const,
                slot,
                value,
                aborted: controller.signal.aborted,
              }),
              (reason) => ({
                kind: "rejected" as const,
                slot,
                reason,
                aborted: controller.signal.aborted,
              }),
            )
            .finally(() => clearTimeout(timer));
        });
        const nonceResults = await Promise.all(nonceCommitPromises);
        const commitmentEntries: Array<{ slot: number; commitments: unknown }> = [];
        const noncePerSlot = new Map<number, { nonceId: string; transcriptHash: string }>();
        for (const r of nonceResults) {
          if (r.kind === "rejected") {
            return reply.code(502).send({
              error: r.aborted ? "frost_nonce_worker_timeout" : "frost_nonce_forward_rejected",
              slot: r.slot,
              requestId,
              reason: r.reason instanceof Error ? r.reason.message : String(r.reason),
            });
          }
          if (r.aborted) {
            return reply.code(502).send({
              error: "frost_nonce_worker_timeout",
              slot: r.slot,
              requestId,
            });
          }
          if (r.value.statusCode !== 200) {
            return reply.code(502).send({
              error: "frost_nonce_unexpected_status",
              slot: r.slot,
              requestId,
              statusCode: r.value.statusCode,
              body: r.value.body,
            });
          }
          const parsedRes = parseFrostNonceCommitmentResponse(r.value.body);
          commitmentEntries.push({ slot: r.slot, commitments: parsedRes.commitments });
          noncePerSlot.set(r.slot, {
            nonceId: parsedRes.nonceId,
            transcriptHash: parsedRes.transcriptHash,
          });
        }
        commitmentEntries.sort((a, b) => a.slot - b.slot);

        // 10. Phase B — fan out partial-sign.
        const partialSignPromises = sortedSelectedSlots.map((slot) => {
          const controller = new AbortController();
          const timer = setTimeout(
            () => controller.abort(),
            mpccaWithdrawFrostAttestWorkerTimeoutMs,
          );
          const body = {
            nonceId: noncePerSlot.get(slot)!.nonceId,
            messageBytes: messageHex,
            commitments: commitmentEntries,
          };
          return singleNodeForwarder(
            "/worker/v2/frost/sign/partial",
            body,
            dkgRoster,
            slot,
            controller.signal,
          )
            .then(
              (value) => ({
                kind: "value" as const,
                slot,
                value,
                aborted: controller.signal.aborted,
              }),
              (reason) => ({
                kind: "rejected" as const,
                slot,
                reason,
                aborted: controller.signal.aborted,
              }),
            )
            .finally(() => clearTimeout(timer));
        });
        const partialResults = await Promise.all(partialSignPromises);
        const signatureShareEntries: Array<{ slot: number; signatureShare: unknown }> = [];
        const partialPerSlot = new Map<number, { transcriptHash: string }>();
        for (const r of partialResults) {
          if (r.kind === "rejected") {
            return reply.code(502).send({
              error: r.aborted ? "frost_partial_worker_timeout" : "frost_partial_forward_rejected",
              slot: r.slot,
              requestId,
              reason: r.reason instanceof Error ? r.reason.message : String(r.reason),
            });
          }
          if (r.aborted) {
            return reply.code(502).send({
              error: "frost_partial_worker_timeout",
              slot: r.slot,
              requestId,
            });
          }
          if (r.value.statusCode !== 200) {
            return reply.code(502).send({
              error: "frost_partial_unexpected_status",
              slot: r.slot,
              requestId,
              statusCode: r.value.statusCode,
              body: r.value.body,
            });
          }
          const parsedRes = parseFrostPartialSignatureResponse(r.value.body);
          if (parsedRes.nonceId !== noncePerSlot.get(r.slot)!.nonceId) {
            return reply.code(502).send({
              error: "frost_partial_nonce_id_drift",
              slot: r.slot,
              requestId,
              expectedNonceId: noncePerSlot.get(r.slot)!.nonceId,
              actualNonceId: parsedRes.nonceId,
            });
          }
          signatureShareEntries.push({ slot: r.slot, signatureShare: parsedRes.signatureShare });
          partialPerSlot.set(r.slot, { transcriptHash: parsedRes.transcriptHash });
        }
        signatureShareEntries.sort((a, b) => a.slot - b.slot);

        // 11. Phase C — aggregate on slot[0].
        const aggregateBody = {
          messageBytes: messageHex,
          commitments: commitmentEntries,
          signatureShares: signatureShareEntries,
        };
        const aggregateSlot = sortedSelectedSlots[0];
        let aggregateRes;
        try {
          aggregateRes = await singleNodeForwarder(
            "/worker/v2/frost/sign/aggregate",
            aggregateBody,
            dkgRoster,
            aggregateSlot,
          );
        } catch (err) {
          return reply.code(502).send({
            error: "frost_aggregate_forward_rejected",
            slot: aggregateSlot,
            requestId,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
        if (aggregateRes.statusCode !== 200) {
          return reply.code(502).send({
            error: "frost_aggregate_unexpected_status",
            slot: aggregateSlot,
            requestId,
            statusCode: aggregateRes.statusCode,
            body: aggregateRes.body,
          });
        }
        const aggregateParsed = parseFrostAggregateSignatureResponse(aggregateRes.body);
        const groupSignature = aggregateParsed.signature;

        // 12. Assemble 27-field withdrawV2CallArgsFields.
        const withdrawV2CallArgsFields = {
          root: parsed.root,
          nullifierHash: parsed.nullifierHash,
          recipient: parsed.recipient,
          recipientHash: parsed.recipientHash,
          amountTag: parsed.amountTag,
          caPayloadHash: caPayloadHashFr,
          requestHash: parsed.requestHash,
          // ASP: asp_root + the 2 LeanIMT depths are public inputs of the withdraw proof, carried
          // on the finalize request (same as root/requestHash). Threaded into the call-args.
          aspRoot: parsed.aspRoot,
          stateTreeDepth: String(parsed.stateTreeDepth),
          aspTreeDepth: String(parsed.aspTreeDepth),
          vaultSequence: String(parsed.vaultSequence),
          withdrawProof: parsed.withdrawProofHex,
          expirySecs: String(parsed.expirySecs),
          groupSignature,
          fallbackBitmap: 0,
          fallbackSignatures: [] as string[],
          newBalanceP: caPayload.newBalanceP,
          newBalanceR: caPayload.newBalanceR,
          newBalanceREffAud: caPayload.newBalanceREffAud,
          amountP: caPayload.amountP,
          amountRSender: caPayload.amountRSender,
          amountRRecip: caPayload.amountRRecip,
          amountREffAud: caPayload.amountREffAud,
          ekVolunAuds: caPayload.ekVolunAuds,
          amountRVolunAuds: caPayload.amountRVolunAuds,
          zkrpNewBalance: caPayload.zkrpNewBalance,
          zkrpAmount: caPayload.zkrpAmount,
          sigmaProtoComm: caPayload.sigmaProtoComm,
          sigmaProtoResp: caPayload.sigmaProtoResp,
          memo: caPayload.memo,
        };

        // 13. Persist updated __finalize.json (write_atomic_replace — overwrites the M4-c4
        //     stub with the M5-c1 fully-assembled artifact).
        const attestationConfig = {
          chainId: parsed.chainId,
          bridge: parsed.attestationConfig.bridge,
          vault: parsed.attestationConfig.vault,
          assetType: parsed.assetType,
          operatorSetVersion: parsed.attestationConfig.operatorSetVersion,
          rosterHash: dkgRosterHash,
          frostGroupPubkey: parsed.attestationConfig.frostGroupPubkey,
          circuitVersionsHash: parsed.attestationConfig.circuitVersionsHash,
        };
        const newFinalizeArtifact = {
          scheme: "mpcca_withdraw_v2_finalize" as const,
          dkgEpoch: parsed.dkgEpoch,
          requestId,
          // notImplementedPhase REMOVED — assembly is complete.
          attestationConfig,
          withdrawV2CallArgsFields,
          mpccaWithdrawFinalizeArtifact: mpccaArtifact,
          frostAttestationTranscriptHashes: {
            nonceCommit: Array.from(noncePerSlot.entries()).map(([slot, v]) => ({
              slot,
              transcriptHash: v.transcriptHash,
            })),
            partialSign: Array.from(partialPerSlot.entries()).map(([slot, v]) => ({
              slot,
              transcriptHash: v.transcriptHash,
            })),
            aggregate: aggregateParsed.transcriptHash,
          },
          transcriptHash: finalizeArtifact.transcriptHash,
          caPayloadHashRaw,
          caPayloadHashFr,
          messageBytes: messageHex,
          createdAtUnixMs: Date.now(),
        };
        const finalizeJson = JSON.stringify(newFinalizeArtifact, null, 2) + "\n";
        // Atomic replace (tmp + rename) — this overwrites the M4-c4 stub.
        const { writeFile: writeFileAtomic, rename: renameAtomic, chmod: chmodAtomic } =
          await import("node:fs/promises");
        const tmpPath = `${finalizeArtifactPath}.tmp.${process.pid}.${Date.now()}`;
        await writeFileAtomic(tmpPath, finalizeJson, { mode: 0o600 });
        await chmodAtomic(tmpPath, 0o600);
        await renameAtomic(tmpPath, finalizeArtifactPath);

        // 14. Return 200.
        return reply.code(200).send({
          accepted: true,
          requestId,
          dkgEpoch: parsed.dkgEpoch,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          caPayloadHashRaw,
          caPayloadHashFr,
          groupSignature,
          withdrawV2CallArgsFields,
          transcriptPath: finalizeArtifactPath,
          message:
            "M5-c1 FROST attestation complete; __finalize.json updated with full 27-field " +
            "WithdrawV2CallArgs. The M5b submit route is now unblocked.",
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
  // V2 deposit FROST attestation orchestrator (goal.md required-work item 2).
  //
  // POST /v2/deposit/frost-attest takes a depositor-supplied DepositFrostAttestRequest carrying
  // (commitment, amount_tag, ca_payload_hash, deposit_nonce, expiry, bridge identity envelope),
  // BCS-encodes the DepositAttestationV2Message domain-separated `EUNOMA_DEPOSIT_BIND_V2`, runs
  // the same 3-phase FROST signing fanout used by the withdraw frost-attest route over the
  // depositor-supplied 5-of-7 selectedSlots, and returns the FROST group signature.
  //
  // Differences from withdraw frost-attest:
  //  - No round2/finalize artifacts to load — deposits have no prior MPCCA ceremony because
  //    amount + balance stay depositor-side. The depositor commits to commitment + amount_tag
  //    locally (Poseidon over their private witness) and the deoperator quorum only signs the
  //    PUBLIC chain envelope. Plaintext amount/blind/secret/nullifier never reach this route
  //    (forbidden-field guard rejects them in parseDepositFrostAttestRequest).
  //  - Caller picks selectedSlots directly (no quorum lock-in from round2). Validated for
  //    length 5, distinctness, range [0, DEOPERATOR_COUNT).
  //  - No vault-in-flight lock — deposits are independent of other deposits / withdraws and
  //    multiple can proceed concurrently as long as worker FROST nonce slots aren't exhausted.
  //
  // Wire shape:
  //   1. Forbidden-plaintext-field guard FIRST on raw body.
  //   2. parseDepositFrostAttestRequest — 15 fields.
  //   3. isSafeId(requestId).
  //   4. Roster + epoch validation against opts.caDkgV2Roster.
  //   5. Build + BCS-encode DepositAttestationV2Message.
  //   6. Phase A: nonce-commit fan-out (AbortController timeouts, default 30s).
  //   7. Phase B: partial-sign fan-out (AbortController timeouts).
  //   8. Phase C: aggregate on selectedSlots[0].
  //   9. Persist artifact at <stateRoot>/coordinator/deposit_frost_attest/<dkgEpoch>__<requestId>.json.
  //  10. Return 200 with caPayloadHash + groupSignature + messageBytesHex + assembled
  //      depositCallArgsFields for the depositor to compose into deposit_with_commitment_v2.
  // =================================================================================================
  const depositFrostAttestWorkerTimeoutMs =
    opts.mpccaWithdrawFinalizeWorkerTimeoutMs ?? 30_000;
  server.post("/v2/deposit/frost-attest", async (req, reply) => {
    const raw = (req.body ?? {}) as Record<string, unknown>;
    let requestId: string | undefined;
    try {
      // 1+2. Parse + forbidden-field guard (inside parseDepositFrostAttestRequest).
      let parsed: DepositFrostAttestRequest;
      try {
        parsed = parseDepositFrostAttestRequest(raw);
      } catch (err) {
        if (err instanceof ForbiddenPlaintextFieldError) {
          return reply
            .code(400)
            .send({ error: "forbidden_plaintext_field", field: err.path });
        }
        if (err instanceof DepositFrostAttestError) {
          return reply.code(400).send({ error: err.code, message: err.message });
        }
        return reply.code(400).send({
          error: "invalid_request",
          message: err instanceof Error ? err.message : "unknown",
        });
      }

      requestId = parsed.requestId;
      if (!isSafeId(requestId)) {
        return reply.code(400).send({
          error: "unsafe_request_id",
          message:
            "requestId must be 1..=128 chars of [A-Za-z0-9._-]; coordinator embeds it into FS paths",
        });
      }

      // 4. Roster + epoch validation.
      const dkgRoster = raw.caDkgV2Roster
        ? parseCaDkgV2Roster(raw.caDkgV2Roster)
        : requireCaDkgV2Roster(opts.caDkgV2Roster);
      validateCaDkgV2Roster(dkgRoster);
      const dkgRosterHash = caDkgV2RosterHash(dkgRoster);
      if (parsed.rosterHash !== dkgRosterHash) {
        return reply.code(400).send({
          error: "stale_roster_hash",
          requestId,
          message: `rosterHash mismatch (request=${parsed.rosterHash}, roster=${dkgRosterHash})`,
        });
      }
      if (parsed.dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          requestId,
          message: `dkgEpoch mismatch (request=${parsed.dkgEpoch}, roster=${dkgRoster.dkgEpoch})`,
        });
      }

      const sortedSelectedSlots = [...parsed.selectedSlots].sort((a, b) => a - b);

      // 5. Build + BCS-encode DepositAttestationV2Message. Identical layout to what Move's
      //    `assert_deop_attestation_v2` verifies inside deposit_with_commitment_v2.
      const attestationMessage = {
        chainId: parsed.chainId,
        bridge: parsed.bridge,
        vault: parsed.vault,
        assetType: parsed.assetType,
        operatorSetVersion: parsed.operatorSetVersion,
        dkgEpoch: parsed.dkgEpoch,
        rosterHash: dkgRosterHash,
        frostGroupPubkey: parsed.frostGroupPubkey,
        commitment: parsed.commitment,
        amountTag: parsed.amountTag,
        caPayloadHash: parsed.caPayloadHash,
        depositNonce: parsed.depositNonce,
        expirySecs: parsed.expirySecs,
        circuitVersionsHash: parsed.circuitVersionsHash,
        // (B) deposit re-key: bind the depositing user into the deop-signed message so a
        // relayer-submitted step2a is authenticated to user_addr. Appended last (matches the Move
        // serializer + struct). The 5-of-7 FROST/fallback signers cover it automatically (they sign
        // the opaque messageBytes — no nonce/partial/aggregate phase change needed).
        userAddr: parsed.userAddr,
      };
      const messageBytes = bcsEncodeDepositAttestationV2(attestationMessage);
      const messageHex = bytesToHex(messageBytes);

      // 6. Phase A — nonce-commit fan-out.
      const nonceCommitPromises = sortedSelectedSlots.map((slot) => {
        const controller = new AbortController();
        const timer = setTimeout(
          () => controller.abort(),
          depositFrostAttestWorkerTimeoutMs,
        );
        return singleNodeForwarder(
          "/worker/v2/frost/sign/nonce-commit",
          { requestId },
          dkgRoster,
          slot,
          controller.signal,
        )
          .then(
            (value) => ({
              kind: "value" as const,
              slot,
              value,
              aborted: controller.signal.aborted,
            }),
            (reason) => ({
              kind: "rejected" as const,
              slot,
              reason,
              aborted: controller.signal.aborted,
            }),
          )
          .finally(() => clearTimeout(timer));
      });
      const nonceResults = await Promise.all(nonceCommitPromises);
      const commitmentEntries: Array<{ slot: number; commitments: unknown }> = [];
      const noncePerSlot = new Map<number, { nonceId: string; transcriptHash: string }>();
      for (const r of nonceResults) {
        if (r.kind === "rejected") {
          return reply.code(502).send({
            error: r.aborted ? "frost_nonce_worker_timeout" : "frost_nonce_forward_rejected",
            slot: r.slot,
            requestId,
            reason: r.reason instanceof Error ? r.reason.message : String(r.reason),
          });
        }
        if (r.aborted) {
          return reply.code(502).send({
            error: "frost_nonce_worker_timeout",
            slot: r.slot,
            requestId,
          });
        }
        if (r.value.statusCode !== 200) {
          return reply.code(502).send({
            error: "frost_nonce_unexpected_status",
            slot: r.slot,
            requestId,
            statusCode: r.value.statusCode,
            body: r.value.body,
          });
        }
        const parsedRes = parseFrostNonceCommitmentResponse(r.value.body);
        commitmentEntries.push({ slot: r.slot, commitments: parsedRes.commitments });
        noncePerSlot.set(r.slot, {
          nonceId: parsedRes.nonceId,
          transcriptHash: parsedRes.transcriptHash,
        });
      }
      commitmentEntries.sort((a, b) => a.slot - b.slot);

      // 7. Phase B — partial-sign fan-out.
      const partialSignPromises = sortedSelectedSlots.map((slot) => {
        const controller = new AbortController();
        const timer = setTimeout(
          () => controller.abort(),
          depositFrostAttestWorkerTimeoutMs,
        );
        const body = {
          nonceId: noncePerSlot.get(slot)!.nonceId,
          messageBytes: messageHex,
          commitments: commitmentEntries,
        };
        return singleNodeForwarder(
          "/worker/v2/frost/sign/partial",
          body,
          dkgRoster,
          slot,
          controller.signal,
        )
          .then(
            (value) => ({
              kind: "value" as const,
              slot,
              value,
              aborted: controller.signal.aborted,
            }),
            (reason) => ({
              kind: "rejected" as const,
              slot,
              reason,
              aborted: controller.signal.aborted,
            }),
          )
          .finally(() => clearTimeout(timer));
      });
      const partialResults = await Promise.all(partialSignPromises);
      const signatureShareEntries: Array<{ slot: number; signatureShare: unknown }> = [];
      const partialPerSlot = new Map<number, { transcriptHash: string }>();
      for (const r of partialResults) {
        if (r.kind === "rejected") {
          return reply.code(502).send({
            error: r.aborted ? "frost_partial_worker_timeout" : "frost_partial_forward_rejected",
            slot: r.slot,
            requestId,
            reason: r.reason instanceof Error ? r.reason.message : String(r.reason),
          });
        }
        if (r.aborted) {
          return reply.code(502).send({
            error: "frost_partial_worker_timeout",
            slot: r.slot,
            requestId,
          });
        }
        if (r.value.statusCode !== 200) {
          return reply.code(502).send({
            error: "frost_partial_unexpected_status",
            slot: r.slot,
            requestId,
            statusCode: r.value.statusCode,
            body: r.value.body,
          });
        }
        const parsedRes = parseFrostPartialSignatureResponse(r.value.body);
        if (parsedRes.nonceId !== noncePerSlot.get(r.slot)!.nonceId) {
          return reply.code(502).send({
            error: "frost_partial_nonce_id_drift",
            slot: r.slot,
            requestId,
            expectedNonceId: noncePerSlot.get(r.slot)!.nonceId,
            actualNonceId: parsedRes.nonceId,
          });
        }
        signatureShareEntries.push({ slot: r.slot, signatureShare: parsedRes.signatureShare });
        partialPerSlot.set(r.slot, { transcriptHash: parsedRes.transcriptHash });
      }
      signatureShareEntries.sort((a, b) => a.slot - b.slot);

      // 8. Phase C — aggregate on first sorted slot.
      const aggregateBody = {
        messageBytes: messageHex,
        commitments: commitmentEntries,
        signatureShares: signatureShareEntries,
      };
      const aggregateSlot = sortedSelectedSlots[0];
      let aggregateRes;
      try {
        aggregateRes = await singleNodeForwarder(
          "/worker/v2/frost/sign/aggregate",
          aggregateBody,
          dkgRoster,
          aggregateSlot,
        );
      } catch (err) {
        return reply.code(502).send({
          error: "frost_aggregate_forward_rejected",
          slot: aggregateSlot,
          requestId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      if (aggregateRes.statusCode !== 200) {
        return reply.code(502).send({
          error: "frost_aggregate_unexpected_status",
          slot: aggregateSlot,
          requestId,
          statusCode: aggregateRes.statusCode,
          body: aggregateRes.body,
        });
      }
      const aggregateParsed = parseFrostAggregateSignatureResponse(aggregateRes.body);
      const groupSignature = aggregateParsed.signature;

      const attestationTranscriptHash = depositAttestationTranscriptHash(
        messageHex,
        groupSignature,
      );

      // 9. Persist artifact for audit.
      if (opts.stateRoot) {
        const { mkdir: mkdirAsync, writeFile: writeFileAsync, rename: renameAsync, chmod: chmodAsync } =
          await import("node:fs/promises");
        const artifactDir = join(opts.stateRoot, "coordinator", "deposit_frost_attest");
        await mkdirAsync(artifactDir, { recursive: true, mode: 0o700 });
        const artifactPath = join(artifactDir, `${parsed.dkgEpoch}__${requestId}.json`);
        const artifact: DepositFrostAttestArtifact = {
          scheme: "deposit_frost_attest_v2",
          dkgEpoch: parsed.dkgEpoch,
          requestId,
          rosterHash: dkgRosterHash,
          selectedSlots: sortedSelectedSlots,
          messageBytesHex: messageHex,
          groupSignature,
          perSlotTranscriptHashes: sortedSelectedSlots.map((slot) => ({
            slot,
            nonceTranscriptHash: noncePerSlot.get(slot)!.transcriptHash,
            partialTranscriptHash: partialPerSlot.get(slot)!.transcriptHash,
          })),
          attestationTranscriptHash,
          createdAtUnixMs: Date.now(),
        };
        const json = JSON.stringify(artifact, null, 2) + "\n";
        const tmpPath = `${artifactPath}.tmp.${process.pid}.${Date.now()}`;
        await writeFileAsync(tmpPath, json, { mode: 0o600 });
        await chmodAsync(tmpPath, 0o600);
        await renameAsync(tmpPath, artifactPath);
      }

      // 10. Return 200.
      return reply.code(200).send({
        accepted: true,
        requestId,
        dkgEpoch: parsed.dkgEpoch,
        rosterHash: dkgRosterHash,
        selectedSlots: sortedSelectedSlots,
        caPayloadHash: parsed.caPayloadHash,
        messageBytesHex: messageHex,
        groupSignature,
        attestationTranscriptHash,
        depositCallArgsFields: {
          // Caller composes these into the 24-arg deposit_with_commitment_v2 call alongside
          // their depositor-only Groth16 proof + CA payload bytes.
          commitment: parsed.commitment,
          amountTag: parsed.amountTag,
          caPayloadHash: parsed.caPayloadHash,
          depositNonce: parsed.depositNonce,
          expirySecs: parsed.expirySecs,
          groupSignature,
          fallbackBitmap: 0,
          fallbackSignatures: [] as string[],
        },
        message:
          "Deposit FROST attestation complete; group signature ready for deposit_with_commitment_v2.",
      });
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply
          .code(400)
          .send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof DepositFrostAttestError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(500).send({
        error: "internal_error",
        requestId,
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
        // 5. Load the finalize transcript. The loader enforces both shape AND identity
        // (dkgEpoch / requestId on disk must match the request tuple) — Codex M5b P1 #2.
        let finalize: Awaited<ReturnType<typeof loadMpccaFinalizeTranscript>>;
        try {
          finalize = await loadMpccaFinalizeTranscript(
            opts.stateRoot,
            parsed.dkgEpoch,
            parsed.requestId,
          );
        } catch (err) {
          if (err instanceof WithdrawSubmitAssemblyError) {
            return reply.code(400).send({
              error: err.code,
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              message: err.message,
            });
          }
          throw err;
        }
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
        // Stage 4 A6 gas split: callers that already verified the FROST attestation via
        // prepare_withdraw_attestation_v2 ask submit to pass an empty groupSignature. Move
        // then consumes the exact prepared public tuple keyed by request_hash.
        const finalizeForAssembly =
          parsed.preparedWithdrawAttestation === true && finalize.withdrawV2CallArgsFields
            ? {
                ...finalize,
                withdrawV2CallArgsFields: {
                  ...finalize.withdrawV2CallArgsFields,
                  groupSignature: "0x",
                  fallbackBitmap: 0,
                  fallbackSignatures: [],
                },
              }
            : finalize;
        let assembleResult: WithdrawV2CallArgsShape | { notImplementedPhase: string };
        try {
          assembleResult = assembleWithdrawV2CallArgs(finalizeForAssembly);
        } catch (err) {
          // Codex M5b P1 #1: structural no-auditor violation surfaces as 400 with the
          // stable code, mirroring the relayer parser's wire shape so callers can
          // branch deterministically.
          if (err instanceof WithdrawSubmitAssemblyError) {
            return reply.code(400).send({
              error: err.code,
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              message: err.message,
            });
          }
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
        async function persistSubmitTranscript(
          payload: Record<string, unknown>,
          opts2: { noClobber?: boolean } = {},
        ): Promise<string> {
          // Codex M5b P2 #3: stamp the finalize transcript's attestationConfig into the
          // submit artifact (audit trail). The relayer NEVER receives this — it only
          // consumes the 27-field WithdrawV2CallArgs.
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
            ...(finalize!.attestationConfig
              ? { attestationConfig: finalize!.attestationConfig }
              : {}),
            preparedWithdrawAttestation: parsed.preparedWithdrawAttestation === true,
            createdAtUnixMs: Date.now(),
            ...payload,
          };
          const transcriptHash = bytesToHex(
            sha256(new TextEncoder().encode(canonicalJsonStringify(artifactWithoutHash))),
          );
          await writeTranscriptArtifactAtomic(
            submitTranscriptPath,
            { ...artifactWithoutHash, transcriptHash },
            { noClobber: opts2.noClobber === true },
          );
          return transcriptHash;
        }

        // Codex M5b P2 #1: idempotent-retry pre-check. If a prior successful submit
        // artifact already exists at this path AND its recorded submitInputHash matches
        // what we'd hand the relayer today, return that artifact verbatim — no rebroadcast.
        // If it exists with completed:true but the inputs differ, return 409 so the
        // caller cannot silently replace a committed audit record. If it exists with
        // completed:false (stub passthrough or any failure state), allow re-attempt.
        //
        // The hash is computed BEFORE the stub-passthrough branch so an existing
        // completed-success artifact short-circuits even if the finalize transcript on
        // disk has somehow regressed to a stub (defense-in-depth).
        const submitInputHash = bytesToHex(
          sha256(new TextEncoder().encode(canonicalJsonStringify(assembleResult))),
        );
        let existingSubmitArtifact: Record<string, unknown> | null = null;
        try {
          const raw = await readFile(submitTranscriptPath, "utf8");
          existingSubmitArtifact = JSON.parse(raw) as Record<string, unknown>;
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
          }
        }
        if (
          existingSubmitArtifact &&
          existingSubmitArtifact.completed === true
        ) {
          const recordedInputHash = existingSubmitArtifact.submitInputHash;
          if (typeof recordedInputHash !== "string" || recordedInputHash !== submitInputHash) {
            return reply.code(409).send({
              error: "mpcca_withdraw_submit_already_completed_with_different_inputs",
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              transcriptPath: submitTranscriptPath,
              message:
                "a prior submit for this (dkgEpoch, requestId) already completed with a " +
                "DIFFERENT assembled WithdrawV2CallArgs; refusing to overwrite the audit " +
                "record. Investigate before retrying.",
            });
          }
          // Inputs are byte-identical — return the existing artifact verbatim. We do
          // NOT re-invoke the relayer (no rebroadcast). Status code mirrors the
          // original outcome: 202 for simulated, 200 for real-confirmed.
          const wasSimulated = existingSubmitArtifact.simulated === true;
          return reply.code(wasSimulated ? 202 : 200).send({
            accepted: existingSubmitArtifact.accepted === true,
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            txHash: existingSubmitArtifact.txHash,
            simulated: wasSimulated,
            completed: true,
            transcriptHash: existingSubmitArtifact.transcriptHash,
            transcriptPath: submitTranscriptPath,
            idempotentReplay: true,
          });
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
        //
        // Codex M5b P1 #4: for `simulated:false` (real submission), chainNodeUrl is
        // REQUIRED. Without it the route would skip chain confirmation entirely and
        // return 200 completed after relayer acceptance — fail closed instead so a
        // misconfigured deploy cannot silently broadcast unconfirmed transactions.
        if (!relayerResult.simulated && !opts.chainNodeUrl) {
          const transcriptHash = await persistSubmitTranscript({
            completed: false,
            simulated: false,
            txHash: relayerResult.txHash,
            chainConfirmationError: "chain_node_url_required_for_real_submit",
          });
          return reply.code(502).send({
            error: "chain_node_url_required_for_real_submit",
            requestId: parsed.requestId,
            dkgEpoch: parsed.dkgEpoch,
            txHash: relayerResult.txHash,
            transcriptHash,
            transcriptPath: submitTranscriptPath,
            message:
              "relayer returned simulated:false but coordinator has no chainNodeUrl " +
              "configured; set APTOS_NODE_URL in the environment or inject `chainNodeUrl` " +
              "into buildCoordinatorServer so the submit route can confirm chain execution",
          });
        }
        let confirmation: { confirmed: boolean; success?: boolean; vmStatus?: string } | null =
          null;
        let postWithdrawResync: Record<string, unknown> | undefined;
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
          // Codex M5b P1 #3: confirmed=true but success=false means the chain ran the
          // tx and ABORTED (e.g. MOVE_ABORT, OUT_OF_GAS). Previously the route returned
          // 200 completed: true with the failed vmStatus only logged in the artifact.
          // Fail closed with a 502 chain_execution_failed surfacing vmStatus so operators
          // see the exact abort reason. Persist the artifact with completed: false so
          // retries (P2 #1) are NOT short-circuited as idempotent.
          if (confirmation.success === false) {
            const transcriptHash = await persistSubmitTranscript({
              completed: false,
              simulated: false,
              txHash: relayerResult.txHash,
              chainSuccess: false,
              chainVmStatus: confirmation.vmStatus,
              chainConfirmationError: "chain_execution_failed",
            });
            return reply.code(502).send({
              error: "chain_execution_failed",
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              txHash: relayerResult.txHash,
              vmStatus: confirmation.vmStatus,
              transcriptHash,
              transcriptPath: submitTranscriptPath,
              message:
                `tx ${relayerResult.txHash} confirmed on-chain with failed execution` +
                (confirmation.vmStatus ? ` (vmStatus=${confirmation.vmStatus})` : ""),
            });
          }

          try {
            const attestationConfig = finalize!.attestationConfig;
            if (!attestationConfig) {
              throw new Error("withdraw_resync_attestation_config_missing");
            }
            const tx = await fetchAptosTransactionByHash(
              opts.chainNodeUrl,
              relayerResult.txHash,
              opts.chainFetch,
            );
            const binding = parseWithdrawEventForSubmitResync(tx, attestationConfig.bridge);
            const resyncPayload = {
              dkgEpoch: parsed.dkgEpoch,
              requestId: parsed.requestId,
              txHash: relayerResult.txHash,
              bridgePackage: attestationConfig.bridge,
              vault: attestationConfig.vault,
              assetType: attestationConfig.assetType,
              root: binding.root,
              nullifierHash: binding.nullifierHash,
              recipientHash: binding.recipientHash,
              requestHash: binding.requestHash,
              eventVaultSequence: binding.eventVaultSequence,
              expectedNextSequence: binding.eventVaultSequence + 1,
              trigger: "after_withdraw",
            };
            // Reuse the public resync route internally so the submit path inherits the same
            // validation, worker fan-out, quorum threshold, and transcript persistence. This is
            // best-effort after a chain-confirmed withdraw: a resync failure must not pretend the
            // already-executed withdraw failed, but it is persisted for ops/debug and surfaced to
            // the caller.
            const resyncRes = await server.inject({
              method: "POST",
              url: "/v2/vault/resync_after_withdraw",
              headers: opts.bearerToken ? { authorization: `Bearer ${opts.bearerToken}` } : {},
              payload: resyncPayload,
            });
            let resyncBody: unknown = null;
            try {
              resyncBody = JSON.parse(resyncRes.payload);
            } catch {
              resyncBody = { raw: resyncRes.payload };
            }
            postWithdrawResync = {
              attempted: true,
              statusCode: resyncRes.statusCode,
              ok: resyncRes.statusCode >= 200 && resyncRes.statusCode < 300,
              body: resyncBody,
            };
          } catch (err) {
            postWithdrawResync = {
              attempted: true,
              ok: false,
              error: err instanceof Error ? err.message : "withdraw_resync_failed",
            };
          }
        }
        // 9. Persist the success submit-transcript artifact. Codex M5b P2 #1: stamp
        // `submitInputHash` so subsequent retries can verify byte-identical inputs.
        // Use noClobber: any prior completed artifact at this path should have already
        // short-circuited the idempotent-retry pre-check; if it didn't (race or stale
        // state on disk) we MUST fail closed rather than overwrite the audit record.
        let submitTranscriptHash: string;
        try {
          submitTranscriptHash = await persistSubmitTranscript(
            {
              completed: true,
              simulated: relayerResult.simulated,
              accepted: relayerResult.accepted,
              submitInputHash,
              txHash: relayerResult.txHash,
              ...(confirmation
                ? {
                    chainSuccess: confirmation.success,
                    chainVmStatus: confirmation.vmStatus,
                  }
                : {}),
              ...(postWithdrawResync ? { postWithdrawResync } : {}),
            },
            { noClobber: true },
          );
        } catch (persistErr) {
          if (
            persistErr instanceof Error &&
            (persistErr as NodeJS.ErrnoException).code === "EEXIST"
          ) {
            // A completed artifact materialized between the idempotent-retry pre-check
            // and now (race window). Fail closed rather than overwrite the audit record.
            return reply.code(409).send({
              error: "mpcca_withdraw_submit_already_completed_with_different_inputs",
              requestId: parsed.requestId,
              dkgEpoch: parsed.dkgEpoch,
              transcriptPath: submitTranscriptPath,
              message:
                "a completed submit artifact materialized concurrently; refusing to " +
                "overwrite the audit record. Re-issue the submit request to read the " +
                "existing artifact's outcome.",
            });
          }
          throw persistErr;
        }
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
          ...(postWithdrawResync ? { postWithdrawResync } : {}),
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

  // M10-c — POST /v2/balance/decrypt. Fan-out + SHA-256 transcript verification.
  // Uses the same `singleNodeForwarder` and `caDkgV2Roster` already wired above.
  // M10-l (codex iter-6 P1-13): bridgeVaultAddress + bridgeAssetType come from
  // env (BRIDGE_VAULT_ADDRESS / BRIDGE_ASSET_TYPE) via CoordinatorConfig; the
  // route rejects any request whose vaultAddress/assetType don't match.
  registerBalanceDecryptRoute(server, {
    getDefaultRoster: () => opts.caDkgV2Roster,
    getBridgeVaultAddress: () => opts.bridgeVaultAddress,
    getBridgeAssetType: () => opts.bridgeAssetType,
    forwarder: singleNodeForwarder,
  });

  // NORMALIZE plan (2026-05-27) — POST /v2/normalize/sigma/s0. Reuses the same
  // bridge-config getters, default-roster source, and per-slot forwarder as the
  // balance-decrypt route so the M10-l chosen-vault gate applies identically.
  registerNormalizeSigmaS0Route(server, {
    getDefaultRoster: () => opts.caDkgV2Roster,
    getBridgeVaultAddress: () => opts.bridgeVaultAddress,
    getBridgeAssetType: () => opts.bridgeAssetType,
    forwarder: singleNodeForwarder,
  });

  // M11: post-withdraw vault-state resync fan-out. Two paths (same behavior,
  // distinguished for audit). Reuses the same roster getter, bridge config
  // getters, and per-slot forwarder as balance-decrypt.
  const vaultResyncOpts = {
    getDefaultRoster: () => opts.caDkgV2Roster,
    getBridgeVaultAddress: () => opts.bridgeVaultAddress,
    getBridgeAssetType: () => opts.bridgeAssetType,
    forwarder: singleNodeForwarder,
    stateRoot: opts.stateRoot,
  };
  registerVaultResyncRoute(server, vaultResyncOpts, "/v2/vault/resync_after_withdraw", "after_withdraw");
  registerVaultResyncRoute(server, vaultResyncOpts, "/v2/vault/resync_before_round1", "before_round1");

  // CP3 deposit-delegate: forward the assembled DepositV3DelegateArgs to the relayer's
  // /v3/relayer/submit/deposit (prepare_deposit_binding_v3 + deposit_step2a_v3). step2b stays
  // user-signed → deposit = 1 user sig. Bearer-protected by the global onRequest hook; the BFF
  // forbidden-plaintext-field guard runs before this, and the relayer re-validates the body.
  server.post("/v2/deposit/delegate-submit", async (req, reply) => {
    if (!opts.depositRelayerSubmitter) {
      return reply
        .code(502)
        .send({ error: "relayer_unreachable", message: "deposit-delegate submitter not configured" });
    }
    try {
      const result = await opts.depositRelayerSubmitter(req.body);
      return reply.code(202).send(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown";
      // The relayer's gas breaker / reserve guard surfaces as relayer_self_submit:<reason> — relay
      // it to the browser so it falls back to Petra-signing prepare/step2a itself.
      if (msg.startsWith("relayer_self_submit:")) {
        return reply
          .code(200)
          .send({ action: "self_submit", reason: msg.slice("relayer_self_submit:".length).trim() });
      }
      return reply.code(502).send({ error: "relayer_returned_error", message: msg });
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
  return async (path, body, roster, slot, signal) => {
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
        signal,
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
  opts: { noClobber?: boolean } = {},
): Promise<void> {
  // Codex M2a P2 #2: write to <path>.tmp.<pid>.<random> with flag 'wx' (O_EXCL +
  // O_CREAT, fails if path exists), fsync via writeFile's flag chain isn't possible in
  // Node's fs/promises — but the create_new + rename is the load-bearing atomicity
  // guarantee: rename(2) on the same FS is atomic and the tmp name is unguessable, so
  // a concurrent writer can't clobber an in-progress write.
  // Loop on AlreadyExists with a fresh random suffix. 16 attempts is far more than
  // enough — collisions on 8 random bytes + pid + ms are astronomically unlikely.
  //
  // Codex M5b P2 #1: opt-in noClobber mode. When `opts.noClobber === true`, we use
  // `link()` (atomic, fails with EEXIST if target exists) + unlink the tmp source
  // instead of `rename()` (which silently replaces). Caller surfaces EEXIST on the
  // FINAL path as a semantic error (e.g. 409 already_completed_with_different_inputs);
  // EEXIST on the TMP path remains an internal retry condition.
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
    } catch (err) {
      if (
        err instanceof Error &&
        (err as NodeJS.ErrnoException).code === "EEXIST"
      ) {
        // tmp suffix collided; retry with a fresh suffix.
        lastErr = err;
        continue;
      }
      throw err;
    }
    try {
      await chmod(tmp, 0o600);
      if (opts.noClobber === true) {
        // link() is atomic across the same filesystem; fails with EEXIST if `path`
        // already exists. We then unlink the tmp source to leave only the final path.
        await link(tmp, path);
        await unlink(tmp).catch(() => undefined);
      } else {
        await rename(tmp, path);
      }
      return;
    } catch (finalizeErr) {
      // best-effort cleanup of the tmp we created (the rename or link may have
      // failed; the tmp could still be sitting on disk).
      await unlink(tmp).catch(() => undefined);
      throw finalizeErr;
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
/**
 * M4 Commit 2 — compare the round2 orchestrate body's identity fields against the persisted
 * `__round1.json` artifact. Catches a caller that supplies a wrong vault_ek / sender / asset
 * / selectedSlots etc., that would otherwise sneak past the worker (the chained-round binding
 * uses the round1 transcript hash, which already differs if any of these drift — but giving
 * a specific 400 here surfaces the mismatch sooner with operator-actionable detail).
 *
 * Returns `undefined` on no mismatch; otherwise a structured `{field, round1Value, requestValue}`
 * describing the first divergence (left-to-right field order).
 */
function compareRound2IdentityWithRound1(
  request: MpccaWithdrawRound2OrchestrateRequest,
  round1: Record<string, unknown>,
  sortedSelectedSlots: number[],
):
  | { field: string; round1Value: unknown; requestValue: unknown }
  | undefined {
  const lowerHex = (v: unknown): string => {
    if (typeof v !== "string") return "";
    return v.replace(/^0x/i, "").toLowerCase();
  };
  const checks: Array<[string, unknown, unknown]> = [
    ["dkgEpoch", round1.dkgEpoch, request.dkgEpoch],
    ["rosterHash", lowerHex(round1.rosterHash), lowerHex(request.rosterHash)],
    [
      "vaultEkTranscriptHash",
      lowerHex(round1.vaultEkTranscriptHash),
      lowerHex(request.vaultEkTranscriptHash),
    ],
    [
      "registrationTranscriptHash",
      lowerHex(round1.registrationTranscriptHash),
      lowerHex(request.registrationTranscriptHash),
    ],
    [
      "vaultStateInitTranscriptHash",
      lowerHex(round1.vaultStateInitTranscriptHash),
      lowerHex(request.vaultStateInitTranscriptHash),
    ],
    ["vaultEk", lowerHex(round1.vaultEk), lowerHex(request.vaultEk)],
    [
      "senderAddress",
      lowerHex(round1.senderAddress),
      lowerHex(request.senderAddress),
    ],
    ["assetType", lowerHex(round1.assetType), lowerHex(request.assetType)],
    ["chainId", round1.chainId, request.chainId],
    ["root", lowerHex(round1.root), lowerHex(request.root)],
    [
      "nullifierHash",
      lowerHex(round1.nullifierHash),
      lowerHex(request.nullifierHash),
    ],
    ["recipient", lowerHex(round1.recipient), lowerHex(request.recipient)],
    [
      "recipientHash",
      lowerHex(round1.recipientHash),
      lowerHex(request.recipientHash),
    ],
    ["amountTag", lowerHex(round1.amountTag), lowerHex(request.amountTag)],
    ["vaultSequence", round1.vaultSequence, request.vaultSequence],
    ["expirySecs", round1.expirySecs, request.expirySecs],
    ["requestHash", lowerHex(round1.requestHash), lowerHex(request.requestHash)],
    ["depositCount", round1.depositCount, request.depositCount],
  ];
  for (const [field, a, b] of checks) {
    if (a !== b) return { field, round1Value: a, requestValue: b };
  }
  // selectedSlots must match (sorted).
  const round1Slots = Array.isArray(round1.selectedSlots)
    ? (round1.selectedSlots as number[])
    : [];
  if (
    round1Slots.length !== sortedSelectedSlots.length ||
    round1Slots.some((v, i) => v !== sortedSelectedSlots[i])
  ) {
    return {
      field: "selectedSlots",
      round1Value: round1Slots,
      requestValue: sortedSelectedSlots,
    };
  }
  // observedDepositTranscriptHashes must match (length + entries).
  const r1Observed = Array.isArray(round1.observedDepositTranscriptHashes)
    ? (round1.observedDepositTranscriptHashes as string[])
    : [];
  if (r1Observed.length !== request.observedDepositTranscriptHashes.length) {
    return {
      field: "observedDepositTranscriptHashes.length",
      round1Value: r1Observed.length,
      requestValue: request.observedDepositTranscriptHashes.length,
    };
  }
  for (let i = 0; i < r1Observed.length; i += 1) {
    if (lowerHex(r1Observed[i]) !== lowerHex(request.observedDepositTranscriptHashes[i])) {
      return {
        field: `observedDepositTranscriptHashes[${i}]`,
        round1Value: r1Observed[i],
        requestValue: request.observedDepositTranscriptHashes[i],
      };
    }
  }
  // The round1 artifact MUST carry transcriptHash + perSlotContributions[5] with
  // ingressTranscriptHash. We don't compare contents here — the caller (round2 route)
  // reads them via direct field access.
  if (typeof round1.transcriptHash !== "string") {
    return {
      field: "transcriptHash",
      round1Value: round1.transcriptHash,
      requestValue: "<derived from round1>",
    };
  }
  if (!Array.isArray(round1.perSlotContributions)) {
    return {
      field: "perSlotContributions",
      round1Value: round1.perSlotContributions,
      requestValue: "<expected array>",
    };
  }
  return undefined;
}

/**
 * M4 commit 4 — cross-check finalize body identity against the persisted __round2.json
 * artifact. Walks every immutable identity field (rosterHash, vault binding hashes, sender,
 * recipient, etc.) and returns the first mismatch for operator triage. The finalize body
 * MUST match round2 byte-for-byte on all these fields; a drift means the coordinator is
 * being asked to finalize a session that doesn't match what round2 produced.
 */
function compareFinalizeIdentityWithRound2(
  request: MpccaWithdrawFinalizeOrchestrateRequest,
  round2: Record<string, unknown>,
  sortedSelectedSlots: number[],
  options: { allowRequestHashUpdate?: boolean } = {},
):
  | { field: string; round2Value: unknown; requestValue: unknown }
  | undefined {
  const lowerHex = (v: unknown): string => {
    if (typeof v !== "string") return "";
    return v.replace(/^0x/i, "").toLowerCase();
  };
  const checks: Array<[string, unknown, unknown]> = [
    ["dkgEpoch", round2.dkgEpoch, request.dkgEpoch],
    ["rosterHash", lowerHex(round2.rosterHash), lowerHex(request.rosterHash)],
    [
      "vaultEkTranscriptHash",
      lowerHex(round2.vaultEkTranscriptHash),
      lowerHex(request.vaultEkTranscriptHash),
    ],
    [
      "registrationTranscriptHash",
      lowerHex(round2.registrationTranscriptHash),
      lowerHex(request.registrationTranscriptHash),
    ],
    [
      "vaultStateInitTranscriptHash",
      lowerHex(round2.vaultStateInitTranscriptHash),
      lowerHex(request.vaultStateInitTranscriptHash),
    ],
    ["vaultEk", lowerHex(round2.vaultEk), lowerHex(request.vaultEk)],
    [
      "senderAddress",
      lowerHex(round2.senderAddress),
      lowerHex(request.senderAddress),
    ],
    ["assetType", lowerHex(round2.assetType), lowerHex(request.assetType)],
    ["chainId", round2.chainId, request.chainId],
    ["root", lowerHex(round2.root), lowerHex(request.root)],
    [
      "nullifierHash",
      lowerHex(round2.nullifierHash),
      lowerHex(request.nullifierHash),
    ],
    ["recipient", lowerHex(round2.recipient), lowerHex(request.recipient)],
    [
      "recipientHash",
      lowerHex(round2.recipientHash),
      lowerHex(request.recipientHash),
    ],
    ["amountTag", lowerHex(round2.amountTag), lowerHex(request.amountTag)],
    ["vaultSequence", round2.vaultSequence, request.vaultSequence],
    ["expirySecs", round2.expirySecs, request.expirySecs],
    // requestHash is intentionally OPTIONAL here. By protocol design, request_hash =
    // Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence,
    // CHAIN_ID). ca_payload_hash depends on post-finalize σ aggregation, so request_hash
    // CANNOT be pre-computed at round1. The user supplies a placeholder requestHash at
    // round1/round2/finalize and the REAL value at frost-attest (which the chain verifies
    // via the FROST-signed message + Groth16 proof). At frost-attest the check is skipped;
    // at finalize it remains enforced (finalize doesn't update ca_payload_hash).
    ...(options.allowRequestHashUpdate
      ? []
      : ([["requestHash", lowerHex(round2.requestHash), lowerHex(request.requestHash)]] as Array<[string, unknown, unknown]>)),
    ["depositCount", round2.depositCount, request.depositCount],
  ];
  for (const [field, a, b] of checks) {
    if (a !== b) return { field, round2Value: a, requestValue: b };
  }
  const round2Slots = Array.isArray(round2.selectedSlots)
    ? (round2.selectedSlots as number[])
    : [];
  if (
    round2Slots.length !== sortedSelectedSlots.length ||
    round2Slots.some((v, i) => v !== sortedSelectedSlots[i])
  ) {
    return {
      field: "selectedSlots",
      round2Value: round2Slots,
      requestValue: sortedSelectedSlots,
    };
  }
  const r2Observed = Array.isArray(round2.observedDepositTranscriptHashes)
    ? (round2.observedDepositTranscriptHashes as string[])
    : [];
  if (r2Observed.length !== request.observedDepositTranscriptHashes.length) {
    return {
      field: "observedDepositTranscriptHashes.length",
      round2Value: r2Observed.length,
      requestValue: request.observedDepositTranscriptHashes.length,
    };
  }
  for (let i = 0; i < r2Observed.length; i += 1) {
    if (lowerHex(r2Observed[i]) !== lowerHex(request.observedDepositTranscriptHashes[i])) {
      return {
        field: `observedDepositTranscriptHashes[${i}]`,
        round2Value: r2Observed[i],
        requestValue: request.observedDepositTranscriptHashes[i],
      };
    }
  }
  if (typeof round2.transcriptHash !== "string") {
    return {
      field: "transcriptHash",
      round2Value: round2.transcriptHash,
      requestValue: "<derived from round2>",
    };
  }
  if (!Array.isArray(round2.perSlotContributions)) {
    return {
      field: "perSlotContributions",
      round2Value: round2.perSlotContributions,
      requestValue: "<expected array>",
    };
  }
  if (!round2.statementInputs || typeof round2.statementInputs !== "object") {
    return {
      field: "statementInputs",
      round2Value: round2.statementInputs,
      requestValue: "<expected object>",
    };
  }
  if (!round2.userProofArtifacts || typeof round2.userProofArtifacts !== "object") {
    return {
      field: "userProofArtifacts",
      round2Value: round2.userProofArtifacts,
      requestValue: "<expected object>",
    };
  }
  return undefined;
}

/**
 * M4 commit 4 — aggregate scalar response shares mod the ed25519 group order.
 * `s[0] = Σ_j s_share_j (mod n)`. Each input is a 32-byte canonical Ed25519 scalar hex (LE).
 */
async function aggregateScalarsModN(hexes: string[]): Promise<string> {
  if (hexes.length === 0) {
    throw new Error("aggregateScalarsModN: empty input");
  }
  const { ed25519 } = await import("@noble/curves/ed25519");
  const { bytesToNumberLE, numberToBytesLE } = await import(
    "@noble/curves/abstract/utils"
  );
  const n = ed25519.CURVE.n;
  let sum = 0n;
  for (let i = 0; i < hexes.length; i += 1) {
    const norm = hexes[i].replace(/^0x/i, "").toLowerCase();
    if (norm.length !== 64) {
      throw new Error(
        `aggregateScalarsModN: input[${i}] must be 64 hex chars; got ${norm.length}`,
      );
    }
    const bytes = new Uint8Array(32);
    for (let b = 0; b < 32; b += 1) {
      bytes[b] = parseInt(norm.slice(b * 2, b * 2 + 2), 16);
    }
    const value = bytesToNumberLE(bytes);
    sum = (sum + value) % n;
  }
  const outBytes = numberToBytesLE(sum, 32);
  return Array.from(outBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

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
