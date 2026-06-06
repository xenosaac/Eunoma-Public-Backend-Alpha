// Relayer HTTP server.
//
// M5a pivot: the route `/v2/relayer/submit/withdraw` accepts the 27 structured
// positional arguments to `eunoma_bridge::withdraw_to_recipient_v2` (see
// move/sources/eunoma_bridge.move:515-543) instead of a pre-signed BCS blob.
//
// Submission flow:
//   1. Fastify accepts POST /v2/relayer/submit/withdraw (bearer-token gated).
//   2. parseWithdrawV2CallArgs runs the recursive forbidden-plaintext-field
//      gate FIRST, then strict shape validation. Plaintext witness fields
//      surface as 400 `forbidden_plaintext_field`; shape failures as 400
//      `invalid_request`.
//   3. The injected submitter callback receives the parsed args and is
//      responsible for invoking `aptos move run` with --simulate by default.
//      The CLI submitter (createAptosCliSubmitter, below) is the production
//      implementation; tests inject mocks for full coverage of the route
//      pipeline.
//
// The legacy `createAptosRestSubmitter` is removed: the relayer no longer
// receives signed BCS, so REST direct-submit is dead code.
import Fastify, { type FastifyInstance } from "fastify";
import {
  ForbiddenPlaintextFieldError,
  WITHDRAW_V2_MONOLITH_CALL_ARGS_ORDER,
  WithdrawV2CallArgsError,
  type WithdrawV2CallArgs,
  parseWithdrawV2CallArgs,
} from "@eunoma/deop-protocol";
import {
  HttpError,
  hexArg,
  hexVector3Arg,
  hexVectorArg,
  requireBearer,
  u64Arg,
} from "@eunoma/shared";
import { spawn as nodeSpawn } from "node:child_process";
import { createHash } from "node:crypto";
import type { WithdrawV3SubmitResult } from "./withdraw_v3_submitter.js";
import type { GasGuard } from "./gas_guard.js";
import type { VaultSequencer } from "./vault_sequencer.js";
import type { SubmitJournal } from "./submit_journal.js";
import type { DepositV3DelegateArgs, DepositV3SubmitHooks, DepositV3SubmitResult } from "./deposit_v3_submitter.js";
import { DepositV3ArgsError, parseDepositV3DelegateArgs } from "./deposit_v3_args.js";

/** The v3 split-tx withdraw submitter (createWithdrawV3Submitter's return), with optional per-step
 *  journaling hooks the route binds to the journal + this call's request_hash. */
export type WithdrawV3SubmitterFn = (
  args: WithdrawV2CallArgs,
  hooks?: {
    completedTxHashes?: string[];
    onStepStart?: (step: number, fn: string) => void;
    onStepDone?: (step: number, fn: string, txHash: string) => void;
    resumeAfterStep?: number;
  },
) => Promise<WithdrawV3SubmitResult>;

export type DepositV3SubmitterFn = (
  args: DepositV3DelegateArgs,
  hooks?: DepositV3SubmitHooks,
) => Promise<DepositV3SubmitResult>;

export interface RelayerSubmitResult {
  accepted: true;
  txHash: string;
  simulated: boolean;
}

/**
 * Structured error type thrown by submitters when the downstream invocation
 * fails. The HTTP route surfaces `code` + `message` over the wire; raw stderr
 * / stdout never enters the response body — those are logged locally to the
 * relayer process stderr for operator debugging.
 *
 * Stable codes:
 *   - `aptos_cli_error`            — `aptos move run` exited non-zero. Operator
 *                                    must read the relayer logs (NOT the
 *                                    HTTP response) for the underlying stderr.
 *   - `aptos_cli_missing_tx_hash`  — CLI exited 0 but stdout did not contain
 *                                    a transaction_hash. Indicates an
 *                                    unexpected CLI output schema.
 */
export class RelayerSubmitterError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "RelayerSubmitterError";
  }
}

export type RelayerWithdrawSubmitter = (
  args: WithdrawV2CallArgs,
) => Promise<RelayerSubmitResult>;

export interface RelayerServerOptions {
  bearerToken?: string;
  /**
   * Injectable submitter for the /v2/relayer/submit/withdraw route. In
   * production this is created via `createAptosCliSubmitter`; tests inject
   * mocks.
   */
  submitter?: RelayerWithdrawSubmitter;
  // ---- CP3: split-v3 withdraw route deps. When withdrawV3Submitter is set, /v3 withdraw is active. ----
  withdrawV3Submitter?: WithdrawV3SubmitterFn;
  /** Gas circuit breaker + reserve guard, checked STRICTLY before submission. */
  gasGuard?: GasGuard;
  /** Single-writer mutex serializing the step2a→step2b critical section. */
  sequencer?: VaultSequencer;
  /** Crash-recovery journal; the route records per-step intent/completed keyed by request_hash. */
  journal?: SubmitJournal;
  /** Deposit-delegate submitter (prepare_deposit_binding_v3 + deposit_step2a_v3). When set, the /v3
   *  deposit route is active. step2b is NEVER relayer-submitted (it is the user's own CA debit). */
  depositV3Submitter?: DepositV3SubmitterFn;
}

export function buildRelayerServer(opts: RelayerServerOptions = {}): FastifyInstance {
  const server = Fastify({ logger: false });
  const submitter = opts.submitter ?? failClosedSubmitter;

  server.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code });
    }
    return reply.code(500).send({ error: "internal_error" });
  });

  server.addHook("onRequest", async (req) => {
    if (req.url === "/v2/relayer/health") return;
    requireBearer(req.headers.authorization, opts.bearerToken);
  });

  server.get("/v2/relayer/health", async () => ({ ok: true }));

  server.post("/v2/relayer/submit/withdraw", async (req, reply) => {
    let args: WithdrawV2CallArgs;
    try {
      args = parseWithdrawV2CallArgs(req.body);
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof WithdrawV2CallArgsError) {
        // Structured invariant violation (e.g. M5a no-auditor gate). Surface
        // the stable error code so callers can branch deterministically.
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
    try {
      const result = await submitter(args);
      return reply.code(202).send(result);
    } catch (err) {
      // Submitter failures (e.g. submit_disabled, aptos CLI error) surface as
      // a 502 with a stable error code. Raw subprocess stderr is NEVER
      // returned in the response body — it is logged locally by the
      // submitter for operator debugging. Operators read the relayer logs to
      // diagnose the underlying CLI failure.
      if (err instanceof RelayerSubmitterError) {
        return reply.code(502).send({
          error: "submit_failed",
          code: err.code,
          message: err.message,
        });
      }
      // Legacy/unstructured submitter errors (e.g. injected mocks throwing
      // bare Error). Keep the existing wire shape but constrain to message
      // text the submitter chose to expose.
      return reply.code(502).send({
        error: "submit_failed",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // CP3: split-v3 withdraw route. Composes gasGuard (self-submit gate) + sequencer (single-writer)
  // + journal (per-step crash recovery) + the 5-tx withdraw_v3_submitter. Recipient is triple-pinned
  // on-chain, so a relayer can only stall — never steal/redirect.
  server.post("/v3/relayer/submit/withdraw", async (req, reply) => {
    if (!opts.withdrawV3Submitter) {
      return reply.code(501).send({ error: "v3_not_configured" });
    }
    let args: WithdrawV2CallArgs;
    try {
      args = parseWithdrawV2CallArgs(req.body);
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof WithdrawV2CallArgsError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }

    // Gas circuit breaker — STRICTLY BEFORE any submission. If the breaker is open / reserve low /
    // RPC read failed, refuse and tell the client to self-submit. step2a must NOT land under the
    // relayer when we bail, or the user could no longer take over (compose_pending_key namespacing).
    if (opts.gasGuard) {
      const decision = await opts.gasGuard.check();
      if (!decision.allow) {
        return reply.code(200).send({ action: "self_submit", reason: decision.reason });
      }
    }

    const journal = opts.journal;
    const requestHash = args.requestHash;
    const resume = buildJournalResume(journal, requestHash);
    const run = (): Promise<WithdrawV3SubmitResult> =>
      opts.withdrawV3Submitter!(
        args,
        journal
          ? {
              completedTxHashes: resume.completedTxHashes,
              onStepStart: (step) => journal.recordIntent(requestHash, step),
              onStepDone: (step, _fn, txHash) => journal.recordCompleted(requestHash, step, txHash),
              resumeAfterStep: resume.resumeAfterStep,
            }
          : undefined,
      );
    try {
      // Serialize the step2a→step2b critical section so concurrent withdraws don't race
      // vault_sequence (only the first step2b would land; the rest abort E_VAULT_SEQUENCE_MISMATCH).
      const result = opts.sequencer ? await opts.sequencer.runExclusive(run) : await run();
      return reply.code(202).send(result);
    } catch (err) {
      if (err instanceof RelayerSubmitterError) {
        const status = terminalSubmitterErrorStatus(err);
        return reply.code(status).send({ error: "submit_failed", code: err.code, message: err.message });
      }
      return reply.code(502).send({
        error: "submit_failed",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  // CP3: deposit-delegate route. Submits prepare_deposit_binding_v3 + deposit_step2a_v3 on the user's
  // behalf (after the Move re-key to user_addr); step2b stays user-signed → deposit = 1 user sig.
  // Fund-inert: the relayer cannot drain (it never submits step2b, the CA debit); user_addr is
  // bound into the deop-signed attestation so a relayer cannot misdirect.
  server.post("/v3/relayer/submit/deposit", async (req, reply) => {
    if (!opts.depositV3Submitter) {
      return reply.code(501).send({ error: "v3_not_configured" });
    }
    let args: DepositV3DelegateArgs;
    try {
      args = parseDepositV3DelegateArgs(req.body);
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      if (err instanceof DepositV3ArgsError) {
        return reply.code(400).send({ error: err.code, message: err.message });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
    if (opts.gasGuard) {
      const decision = await opts.gasGuard.check();
      if (!decision.allow) {
        return reply.code(200).send({ action: "self_submit", reason: decision.reason });
      }
    }
    const journal = opts.journal;
    const requestHash = depositDelegateRequestHash(args);
    const resume = buildJournalResume(journal, requestHash);
    try {
      const result = await opts.depositV3Submitter(
        args,
        journal
          ? {
              completedTxHashes: resume.completedTxHashes,
              onStepStart: (step) => journal.recordIntent(requestHash, step),
              onStepDone: (step, _fn, txHash) => journal.recordCompleted(requestHash, step, txHash),
              resumeAfterStep: resume.resumeAfterStep,
            }
          : undefined,
      );
      return reply.code(202).send(result);
    } catch (err) {
      if (err instanceof RelayerSubmitterError) {
        return reply.code(502).send({ error: "submit_failed", code: err.code, message: err.message });
      }
      return reply.code(502).send({
        error: "submit_failed",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  return server;
}

export function depositDelegateRequestHash(args: DepositV3DelegateArgs): string {
  const stablePublicParts = [
    args.assetAddr,
    args.userAddr,
    args.commitment,
    args.caPayloadHash,
    args.depositNonce,
  ];
  return `0x${createHash("sha256").update(stablePublicParts.join("|")).digest("hex")}`;
}

function terminalSubmitterErrorStatus(err: RelayerSubmitterError): 409 | 502 {
  if (err.code === "nullifier_already_spent") return 409;
  return 502;
}

function buildJournalResume(
  journal: SubmitJournal | undefined,
  requestHash: string,
): { completedTxHashes: string[]; resumeAfterStep: number } {
  if (!journal) return { completedTxHashes: [], resumeAfterStep: -1 };
  const completed = new Map<number, string>();
  for (const entry of journal.entries(requestHash)) {
    if (entry.phase === "completed" && entry.txHash) {
      completed.set(entry.step, entry.txHash);
    }
  }
  const completedTxHashes: string[] = [];
  for (let step = 0; ; step += 1) {
    const txHash = completed.get(step);
    if (!txHash) break;
    completedTxHashes.push(txHash);
  }
  return {
    completedTxHashes,
    resumeAfterStep: completedTxHashes.length - 1,
  };
}

async function failClosedSubmitter(): Promise<RelayerSubmitResult> {
  throw new Error("relayer submitter is not configured");
}

// ---------------------------------------------------------------------------
// CLI submitter (the production path)
// ---------------------------------------------------------------------------

/**
 * Minimal interface to `child_process.spawn` so tests can inject a mock.
 */
export type SpawnAptosFn = (
  command: string,
  args: string[],
) => {
  stdout: AsyncIterable<Buffer | string>;
  stderr: AsyncIterable<Buffer | string>;
  /** Resolves with the process exit code (or null on signal termination). */
  done: Promise<number | null>;
};

export interface CreateAptosCliSubmitterOptions {
  /**
   * Real-submit request. When omitted/`false` the submitter appends
   * `--simulate` to the CLI args. When `true`, the factory ALSO requires the
   * env (default: `process.env`) to set `RELAYER_SUBMIT_ENABLED=1` — without
   * that env approval, construction throws so a misconfigured caller cannot
   * silently bypass the human-approval boundary. There is no per-call
   * override: the submit/simulate posture is fixed at construction.
   */
  submit?: boolean;
  /**
   * Process environment used to gate real-submit construction. Defaults to
   * `process.env`. Tests inject a deterministic env map.
   */
  env?: NodeJS.ProcessEnv;
  /**
   * Override for the spawn implementation. Defaults to `node:child_process`'s
   * `spawn`. Tests inject a deterministic mock that captures the argv vector
   * and emits a canned stdout fixture.
   */
  spawnAptos?: SpawnAptosFn;
  /**
   * Override for the aptos CLI path. Defaults to `"aptos"` (PATH lookup).
   */
  aptosBin?: string;
  /**
   * Sink for local-only stderr logging when the CLI exits non-zero. Defaults
   * to `process.stderr`. Tests inject a buffered sink to assert the bytes
   * land HERE and not in the thrown error / HTTP response body.
   */
  stderrSink?: { write: (chunk: string) => void };
}

/**
 * Build a submitter that invokes `aptos move run --function-id <pkg>::eunoma_bridge::withdraw_to_recipient_v2`
 * with the 27 positional arguments in canonical order. Returns the
 * transaction hash parsed from stdout.
 *
 * Default behavior is --simulate. To actually broadcast, the caller must
 * pass `opts.submit = true` AND the process env must set
 * `RELAYER_SUBMIT_ENABLED=1` — otherwise construction throws. The
 * simulate/submit posture is fixed at construction time; there is no
 * per-call override.
 */
export function createAptosCliSubmitter(
  bridgePackage: string,
  adminProfile: string | undefined,
  opts: CreateAptosCliSubmitterOptions = {},
): RelayerWithdrawSubmitter {
  if (!bridgePackage || !/^0x[0-9a-fA-F]+$/.test(bridgePackage)) {
    throw new Error("bridgePackage must be a non-empty 0x-prefixed hex address");
  }
  const spawnFn = opts.spawnAptos ?? defaultSpawnAptos;
  const aptosBin = opts.aptosBin ?? "aptos";
  const env = opts.env ?? process.env;
  // Env approval is a HARD GATE for real-submit construction. A caller that
  // requests submit:true without RELAYER_SUBMIT_ENABLED=1 in the env hits
  // this throw at construction — before any HTTP request is ever served — so
  // a misconfigured deploy cannot silently broadcast real transactions.
  if (opts.submit === true && env.RELAYER_SUBMIT_ENABLED !== "1") {
    throw new Error(
      "createAptosCliSubmitter: submit=true requires RELAYER_SUBMIT_ENABLED=1 in the env",
    );
  }
  const simulate = opts.submit !== true;
  const stderrSink = opts.stderrSink ?? defaultStderrSink;

  return async (callArgs: WithdrawV2CallArgs): Promise<RelayerSubmitResult> => {
    const positionalArgs = encodeCallArgs(callArgs);
    const cliArgs = [
      "move",
      "run",
      "--function-id",
      `${bridgePackage}::eunoma_bridge::withdraw_to_recipient_v2`,
      ...(adminProfile ? ["--profile", adminProfile] : []),
      "--assume-yes",
      ...(simulate ? ["--simulate"] : []),
      "--args",
      ...positionalArgs,
    ];

    const { stdout, stderr, done } = spawnFn(aptosBin, cliArgs);

    let stdoutText = "";
    let stderrText = "";
    const collectOut = (async () => {
      for await (const chunk of stdout) stdoutText += chunkToString(chunk);
    })();
    const collectErr = (async () => {
      for await (const chunk of stderr) stderrText += chunkToString(chunk);
    })();
    const [exitCode] = await Promise.all([done, collectOut, collectErr]);

    if (exitCode !== 0) {
      // Log stderr LOCALLY (relayer process) so the operator can grep their
      // own logs for the underlying CLI failure. The error thrown to the
      // route handler carries an opaque code + generic message — raw stderr
      // text NEVER enters the HTTP response body.
      stderrSink.write(
        `[relayer] aptos cli exited ${exitCode ?? "(signal)"}; stderr=\n${stderrText}\n`,
      );
      throw new RelayerSubmitterError(
        "aptos_cli_error",
        "Aptos CLI invocation failed; check relayer logs for details.",
      );
    }

    const txHash = parseTxHashFromAptosCliStdout(stdoutText);
    if (!txHash) {
      // Diagnostic: log BOTH stdout + stderr LOCALLY (process.stderr) so the
      // operator can see why the CLI returned 0 without emitting a
      // transaction_hash. The HTTP response still carries only the opaque
      // error code — raw output never leaves the relayer process.
      stderrSink.write(
        `[relayer] aptos cli exit=0 but no transaction_hash; stdout=\n${stdoutText}\n---stderr=\n${stderrText}\n---\n`,
      );
      throw new RelayerSubmitterError(
        "aptos_cli_missing_tx_hash",
        `aptos cli stdout missing transaction_hash (simulate=${simulate})`,
      );
    }
    return { accepted: true, txHash, simulated: simulate };
  };
}

/**
 * Encode a WithdrawV2CallArgs into the 27 CLI argument strings in the canonical
 * Move-signature order. Exported for the killer test that asserts byte-for-byte
 * parity with the Move signature.
 */
export function encodeCallArgs(args: WithdrawV2CallArgs): string[] {
  // Legacy monolith ABI order. The parsed HTTP body also carries V4 conservation
  // fields used by the split submitter; `withdraw_to_recipient_v2` itself still
  // accepts the original 32 positional args.
  return WITHDRAW_V2_MONOLITH_CALL_ARGS_ORDER.map((key) => encodeField(key, args[key]));
}

export function encodeField(key: keyof WithdrawV2CallArgs, value: WithdrawV2CallArgs[keyof WithdrawV2CallArgs]): string {
  switch (key) {
    case "assetAddr":
    case "recipient": {
      // Move param type is `address`, NOT `vector<u8>`. Aptos CLI args for an
      // address parameter must use the `address:0x...` prefix; `hex:0x...`
      // gets BCS-decoded as a `vector<u8>` (length-prefixed) and the on-chain
      // function deserialization rejects with FAILED_TO_DESERIALIZE_ARGUMENT.
      // V4 (CP5 RC1): asset_addr is the same `address` shape as recipient — it
      // is the registry routing key resolved on-chain, encoded identically.
      const clean = String(value).replace(/^0x/i, "").toLowerCase();
      if (!/^[0-9a-f]+$/.test(clean) || clean.length > 64) {
        throw new Error(`${key} must be 0x-prefixed hex address (≤32 bytes): ${value}`);
      }
      return `address:0x${clean.padStart(64, "0")}`;
    }
    case "root":
    case "nullifierHash":
    case "recipientHash":
    case "amountTag":
    case "caPayloadHash":
    case "requestHash":
    case "aspRoot":
    // V4 (CP2 CP1): change_commitment is a 32-byte Fr public[12], encoded `hex:`
    // exactly like root (EMPTY = 32 zero bytes for a full withdraw).
    case "changeCommitment":
    case "amountPDigest":
    case "withdrawProof":
    case "groupSignature":
    case "zkrpNewBalance":
    case "zkrpAmount":
    case "memo":
      return hexArg(value as string);
    case "vaultSequence":
    case "expirySecs":
    case "stateTreeDepth":
    case "aspTreeDepth":
      return u64Arg(value as string);
    case "fallbackBitmap":
      // u8 is encoded as a decimal-tagged u8:N for the aptos CLI.
      return `u8:${value as number}`;
    case "fallbackSignatures":
    case "newBalanceP":
    case "newBalanceR":
    case "newBalanceREffAud":
    case "amountP":
    case "amountPOld":
    case "amountPRem":
    case "amountRSender":
    case "amountRRecip":
    case "amountREffAud":
    case "ekVolunAuds":
    case "sigmaProtoComm":
    case "sigmaProtoResp":
      return hexVectorArg(value as string[]);
    case "amountRVolunAuds":
      return hexVector3Arg(value as string[][]);
    default: {
      const exhaustive: never = key;
      throw new Error(`unhandled WithdrawV2CallArgs key: ${exhaustive as string}`);
    }
  }
}

export function parseTxHashFromAptosCliStdout(stdout: string): string | undefined {
  // The aptos CLI prints a JSON object with a "Result" key containing
  // "transaction_hash". We accept either the raw JSON form
  //   "transaction_hash": "0x.."
  // or the bare regex match.
  const m = stdout.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  if (m) return m[1];
  return undefined;
}

export function chunkToString(chunk: Buffer | string): string {
  if (typeof chunk === "string") return chunk;
  return chunk.toString("utf8");
}

export const defaultSpawnAptos: SpawnAptosFn = (command, args) => {
  const proc = nodeSpawn(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    ...(process.env.APTOS_CLI_CWD ? { cwd: process.env.APTOS_CLI_CWD } : {}),
  });
  const done = new Promise<number | null>((resolve, reject) => {
    proc.on("close", (code) => resolve(code));
    proc.on("error", (err) => reject(err));
  });
  return { stdout: proc.stdout, stderr: proc.stderr, done };
};

const defaultStderrSink: { write: (chunk: string) => void } = {
  write: (chunk: string) => {
    process.stderr.write(chunk);
  },
};
