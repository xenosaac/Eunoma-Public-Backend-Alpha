// CP3: split-v3 withdraw submitter.
//
// Drives the split-v3/V4 withdraw txs (prepare_withdraw_proof_v4 → prepare_withdraw_attestation_v3 →
// prepare_withdraw_payload_v3 → [prepare_withdraw_conservation_v4 for partial only] →
// withdraw_step2a_eunoma_verify_v3 →
// withdraw_step2b_invoke_framework_v3) from ONE dedicated low-privilege relayer key, in order.
//
// Why split-v3 instead of the monolith withdraw_to_recipient_v2: the monolith exceeds the Aptos
// per-tx execution-gas cap; the v3 entries split the work. WHO submits is irrelevant to fund
// safety — the recipient is triple-pinned (recipient_hash is a Groth16 public input + the FROST
// attestation + step2b's ca_payload_hash recompute), funds move via vault_signer_cap, and the
// `_relayer`/`relayer` signer is never an authority. A malicious/compromised relayer can only
// STALL, never steal or redirect. (eunoma_bridge.move withdraw_step2a/2b_v3.)
//
// CRITICAL: all 5 txs MUST be submitted from the SAME key — withdraw_step2a/2b key their pending
// rows by compose_pending_key(submitter, request_hash). A consistent submitter is required for
// step2b to find step2a's finalization row.
//
// The encoding reuses encodeField from server.ts so the per-field CLI arg encoding is
// single-sourced with the monolith path (one place to keep correct vs the Move signatures).
import type { WithdrawV2CallArgs } from "@eunoma/deop-protocol";
import {
  RelayerSubmitterError,
  type SpawnAptosFn,
  chunkToString,
  defaultSpawnAptos,
  encodeField,
  parseTxHashFromAptosCliStdout,
} from "./server.js";

/** One v3 entry + the ordered subset of WithdrawV2CallArgs keys matching its Move signature. */
export interface WithdrawV3Entry {
  readonly fn: string;
  readonly keys: ReadonlyArray<keyof WithdrawV2CallArgs>;
  readonly maxGas?: number;
  readonly skip?: (args: WithdrawV2CallArgs) => boolean;
}

const DEFAULT_WITHDRAW_V3_MAX_GAS = 2_000_000;
const DEFAULT_WITHDRAW_V3_GAS_UNIT_PRICE = 100;
const DEFAULT_APTOS_CLI_RETRY_ATTEMPTS = 12;
const DEFAULT_APTOS_CLI_RETRY_DELAY_MS = 5_000;
const RECOVERABLE_PENDING_ABORT_BY_FN: Record<string, string> = {
  prepare_withdraw_proof_v4: "E_PENDING_WITHDRAW_PROOF",
  prepare_withdraw_attestation_v3: "E_PENDING_WITHDRAW_ATTESTATION",
  prepare_withdraw_payload_v3: "E_PENDING_WITHDRAW_PAYLOAD",
  prepare_withdraw_conservation_v4: "E_PENDING_WITHDRAW_PAYLOAD",
  withdraw_step2a_eunoma_verify_v3: "E_PENDING_WITHDRAW_FINALIZATION",
};
const TERMINAL_MOVE_ABORT_CODE_BY_NAME: Record<string, string> = {
  E_NULLIFIER_ALREADY_SPENT: "nullifier_already_spent",
};

/**
 * The 5 v3 withdraw entries in submission order. Each `keys` list is the EXACT positional argument
 * order of the corresponding Move entry in eunoma_bridge.move (the leading `&signer` is implicit
 * and supplied by --profile, not an --arg). If a Move signature changes, update the matching list
 * here; the per-entry arg-count assertions in the vitest guard against silent drift.
 */
export const WITHDRAW_V3_ENTRIES: ReadonlyArray<WithdrawV3Entry> = [
  {
    fn: "prepare_withdraw_proof_v4",
    keys: [
      // V4 (CP5 RC1): asset_addr is the explicit +1 routing key, FIRST positional
      // arg (after the implicit `_sender: &signer`). V4 (CP2 CP1): change_commitment
      // is public[12], inserted AFTER aspTreeDepth and BEFORE vaultSequence —
      // matching the Move signature eunoma_bridge.move:prepare_withdraw_proof_v3
      // exactly (asset_addr, …, asp_root, state_tree_depth, asp_tree_depth,
      // change_commitment, vault_sequence, amount_p_digest, withdraw_proof). 14 args.
      "assetAddr",
      // ASP (2026-05-30): asp_root + the 2 LeanIMT depths are inserted AFTER requestHash and
      // BEFORE changeCommitment — matching prepare_withdraw_proof_v3's Move signature exactly.
      "root", "nullifierHash", "recipientHash", "amountTag", "caPayloadHash",
      "requestHash", "aspRoot", "stateTreeDepth", "aspTreeDepth",
      "changeCommitment", "vaultSequence", "amountPDigest", "withdrawProof",
    ],
  },
  {
    fn: "prepare_withdraw_attestation_v3",
    keys: [
      // V4 (CP5 RC1): asset_addr FIRST positional arg — the Move entry resolves
      // asset_type from the registry to rebuild the FROST attestation message
      // (which binds asset_type_addr). 12 → 13 args.
      "assetAddr",
      "root", "nullifierHash", "recipient", "recipientHash", "amountTag",
      "caPayloadHash", "requestHash", "vaultSequence", "expirySecs",
      "groupSignature", "fallbackBitmap", "fallbackSignatures",
    ],
  },
  {
    fn: "prepare_withdraw_payload_v3",
    keys: [
      // V4 (CP5 RC1): asset_addr FIRST positional arg — registry resolution +
      // status gate + ca_payload_hash recompute source. 17 → 18 args.
      "assetAddr",
      "recipient", "caPayloadHash", "requestHash",
      "newBalanceP", "newBalanceR", "newBalanceREffAud",
      "amountP", "amountRSender", "amountRRecip", "amountREffAud",
      "ekVolunAuds", "amountRVolunAuds", "zkrpNewBalance", "zkrpAmount",
      "sigmaProtoComm", "sigmaProtoResp", "memo",
    ],
  },
  {
    fn: "prepare_withdraw_conservation_v4",
    keys: [
      // V4 B-prime partial withdraw only. `amountPOld` is the spent note's
      // Pedersen amount points, `amountP` is the withdrawn CA-transfer leg,
      // and `amountPRem` is the remainder/change-note leg. The Move entry
      // also pins amountPOld to `amountPDigest`, the proof public[8].
      "assetAddr",
      "requestHash", "amountPDigest", "amountPOld", "amountP", "amountPRem",
    ],
    skip: (args) => isEmptyChangeCommitment(args.changeCommitment),
  },
  {
    fn: "withdraw_step2a_eunoma_verify_v3",
    keys: [
      // V4 (CP5 RC1): asset_addr FIRST positional arg — registry resolution +
      // status gate + Poseidon-link, then writes the finalization row (which
      // stores asset_addr + change_commitment for step2b to re-resolve / emit).
      // V4 (CP2 CP1): change_commitment public[12] is re-asserted against the
      // V3b proof-cache row on the cache-hit, inserted AFTER requestHash and
      // BEFORE vaultSequence — matching the Move signature
      // eunoma_bridge.move:withdraw_step2a_eunoma_verify_v3 exactly
      // (…, request_hash, change_commitment, vault_sequence, expiry_secs). 10 → 11 args.
      "assetAddr",
      "root", "nullifierHash", "recipient", "recipientHash", "amountTag",
      "caPayloadHash", "requestHash", "changeCommitment", "vaultSequence", "expirySecs",
    ],
  },
  {
    fn: "withdraw_step2b_invoke_framework_v3",
    keys: [
      // V4 (CP5 RC1): NO asset_addr arg. step2b re-resolves the SAME registry row
      // from `entry.asset_addr` stored on the finalization row by step2a — the
      // Move signature takes NO asset_addr positional. Shape unchanged: 15 args.
      "requestHash",
      "newBalanceP", "newBalanceR", "newBalanceREffAud",
      "amountP", "amountRSender", "amountRRecip", "amountREffAud",
      "ekVolunAuds", "amountRVolunAuds", "zkrpNewBalance", "zkrpAmount",
      "sigmaProtoComm", "sigmaProtoResp", "memo",
    ],
  },
] as const;

export interface WithdrawV3SubmitResult {
  accepted: true;
  simulated: boolean;
  /** Tx hashes in submission order. Full withdraw has 5; partial includes conservation and has 6. */
  txHashes: string[];
}

export interface CreateWithdrawV3SubmitterOptions {
  /** Real-submit request. Default false → appends --simulate. When true, REQUIRES
   *  env.RELAYER_SUBMIT_ENABLED=1 (human-approval boundary), else construction throws. */
  submit?: boolean;
  env?: NodeJS.ProcessEnv;
  spawnAptos?: SpawnAptosFn;
  aptosBin?: string;
  stderrSink?: { write: (chunk: string) => void };
  /** Per-tx callbacks for journaling/observability (request_hash supplied by the caller per call
   *  is not known here, so these report the step index 0..4 + Move fn + tx hash on completion). */
  onStepStart?: (step: number, fn: string) => void;
  onStepDone?: (step: number, fn: string, txHash: string) => void;
  retryAttempts?: number;
  retryDelayMs?: number;
}

/** Encode one v3 entry's positional CLI args from a WithdrawV2CallArgs (reuses encodeField). */
export function encodeV3EntryArgs(entry: WithdrawV3Entry, args: WithdrawV2CallArgs): string[] {
  return entry.keys.map((k) => encodeField(k, args[k]));
}

function isEmptyChangeCommitment(value: string): boolean {
  const clean = value.replace(/^0x/i, "").toLowerCase();
  return clean.length === 64 && /^0+$/.test(clean);
}

/**
 * Build a submitter that drives the 5 v3 withdraw txs in order from one relayer key. Returns the 5
 * tx hashes. Defaults to --simulate; real broadcast requires opts.submit=true AND
 * RELAYER_SUBMIT_ENABLED=1 (fixed at construction, mirroring createAptosCliSubmitter).
 *
 * On any tx failure the sequence aborts and a RelayerSubmitterError is thrown — raw stderr is
 * logged LOCALLY (stderrSink), never returned. The caller's journal/recovery (submit_journal)
 * reconciles against on-chain state (pending tables + nullifier) to decide resume-vs-done. This
 * submitter only retries pre-submit Aptos CLI transport/rate-limit failures that return no tx hash;
 * semantic Move aborts still fail closed immediately.
 */
export function createWithdrawV3Submitter(
  bridgePackage: string,
  relayerProfile: string | undefined,
  opts: CreateWithdrawV3SubmitterOptions = {},
): (args: WithdrawV2CallArgs) => Promise<WithdrawV3SubmitResult> {
  if (!bridgePackage || !/^0x[0-9a-fA-F]+$/.test(bridgePackage)) {
    throw new Error("bridgePackage must be a non-empty 0x-prefixed hex address");
  }
  const spawnFn = opts.spawnAptos ?? defaultSpawnAptos;
  const aptosBin = opts.aptosBin ?? "aptos";
  const env = opts.env ?? process.env;
  if (opts.submit === true && env.RELAYER_SUBMIT_ENABLED !== "1") {
    throw new Error(
      "createWithdrawV3Submitter: submit=true requires RELAYER_SUBMIT_ENABLED=1 in the env",
    );
  }
  const simulate = opts.submit !== true;
  const stderrSink = opts.stderrSink ?? { write: (c: string) => void process.stderr.write(c) };
  const retryAttempts = Number.parseInt(
    String(
      opts.retryAttempts ??
        env.RELAYER_APTOS_CLI_RETRY_ATTEMPTS ??
        String(DEFAULT_APTOS_CLI_RETRY_ATTEMPTS),
    ),
    10,
  );
  const retryDelayMs = Number.parseInt(
    String(
      opts.retryDelayMs ??
        env.RELAYER_APTOS_CLI_RETRY_DELAY_MS ??
        String(DEFAULT_APTOS_CLI_RETRY_DELAY_MS),
    ),
    10,
  );
  const maxAttempts = Number.isInteger(retryAttempts) && retryAttempts > 0 ? retryAttempts : 1;
  const baseRetryDelayMs =
    Number.isInteger(retryDelayMs) && retryDelayMs >= 0
      ? retryDelayMs
      : DEFAULT_APTOS_CLI_RETRY_DELAY_MS;

  return async (
    callArgs: WithdrawV2CallArgs,
    hooks: {
      completedTxHashes?: string[];
      onStepStart?: (step: number, fn: string) => void;
      onStepDone?: (step: number, fn: string, txHash: string) => void;
      resumeAfterStep?: number;
    } = {},
  ): Promise<WithdrawV3SubmitResult> => {
    const txHashes: string[] = [...(hooks.completedTxHashes ?? [])];
    const resumeAfterStep =
      Number.isInteger(hooks.resumeAfterStep) && hooks.resumeAfterStep !== undefined
        ? hooks.resumeAfterStep
        : -1;
    const executedEntries = WITHDRAW_V3_ENTRIES.filter((entry) => !(entry.skip?.(callArgs) ?? false));
    for (let stepIndex = 0; stepIndex < executedEntries.length; stepIndex += 1) {
      const entry = executedEntries[stepIndex];
      if (stepIndex <= resumeAfterStep) continue;
      if (entry.skip?.(callArgs)) continue;
      (hooks.onStepStart ?? opts.onStepStart)?.(stepIndex, entry.fn);
      const positional = encodeV3EntryArgs(entry, callArgs);
      const cliArgs = [
        "move",
        "run",
      "--function-id",
      `${bridgePackage}::eunoma_bridge::${entry.fn}`,
      ...(relayerProfile ? ["--profile", relayerProfile] : []),
      "--max-gas",
      String(entry.maxGas ?? DEFAULT_WITHDRAW_V3_MAX_GAS),
      "--gas-unit-price",
      String(DEFAULT_WITHDRAW_V3_GAS_UNIT_PRICE),
      "--assume-yes",
      ...(simulate ? ["--simulate"] : []),
      "--args",
        ...positional,
      ];

      const step = stepIndex + 1;
      let txHash: string | undefined;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        const { stdoutText, stderrText, exitCode } = await runAptosCli(spawnFn, aptosBin, cliArgs);
        txHash = parseTxHashFromAptosCliStdout(stdoutText);
        if (!txHash) {
          const recovered = recoverableAlreadyPreparedMarker(
            entry,
            stdoutText,
            stderrText,
            simulate,
            stepIndex,
          );
          if (recovered) {
            stderrSink.write(
              `[relayer-v3] ${entry.fn} (step ${step}/5) recovered already-prepared on-chain state; ` +
                `continuing with marker=${recovered}\n`,
            );
            txHash = recovered;
            break;
          }
          const terminalAbort = parseTerminalMoveAbort(stdoutText, stderrText);
          if (terminalAbort) {
            stderrSink.write(
              `[relayer-v3] ${entry.fn} (step ${step}/5) terminal Move abort ` +
                `${terminalAbort.abortName}; stdout/stderr logged locally\n`,
            );
            throw new RelayerSubmitterError(
              terminalAbort.code,
              `${entry.fn} failed because the note was already spent (${terminalAbort.abortName})`,
            );
          }
        }
        if (exitCode === 0 && txHash) break;
        const retryable = isRetryableAptosCliTransportFailure(stdoutText, stderrText);
        if (retryable && attempt < maxAttempts) {
          stderrSink.write(
            `[relayer-v3] ${entry.fn} (step ${step}/5) retryable Aptos CLI transport failure ` +
              `(attempt ${attempt}/${maxAttempts}); backing off\n`,
          );
          await sleep(baseRetryDelayMs * attempt);
          continue;
        }
        if (exitCode !== 0) {
          stderrSink.write(
            `[relayer-v3] ${entry.fn} (step ${step}/5) exited ${exitCode ?? "(signal)"}; stderr=\n${stderrText}\n`,
          );
          throw new RelayerSubmitterError(
            "aptos_cli_error",
            `Aptos CLI ${entry.fn} failed (step ${step}/5); check relayer logs for details.`,
          );
        }
        stderrSink.write(
          `[relayer-v3] ${entry.fn} (step ${step}/5) exit=0 but no transaction_hash; stdout=\n${stdoutText}\n`,
        );
        throw new RelayerSubmitterError(
          "aptos_cli_missing_tx_hash",
          `${entry.fn} stdout missing transaction_hash (simulate=${simulate})`,
        );
      }
      if (!txHash) throw new RelayerSubmitterError("aptos_cli_missing_tx_hash", `${entry.fn} stdout missing transaction_hash`);
      txHashes.push(txHash);
      (hooks.onStepDone ?? opts.onStepDone)?.(stepIndex, entry.fn, txHash);
    }
    return { accepted: true, simulated: simulate, txHashes };
  };
}

async function runAptosCli(
  spawnFn: SpawnAptosFn,
  aptosBin: string,
  cliArgs: string[],
): Promise<{ stdoutText: string; stderrText: string; exitCode: number | null }> {
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
  return { stdoutText, stderrText, exitCode };
}

function isRetryableAptosCliTransportFailure(stdoutText: string, stderrText: string): boolean {
  const text = `${stdoutText}\n${stderrText}`.toLowerCase();
  if (text.includes("move abort") || text.includes("simulation failed with status")) return false;
  return (
    text.includes("rate limit") ||
    text.includes("ratelimit") ||
    text.includes("too many requests") ||
    text.includes("http 429") ||
    text.includes("bad_status:429") ||
    text.includes("status 429") ||
    text.includes(" 429 ") ||
    text.includes("5xx") ||
    text.includes("http 500") ||
    text.includes("http 502") ||
    text.includes("http 503") ||
    text.includes("http 504")
  );
}

function recoverableAlreadyPreparedMarker(
  entry: WithdrawV3Entry,
  stdoutText: string,
  stderrText: string,
  simulate: boolean,
  stepIndex: number,
): string | undefined {
  if (simulate) return undefined;
  const abortName = RECOVERABLE_PENDING_ABORT_BY_FN[entry.fn];
  if (!abortName) return undefined;
  const text = `${stdoutText}\n${stderrText}`.toLowerCase();
  if (!text.includes("move abort")) return undefined;
  if (!text.includes(abortName.toLowerCase())) return undefined;
  return `recovered:${entry.fn}:step${stepIndex}`;
}

function parseTerminalMoveAbort(
  stdoutText: string,
  stderrText: string,
): { code: string; abortName: string } | null {
  const text = `${stdoutText}\n${stderrText}`;
  for (const [abortName, code] of Object.entries(TERMINAL_MOVE_ABORT_CODE_BY_NAME)) {
    if (text.includes(abortName)) return { code, abortName };
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
