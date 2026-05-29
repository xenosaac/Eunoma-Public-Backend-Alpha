// CP3: split-v3 withdraw submitter.
//
// Drives the 5 v3 withdraw txs (prepare_withdraw_proof_v3 → prepare_withdraw_attestation_v3 →
// prepare_withdraw_payload_v3 → withdraw_step2a_eunoma_verify_v3 →
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
}

/**
 * The 5 v3 withdraw entries in submission order. Each `keys` list is the EXACT positional argument
 * order of the corresponding Move entry in eunoma_bridge.move (the leading `&signer` is implicit
 * and supplied by --profile, not an --arg). If a Move signature changes, update the matching list
 * here; the per-entry arg-count assertions in the vitest guard against silent drift.
 */
export const WITHDRAW_V3_ENTRIES: ReadonlyArray<WithdrawV3Entry> = [
  {
    fn: "prepare_withdraw_proof_v3",
    keys: [
      "root", "nullifierHash", "recipientHash", "amountTag", "caPayloadHash",
      "requestHash", "vaultSequence", "amountP", "withdrawProof",
    ],
  },
  {
    fn: "prepare_withdraw_attestation_v3",
    keys: [
      "root", "nullifierHash", "recipient", "recipientHash", "amountTag",
      "caPayloadHash", "requestHash", "vaultSequence", "expirySecs",
      "groupSignature", "fallbackBitmap", "fallbackSignatures",
    ],
  },
  {
    fn: "prepare_withdraw_payload_v3",
    keys: [
      "recipient", "caPayloadHash", "requestHash",
      "newBalanceP", "newBalanceR", "newBalanceREffAud",
      "amountP", "amountRSender", "amountRRecip", "amountREffAud",
      "ekVolunAuds", "amountRVolunAuds", "zkrpNewBalance", "zkrpAmount",
      "sigmaProtoComm", "sigmaProtoResp", "memo",
    ],
  },
  {
    fn: "withdraw_step2a_eunoma_verify_v3",
    keys: [
      "root", "nullifierHash", "recipient", "recipientHash", "amountTag",
      "caPayloadHash", "requestHash", "vaultSequence", "expirySecs",
    ],
  },
  {
    fn: "withdraw_step2b_invoke_framework_v3",
    keys: [
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
  /** Tx hashes in submission order: [proof, attestation, payload, step2a, step2b]. */
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
}

/** Encode one v3 entry's positional CLI args from a WithdrawV2CallArgs (reuses encodeField). */
export function encodeV3EntryArgs(entry: WithdrawV3Entry, args: WithdrawV2CallArgs): string[] {
  return entry.keys.map((k) => encodeField(k, args[k]));
}

/**
 * Build a submitter that drives the 5 v3 withdraw txs in order from one relayer key. Returns the 5
 * tx hashes. Defaults to --simulate; real broadcast requires opts.submit=true AND
 * RELAYER_SUBMIT_ENABLED=1 (fixed at construction, mirroring createAptosCliSubmitter).
 *
 * On any tx failure the sequence aborts and a RelayerSubmitterError is thrown — raw stderr is
 * logged LOCALLY (stderrSink), never returned. The caller's journal/recovery (submit_journal)
 * reconciles against on-chain state (pending tables + nullifier) to decide resume-vs-done; this
 * submitter performs straight in-order submission and does not itself retry.
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

  return async (
    callArgs: WithdrawV2CallArgs,
    hooks: {
      onStepStart?: (step: number, fn: string) => void;
      onStepDone?: (step: number, fn: string, txHash: string) => void;
    } = {},
  ): Promise<WithdrawV3SubmitResult> => {
    const txHashes: string[] = [];
    for (const entry of WITHDRAW_V3_ENTRIES) {
      (hooks.onStepStart ?? opts.onStepStart)?.(txHashes.length, entry.fn);
      const positional = encodeV3EntryArgs(entry, callArgs);
      const cliArgs = [
        "move",
        "run",
        "--function-id",
        `${bridgePackage}::eunoma_bridge::${entry.fn}`,
        ...(relayerProfile ? ["--profile", relayerProfile] : []),
        "--assume-yes",
        ...(simulate ? ["--simulate"] : []),
        "--args",
        ...positional,
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

      const step = txHashes.length + 1;
      if (exitCode !== 0) {
        stderrSink.write(
          `[relayer-v3] ${entry.fn} (step ${step}/5) exited ${exitCode ?? "(signal)"}; stderr=\n${stderrText}\n`,
        );
        throw new RelayerSubmitterError(
          "aptos_cli_error",
          `Aptos CLI ${entry.fn} failed (step ${step}/5); check relayer logs for details.`,
        );
      }
      const txHash = parseTxHashFromAptosCliStdout(stdoutText);
      if (!txHash) {
        stderrSink.write(
          `[relayer-v3] ${entry.fn} (step ${step}/5) exit=0 but no transaction_hash; stdout=\n${stdoutText}\n`,
        );
        throw new RelayerSubmitterError(
          "aptos_cli_missing_tx_hash",
          `${entry.fn} stdout missing transaction_hash (simulate=${simulate})`,
        );
      }
      txHashes.push(txHash);
      (hooks.onStepDone ?? opts.onStepDone)?.(txHashes.length - 1, entry.fn, txHash);
    }
    return { accepted: true, simulated: simulate, txHashes };
  };
}
