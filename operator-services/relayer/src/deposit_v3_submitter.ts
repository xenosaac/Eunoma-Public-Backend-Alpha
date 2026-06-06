// CP3: deposit-delegate submitter (the deposit 3→1-sig path).
//
// After the Move deposit re-key, prepare_deposit_binding_v3_for_user + deposit_step2a_eunoma_verify_v3 take an
// explicit `user_addr` and key their pending rows by it (not the submitter). So the relayer can
// submit those two on the user's behalf, leaving ONLY deposit_step2b (the user's own CA debit,
// confidential_transfer_raw(sender)) for the user to sign → 1 user signature.
//
// SAFETY: a relayer cannot misdirect — user_addr is bound into the deop-signed FROST attestation
// (CP1/CP2), so a relayer-submitted step2a is authenticated to that user; if the relayer used a
// wrong user_addr, the user's later step2b (keyed by its own signer) would simply not find the
// finalization row (E_NO_PENDING_FINALIZATION; fund-safe fail-closed). step2b is NEVER relayer-
// submitted (it debits the user's own balance). The relayer must verify the coordinator-attested
// user_addr equals the one it submits BEFORE broadcasting.
//
// Positional arg ORDER below mirrors the post-re-key Move signatures EXACTLY (a mismatch →
// FAILED_TO_DESERIALIZE_ARGUMENT on-chain). CP6 testnet validates the actual deserialize end-to-end.
import { hexArg, hexVector3Arg, hexVectorArg, u64Arg } from "@eunoma/shared";
import {
  RelayerSubmitterError,
  type SpawnAptosFn,
  chunkToString,
  defaultSpawnAptos,
  parseTxHashFromAptosCliStdout,
} from "./server.js";

export interface DepositV3DelegateArgs {
  assetAddr: string;
  userAddr: string;
  commitment: string;
  amountTag: string;
  amountP: string[];
  depositBindingProof: string;
  caPayloadHash: string;
  depositNonce: string;
  expirySecs: string;
  groupSignature: string;
  fallbackBitmap: number;
  fallbackSignatures: string[];
  newBalanceP: string[];
  newBalanceR: string[];
  newBalanceREffAud: string[];
  amountRSender: string[];
  amountRRecip: string[];
  amountREffAud: string[];
  ekVolunAuds: string[];
  amountRVolunAuds: string[][];
  zkrpNewBalance: string;
  zkrpAmount: string;
  sigmaProtoComm: string[];
  sigmaProtoResp: string[];
  memo: string;
}

type FieldType = "address" | "hex" | "u64" | "u8" | "hexVector" | "hexVector3";

const FIELD_TYPES: Record<keyof DepositV3DelegateArgs, FieldType> = {
  assetAddr: "address",
  userAddr: "address",
  commitment: "hex",
  amountTag: "hex",
  amountP: "hexVector",
  depositBindingProof: "hex",
  caPayloadHash: "hex",
  depositNonce: "hex",
  expirySecs: "u64",
  groupSignature: "hex",
  fallbackBitmap: "u8",
  fallbackSignatures: "hexVector",
  newBalanceP: "hexVector",
  newBalanceR: "hexVector",
  newBalanceREffAud: "hexVector",
  amountRSender: "hexVector",
  amountRRecip: "hexVector",
  amountREffAud: "hexVector",
  ekVolunAuds: "hexVector",
  amountRVolunAuds: "hexVector3",
  zkrpNewBalance: "hex",
  zkrpAmount: "hex",
  sigmaProtoComm: "hexVector",
  sigmaProtoResp: "hexVector",
  memo: "hex",
};

function addressArg(value: string): string {
  const clean = value.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length > 64) {
    throw new Error(`address must be 0x-prefixed hex (≤32 bytes): ${value}`);
  }
  return `address:0x${clean.padStart(64, "0")}`;
}

export function encodeDepositField(
  key: keyof DepositV3DelegateArgs,
  value: DepositV3DelegateArgs[keyof DepositV3DelegateArgs],
): string {
  switch (FIELD_TYPES[key]) {
    case "address":
      return addressArg(value as string);
    case "hex":
      return hexArg(value as string);
    case "u64":
      return u64Arg(value as string);
    case "u8":
      return `u8:${value as number}`;
    case "hexVector":
      return hexVectorArg(value as string[]);
    case "hexVector3":
      return hexVector3Arg(value as string[][]);
  }
}

export interface DepositV3DelegateEntry {
  readonly fn: string;
  readonly keys: ReadonlyArray<keyof DepositV3DelegateArgs>;
}

/** The 2 relayer-delegated deposit entries, in order. Key lists match the post-re-key Move
 *  signatures exactly (leading &signer excluded). step2b is NOT here — it is user-signed. */
export const DEPOSIT_V3_DELEGATE_ENTRIES: ReadonlyArray<DepositV3DelegateEntry> = [
  {
    fn: "prepare_deposit_binding_v3_for_user",
    keys: ["assetAddr", "userAddr", "commitment", "amountTag", "amountP", "depositBindingProof"],
  },
  {
    fn: "deposit_step2a_eunoma_verify_v3",
    keys: [
      "assetAddr", "userAddr", "commitment", "amountTag", "caPayloadHash", "depositNonce",
      "depositBindingProof", "expirySecs", "groupSignature", "fallbackBitmap",
      "fallbackSignatures", "newBalanceP", "newBalanceR", "newBalanceREffAud",
      "amountP", "amountRSender", "amountRRecip", "amountREffAud", "ekVolunAuds",
      "amountRVolunAuds", "zkrpNewBalance", "zkrpAmount", "sigmaProtoComm",
      "sigmaProtoResp", "memo",
    ],
  },
] as const;

export function encodeDepositV3EntryArgs(
  entry: DepositV3DelegateEntry,
  args: DepositV3DelegateArgs,
): string[] {
  return entry.keys.map((k) => encodeDepositField(k, args[k]));
}

export interface DepositV3SubmitResult {
  accepted: true;
  simulated: boolean;
  /** Tx hashes in submission order: [prepare, step2a]. */
  txHashes: string[];
}

export interface DepositV3SubmitHooks {
  completedTxHashes?: string[];
  onStepStart?: (step: number, fn: string) => void;
  onStepDone?: (step: number, fn: string, txHash: string) => void;
  resumeAfterStep?: number;
}

export interface CreateDepositV3SubmitterOptions {
  submit?: boolean;
  env?: NodeJS.ProcessEnv;
  spawnAptos?: SpawnAptosFn;
  aptosBin?: string;
  stderrSink?: { write: (chunk: string) => void };
  onStepStart?: (step: number, fn: string) => void;
  onStepDone?: (step: number, fn: string, txHash: string) => void;
  retryAttempts?: number;
  retryDelayMs?: number;
}

const DEFAULT_DEPOSIT_V3_MAX_GAS = 2_000_000;
const DEFAULT_DEPOSIT_V3_GAS_UNIT_PRICE = 100;
const DEFAULT_APTOS_CLI_RETRY_ATTEMPTS = 12;
const DEFAULT_APTOS_CLI_RETRY_DELAY_MS = 5_000;
const RECOVERABLE_PENDING_ABORT_BY_FN: Record<string, string> = {
  prepare_deposit_binding_v3_for_user: "E_PENDING_DEPOSIT_BINDING",
  deposit_step2a_eunoma_verify_v3: "E_PENDING_DEPOSIT_FINALIZATION",
};

/**
 * Build a submitter that drives prepare_deposit_binding_v3 + deposit_step2a_v3 on the user's behalf
 * from the dedicated relayer key. Returns the 2 tx hashes. --simulate by default; real broadcast
 * requires submit=true AND RELAYER_SUBMIT_ENABLED=1 (fixed at construction). step2b is the user's.
 */
export function createDepositV3Submitter(
  bridgePackage: string,
  relayerProfile: string | undefined,
  opts: CreateDepositV3SubmitterOptions = {},
): (args: DepositV3DelegateArgs, hooks?: DepositV3SubmitHooks) => Promise<DepositV3SubmitResult> {
  if (!bridgePackage || !/^0x[0-9a-fA-F]+$/.test(bridgePackage)) {
    throw new Error("bridgePackage must be a non-empty 0x-prefixed hex address");
  }
  const spawnFn = opts.spawnAptos ?? defaultSpawnAptos;
  const aptosBin = opts.aptosBin ?? "aptos";
  const env = opts.env ?? process.env;
  if (opts.submit === true && env.RELAYER_SUBMIT_ENABLED !== "1") {
    throw new Error(
      "createDepositV3Submitter: submit=true requires RELAYER_SUBMIT_ENABLED=1 in the env",
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
    callArgs: DepositV3DelegateArgs,
    hooks: DepositV3SubmitHooks = {},
  ): Promise<DepositV3SubmitResult> => {
    const txHashes: string[] = [...(hooks.completedTxHashes ?? [])];
    const resumeAfterStep =
      Number.isInteger(hooks.resumeAfterStep) && hooks.resumeAfterStep !== undefined
        ? hooks.resumeAfterStep
        : -1;

    for (let stepIndex = 0; stepIndex < DEPOSIT_V3_DELEGATE_ENTRIES.length; stepIndex += 1) {
      const entry = DEPOSIT_V3_DELEGATE_ENTRIES[stepIndex];
      if (stepIndex <= resumeAfterStep) continue;
      (hooks.onStepStart ?? opts.onStepStart)?.(stepIndex, entry.fn);
      const positional = encodeDepositV3EntryArgs(entry, callArgs);
      const cliArgs = [
        "move",
        "run",
        "--function-id",
        `${bridgePackage}::eunoma_bridge::${entry.fn}`,
        ...(relayerProfile ? ["--profile", relayerProfile] : []),
        "--max-gas",
        String(DEFAULT_DEPOSIT_V3_MAX_GAS),
        "--gas-unit-price",
        String(DEFAULT_DEPOSIT_V3_GAS_UNIT_PRICE),
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
          const recovered = recoverableAlreadyPreparedMarker(entry, stdoutText, stderrText, simulate, stepIndex);
          if (recovered) {
            stderrSink.write(
              `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) recovered already-prepared on-chain state; ` +
                `continuing with marker=${recovered}\n`,
            );
            txHash = recovered;
            break;
          }
        }
        if (exitCode === 0 && txHash) break;
        const retryable = isRetryableAptosCliTransportFailure(stdoutText, stderrText);
        if (retryable && attempt < maxAttempts) {
          stderrSink.write(
            `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) retryable Aptos CLI transport failure ` +
              `(attempt ${attempt}/${maxAttempts}); backing off\n`,
          );
          await sleep(baseRetryDelayMs * attempt);
          continue;
        }
        if (exitCode !== 0) {
          stderrSink.write(
            `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) exited ${exitCode ?? "(signal)"}; stderr=\n${stderrText}\n`,
          );
          throw new RelayerSubmitterError(
            "aptos_cli_error",
            `Aptos CLI ${entry.fn} failed (step ${step}/2); check relayer logs for details.`,
          );
        }
        stderrSink.write(
          `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) exit=0 but no transaction_hash; stdout=\n${stdoutText}\n`,
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
  entry: DepositV3DelegateEntry,
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
