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
    keys: ["userAddr", "commitment", "amountTag", "amountP", "depositBindingProof"],
  },
  {
    fn: "deposit_step2a_eunoma_verify_v3",
    keys: [
      "userAddr", "commitment", "amountTag", "caPayloadHash", "depositNonce",
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

export interface CreateDepositV3SubmitterOptions {
  submit?: boolean;
  env?: NodeJS.ProcessEnv;
  spawnAptos?: SpawnAptosFn;
  aptosBin?: string;
  stderrSink?: { write: (chunk: string) => void };
}

/**
 * Build a submitter that drives prepare_deposit_binding_v3 + deposit_step2a_v3 on the user's behalf
 * from the dedicated relayer key. Returns the 2 tx hashes. --simulate by default; real broadcast
 * requires submit=true AND RELAYER_SUBMIT_ENABLED=1 (fixed at construction). step2b is the user's.
 */
export function createDepositV3Submitter(
  bridgePackage: string,
  relayerProfile: string | undefined,
  opts: CreateDepositV3SubmitterOptions = {},
): (args: DepositV3DelegateArgs) => Promise<DepositV3SubmitResult> {
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

  return async (callArgs: DepositV3DelegateArgs): Promise<DepositV3SubmitResult> => {
    const txHashes: string[] = [];
    for (const entry of DEPOSIT_V3_DELEGATE_ENTRIES) {
      const positional = encodeDepositV3EntryArgs(entry, callArgs);
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
          `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) exited ${exitCode ?? "(signal)"}; stderr=\n${stderrText}\n`,
        );
        throw new RelayerSubmitterError(
          "aptos_cli_error",
          `Aptos CLI ${entry.fn} failed (step ${step}/2); check relayer logs for details.`,
        );
      }
      const txHash = parseTxHashFromAptosCliStdout(stdoutText);
      if (!txHash) {
        stderrSink.write(
          `[relayer-v3-deposit] ${entry.fn} (step ${step}/2) exit=0 but no transaction_hash; stdout=\n${stdoutText}\n`,
        );
        throw new RelayerSubmitterError(
          "aptos_cli_missing_tx_hash",
          `${entry.fn} stdout missing transaction_hash (simulate=${simulate})`,
        );
      }
      txHashes.push(txHash);
    }
    return { accepted: true, simulated: simulate, txHashes };
  };
}
