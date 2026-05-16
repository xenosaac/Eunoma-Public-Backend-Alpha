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
  WITHDRAW_V2_CALL_ARGS_ORDER,
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

export interface RelayerSubmitResult {
  accepted: true;
  txHash: string;
  simulated: boolean;
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
      // a 502 with the message body — operators read this to decide whether
      // to retry. We never leak the request body in the error.
      return reply.code(502).send({
        error: "submit_failed",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  return server;
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
   * Real submit flag. `false` (the default) appends `--simulate` to the CLI
   * args. Production rollout from M5b/5c/5d will set this `true` only after
   * explicit operator approval and `RELAYER_SUBMIT_ENABLED=1` in the env.
   */
  submit?: boolean;
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
}

/**
 * Build a submitter that invokes `aptos move run --function-id <pkg>::eunoma_bridge::withdraw_to_recipient_v2`
 * with the 27 positional arguments in canonical order. Returns the
 * transaction hash parsed from stdout.
 *
 * Default behavior is --simulate. Set `opts.submit = true` to actually
 * broadcast (which requires `ADMIN_PROFILE` to point at a configured Aptos
 * CLI profile and `RELAYER_SUBMIT_ENABLED=1` in the env).
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
  const simulate = opts.submit !== true;

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
      const trimmed = stderrText.split(/\n/).filter(Boolean).slice(0, 5).join(" | ");
      throw new Error(
        `aptos cli exited ${exitCode ?? "(signal)"}${trimmed ? `: ${trimmed}` : ""}`,
      );
    }

    const txHash = parseTxHashFromAptosCliStdout(stdoutText);
    if (!txHash) {
      throw new Error(
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
  // Iterate over WITHDRAW_V2_CALL_ARGS_ORDER so the order ALWAYS matches the
  // exported manifest. If the manifest drifts from the Move source, the
  // parser test in deop-protocol catches it; if the encoder drifts from the
  // manifest, the killer test in tests/server.test.ts catches it.
  return WITHDRAW_V2_CALL_ARGS_ORDER.map((key) => encodeField(key, args[key]));
}

function encodeField(key: keyof WithdrawV2CallArgs, value: WithdrawV2CallArgs[keyof WithdrawV2CallArgs]): string {
  switch (key) {
    case "root":
    case "nullifierHash":
    case "recipient":
    case "recipientHash":
    case "amountTag":
    case "caPayloadHash":
    case "requestHash":
    case "withdrawProof":
    case "groupSignature":
    case "zkrpNewBalance":
    case "zkrpAmount":
    case "memo":
      return hexArg(value as string);
    case "vaultSequence":
    case "expirySecs":
      return u64Arg(value as string);
    case "fallbackBitmap":
      // u8 is encoded as a decimal-tagged u8:N for the aptos CLI.
      return `u8:${value as number}`;
    case "fallbackSignatures":
    case "newBalanceP":
    case "newBalanceR":
    case "newBalanceREffAud":
    case "amountP":
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

function parseTxHashFromAptosCliStdout(stdout: string): string | undefined {
  // The aptos CLI prints a JSON object with a "Result" key containing
  // "transaction_hash". We accept either the raw JSON form
  //   "transaction_hash": "0x.."
  // or the bare regex match.
  const m = stdout.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  if (m) return m[1];
  return undefined;
}

function chunkToString(chunk: Buffer | string): string {
  if (typeof chunk === "string") return chunk;
  return chunk.toString("utf8");
}

const defaultSpawnAptos: SpawnAptosFn = (command, args) => {
  const proc = nodeSpawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  const done = new Promise<number | null>((resolve, reject) => {
    proc.on("close", (code) => resolve(code));
    proc.on("error", (err) => reject(err));
  });
  return { stdout: proc.stdout, stderr: proc.stderr, done };
};
