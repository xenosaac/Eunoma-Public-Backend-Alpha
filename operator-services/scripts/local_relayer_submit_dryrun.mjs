#!/usr/bin/env node
// Local relayer submit dry-run.
//
// Posts a SYNTHETIC WithdrawV2CallArgs fixture to the relayer's
// /v2/relayer/submit/withdraw endpoint and prints the result. This script
// does NOT submit to testnet. Real submission requires
//   RELAYER_SUBMIT_ENABLED=1  (relayer env)
//   ADMIN_PROFILE=<name>      (relayer env, points at an aptos CLI profile)
//   BRIDGE_PACKAGE_ADDRESS=<addr>
// AND explicit operator approval. See M5b/5c/5d.
//
// In --mock mode the relayer is configured with an in-process mock submitter
// (no aptos CLI required), so this script can run on developer machines that
// don't have the aptos CLI installed. In non-mock mode the relayer is
// expected to already be running with a configured CLI submitter.
//
// Args:
//   --coordinator-url <url>   optional override; otherwise read from the
//                              local-cluster.json plan
//   --bridge-address <addr>   0x-prefixed hex address of the bridge package
//                              (required; spliced into --function-id by the
//                              relayer's CLI submitter)
//   --bearer-token <token>    optional bearer token for the relayer; defaults
//                              to the plan's RELAYER_BEARER_TOKEN
//   --mock                    if set, run the relayer in-process with a
//                              mock submitter (no real aptos CLI invocation)
//
// Exit codes:
//   0 success
//   1 generic failure
//   2 usage / preflight failure
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const COMMAND_NAME = "local:relayer-submit-dryrun";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = parseArgs(process.argv.slice(2));

if (args.errors.length > 0) {
  console.error(`Usage: node scripts/local_relayer_submit_dryrun.mjs ` +
    `[--coordinator-url URL] --bridge-address 0xPKG [--bearer-token TOK] [--mock]`);
  for (const e of args.errors) console.error("  error: " + e);
  process.exit(2);
}

if (!args.bridgeAddress) {
  console.error(
    "missing --bridge-address. The relayer needs a package address to splice into the Move --function-id.",
  );
  process.exit(2);
}

const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const planPath = resolve(stateRoot, "cluster/local-cluster.json");

let relayerUrl;
let relayerBearer;
let relayerInProcess;

if (args.mock) {
  // In --mock mode we bring up a relayer in-process bound to an ephemeral
  // port with a mock submitter. No external relayer is contacted; no aptos
  // CLI is invoked.
  const { buildRelayerServer } = await import("../relayer/dist/index.js").catch(async (err) => {
    console.error("could not import @eunoma/relayer dist build. Run `npm run -w @eunoma/relayer build` first.");
    console.error(String(err));
    process.exit(1);
  });
  const mockSubmitter = async () => ({
    accepted: true,
    txHash: "0x" + "11".repeat(32),
    simulated: true,
  });
  const server = buildRelayerServer({
    submitter: mockSubmitter,
  });
  // listen on port 0 so the kernel assigns a free one
  await server.listen({ host: "127.0.0.1", port: 0 });
  const address = server.server.address();
  if (!address || typeof address === "string") {
    console.error("failed to determine ephemeral relayer port");
    process.exit(1);
  }
  relayerUrl = `http://127.0.0.1:${address.port}`;
  relayerBearer = undefined;
  relayerInProcess = server;
} else {
  if (!existsSync(planPath)) {
    console.error(
      "local cluster config not found. Run `npm run local:cluster:config -- --force` first, or pass --mock.",
    );
    process.exit(2);
  }
  const plan = JSON.parse(readFileSync(planPath, "utf8"));
  relayerUrl = `http://127.0.0.1:${plan.relayer.port}`;
  relayerBearer = args.bearerToken ?? plan.relayer.env?.RELAYER_BEARER_TOKEN;
}

console.log(
  "This script does NOT submit to testnet. Real submission requires " +
    "RELAYER_SUBMIT_ENABLED=1 + ADMIN_PROFILE configured + explicit operator approval. " +
    "See M5b/5c/5d.",
);

const callArgs = buildSyntheticWithdrawV2CallArgs();
const callArgsKeys = Object.keys(callArgs);

let statusCode = -1;
let body;
let outcomeError;
try {
  const res = await fetch(`${relayerUrl}/v2/relayer/submit/withdraw`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(callArgs),
  });
  statusCode = res.status;
  body = await safeJson(res);
} catch (err) {
  outcomeError = err instanceof Error ? err.message : String(err);
} finally {
  if (relayerInProcess) await relayerInProcess.close();
}

const txHashOrSimulationStatus =
  body && typeof body === "object"
    ? body.txHash ?? body.error ?? "(no body)"
    : "(network_error)";

console.log(
  JSON.stringify(
    {
      ok: statusCode === 202 && !outcomeError,
      command: COMMAND_NAME,
      relayerUrl,
      bridgeAddress: args.bridgeAddress,
      mock: !!args.mock,
      withdrawCallArgsKeys: callArgsKeys,
      withdrawCallArgsKeysCount: callArgsKeys.length,
      statusCode,
      txHashOrSimulationStatus,
      ...(outcomeError ? { error: outcomeError } : {}),
      ...(body ? { responseBody: body } : {}),
    },
    null,
    2,
  ),
);

if (outcomeError) {
  process.exit(1);
}
if (statusCode !== 202) {
  process.exit(1);
}

// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    coordinatorUrl: undefined,
    bridgeAddress: undefined,
    bearerToken: undefined,
    mock: false,
    errors: [],
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--coordinator-url":
        out.coordinatorUrl = argv[++i];
        if (!out.coordinatorUrl) out.errors.push("--coordinator-url requires a value");
        break;
      case "--bridge-address":
        out.bridgeAddress = argv[++i];
        if (!out.bridgeAddress) out.errors.push("--bridge-address requires a value");
        else if (!/^0x[0-9a-fA-F]+$/.test(out.bridgeAddress)) {
          out.errors.push("--bridge-address must be a 0x-prefixed hex string");
        }
        break;
      case "--bearer-token":
        out.bearerToken = argv[++i];
        if (!out.bearerToken) out.errors.push("--bearer-token requires a value");
        break;
      case "--mock":
        out.mock = true;
        break;
      case "--help":
      case "-h":
        out.errors.push("help requested");
        break;
      default:
        out.errors.push(`unknown argument: ${arg}`);
        break;
    }
  }
  return out;
}

function headers() {
  const out = { "content-type": "application/json" };
  if (relayerBearer) out.authorization = `Bearer ${relayerBearer}`;
  return out;
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return { error: "non_json_response", status: res.status };
  }
}

/**
 * Deterministic 27-field WithdrawV2CallArgs body. Chunk counts mirror the
 * Aptos CA SDK conventions:
 *   - 8 chunks for new_balance_*
 *   - 4 chunks for amount_*
 *   - 30 sigma commitments / 25 sigma responses
 * The 27 keys appear in the EXACT order
 * move/sources/eunoma_bridge.move:515-543 specifies, so the relayer's
 * Object.keys() invariant assertion lines up.
 */
function buildSyntheticWithdrawV2CallArgs() {
  const hex32 = (seed) =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join(
      "",
    );
  const hexN = (n, seed) =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");

  return {
    root: hex32(0x10),
    nullifierHash: hex32(0x11),
    recipient: hex32(0x12),
    recipientHash: hex32(0x13),
    amountTag: hex32(0x14),
    caPayloadHash: hex32(0x15),
    requestHash: hex32(0x16),
    vaultSequence: "42",
    withdrawProof: hexN(192, 0x20),
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
    newBalanceREffAud: [],
    amountP: Array.from({ length: 4 }, (_, i) => hex32(0x60 + i)),
    amountRSender: Array.from({ length: 4 }, (_, i) => hex32(0x70 + i)),
    amountRRecip: Array.from({ length: 4 }, (_, i) => hex32(0x80 + i)),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: hexN(672, 0x90),
    zkrpAmount: hexN(672, 0xa0),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
    memo: "",
  };
}
