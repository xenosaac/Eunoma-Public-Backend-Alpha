#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// =============================================================================================
// Milestone 2 sub-milestone 2b — confirmed-deposit observer (single-shot poll).
//
// Reads confirmed DepositEventV2 envelopes from an Aptos fullnode REST endpoint and POSTs
// each to /v2/vault_state/observe_deposit on the coordinator. Each POST advances the per-worker
// `deposit_count_observed` cursor by exactly one (strict monotonicity is enforced both on the
// orchestrator and at the worker — see crypto-worker-rust::vault_state_v2::observe_deposit_v2).
//
// Aptos `#[event]` module events (`event::emit(DepositEventV2 { ... })`) are accessed through
// the events-by-handle accessor in two patterns:
//
//   1. Per-handle accessor (legacy event handles on a resource): NOT applicable here.
//   2. Module event by struct type: GET /v1/accounts/{module_address}/events/{event_struct_type}
//      where event_struct_type is the canonical fully-qualified Move struct path, e.g.
//      `0xABC::eunoma_bridge::DepositEventV2`.
//
// We accept the accessor URL as `--events-url` with a default-construction pattern:
//   `${aptos_node_url}/v1/accounts/${bridge_address}/events/${bridge_address}::eunoma_bridge::DepositEventV2`
//
// The operator should sanity-check this URL against a local cluster or test their bridge
// publish before driving real funds through.
//
// Exit codes — operator runbook contract:
//   0   success — all events processed; cursor advanced cleanly.
//   1   generic request/parse failure (network, malformed event JSON, coordinator 5xx etc.).
//   2   usage error.
//   24  vault_state_init_provenance_unknown — Milestone 2a prereq missing. Operator action:
//       re-run `npm run local:vault-state:init`.
//   25  cursor_divergence — worker cursors disagree; investigate per-slot vault_state_v2.json.
// =============================================================================================
const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_INIT_PROVENANCE = 24;
const EXIT_CURSOR_DIVERGENCE = 25;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let coordinatorUrl;
let aptosNodeUrl;
let bridgeAddress;
let eventsUrl; // optional override; if not set, we construct from aptosNodeUrl + bridgeAddress
let dkgEpoch;
let vaultEk;
let senderAddress;
let assetType;
let chainId;
let startSequence; // optional u64 string — start polling from this sequence number
let limit; // optional u64 — fetch at most this many events
let maxIterations; // optional u64 — process at most this many events in one run
let bearerToken;
let caDkgTranscriptHash;

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case "--coordinator-url":
      coordinatorUrl = args[++i];
      break;
    case "--aptos-node-url":
      aptosNodeUrl = args[++i];
      break;
    case "--bridge-address":
      bridgeAddress = args[++i];
      break;
    case "--events-url":
      eventsUrl = args[++i];
      break;
    case "--dkg-epoch":
      dkgEpoch = args[++i];
      break;
    case "--vault-ek":
      vaultEk = args[++i];
      break;
    case "--sender-address":
      senderAddress = args[++i];
      break;
    case "--asset-type":
      assetType = args[++i];
      break;
    case "--chain-id":
      chainId = args[++i];
      break;
    case "--start-sequence":
      startSequence = args[++i];
      break;
    case "--limit":
      limit = args[++i];
      break;
    case "--max-iterations":
      maxIterations = args[++i];
      break;
    case "--bearer-token":
      bearerToken = args[++i];
      break;
    case "--ca-dkg-transcript-hash":
      caDkgTranscriptHash = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_deposit_observer --coordinator-url URL --aptos-node-url URL\n" +
          "                              --bridge-address HEX --dkg-epoch N --vault-ek HEX\n" +
          "                              --sender-address HEX --asset-type HEX --chain-id N\n" +
          "                              --ca-dkg-transcript-hash HEX\n" +
          "                              [--events-url URL] [--start-sequence N] [--limit N]\n" +
          "                              [--max-iterations N] [--bearer-token TOKEN]\n" +
          "\n" +
          "Single-shot poll: reads DepositEventV2 events from the Aptos fullnode (paginated by\n" +
          "the per-handle sequence_number), POSTs each to /v2/vault_state/observe_deposit. The\n" +
          "coordinator advances every worker's deposit_count_observed cursor by one per call.\n" +
          "\n" +
          "Aptos events URL: --events-url is RECOMMENDED for testnet/prod because Aptos' REST\n" +
          "spec for module events varies between fullnode versions. The default constructor\n" +
          "  ${aptosNodeUrl}/v1/accounts/${bridgeAddress}/events/${bridgeAddress}::eunoma_bridge::DepositEventV2\n" +
          "works for some fullnodes but may return 404 on others — verify against your node before\n" +
          "running this against real funds.\n" +
          "\n" +
          "Exit codes:\n" +
          `  ${EXIT_SUCCESS}   success — all events processed\n` +
          `  ${EXIT_GENERIC_FAILURE}   generic request/parse failure\n` +
          `  ${EXIT_USAGE_ERROR}   usage error\n` +
          `  ${EXIT_INIT_PROVENANCE}  vault_state_init_provenance_unknown — re-run local:vault-state:init\n` +
          `  ${EXIT_CURSOR_DIVERGENCE}  cursor_divergence — workers disagree on cursor; investigate\n`,
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

if (!aptosNodeUrl) {
  console.error("--aptos-node-url is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!bridgeAddress) {
  console.error("--bridge-address is required (the Aptos module address that published eunoma_bridge)");
  process.exit(EXIT_USAGE_ERROR);
}
if (!dkgEpoch || !/^[0-9]+$/.test(dkgEpoch)) {
  console.error("--dkg-epoch is required and must be a decimal string");
  process.exit(EXIT_USAGE_ERROR);
}
if (!vaultEk) {
  console.error("--vault-ek is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!senderAddress) {
  console.error("--sender-address is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!assetType) {
  console.error("--asset-type is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!chainId) {
  console.error("--chain-id is required");
  process.exit(EXIT_USAGE_ERROR);
}
if (!caDkgTranscriptHash) {
  console.error("--ca-dkg-transcript-hash is required (the coordinator validates this against the persisted Phase 2 transcript)");
  process.exit(EXIT_USAGE_ERROR);
}
const chainIdNum = Number.parseInt(chainId, 10);
if (!Number.isInteger(chainIdNum) || chainIdNum < 0 || chainIdNum > 255) {
  console.error("--chain-id must be a u8 integer (0..255)");
  process.exit(EXIT_USAGE_ERROR);
}

const planPath = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
  "cluster/local-cluster.json",
);
let plan;
if (existsSync(planPath)) {
  plan = JSON.parse(readFileSync(planPath, "utf8"));
  if (!coordinatorUrl) coordinatorUrl = `http://127.0.0.1:${plan.coordinator.port}`;
  if (!bearerToken) bearerToken = plan.coordinator.env.COORDINATOR_BEARER_TOKEN;
}

if (!coordinatorUrl) {
  console.error("--coordinator-url is required when no local cluster plan is found");
  process.exit(EXIT_USAGE_ERROR);
}

// Normalize the bridge address — Aptos addresses sometimes have a 0x prefix.
const normalizedBridge = bridgeAddress.startsWith("0x")
  ? bridgeAddress
  : `0x${bridgeAddress}`;

// Construct the events accessor URL if not supplied. The path format follows Aptos's module
// event accessor: /v1/accounts/<module_address>/events/<event_struct_type>.
//
// Goal.md M3: prefer DepositConfirmedV2 (carries on-chain `deposit_count` + vault_addr +
// asset_type natively) over the legacy DepositEventV2 (synthesized depositCount from
// sequence_number). Operators can override via --events-url to fall back to DepositEventV2
// if their chain doesn't have the M3 contract yet.
if (!eventsUrl) {
  const accessor = `${normalizedBridge}::eunoma_bridge::DepositConfirmedV2`;
  // Construct manually because URL doesn't permit colons in pathnames cleanly without encoding.
  const base = aptosNodeUrl.replace(/\/+$/, "");
  eventsUrl = `${base}/v1/accounts/${normalizedBridge}/events/${encodeURIComponent(accessor)}`;
}

// =============================================================================================
// Poll the fullnode for events. Aptos returns them as an array of
// { sequence_number, type, data, guid: { creation_number, account_address } }.
//
// We support pagination via `start` (sequence_number) + `limit` query params. The fullnode
// caps `limit` at 100 by default; we honor that.
// =============================================================================================
const queryParams = new URLSearchParams();
if (startSequence) queryParams.set("start", startSequence);
if (limit) queryParams.set("limit", limit);
const fetchUrl = queryParams.toString() ? `${eventsUrl}?${queryParams}` : eventsUrl;

let eventsRes;
try {
  eventsRes = await fetch(fetchUrl);
} catch (err) {
  console.error(`fullnode request failed: ${err?.message ?? err}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
if (!eventsRes.ok) {
  const text = await eventsRes.text();
  console.error(`fullnode returned ${eventsRes.status}: ${text}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
let events;
try {
  events = await eventsRes.json();
} catch (err) {
  console.error(`fullnode returned non-JSON: ${err?.message ?? err}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
if (!Array.isArray(events)) {
  console.error(`fullnode returned non-array events body: ${JSON.stringify(events)}`);
  process.exit(EXIT_GENERIC_FAILURE);
}

if (events.length === 0) {
  console.log(
    JSON.stringify({ ok: true, processed: 0, message: "no events to process" }, null, 2),
  );
  process.exit(EXIT_SUCCESS);
}

const maxIters = maxIterations ? Number.parseInt(maxIterations, 10) : events.length;

const processed = [];
for (let i = 0; i < events.length && i < maxIters; i += 1) {
  const event = events[i];
  // Validate event shape minimally.
  if (
    !event ||
    typeof event !== "object" ||
    typeof event.sequence_number !== "string" ||
    typeof event.type !== "string" ||
    !event.data ||
    typeof event.data !== "object"
  ) {
    console.error(`malformed event at index ${i}: ${JSON.stringify(event)}`);
    process.exit(EXIT_GENERIC_FAILURE);
  }
  const {
    commitment,
    amount_tag,
    ca_payload_hash,
    deposit_nonce,
    deposit_count: onChainDepositCount,
    vault_addr: eventVaultAddr,
    asset_type: eventAssetType,
  } = event.data;
  // Each event field is a `vector<u8>` on-chain; Aptos serialises this as a 0x-prefixed hex
  // string in the JSON response. Strip the prefix to align with our 32-byte hex format.
  const stripHex = (h) =>
    typeof h === "string" && h.startsWith("0x") ? h.slice(2) : h;
  // Goal.md M3 defense-in-depth: when reading DepositConfirmedV2 (default), cross-check
  // event.asset_type matches the operator's expected asset_type. Mismatched asset → stale
  // or cross-vault event, fail closed.
  if (eventAssetType !== undefined && stripHex(eventAssetType).toLowerCase() !== stripHex(assetType).toLowerCase()) {
    console.error(
      `event ${event.sequence_number} asset_type=${eventAssetType} does not match operator expected ${assetType} — stale or cross-vault event, refusing to advance cursor`,
    );
    process.exit(EXIT_GENERIC_FAILURE);
  }
  for (const [name, value] of [
    ["commitment", commitment],
    ["amount_tag", amount_tag],
    ["ca_payload_hash", ca_payload_hash],
    ["deposit_nonce", deposit_nonce],
  ]) {
    if (typeof value !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(value)) {
      console.error(`event ${event.sequence_number} field ${name} not 32-byte hex: ${value}`);
      process.exit(EXIT_GENERIC_FAILURE);
    }
  }

  const sequenceNumber = event.sequence_number;
  // Goal.md M3: prefer the on-chain DepositConfirmedV2.deposit_count when present (the
  // chain-authoritative monotonic counter). Legacy DepositEventV2 fallback uses
  // (sequence_number + 1) — but the goal.md M3 contract is "observer updates worker-local
  // state shares only via the confirmed deposit_count emitted by the chain", so the
  // operator should be reading DepositConfirmedV2 (default since this commit).
  let depositCount;
  if (onChainDepositCount !== undefined) {
    depositCount = String(onChainDepositCount);
  } else {
    depositCount = (BigInt(sequenceNumber) + 1n).toString();
  }
  if (BigInt(depositCount) > BigInt(Number.MAX_SAFE_INTEGER)) {
    console.error(
      `depositCount ${depositCount} exceeds Number.MAX_SAFE_INTEGER; coordinator expects a JSON number`,
    );
    process.exit(EXIT_GENERIC_FAILURE);
  }

  // Aptos events include a guid: { creation_number, account_address }. For module events
  // emitted via event::emit, the guid may be present or may be absent. We construct an
  // opaque string regardless.
  let eventGuid;
  if (event.guid && typeof event.guid === "object") {
    const creation = event.guid.creation_number ?? event.guid.creation_num ?? "0";
    const account = event.guid.account_address ?? normalizedBridge;
    eventGuid = `${creation}:${account}`;
  } else {
    // Module events without guid → synthesize from event type + sequence.
    eventGuid = `module-event:${event.type}:${sequenceNumber}`;
  }

  // We don't have direct access to the transaction version in the events accessor response.
  // Aptos returns a `version` field on each event in newer fullnode versions; fall back to
  // sequence_number repurposed if missing (the observer's downstream auditors can cross-check
  // against the explorer using sequence_number + bridge_address).
  const txVersion =
    typeof event.version === "string"
      ? event.version
      : typeof event.transaction_version === "string"
        ? event.transaction_version
        : sequenceNumber;

  const payload = {
    requestId: `vault-state-observe-${dkgEpoch}-${depositCount}-${Date.now()}`,
    dkgEpoch,
    vaultEk,
    senderAddress,
    assetType,
    chainId: chainIdNum,
    depositCount: Number(depositCount),
    commitment: stripHex(commitment),
    amountTag: stripHex(amount_tag),
    caPayloadHash: stripHex(ca_payload_hash),
    depositNonce: stripHex(deposit_nonce),
    sequenceNumber,
    txVersion,
    eventGuid,
  };
  if (caDkgTranscriptHash) payload.caDkgTranscriptHash = caDkgTranscriptHash;

  const headers = { "content-type": "application/json" };
  if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;

  let res;
  try {
    res = await fetch(new URL("/v2/vault_state/observe_deposit", coordinatorUrl), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error(
      `coordinator request for depositCount=${depositCount} failed: ${err?.message ?? err}`,
    );
    process.exit(EXIT_GENERIC_FAILURE);
  }
  let body;
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  if (res.status === 400 && body?.error === "vault_state_init_provenance_unknown") {
    console.error(
      "Milestone 2a init provenance missing — re-run `npm run local:vault-state:init` to refresh the init transcript before retrying.",
    );
    process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
    process.exit(EXIT_INIT_PROVENANCE);
  }
  if (res.status === 502 && body?.error === "cursor_divergence") {
    console.error(
      `cursor_divergence at slot ${body?.slot}: workers disagree on cursor. Investigate per-slot vault_state_v2.json.`,
    );
    process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
    process.exit(EXIT_CURSOR_DIVERGENCE);
  }
  if (!res.ok) {
    console.error(
      `coordinator returned ${res.status} for depositCount=${depositCount}: ${JSON.stringify(body)}`,
    );
    process.exit(EXIT_GENERIC_FAILURE);
  }
  processed.push({
    sequenceNumber,
    depositCount: body.depositCount,
    transcriptHash: body.transcriptHash,
    transcriptPath: body.transcriptPath,
  });
}

console.log(
  JSON.stringify(
    {
      ok: true,
      processed: processed.length,
      events: processed,
    },
    null,
    2,
  ),
);
