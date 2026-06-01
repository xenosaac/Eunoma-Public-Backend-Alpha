#!/usr/bin/env node
// ASP re-fork cycle runner (one epoch). Reads the persisted approved-set state + any new deposits,
// screens via Chainalysis (real, deposit-side), rebuilds the ASP LeanIMT, publishes the full set
// to IPFS, persists the new state, and emits {rootHex, cid, recordArgs} so the caller records the
// root on-chain via the asp-recorder delegate (record_asp_root_via_delegate). Off-chain → 0 gas.
//
// Usage:
//   node local_run_asp_cycle.mjs --state PATH [--new-deposits PATH] [--bridge 0x..] [--record]
//                                [--asp-set-out PATH | --state-dir DIR]
//   --record (optional) actually submits the on-chain record via `aptos move run` using the
//            EUNOMA_ASP_RECORDER_PROFILE aptos CLI profile (the low-priv delegate). Without it,
//            only prints recordArgs (CP3/dev mode).
//   --asp-set-out PATH  explicit path for the public ASP-set artifact the coordinator serves.
//   --state-dir DIR     when set, the ASP-set artifact is written to
//                       <DIR>/coordinator/asp_set.json (the path GET /v2/asp-set + /v2/asp-root-current
//                       read). --asp-set-out wins if both are supplied.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { runAspReforkEpoch, aspRecordCliArgs } from "./local_asp_refork.mjs";

const args = process.argv.slice(2);
const getArg = (n, req = false) => { const i = args.indexOf(n); if (i < 0) { if (req) { console.error(`missing ${n}`); process.exit(2); } return undefined; } return args[i + 1]; };
const has = (n) => args.includes(n);

const statePath = getArg("--state", true);
const newDepositsPath = getArg("--new-deposits");
const bridge = getArg("--bridge");
const doRecord = has("--record");
const aspSetOut = getArg("--asp-set-out");
const stateDir = getArg("--state-dir");

const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : { approved: [] };
const newDeposits = newDepositsPath && existsSync(newDepositsPath) ? JSON.parse(readFileSync(newDepositsPath, "utf8")) : [];

const r = await runAspReforkEpoch({ state, newDeposits });

// persist new approved-set state (public commitments + senders only)
writeFileSync(statePath, JSON.stringify({ approved: r.approved }, null, 2) + "\n");

// persist the PUBLIC ASP-set artifact so the coordinator can serve it at /v2/asp-set +
// /v2/asp-root-current. r.artifact already carries { scheme, treeDepth, rootHex, commitments,
// ipfsCid } (commitments only — no secrets; LeanIMTTree's forbidden-field gate enforces this).
const aspSetPath = aspSetOut
  ? aspSetOut
  : stateDir
    ? join(stateDir, "coordinator", "asp_set.json")
    : null;
if (aspSetPath) {
  mkdirSync(dirname(aspSetPath), { recursive: true });
  const tmp = aspSetPath + ".tmp";
  writeFileSync(tmp, JSON.stringify(r.artifact, null, 2) + "\n", { mode: 0o644 });
  // atomic publish
  const { renameSync } = await import("node:fs");
  renameSync(tmp, aspSetPath);
}

const recordArgs = bridge ? aspRecordCliArgs({ bridgeAddr: bridge, rootHex: r.rootHex, cid: r.cid }) : null;

let recordTx = null;
if (doRecord) {
  if (!bridge) { console.error("--record requires --bridge"); process.exit(2); }
  const profile = process.env.EUNOMA_ASP_RECORDER_PROFILE || "asp-recorder";
  const out = execFileSync("aptos", [...recordArgs, "--profile", profile], { encoding: "utf8" });
  const j = out.slice(out.indexOf("{"));
  try { recordTx = JSON.parse(j).Result?.transaction_hash ?? null; } catch { recordTx = null; }
}

process.stdout.write(JSON.stringify({
  ok: true,
  rootHex: r.rootHex,
  depth: r.depth,
  cid: r.cid,
  ipfsSource: r.ipfsSource,
  approvedCount: r.approved.length,
  revokedCount: r.revoked.length,
  rejectedNewCount: r.rejectedNew.length,
  aspSetFile: aspSetPath,
  recordArgs,
  recordTx,
}, null, 2) + "\n");

// CLI: exit cleanly even if the KYT provider's HTTP keep-alive socket (undici global agent)
// would otherwise hold the event loop open.
process.exit(0);
