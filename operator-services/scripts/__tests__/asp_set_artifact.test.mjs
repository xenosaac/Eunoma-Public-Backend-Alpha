// Test: scripts/local_run_asp_cycle.mjs writes the PUBLIC asp_set.json the coordinator serves at
// /v2/asp-set + /v2/asp-root-current.
//
// Hermetic: the production ChainalysisSanctionsProvider really executes HTTP, so we point it at a
// local fake sanctions API (via CHAINALYSIS_SANCTIONS_BASE_URL) that returns "clean" for every
// address. IPFS falls back to the LocalDevPublisher when no PINATA_JWT/WEB3_STORAGE_TOKEN is set
// (no network). This exercises the real provider + cycle wiring without touching live services.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "local_run_asp_cycle.mjs");
const cm = (s) => "0x" + s.padStart(64, "0");

const { LocalDevPublisher } = await import(
  `file://${resolve(dirname(fileURLToPath(import.meta.url)), "..", "ipfs_publisher.mjs")}`
);

// Spin up a fake Chainalysis sanctions API that returns clean (empty identifications) for all.
function startFakeSanctionsApi() {
  return new Promise((resolveServer) => {
    const sockets = new Set();
    const server = createServer((req, res) => {
      // GET /address/{addr} → { identifications: [] } == not sanctioned.
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify({ identifications: [] }));
    });
    server.on("connection", (s) => {
      sockets.add(s);
      s.on("close", () => sockets.delete(s));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolveServer({ server, sockets, baseUrl: `http://127.0.0.1:${port}/api/v1` });
    });
  });
}

// Force-close any lingering keep-alive sockets so server.close() resolves promptly.
function stopServer({ server, sockets }) {
  for (const s of sockets) s.destroy();
  return new Promise((res) => server.close(res));
}

function startFakeAptosTxApi({ rootLog }) {
  return new Promise((resolveServer) => {
    const sockets = new Set();
    const server = createServer((req, res) => {
      if (req.method === "GET" && /^\/v1\/transactions\/by_hash\/0x[0-9a-fA-F]+$/.test(req.url || "")) {
        const root = existsSync(rootLog) ? readFileSync(rootLog, "utf8").trim() : cm("0");
        res.writeHead(200, { "content-type": "application/json", connection: "close" });
        res.end(JSON.stringify({
          type: "user_transaction",
          success: true,
          vm_status: "Executed successfully",
          version: "123",
          events: [
            {
              type: "0xbridge::eunoma_bridge::ASPRootRecorded",
              data: { root, ipfs_cid: "local-test-cid" },
            },
          ],
        }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify({ message: "not found" }));
    });
    server.on("connection", (s) => {
      sockets.add(s);
      s.on("close", () => sockets.delete(s));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolveServer({ server, sockets, baseUrl: `http://127.0.0.1:${port}/v1` });
    });
  });
}

// Async spawn (NOT spawnSync): the subprocess calls back into the fake sanctions HTTP server that
// runs in THIS process's event loop, so the main thread must stay free to answer it.
function run(args, env = {}) {
  return new Promise((resolveRun) => {
    const child = spawn("node", [SCRIPT, ...args], { env: { ...process.env, ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (status) => resolveRun({ status, stdout, stderr }));
  });
}

test("local_run_asp_cycle writes <stateDir>/coordinator/asp_set.json with the served shape", async () => {
  const srv = await startFakeSanctionsApi();
  const { server, baseUrl } = srv;
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-"));
  try {
    const statePath = join(tmp, "asp_state.json");
    const newDepositsPath = join(tmp, "new_deposits.json");
    writeFileSync(statePath, JSON.stringify({ approved: [] }));
    writeFileSync(
      newDepositsPath,
      JSON.stringify([
        { commitment: cm("c1"), sender: "0xcleanA" },
        { commitment: cm("c2"), sender: "0xcleanB" },
        { commitment: cm("c3"), sender: "0xcleanC" },
      ]),
    );

    const r = await run(
      ["--state", statePath, "--new-deposits", newDepositsPath, "--state-dir", tmp],
      { CHAINALYSIS_API_KEY: "test-key", CHAINALYSIS_SANCTIONS_BASE_URL: baseUrl },
    );
    assert.equal(r.status, 0, r.stderr);

    const aspPath = join(tmp, "coordinator", "asp_set.json");
    assert.ok(existsSync(aspPath), "asp_set.json written under <stateDir>/coordinator");
    const artifact = JSON.parse(readFileSync(aspPath, "utf8"));

    // Shape the coordinator maps to { aspRootHex, aspTreeDepth, ipfsCid, commitments }.
    assert.equal(artifact.scheme, "eunoma_asp_set_v1");
    assert.match(artifact.rootHex, /^0x[0-9a-f]{64}$/);
    assert.equal(typeof artifact.treeDepth, "number");
    assert.ok(Array.isArray(artifact.commitments));
    assert.equal(artifact.commitments.length, 3);
    for (const c of artifact.commitments) assert.match(c, /^0x[0-9a-f]{64}$/);
    assert.equal(typeof artifact.ipfsCid, "string");

    // No secret-shaped fields leaked into the public artifact.
    const flat = JSON.stringify(artifact);
    assert.doesNotMatch(flat, /secret|nullifier|_blind|"amount"|"dk"/i);

    // stdout reports the path it wrote.
    const out = JSON.parse(r.stdout.slice(r.stdout.indexOf("{")));
    assert.equal(out.aspSetFile, aspPath);

    // CP5 RC6(A): a HISTORY snapshot keyed by root hex is also written, so the coordinator's
    // GET /v2/asp-set/at/:rootHex can serve this exact set inside the ASP_ROOT_TTL window.
    const rootBare = artifact.rootHex.replace(/^0x/i, "").toLowerCase();
    const histPath = join(tmp, "coordinator", "asp_set_history", `${rootBare}.json`);
    assert.ok(existsSync(histPath), "asp_set_history/<rootHex>.json written under <stateDir>");
    const hist = JSON.parse(readFileSync(histPath, "utf8"));
    assert.equal(hist.rootHex, artifact.rootHex, "history snapshot is the same root");
    assert.deepEqual(hist.commitments, artifact.commitments, "history snapshot carries the set");
    assert.equal(typeof hist.updatedAtUnix, "number", "history snapshot carries the record time");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(srv);
  }
});

test("local_run_asp_cycle --asp-set-out wins over --state-dir", async () => {
  const srv = await startFakeSanctionsApi();
  const { server, baseUrl } = srv;
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-out-"));
  try {
    const statePath = join(tmp, "asp_state.json");
    writeFileSync(statePath, JSON.stringify({ approved: [] }));
    const explicit = join(tmp, "explicit_asp.json");
    const r = await run(
      ["--state", statePath, "--state-dir", tmp, "--asp-set-out", explicit],
      { CHAINALYSIS_API_KEY: "test-key", CHAINALYSIS_SANCTIONS_BASE_URL: baseUrl },
    );
    assert.equal(r.status, 0, r.stderr);
    assert.ok(existsSync(explicit));
    assert.ok(!existsSync(join(tmp, "coordinator", "asp_set.json")));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(srv);
  }
});

// ── OB6: LocalDevPublisher keeps the "local-" prefix + testnet-alpha caveat ─────────────────────
// The dev fallback CID must be unmistakably NOT a real IPFS pin: "local-" prefix + an explicit
// testnet-alpha caveat. The on-chain ASP root may reference this CID on alpha; mainnet must set a
// real pin token. This guards against the prefix/caveat silently regressing.
test("OB6: LocalDevPublisher returns a 'local-' CID + testnet-alpha caveat (never mistaken for a pin)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "asp-localpub-"));
  try {
    const pub = new LocalDevPublisher({ dir: tmp });
    const { cid, source, caveat } = await pub.publish({ scheme: "eunoma_asp_set_v1", commitments: [cm("c1")] });
    assert.ok(cid.startsWith("local-"), "dev fallback CID is prefixed 'local-' (NOT a real IPFS pin)");
    assert.doesNotMatch(cid, /^(bafy|Qm)/, "must not look like a real CIDv0/CIDv1");
    assert.equal(source, "local-dev-fallback");
    assert.match(caveat, /testnet-alpha/i, "carries the explicit testnet-alpha caveat");
    assert.match(caveat, /PINATA_JWT/, "caveat tells the operator how to get a real pin");
    assert.ok(existsSync(join(tmp, `${cid}.json`)), "wrote the set locally (content-addressed)");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("local_run_asp_cycle --record invokes aptos from operator-services cwd", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-record-"));
  const node = await startFakeAptosTxApi({ rootLog: join(tmp, "aptos-root.txt") });
  try {
    const statePath = join(tmp, "asp_state.json");
    const fakeBin = join(tmp, "bin");
    const cwdLog = join(tmp, "aptos-cwd.txt");
    const rootLog = join(tmp, "aptos-root.txt");
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(statePath, JSON.stringify({ approved: [] }));
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
pwd > "${cwdLog}"
for arg in "$@"; do
  if [[ "$arg" == hex:0x* ]]; then
    printf "%s" "\${arg#hex:}" > "${rootLog}"
    break
  fi
done
cat <<'JSON'
{
  "Result": {
    "transaction_hash": "0x1111111111111111111111111111111111111111111111111111111111111111"
  }
}
JSON
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const r = await run(
      ["--state", statePath, "--bridge", "0xbridge", "--record"],
      {
        CHAINALYSIS_API_KEY: "test-key",
        APTOS_NODE_URL: node.baseUrl,
        PATH: `${fakeBin}:${process.env.PATH}`,
        EUNOMA_ASP_RECORDER_PROFILE: "test-profile",
      },
    );
    assert.equal(r.status, 0, r.stderr);
    assert.equal(realpathSync(readFileSync(cwdLog, "utf8").trim()), realpathSync(resolve(dirname(SCRIPT), "..")));
    const out = JSON.parse(r.stdout.slice(r.stdout.indexOf("{")));
    assert.equal(out.recordTx, "0x1111111111111111111111111111111111111111111111111111111111111111");
    assert.equal(out.recordStatus, "recorded");
    assert.ok(existsSync(out.recordSidecar), "record sidecar written after confirmed ASP root record");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(node);
  }
});

test("local_run_asp_cycle --record honors APTOS_CLI_CWD", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-record-cwd-"));
  const node = await startFakeAptosTxApi({ rootLog: join(tmp, "aptos-root.txt") });
  try {
    const statePath = join(tmp, "asp_state.json");
    const fakeBin = join(tmp, "bin");
    const aptosCwd = join(tmp, "aptos-cwd");
    const cwdLog = join(tmp, "aptos-cwd.txt");
    const rootLog = join(tmp, "aptos-root.txt");
    mkdirSync(fakeBin, { recursive: true });
    mkdirSync(aptosCwd, { recursive: true });
    writeFileSync(statePath, JSON.stringify({ approved: [] }));
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
pwd > "${cwdLog}"
for arg in "$@"; do
  if [[ "$arg" == hex:0x* ]]; then
    printf "%s" "\${arg#hex:}" > "${rootLog}"
    break
  fi
done
cat <<'JSON'
{
  "Result": {
    "transaction_hash": "0x2222222222222222222222222222222222222222222222222222222222222222"
  }
}
JSON
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const r = await run(
      ["--state", statePath, "--bridge", "0xbridge", "--record"],
      {
        APTOS_CLI_CWD: aptosCwd,
        CHAINALYSIS_API_KEY: "test-key",
        APTOS_NODE_URL: node.baseUrl,
        PATH: `${fakeBin}:${process.env.PATH}`,
        EUNOMA_ASP_RECORDER_PROFILE: "test-profile",
      },
    );
    assert.equal(r.status, 0, r.stderr);
    assert.equal(realpathSync(readFileSync(cwdLog, "utf8").trim()), realpathSync(aptosCwd));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(node);
  }
});

test("local_run_asp_cycle --record fails hard when aptos output has no transaction hash", async () => {
  const srv = await startFakeSanctionsApi();
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-record-nohash-"));
  try {
    const statePath = join(tmp, "asp_state.json");
    const newDepositsPath = join(tmp, "new_deposits.json");
    const fakeBin = join(tmp, "bin");
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(statePath, JSON.stringify({ approved: [] }, null, 2));
    writeFileSync(newDepositsPath, JSON.stringify([{ commitment: cm("c9"), sender: "0xcleanA" }]));
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
cat <<'JSON'
{
  "Result": {
    "status": "accepted_without_hash"
  }
}
JSON
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const r = await run(
      [
        "--state", statePath,
        "--new-deposits", newDepositsPath,
        "--state-dir", tmp,
        "--bridge", "0xbridge",
        "--record",
      ],
      {
        CHAINALYSIS_API_KEY: "test-key",
        CHAINALYSIS_SANCTIONS_BASE_URL: srv.baseUrl,
        PATH: `${fakeBin}:${process.env.PATH}`,
        EUNOMA_ASP_RECORDER_PROFILE: "test-profile",
      },
    );
    assert.notEqual(r.status, 0, "record mode exits non-zero without a tx hash");
    assert.match(r.stderr, /transaction_hash/i);
    assert.ok(!existsSync(join(tmp, "coordinator", "asp_set.json")), "does not publish asp_set.json");
    assert.deepEqual(JSON.parse(readFileSync(statePath, "utf8")), { approved: [] }, "does not mutate approved state");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(srv);
  }
});

// ── OB6: the cycle threads CHANGE notes into the pinned LABEL-set + records cid+rootHex ──────────
// End-to-end through local_run_asp_cycle.mjs: a partial-withdraw change note is merged by LABEL
// INHERITANCE (no screenAddress), the pinned artifact carries the LABEL-set (labels +
// labelByCommitment), and the cycle emits the asp-recorder delegate record args (cid+rootHex).
test("OB6: cycle merges a change note by label + pins the LABEL-set + emits delegate record args", async () => {
  const srv = await startFakeSanctionsApi();
  const tmp = mkdtempSync(join(tmpdir(), "asp-cycle-chg-"));
  try {
    const { baseUrl } = srv;
    const parentLabel = cm("lab0");
    const parentCommitment = cm("p0");

    // Epoch 1: approve the parent deposit (sender screened clean).
    const statePath = join(tmp, "asp_state.json");
    writeFileSync(statePath, JSON.stringify({ approved: [] }));
    const e1Deposits = join(tmp, "e1_deposits.json");
    writeFileSync(e1Deposits, JSON.stringify([{ commitment: parentCommitment, sender: "0xdepA", label: parentLabel }]));
    const r1 = await run(
      ["--state", statePath, "--new-deposits", e1Deposits, "--state-dir", tmp],
      { CHAINALYSIS_API_KEY: "test-key", CHAINALYSIS_SANCTIONS_BASE_URL: baseUrl },
    );
    assert.equal(r1.status, 0, r1.stderr);

    // Epoch 2: a change note inherits the parent label; cycle records via the delegate (prints args).
    const changeNotesPath = join(tmp, "e2_changes.json");
    writeFileSync(changeNotesPath, JSON.stringify([{ commitment: cm("chg0"), label: parentLabel, parentCommitment }]));
    const r2 = await run(
      ["--state", statePath, "--change-notes", changeNotesPath, "--state-dir", tmp, "--bridge", "0xbridge"],
      { CHAINALYSIS_API_KEY: "test-key", CHAINALYSIS_SANCTIONS_BASE_URL: baseUrl },
    );
    assert.equal(r2.status, 0, r2.stderr);
    const out2 = JSON.parse(r2.stdout.slice(r2.stdout.indexOf("{")));

    // Change note entered (inherited), nothing rejected, and the LABEL-set was pinned.
    assert.equal(out2.approvedCount, 2, "parent + change note in approved set");
    assert.equal(out2.changeNotesRejectedCount, 0, "change note merged by inheritance (parent label live)");
    assert.equal(out2.labelCount, 1, "the deposit-scoped LABEL is the pinned approval unit (1 label, 2 commitments)");
    assert.match(out2.rootHex, /^0x[0-9a-f]{64}$/);
    assert.ok(typeof out2.cid === "string" && out2.cid.length > 0, "pinned to IPFS → cid");

    // The cycle emits the LOW-PRIV asp-recorder delegate record call carrying cid+rootHex.
    assert.ok(Array.isArray(out2.recordArgs), "delegate record args emitted");
    assert.ok(out2.recordArgs.some((a) => String(a).includes("record_asp_root_via_delegate")),
      "records via the low-priv asp-recorder delegate");

    // The pinned artifact carries the LABEL-set: parent + change share ONE label.
    const artifact = JSON.parse(readFileSync(join(tmp, "coordinator", "asp_set.json"), "utf8"));
    assert.ok(Array.isArray(artifact.labels) && artifact.labels.includes(parentLabel.toLowerCase()),
      "pinned LABEL-set includes the deposit-scoped label");
    assert.equal(artifact.labelByCommitment[cm("chg0").toLowerCase()], parentLabel.toLowerCase(),
      "change-note commitment maps to its parent's label");
    assert.equal(artifact.labelByCommitment[parentCommitment.toLowerCase()], parentLabel.toLowerCase(),
      "parent commitment maps to the same label");
    // Still no secrets in the public set.
    assert.doesNotMatch(JSON.stringify(artifact), /secret|nullifier|_blind|"amount"|"dk"/i);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
    await stopServer(srv);
  }
});
