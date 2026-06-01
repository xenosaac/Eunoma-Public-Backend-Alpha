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
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "local_run_asp_cycle.mjs");
const cm = (s) => "0x" + s.padStart(64, "0");

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
