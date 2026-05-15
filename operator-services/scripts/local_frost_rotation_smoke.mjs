#!/usr/bin/env node
// Full FROST rotation propagation gate.
//
// Flow:
//   1. Spawn the 7-node + 7-worker + coordinator + relayer cluster.
//   2. Capture seeded frostGroupPubkey from the in-memory plan.
//   3. Run local_frost_dkg_v2.mjs as a child process — produces artifact + rotated
//      frost_key_package.json on disk per slot.
//   4. Run local_frost_rotation_apply.mjs as a child process — rewrites env files
//      atomically with the rotated DeoperatorRoster (new rosterHash, dkgEpoch+1,
//      new frostGroupPubkey, rotated frostVerifyingShares).
//   5. Restart coordinator + 7 nodes via the shared spawnCluster handle. Workers
//      stay alive (they already have rotated key material on disk).
//   6. Wait for coordinator /v2/health, confirm rosterHash matches the rotated
//      hash from step 4.
//   7. Drive a 5-of-7 FROST sign across workers 0..4 directly on loopback
//      (deoperator-node does not forward FROST signing). The aggregate step
//      internally verifies the produced signature against the rotated
//      frost_public_package.json — that on its own proves the rotated key works.
//   8. Externally re-verify the same signature with @noble/ed25519 against
//      the rotated group pubkey (must succeed) and against the seeded group
//      pubkey (must fail).
//
// Test message: keccak256(b"eunoma-rotation-smoke-v1"), stable and witness-free.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha3_256 } from "@eunoma/shared";
import { sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { spawnCluster } from "./_lib/spawn_cluster.mjs";

ed.hashes.sha512 = sha512;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const clusterDir = resolve(stateRoot, "cluster");
const planPath = resolve(clusterDir, "local-cluster.json");

if (!existsSync(planPath)) {
  console.error("local cluster config not found. Run `npm run local:cluster:config -- --force` first.");
  process.exit(2);
}

// Wipe stale per-slot DKG session state — these accumulate across runs and break round2.
for (let slot = 0; slot < 7; slot += 1) {
  const dkgDir = resolve(stateRoot, `slot-${slot}/frost_dkg_v2`);
  if (existsSync(dkgDir)) {
    const inner = readdirSync(dkgDir);
    for (const name of inner) {
      removeRecursive(resolve(dkgDir, name));
    }
  }
}

const initialPlan = JSON.parse(readFileSync(planPath, "utf8"));
const seededGroupPubkey = initialPlan.roster.frostGroupPubkey;
const seededRosterHash = initialPlan.rosterHash;

console.log(`smoke: starting cluster with seeded rosterHash=${seededRosterHash} groupPubkey=${seededGroupPubkey}`);

const handle = spawnCluster(initialPlan, {
  log: (name, line) => {
    // keep verbose worker output out of the smoke transcript by default
    if (!process.env.SMOKE_VERBOSE && /eslintignore-noop/.test(name)) return;
    if (process.env.SMOKE_VERBOSE) console.log(`[${name}] ${line}`);
  },
});

let exitCode = 1;
try {
  await waitForHealth(`http://127.0.0.1:${initialPlan.coordinator.port}`, 60_000);
  for (const node of initialPlan.nodes) {
    await waitForHealth(`http://127.0.0.1:${node.port}`, 60_000, "/deop/v2/health");
  }
  for (const worker of initialPlan.workers) {
    await waitForWorker(`http://127.0.0.1:${worker.port}`, 60_000);
  }
  console.log("smoke: cluster up; running FROST DKG to produce rotation artifact");

  const requestId = `rotation-smoke-${Date.now()}`;
  const dkg = spawnSync(process.execPath, [resolve(scriptDir, "local_frost_dkg_v2.mjs")], {
    cwd: serviceRoot,
    env: { ...process.env, REQUEST_ID: requestId },
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  if (dkg.status !== 0) {
    process.stderr.write(dkg.stderr || "");
    process.stdout.write(dkg.stdout || "");
    throw new Error(`local_frost_dkg_v2.mjs failed with status ${dkg.status}`);
  }
  const artifactPath = resolve(clusterDir, `frost_dkg/${requestId}.json`);
  if (!existsSync(artifactPath)) {
    throw new Error(`expected DKG artifact at ${artifactPath} not found`);
  }
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  console.log(`smoke: DKG complete; artifact at ${artifactPath}; new groupPubkey=${artifact.groupPublicKey}`);

  console.log("smoke: running rotation apply (rewriting env files atomically)");
  const apply = spawnSync(
    process.execPath,
    [resolve(scriptDir, "local_frost_rotation_apply.mjs"), "--dkg-artifact", artifactPath],
    {
      cwd: serviceRoot,
      env: process.env,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (apply.status !== 0) {
    process.stderr.write(apply.stderr || "");
    process.stdout.write(apply.stdout || "");
    throw new Error(`local_frost_rotation_apply.mjs failed with status ${apply.status}`);
  }
  const rotatedPlan = JSON.parse(readFileSync(planPath, "utf8"));
  const rotatedRosterHash = rotatedPlan.rosterHash;
  const rotatedGroupPubkey = rotatedPlan.roster.frostGroupPubkey;
  if (rotatedRosterHash === seededRosterHash) {
    throw new Error("apply did not change rosterHash — propagation broken");
  }
  if (rotatedGroupPubkey === seededGroupPubkey) {
    throw new Error("apply did not change frostGroupPubkey — propagation broken");
  }
  console.log(`smoke: apply complete; rotated rosterHash=${rotatedRosterHash} rotated groupPubkey=${rotatedGroupPubkey}`);

  console.log("smoke: restarting coordinator + 7 nodes with rotated env files (workers stay alive)");
  await handle.restartCoordinatorAndNodes(rotatedPlan);
  await waitForHealth(`http://127.0.0.1:${rotatedPlan.coordinator.port}`, 60_000);
  for (const node of rotatedPlan.nodes) {
    await waitForHealth(`http://127.0.0.1:${node.port}`, 60_000, "/deop/v2/health");
  }
  const health = await fetchJson(`http://127.0.0.1:${rotatedPlan.coordinator.port}/v2/health`);
  if (health.rosterHash !== rotatedRosterHash) {
    throw new Error(
      `coordinator /v2/health rosterHash=${health.rosterHash} != rotated rosterHash=${rotatedRosterHash}`,
    );
  }
  console.log(`smoke: coordinator /v2/health rosterHash=${health.rosterHash} matches rotated hash`);

  console.log("smoke: driving 5-of-7 FROST sign across workers 0..4 directly");
  const messageBytes = bytesToHex(sha3_256(new TextEncoder().encode("eunoma-rotation-smoke-v1")));
  const quorumSlots = [0, 1, 2, 3, 4];
  const nonceCommits = [];
  for (const slot of quorumSlots) {
    const url = `http://127.0.0.1:${rotatedPlan.workers[slot].port}/worker/v2/frost/sign/nonce-commit`;
    const result = await postJson(url, { requestId });
    nonceCommits.push({ slot, ...result });
  }
  const commitments = nonceCommits.map((nc) => ({ slot: nc.slot, commitments: nc.commitments }));
  const signatureShares = [];
  for (const nc of nonceCommits) {
    const url = `http://127.0.0.1:${rotatedPlan.workers[nc.slot].port}/worker/v2/frost/sign/partial`;
    const partial = await postJson(url, {
      nonceId: nc.nonce_id,
      messageBytes,
      commitments,
    });
    signatureShares.push({ slot: nc.slot, signatureShare: partial.signature_share });
  }
  const aggregateUrl = `http://127.0.0.1:${rotatedPlan.workers[0].port}/worker/v2/frost/sign/aggregate`;
  const aggregate = await postJson(aggregateUrl, {
    messageBytes,
    commitments,
    signatureShares,
  });
  const signatureHex = aggregate.signature;
  if (!/^[0-9a-f]{128}$/i.test(signatureHex)) {
    throw new Error(`worker aggregate returned non-64-byte signature: ${signatureHex}`);
  }
  console.log(`smoke: 5-of-7 aggregate signature produced (64 bytes); worker self-verified during aggregate`);

  const sigBytes = hexToU8(signatureHex);
  const msgBytes = hexToU8(messageBytes);
  const rotatedPubBytes = hexToU8(rotatedGroupPubkey);
  const seededPubBytes = hexToU8(seededGroupPubkey);

  const verifyRotated = ed.verify(sigBytes, msgBytes, rotatedPubBytes);
  if (!verifyRotated) {
    throw new Error("@noble/ed25519 verify against rotated groupPubkey returned false — propagation broken");
  }
  console.log("smoke: external ed25519 verify against rotated groupPubkey = PASS");

  const verifySeeded = ed.verify(sigBytes, msgBytes, seededPubBytes);
  if (verifySeeded) {
    throw new Error("@noble/ed25519 verify against SEEDED groupPubkey returned true — keys did not actually rotate");
  }
  console.log("smoke: external ed25519 verify against seeded groupPubkey = FAIL (as expected)");

  console.log("");
  console.log("============================================================");
  console.log("  FROST ROTATION PROPAGATION SMOKE: PASS");
  console.log("============================================================");
  console.log(`  seeded rosterHash:      ${seededRosterHash}`);
  console.log(`  rotated rosterHash:     ${rotatedRosterHash}`);
  console.log(`  seeded groupPubkey:     ${seededGroupPubkey}`);
  console.log(`  rotated groupPubkey:    ${rotatedGroupPubkey}`);
  console.log(`  sign(rotated-pubkey):   PASS`);
  console.log(`  sign(seeded-pubkey):    FAIL (as expected)`);
  console.log("============================================================");
  exitCode = 0;
} catch (err) {
  console.error(`smoke FAILED: ${err.message}`);
  if (err.stack) console.error(err.stack);
} finally {
  handle.kill();
  setTimeout(() => process.exit(exitCode), 500).unref();
}

async function waitForHealth(baseUrl, timeoutMs, path = "/v2/health") {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(new URL(path, baseUrl), { method: "GET" });
      if (res.ok) {
        try {
          return await res.json();
        } catch {
          return { ok: true };
        }
      }
    } catch (err) {
      lastErr = err;
    }
    await sleep(200);
  }
  throw new Error(`timed out waiting for ${baseUrl}${path}: ${lastErr?.message ?? "no response"}`);
}

async function waitForWorker(baseUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(new URL("/worker/v2/health", baseUrl), { method: "GET" });
      if (res.ok || res.status === 404 || res.status === 405) return true;
      // Also accept 400 from nonce-commit smoke probe — any HTTP response means it's listening
    } catch (err) {
      lastErr = err;
      try {
        const probe = await fetch(new URL("/worker/v2/frost/sign/nonce-commit", baseUrl), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        });
        if (probe.status >= 200 && probe.status < 500) return true;
      } catch (_) {
        // keep waiting
      }
    }
    await sleep(200);
  }
  throw new Error(`timed out waiting for worker ${baseUrl}: ${lastErr?.message ?? "no response"}`);
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`POST ${url} -> ${res.status}: ${text}`);
  return JSON.parse(text);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function hexToU8(hex) {
  const clean = hex.replace(/^0x/i, "").toLowerCase();
  if (clean.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function removeRecursive(path) {
  if (!existsSync(path)) return;
  try {
    rmSync(path, { recursive: true, force: true });
  } catch (_) {
    // ignore — caller has bigger problems if this matters
  }
}
