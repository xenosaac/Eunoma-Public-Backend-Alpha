// Publish `eunoma_pool` (poseidon_local) then `eunoma_bridge` to the target
// deploy's bridge address. State-persisting replacement for the deleted
// testnet_publish_bridge.sh.
//
// Env requirements:
//   PROFILE            Aptos CLI profile that owns BRIDGE_ADDR (e.g. eunoma-blocker1-l2-admin)
//   EUNOMA_DEPLOY_ID   Target deploy slot in testnet_state.json
//                      (e.g. blocker1_l2_2026_05_12)
//
// The target slot's bridge_addr must already be populated in testnet_state.json
// before this script runs (user pastes the address after `aptos init`).
//
// Each successful publish writes:
//   deploys.<target>.publishes.{poseidon_local,eunoma_bridge} = {tx, gas_used, gas_unit_price, address}
//
// Aptos CLI note: `aptos move publish` does NOT support --json-output-file.
// The JSON Result is printed to stdout (after any preamble text); we capture
// stdout via execSync + parse the first '{' onwards. Mirrors the parser used
// by operator-services/scripts/testnet_init_vault.ts.

import { execSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  targetBridge,
  targetDeployId,
  updateTargetDeploy,
} from './_lib/state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

const PROFILE = process.env.PROFILE;
if (!PROFILE) throw new Error('PROFILE env var required (e.g. eunoma-blocker1-l2-admin)');

const BRIDGE_ADDR = targetBridge(); // throws if target slot missing bridge_addr
const DEPLOY_ID = targetDeployId();
console.log(`[publish] target deploy=${DEPLOY_ID} bridge=${BRIDGE_ADDR} profile=${PROFILE}`);

function publishPackage(
  packageDir: string,
  namedAddresses: string,
): { tx: string; gas_used: number; gas_unit_price: number } {
  const cmd =
    `aptos move publish --profile ${PROFILE} --package-dir "${packageDir}" ` +
    `--included-artifacts none --assume-yes ` +
    `--max-gas 1500000 --named-addresses "${namedAddresses}"`;
  console.log(`\n[publish] $ ${cmd}  (cwd=${REPO_ROOT})`);
  const stdout = execSync(cmd, { encoding: 'utf-8', cwd: REPO_ROOT });
  process.stdout.write(stdout);

  const jsonStart = stdout.indexOf('{');
  if (jsonStart === -1) {
    throw new Error(`no JSON in publish stdout:\n${stdout.slice(-800)}`);
  }
  const r = JSON.parse(stdout.slice(jsonStart));
  const t = r?.Result;
  if (!t || t.success !== true) {
    throw new Error(
      `publish failed: vm_status=${t?.vm_status ?? 'n/a'} body=${JSON.stringify(r).slice(0, 400)}`,
    );
  }
  return {
    tx: t.transaction_hash,
    gas_used: Number(t.gas_used),
    gas_unit_price: Number(t.gas_unit_price ?? 100),
  };
}

// 1/2 — eunoma_pool (poseidon_local copy)
const poseidon = publishPackage(
  path.join(REPO_ROOT, 'move', 'poseidon_local'),
  `eunoma_pool=${BRIDGE_ADDR}`,
);
updateTargetDeploy((d) => {
  d.publishes ??= {};
  d.publishes.poseidon_local = { ...poseidon, address: BRIDGE_ADDR };
});
console.log(`[publish] poseidon_local tx=${poseidon.tx} gas=${poseidon.gas_used}`);

// 2/2 — eunoma_bridge (depends on eunoma_pool)
const bridge = publishPackage(
  path.join(REPO_ROOT, 'move'),
  `eunoma=${BRIDGE_ADDR},eunoma_pool=${BRIDGE_ADDR}`,
);
updateTargetDeploy((d) => {
  d.publishes ??= {};
  d.publishes.eunoma_bridge = { ...bridge, address: BRIDGE_ADDR };
});
console.log(`[publish] eunoma_bridge tx=${bridge.tx} gas=${bridge.gas_used}`);
console.log(`\n[publish] state persisted to deploys.${DEPLOY_ID}.publishes.*`);
