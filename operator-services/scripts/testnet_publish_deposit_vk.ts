// Publish deposit-binding VK + prepared deposit-binding VK to the target
// deploy's bridge. State-persisting replacement for the deleted
// testnet_publish_vk.sh (also subsumes the previously-missing prepared-VK
// shell — both VKs publish in one run).
//
// Env requirements:
//   PROFILE            Aptos CLI profile that owns BRIDGE_ADDR
//   EUNOMA_DEPLOY_ID   Target deploy slot in testnet_state.json
//
// Reads:  circuits/generated/move_fixtures/vk_bytes.json (DEPOSIT VK, IC=5).
//         WITHDRAW VK is not handled here — see testnet_init_withdraw.ts.
//
// Writes (per tx):
//   deploys.<target>.vk.publish_deposit_binding_vk_tx | _gas
//   deploys.<target>.vk.publish_prepared_deposit_binding_vk_tx | _gas
//
// Aptos CLI note: `aptos move run` does NOT support --json-output-file.
// Capture stdout via execSync + parse the first '{' onwards.

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { targetBridge, targetDeployId, updateTargetDeploy } from './_lib/state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VK_FILE = path.join(REPO_ROOT, 'circuits/generated/move_fixtures/vk_bytes.json');

const PROFILE = process.env.PROFILE;
if (!PROFILE) throw new Error('PROFILE env var required');

const BRIDGE_ADDR = targetBridge();
const DEPLOY_ID = targetDeployId();
console.log(`[publish_deposit_vk] target deploy=${DEPLOY_ID} bridge=${BRIDGE_ADDR} profile=${PROFILE}`);

const vk = JSON.parse(fs.readFileSync(VK_FILE, 'utf-8'));
if (!Array.isArray(vk.ic) || vk.ic.length !== 5) {
  throw new Error(
    `expected deposit VK with 5 IC slots (matches publish_deposit_binding_vk's ic_0..ic_4); got ${vk.ic?.length}`,
  );
}

function runEntry(
  funcId: string,
  hexArgs: string[],
): { tx: string; gas_used: number; gas_unit_price: number } {
  const args = hexArgs.map((h) => `"hex:${h}"`).join(' ');
  const cmd =
    `aptos move run --profile ${PROFILE} --function-id "${funcId}" ${args ? `--args ${args}` : ''} ` +
    `--max-gas 200000 --assume-yes`;
  console.log(`\n[run] $ ${cmd}`);
  const stdout = execSync(cmd, { encoding: 'utf-8' });
  process.stdout.write(stdout);

  const jsonStart = stdout.indexOf('{');
  if (jsonStart === -1) throw new Error(`no JSON in run stdout:\n${stdout.slice(-800)}`);
  const r = JSON.parse(stdout.slice(jsonStart));
  const t = r?.Result;
  if (!t || t.success !== true) {
    throw new Error(
      `run failed: vm_status=${t?.vm_status ?? 'n/a'} body=${JSON.stringify(r).slice(0, 400)}`,
    );
  }
  return {
    tx: t.transaction_hash,
    gas_used: Number(t.gas_used),
    gas_unit_price: Number(t.gas_unit_price ?? 100),
  };
}

// 1/2 — publish_deposit_binding_vk(alpha_g1, beta_g2, gamma_g2, delta_g2, ic_0..ic_4)
const depositPub = runEntry(
  `${BRIDGE_ADDR}::eunoma_bridge::publish_deposit_binding_vk`,
  [vk.alpha_g1, vk.beta_g2, vk.gamma_g2, vk.delta_g2, ...vk.ic],
);
updateTargetDeploy((d) => {
  d.vk ??= {};
  d.vk.publish_deposit_binding_vk_tx = depositPub.tx;
  d.vk.publish_deposit_binding_vk_gas = depositPub.gas_used;
});
console.log(`[publish_deposit_vk] tx=${depositPub.tx} gas=${depositPub.gas_used}`);

// 2/2 — publish_prepared_deposit_binding_vk() (no args; reads stored VK on chain)
const prepared = runEntry(
  `${BRIDGE_ADDR}::eunoma_bridge::publish_prepared_deposit_binding_vk`,
  [],
);
updateTargetDeploy((d) => {
  d.vk ??= {};
  d.vk.publish_prepared_deposit_binding_vk_tx = prepared.tx;
  d.vk.publish_prepared_deposit_binding_vk_gas = prepared.gas_used;
});
console.log(`[publish_prepared_deposit_vk] tx=${prepared.tx} gas=${prepared.gas_used}`);

console.log(`\n[publish_deposit_vk] state persisted to deploys.${DEPLOY_ID}.vk.*`);
