// testnet_state.json helpers — multi-deploy schema with separated
// "active" vs "target" selectors (see plan-for-this-frolicking-wilkes.md
// Phase 1 P1.1).
//
// Resolution order:
//   - EUNOMA_STATE_PATH env → operator-services/scripts/testnet_state.json
//   - No hardcoded fallback to a literal bridge address anywhere.
//
// Active vs target:
//   - active = current production deploy (what runtime operators chain-read);
//     selected by state.active_deploy
//   - target = the deploy id redeploy scripts read/write while standing up a
//     new bridge; selected by EUNOMA_DEPLOY_ID env, defaulting to
//     state.active_deploy when unset
//
// During a fresh-address redeploy run, every command must set
//   EUNOMA_DEPLOY_ID=<new-deploy-id>
// so publish + init txns and state writes route to the new slot. active_deploy
// flips ONCE, at the cutover step, via flipActiveDeploy().

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PATH = path.resolve(__dirname, '..', 'testnet_state.json');

export interface DeployRecord {
  bridge_addr: string;
  admin_address: string;
  publish_date: string;
  note?: string;
  publishes?: Record<string, any>;
  vk?: Record<string, any>;
  vault?: Record<string, any>;
  user_ca?: Record<string, any>;
  recipient_ca?: Record<string, any>;
  deposits?: any[];
  deposit?: Record<string, any>;
  withdraw?: Record<string, any>;
  // Open shape — scripts may attach additional sub-objects (operator set,
  // root history, etc.) without a schema bump.
  [k: string]: any;
}

export interface TestnetState {
  active_deploy: string;
  network: 'testnet' | 'mainnet';
  chain_id: number;
  deploys: Record<string, DeployRecord>;
  // tolerate legacy top-level keys during the migration window; readers and
  // writers never touch them.
  [k: string]: any;
}

function statePath(): string {
  return process.env.EUNOMA_STATE_PATH ?? DEFAULT_PATH;
}

export function loadState(): TestnetState {
  return JSON.parse(fs.readFileSync(statePath(), 'utf-8'));
}

export function saveState(s: TestnetState): void {
  fs.writeFileSync(statePath(), JSON.stringify(s, null, 2) + '\n');
}

export function activeDeployId(): string {
  return loadState().active_deploy;
}

/**
 * Target deploy = the one redeploy scripts read/write while standing up a new
 * bridge. Defaults to active_deploy when EUNOMA_DEPLOY_ID is unset.
 */
export function targetDeployId(): string {
  return process.env.EUNOMA_DEPLOY_ID ?? loadState().active_deploy;
}

function getOrThrow(s: TestnetState, id: string, field?: string): DeployRecord {
  const d = s.deploys?.[id];
  if (!d) {
    throw new Error(
      `testnet_state.json: missing deploys["${id}"]${field ? ` (need ${field})` : ''}`,
    );
  }
  return d;
}

export function activeBridge(): string {
  const s = loadState();
  const d = getOrThrow(s, s.active_deploy, 'bridge_addr');
  if (!d.bridge_addr) {
    throw new Error(`active deploy "${s.active_deploy}" has no bridge_addr`);
  }
  return d.bridge_addr;
}

export function activeVault(): string {
  const s = loadState();
  const d = getOrThrow(s, s.active_deploy, 'vault.address');
  const addr = d.vault?.address;
  if (!addr) {
    throw new Error(`active deploy "${s.active_deploy}" has no vault.address`);
  }
  return addr;
}

export function targetDeploy(): DeployRecord {
  return getOrThrow(loadState(), targetDeployId());
}

export function targetBridge(): string {
  const d = targetDeploy();
  if (!d.bridge_addr) {
    throw new Error(`target deploy "${targetDeployId()}" has no bridge_addr`);
  }
  return d.bridge_addr;
}

export function targetVault(): string {
  const d = targetDeploy();
  const addr = d.vault?.address;
  if (!addr) {
    throw new Error(`target deploy "${targetDeployId()}" has no vault.address yet`);
  }
  return addr;
}

/**
 * Read-modify-write the target deploy slot. Use for ALL writes from publish /
 * init scripts so tx hashes + gas land in the staged slot atomically.
 */
export function updateTargetDeploy(mutator: (d: DeployRecord) => void): void {
  const s = loadState();
  const id = targetDeployId();
  const d = getOrThrow(s, id);
  mutator(d);
  s.deploys[id] = d;
  saveState(s);
}

/**
 * Final cutover. Refuses to flip unless the target slot has the bare minimum
 * production-ready fields. Idempotent for repeat runs that land on the same
 * deploy id.
 */
export function flipActiveDeploy(newId: string): void {
  const s = loadState();
  const d = getOrThrow(s, newId);
  if (!d.bridge_addr || !d.vault?.address || !d.vk?.publish_withdraw_proof_vk_tx) {
    throw new Error(
      `refuse to flip active_deploy → "${newId}": slot missing bridge_addr / vault.address / vk.publish_withdraw_proof_vk_tx`,
    );
  }
  s.active_deploy = newId;
  saveState(s);
}
