/**
 * Phase 1 — wallet generation + funding orchestration script.
 *
 * NOTE: For Gate 4d this was executed manually via `aptos init` + `aptos account
 * transfer` from basement-admin. This script captures the canonical sequence so a
 * follow-up dispatch can re-run it idempotently. The captured tx hashes / addresses
 * for the run on 2026-05-07 are persisted in scripts/testnet_state.json (READ-ONLY
 * source-of-truth for downstream phases).
 *
 * Run: cd operator-services && npx tsx scripts/testnet_setup_wallets.ts
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PROFILES = [
  { name: 'bridge-admin', octas: 1_000_000_000 },
  { name: 'bridge-user', octas: 500_000_000 },
  { name: 'bridge-relayer', octas: 200_000_000 },
  { name: 'bridge-spare', octas: 200_000_000 },
];
const BASEMENT_PROFILE_DIR = '/Users/isaaczhang/Desktop/AGENT/Projects/basement';

function sh(cmd: string): string {
  console.log(`$ ${cmd}`);
  return execSync(cmd, { encoding: 'utf-8' });
}

async function main() {
  const repoRoot = path.resolve(__dirname, '../..');
  process.chdir(repoRoot);

  console.log('--- Phase 1.1: generate 4 sub-wallet profiles ---');
  for (const p of PROFILES) {
    try {
      sh(`aptos init --network testnet --skip-faucet --profile ${p.name} --assume-yes`);
    } catch (e) {
      console.log(`  ${p.name}: profile may already exist (continuing)`);
    }
  }

  console.log('\n--- Phase 1.2: read addresses from .aptos/config.yaml ---');
  const cfg = fs.readFileSync(path.join(repoRoot, '.aptos/config.yaml'), 'utf-8');
  // Naive YAML parse (avoid extra deps): grep for "<profile>:" then "account:".
  const addrs: Record<string, string> = {};
  for (const p of PROFILES) {
    const m = new RegExp(`\\s+${p.name}:\\s*\\n[\\s\\S]*?account:\\s*([0-9a-fA-Fx]+)`).exec(cfg);
    if (!m) throw new Error(`No address for profile ${p.name}`);
    addrs[p.name] = m[1].startsWith('0x') ? m[1] : `0x${m[1]}`;
    console.log(`  ${p.name} → ${addrs[p.name]}`);
  }

  console.log('\n--- Phase 1.3: transfer-fund from basement-admin ---');
  const txs: Record<string, string> = {};
  for (const p of PROFILES) {
    const cmd =
      `cd ${BASEMENT_PROFILE_DIR} && ` +
      `aptos account transfer --account ${addrs[p.name]} --amount ${p.octas} ` +
      `--profile basement-admin --assume-yes`;
    const out = sh(cmd);
    const m = /"transaction_hash":\s*"(0x[0-9a-f]+)"/.exec(out);
    txs[p.name] = m ? m[1] : 'UNKNOWN';
    console.log(`  ${p.name} funding tx: ${txs[p.name]}`);
  }

  console.log('\n--- Phase 1.4: persist state ---');
  const state = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'testnet_state.json'), 'utf-8'),
  );
  for (const p of PROFILES) {
    const k = p.name.replace('-', '_');
    state.wallets[k] = { address: addrs[p.name], funded_octas: p.octas, funding_tx: txs[p.name] };
  }
  fs.writeFileSync(path.join(__dirname, 'testnet_state.json'), JSON.stringify(state, null, 2));
  console.log('Done.');
}

main().catch((e) => {
  console.error('FAILED:', e);
  process.exit(1);
});
