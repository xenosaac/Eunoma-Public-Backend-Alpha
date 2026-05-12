// One-shot migration: lift a legacy flat testnet_state.json into the
// multi-deploy schema introduced by BLOCKER 1 Layer 2.
//
// Legacy shape (top-level): { wallets, publishes, vk, vault, user_ca,
//   recipient_ca, deposits, deposit, withdraw, ... }
//
// New shape:
// {
//   active_deploy: "<legacy-id-name>",
//   network, chain_id,
//   deploys: {
//     "<legacy-id-name>": { bridge_addr, admin_address, publish_date,
//                            publishes, vk, vault, user_ca, ... },
//     "<staged-id-name>": { bridge_addr: "", admin_address: "", publish_date }
//   }
// }
//
// Run once per operator machine after pulling the Layer 2 changes:
//   tsx operator-services/scripts/_lib/migrate_state_to_deploys.ts \
//     --legacy-id phase_f_w3_2026_05_11 \
//     --staged-id blocker1_l2_2026_05_12
// (or set defaults below). Idempotent: re-running on an already-migrated file
// is a no-op + log.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = process.env.EUNOMA_STATE_PATH ??
  path.resolve(__dirname, '..', 'testnet_state.json');

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return fallback;
}

const LEGACY_ID = arg('legacy-id', 'phase_f_w3_2026_05_11');
const STAGED_ID = arg('staged-id', 'blocker1_l2_2026_05_12');
const STAGED_DATE = arg('staged-date', new Date().toISOString().slice(0, 10).replace(/-/g, '_'));

const raw = fs.readFileSync(STATE_PATH, 'utf-8');
const s = JSON.parse(raw);

if (s.active_deploy && s.deploys) {
  console.log(`[migrate] already in multi-deploy schema (active_deploy=${s.active_deploy}); skipping legacy lift`);
  if (!s.deploys[STAGED_ID]) {
    s.deploys[STAGED_ID] = {
      bridge_addr: '',
      admin_address: '',
      publish_date: STAGED_DATE,
      note: 'Staged deploy slot — bridge_addr + admin_address populated by user before S1',
    };
    fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, 2) + '\n');
    console.log(`[migrate] added empty staged slot deploys.${STAGED_ID}`);
  } else {
    console.log(`[migrate] staged slot deploys.${STAGED_ID} already exists`);
  }
  process.exit(0);
}

const bridge =
  s.wallets?.[LEGACY_ID]?.address ??
  s.wallets?.phase_f_w3?.address ??
  null;
if (!bridge) {
  console.error('[migrate] FATAL: cannot find a bridge address in legacy state');
  process.exit(1);
}

const legacy = {
  bridge_addr: bridge,
  admin_address: bridge,
  publish_date: s.publish_date ?? STAGED_DATE,
  note: s._comment ?? '',
  publishes: s.publishes ?? {},
  vk: s.vk ?? {},
  vault: s.vault ?? {},
  user_ca: s.user_ca ?? {},
  recipient_ca: s.recipient_ca ?? {},
  deposits: s.deposits ?? [],
  deposit: s.deposit ?? {},
  withdraw: s.withdraw ?? {},
};

const next = {
  _comment:
    'Multi-deploy schema (BLOCKER 1 Layer 2). active_deploy selects the production-current entry under deploys.*. Redeploy scripts set EUNOMA_DEPLOY_ID=<staged-id> so reads/writes route to the staged slot without disturbing active.',
  active_deploy: LEGACY_ID,
  network: s.network ?? 'testnet',
  chain_id: s.chain_id ?? 2,
  deploys: {
    [LEGACY_ID]: legacy,
    [STAGED_ID]: {
      bridge_addr: '',
      admin_address: '',
      publish_date: STAGED_DATE,
      note: 'Staged deploy slot — bridge_addr + admin_address populated by user before S1',
    },
  },
};

const backupPath = STATE_PATH + '.pre-multi-deploy-migration';
fs.copyFileSync(STATE_PATH, backupPath);
fs.writeFileSync(STATE_PATH, JSON.stringify(next, null, 2) + '\n');
console.log(`[migrate] legacy schema lifted into deploys.${LEGACY_ID}`);
console.log(`[migrate] empty staged slot added at deploys.${STAGED_ID}`);
console.log(`[migrate] backup written to ${backupPath}`);
console.log(`[migrate] populate deploys.${STAGED_ID}.{bridge_addr,admin_address} before S1`);
