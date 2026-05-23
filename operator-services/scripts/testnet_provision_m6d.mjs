#!/usr/bin/env node
// =============================================================================================
// RETIRED for A6. This pre-A6 provisioning runbook used old VK publish paths.
//
// This file is intentionally retained as a fail-closed tombstone so old runbooks/scripts do not
// accidentally execute the pre-A6 verification-key publication path.
//
// Use the A6 runbook instead:
//   1. aptos move publish --package-dir move --profile <admin> --assume-yes
//   2. RELAYER_SUBMIT_ENABLED=1 node scripts/testnet_rotate_a6_vks.mjs --submit --profile <admin>
//
// Exit codes:
//   0    help printed
//   2    retired script invoked
// =============================================================================================
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE_ERROR = 2;
const EXIT_APTOS_CLI_MISSING = 60;
const EXIT_PROFILE_NOT_CONFIGURED = 61;
const EXIT_PUBLISH_FAILED = 62;
const EXIT_VK_CONVERSION_FAILED = 63;
const EXIT_VK_PUBLISH_FAILED = 64;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

const args = process.argv.slice(2);
let profile;
let nodeUrl = "https://fullnode.testnet.aptoslabs.com";
let dryRun = false;
let skipPublish = false;
let bridgeAddress;

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  switch (arg) {
    case "--profile":
      profile = args[++i];
      break;
    case "--node-url":
      nodeUrl = args[++i];
      break;
    case "--dry-run":
      dryRun = true;
      break;
    case "--skip-publish":
      skipPublish = true;
      break;
    case "--bridge-address":
      bridgeAddress = args[++i];
      break;
    case "--help":
    case "-h":
      printHelp();
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${arg}`);
      process.exit(EXIT_USAGE_ERROR);
  }
}

function printHelp() {
  console.log(
    "testnet_provision_m6d.mjs is retired for A6 and always exits before Aptos actions.\n\n" +
      "Current A6 admin sequence:\n" +
      "  1. aptos move publish --package-dir move --profile <admin> --assume-yes\n" +
      "  2. RELAYER_SUBMIT_ENABLED=1 node scripts/testnet_rotate_a6_vks.mjs --submit --profile <admin>\n" +
      "  3. Run the fresh v2.1 vault ceremony scripts.\n\n" +
      "Legacy args are accepted only so stale automation reaches the retired-script guard.",
  );
}

if (!profile) {
  console.error("missing required --profile");
  process.exit(EXIT_USAGE_ERROR);
}

console.error(
  "testnet_provision_m6d.mjs is retired for A6 because it references pre-A6 VK publish flows. " +
    "Use aptos move publish followed by scripts/testnet_rotate_a6_vks.mjs.",
);
process.exit(EXIT_USAGE_ERROR);

// =============================================================================================
// Step 1: aptos CLI sanity check.
// =============================================================================================
const versionCheck = spawnSync("aptos", ["--version"], { stdio: "pipe", encoding: "utf8" });
if (versionCheck.status !== 0) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "aptos_cli_missing",
        message:
          "The `aptos` CLI binary is not on PATH. Install via " +
          "`curl -fsSL https://aptos.dev/scripts/install_cli.py | python3` or download from " +
          "https://github.com/aptos-labs/aptos-core/releases. M6-d cannot proceed without it.",
        underlying: versionCheck.stderr,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_APTOS_CLI_MISSING);
}
console.log(`aptos CLI: ${versionCheck.stdout.trim()}`);

// =============================================================================================
// Step 2: profile check — confirm funded.
// =============================================================================================
const balanceCheck = spawnSync(
  "aptos",
  ["account", "list", "--query", "balance", "--profile", profile],
  { stdio: "pipe", encoding: "utf8" },
);
if (balanceCheck.status !== 0) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "profile_not_configured",
        message:
          `Aptos profile '${profile}' not configured. Initialize via ` +
          `\`aptos init --profile ${profile} --network testnet\` and fund via the testnet ` +
          "faucet: https://aptos.dev/network/faucet (need ~0.5 APT for publish + 0.1 APT per VK init).",
        underlying: balanceCheck.stderr,
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_PROFILE_NOT_CONFIGURED);
}
console.log(`profile '${profile}' balance check: ${balanceCheck.stdout.trim().slice(0, 200)}`);

// =============================================================================================
// Step 3: publish bridge package.
// =============================================================================================
if (!skipPublish) {
  console.log("▶ publishing bridge Move package");
  const publishArgs = [
    "move",
    "publish",
    "--profile",
    profile,
    "--package-dir",
    resolve(repoRoot, "move"),
    "--assume-yes",
  ];
  if (dryRun) {
    console.log(`[DRY RUN] aptos ${publishArgs.join(" ")}`);
  } else {
    const publishResult = spawnSync("aptos", publishArgs, { stdio: "inherit" });
    if (publishResult.status !== 0) {
      console.error(
        JSON.stringify(
          {
            ok: false,
            error: "publish_failed",
            message:
              "Move publish failed. Check: (a) compilation errors via " +
              "`aptos move compile --dev --package-dir move`, (b) account has enough APT for " +
              "gas, (c) named addresses in move/Move.toml resolve to the profile address.",
            exitCode: publishResult.status,
          },
          null,
          2,
        ),
      );
      process.exit(EXIT_PUBLISH_FAILED);
    }
  }
  // Resolve bridge address from profile (assumes package published under profile account).
  const acctCheck = spawnSync(
    "aptos",
    ["account", "list", "--profile", profile, "--query", "modules"],
    { stdio: "pipe", encoding: "utf8" },
  );
  if (acctCheck.status === 0 && acctCheck.stdout.includes("eunoma_bridge")) {
    // Address is the profile address; we'd parse `aptos config show-profiles --profile NAME` for it.
    const profileShow = spawnSync(
      "aptos",
      ["config", "show-profiles", "--profile", profile],
      { stdio: "pipe", encoding: "utf8" },
    );
    const accountMatch = profileShow.stdout.match(/"account":\s*"([0-9a-fA-F]+)"/);
    if (accountMatch) {
      bridgeAddress = `0x${accountMatch[1]}`;
    }
  }
}

if (!bridgeAddress) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "bridge_address_unresolved",
        message:
          "Could not resolve the bridge package address. Pass --bridge-address explicitly, or " +
          "use --skip-publish if already published.",
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_PUBLISH_FAILED);
}
console.log(`✓ bridge package at ${bridgeAddress}`);

// =============================================================================================
// Step 4: convert + publish Groth16 VKs.
//
// The existing circuits/scripts/extract_withdraw_vk.js converts the snarkjs vk.json into the
// Move-friendly BCS shape (alpha_g1, beta_g2, gamma_g2, delta_g2, ic[]). We invoke it +
// then submit the publish_*_vk_v2 admin entries via the aptos CLI.
// =============================================================================================
console.log("▶ converting Groth16 VKs to Move BCS shape");
const extractScript = resolve(repoRoot, "circuits", "scripts", "extract_withdraw_vk.js");
if (!existsSync(extractScript)) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: "vk_conversion_script_missing",
        message:
          `${extractScript} not found. The circuits/ package must be built first: ` +
          "`cd circuits && npm install && npm run all`.",
      },
      null,
      2,
    ),
  );
  process.exit(EXIT_VK_CONVERSION_FAILED);
}

const vkDir = resolve(repoRoot, "circuits", "generated", "move_fixtures");
if (!existsSync(vkDir)) {
  mkdirSync(vkDir, { recursive: true });
}

// Output env block for testnet:e2e.
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const provisionStatePath = resolve(stateRoot, "testnet_m6d_provision.json");
mkdirSync(dirname(provisionStatePath), { recursive: true });
const provisionState = {
  schema: "eunoma_v2_testnet_m6d_provision_v1",
  profile,
  nodeUrl,
  bridgeAddress,
  dryRun,
  skippedPublish: skipPublish,
  // NOTE: real publish_*_vk_v2 admin entry calls + tx hashes go here; in dry-run we just
  // record the planned operations. Operators MUST review the dry-run output before
  // executing real submissions.
  vkPublishOperations: [
    {
      action: "publish_deposit_binding_vk_v2",
      sourceFile: "circuits/generated/deposit_binding_vk.json",
      txHash: dryRun ? "<dry-run>" : "<not yet executed>",
    },
    {
      action: "publish_prepared_deposit_binding_vk_v2",
      sourceFile: "circuits/generated/deposit_binding_vk.json (prepared)",
      txHash: dryRun ? "<dry-run>" : "<not yet executed>",
    },
    {
      action: "publish_withdraw_proof_vk_v2",
      sourceFile: "circuits/generated/withdrawal_proof_vk.json",
      txHash: dryRun ? "<dry-run>" : "<not yet executed>",
    },
    {
      action: "publish_prepared_withdraw_proof_vk_v2",
      sourceFile: "circuits/generated/withdrawal_proof_vk.json (prepared)",
      txHash: dryRun ? "<dry-run>" : "<not yet executed>",
    },
    {
      action: "publish_vault_public_inputs_v2",
      sourceFile: "(derived from vault config)",
      txHash: dryRun ? "<dry-run>" : "<not yet executed>",
    },
  ],
  nextSteps: [
    `export BRIDGE_PACKAGE_ADDRESS=${bridgeAddress}`,
    `export APTOS_TESTNET_NODE_URL=${nodeUrl}`,
    `export ADMIN_PROFILE=${profile}`,
    `export RELAYER_SUBMIT_ENABLED=1`,
    `export RELAYER_BEARER_TOKEN=<generate via openssl rand -hex 32>`,
    `export EUNOMA_TESTNET_REQUEST_ID=<unique per withdraw>`,
    `export EUNOMA_TESTNET_DKG_EPOCH=1`,
    `export EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON=<path to witness JSON>`,
    `npm run testnet:e2e`,
  ],
  caveat:
    "M6-d real provisioning requires HUMAN OPERATOR review of each Aptos CLI command BEFORE " +
    "execution. This script's --dry-run mode prints the planned commands without sending real " +
    "transactions. The publish_*_vk_v2 admin entry calls are NOT YET WIRED into this script; " +
    "operators must manually invoke `aptos move run --function-id <bridge>::eunoma_bridge::publish_*` " +
    "for each VK. Documented as a runbook in circuits/CHAIN_VARIANT.md.",
  createdAtUnixMs: Date.now(),
};
writeFileSync(provisionStatePath, JSON.stringify(provisionState, null, 2) + "\n");
console.log(`✓ provision state written to ${provisionStatePath}`);

console.log(
  JSON.stringify(
    {
      ok: true,
      command: "testnet:provision:m6d",
      bridgeAddress,
      nodeUrl,
      profile,
      dryRun,
      provisionStatePath,
      vkPublishOperations: provisionState.vkPublishOperations,
      nextSteps: provisionState.nextSteps,
      message:
        "M6-d operational provisioning scaffold complete. To execute on a real Aptos testnet: " +
        "(1) re-run WITHOUT --dry-run, (2) manually invoke `aptos move run` for each " +
        "publish_*_vk_v2 admin entry, (3) source the nextSteps env block, (4) run `npm run testnet:e2e`.",
    },
    null,
    2,
  ),
);
process.exit(EXIT_SUCCESS);
