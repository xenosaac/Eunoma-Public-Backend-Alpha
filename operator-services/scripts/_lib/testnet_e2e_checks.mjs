// =============================================================================================
// M6 closure — chain-query, artifact-read, and final-report assembly helpers for testnet:e2e.
//
// This module is loaded by scripts/testnet_e2e_v2.mjs. It exists so the top-level orchestrator
// stays readable while the binding-final-gate validation logic lives in one place and stays
// testable in isolation.
//
// Hard contract (goal.md Final Acceptance, see /goal.md):
//   - Every prereq that's missing produces ONE structured entry in `missing[]` with
//     { key, message, remediation, priority }.
//   - On success, `snapshot` carries every value the final report will need, so the
//     orchestrator never re-queries the chain.
//   - On final-report assembly, ANY artifact missing or malformed produces a hard exit-1
//     with `final_report_artifacts_missing` — NO completion language is emitted.
// =============================================================================================
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve, join } from "node:path";

const HEX64 = /^(0x)?[0-9a-fA-F]{64}$/;
const TX_HASH_RE = /^(0x)?[0-9a-fA-F]{64}$/;

// =============================================================================================
// Low-level fetch + REST helpers
// =============================================================================================

export async function fetchJson(url, init) {
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    return { status: 0, ok: false, body: null, text: "", error: err?.message ?? String(err) };
  }
  const text = await res.text();
  let body = null;
  try {
    body = text.length === 0 ? null : JSON.parse(text);
  } catch {
    body = null;
  }
  return { status: res.status, ok: res.ok, body, text };
}

function trimSlash(s) {
  return s.replace(/\/+$/, "");
}

export async function getResource(nodeUrl, address, resourceType) {
  const url = `${trimSlash(nodeUrl)}/v1/accounts/${address}/resource/${encodeURIComponent(
    resourceType,
  )}`;
  return fetchJson(url);
}

export async function getModules(nodeUrl, address) {
  const url = `${trimSlash(nodeUrl)}/v1/accounts/${address}/modules?limit=200`;
  return fetchJson(url);
}

export async function getTransactionByHash(nodeUrl, txHash) {
  const url = `${trimSlash(nodeUrl)}/v1/transactions/by_hash/${txHash}`;
  return fetchJson(url);
}

export async function getAccount(nodeUrl, address) {
  return fetchJson(`${trimSlash(nodeUrl)}/v1/accounts/${address}`);
}

// =============================================================================================
// CLI / FS helpers
// =============================================================================================

export function checkAptosCli() {
  const r = spawnSync("aptos", ["--version"], { encoding: "utf8" });
  if (r.status !== 0 && r.status !== null) {
    return { ok: false, message: `aptos --version exited ${r.status}: ${r.stderr || r.stdout}` };
  }
  if (r.error) {
    return { ok: false, message: `aptos CLI not on PATH: ${r.error.message}` };
  }
  return { ok: true, version: (r.stdout || "").trim() };
}

export function listProfiles() {
  const r = spawnSync("aptos", ["config", "show-profiles"], { encoding: "utf8" });
  if (r.status !== 0 || r.error) {
    return { ok: false, profiles: [], error: r.stderr || r.error?.message || "" };
  }
  const profiles = [];
  for (const line of (r.stdout || "").split("\n")) {
    const m = line.match(/^\s*([A-Za-z0-9_.-]+):\s*$/);
    if (m) profiles.push(m[1]);
  }
  return { ok: true, profiles };
}

export function readJsonIfExists(absPath) {
  if (!existsSync(absPath)) return null;
  try {
    return JSON.parse(readFileSync(absPath, "utf8"));
  } catch {
    return null;
  }
}

export function stateRootJoin(serviceRoot, stateRootEnv, ...segments) {
  return resolve(serviceRoot, stateRootEnv ?? ".agent-local/eunoma-v2", ...segments);
}

export function isHex64(s) {
  return typeof s === "string" && HEX64.test(s);
}

export function isTxHash(s) {
  return typeof s === "string" && TX_HASH_RE.test(s);
}

export function strip0x(s) {
  return typeof s === "string" && s.startsWith("0x") ? s.slice(2) : s;
}

export function add0x(s) {
  if (typeof s !== "string") return s;
  return s.startsWith("0x") ? s : `0x${s}`;
}

export function eqHexLoose(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return strip0x(a).toLowerCase() === strip0x(b).toLowerCase();
}

// =============================================================================================
// runPreflight — the binding gate's structural validator
//
// Returns { ok: true, snapshot } | { ok: false, missing: Array<{key, message, remediation, priority}> }
//
// priorities (in exit-code precedence order):
//   "m6b"             — withdraw prover missing (exit 40)
//   "m6d-cli"         — Aptos CLI / profile / account-funding missing (exit 41)
//   "m6d-chain"       — bridge / module / VK / vault / config not on chain (exit 41)
//   "m6d-artifact"    — local artifact required to proceed is missing (exit 41)
//   "m6c-env"         — per-run env var missing or malformed (exit 2)
// =============================================================================================

export async function runPreflight(opts) {
  const { env, serviceRoot, stateRoot } = opts;
  const missing = [];
  const snapshot = {};

  const nodeUrl = env.APTOS_TESTNET_NODE_URL;
  const bridgeAddress = env.BRIDGE_PACKAGE_ADDRESS ? add0x(env.BRIDGE_PACKAGE_ADDRESS) : null;
  const vaultAddress = env.EUNOMA_TESTNET_VAULT_ADDRESS
    ? add0x(env.EUNOMA_TESTNET_VAULT_ADDRESS)
    : null;
  const assetType = env.EUNOMA_TESTNET_ASSET_TYPE ? add0x(env.EUNOMA_TESTNET_ASSET_TYPE) : null;
  const dkgEpoch = env.EUNOMA_TESTNET_DKG_EPOCH;
  const adminProfile = env.ADMIN_PROFILE;

  // ----- 1. aptos CLI -----
  const cli = checkAptosCli();
  if (!cli.ok) {
    missing.push({
      key: "aptos_cli",
      message: cli.message ?? "aptos CLI not on PATH",
      remediation:
        "Install the Aptos CLI: https://aptos.dev/cli-tools/aptos-cli — required for vault init, " +
        "deposit submission, and relayer CLI submitter.",
      priority: "m6d-cli",
    });
  } else {
    snapshot.aptosCliVersion = cli.version;
  }

  // ----- 2. ADMIN_PROFILE present in aptos config show-profiles -----
  if (adminProfile) {
    const profs = listProfiles();
    if (!profs.ok || !profs.profiles.includes(adminProfile)) {
      missing.push({
        key: "admin_profile",
        message: `aptos config show-profiles does not include '${adminProfile}'`,
        remediation: `aptos init --profile ${adminProfile} --network testnet (then fund the address from https://aptos.dev/network/faucet)`,
        priority: "m6d-cli",
      });
    }
  }

  // ----- 3. ADMIN_PROFILE account exists + funded -----
  // We can only check the account if we know its address. Resolve from `aptos account list`
  // for the profile, or fall back to the BRIDGE_PACKAGE_ADDRESS (which is the admin address in
  // the canonical setup).
  if (nodeUrl && adminProfile) {
    const adminAddr = resolveProfileAddress(adminProfile) ?? bridgeAddress;
    if (adminAddr) {
      const acctRes = await getAccount(nodeUrl, adminAddr);
      if (!acctRes.ok) {
        missing.push({
          key: "admin_account_funded",
          message: `Aptos /v1/accounts/${adminAddr} -> ${acctRes.status}: account not visible on testnet`,
          remediation: `aptos account fund-with-faucet --account ${adminProfile} --amount 100000000`,
          priority: "m6d-cli",
        });
      } else {
        snapshot.adminAddress = adminAddr;
        const coinRes = await getResource(
          nodeUrl,
          adminAddr,
          "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        );
        if (coinRes.ok && coinRes.body?.data?.coin?.value !== undefined) {
          const balance = BigInt(coinRes.body.data.coin.value);
          snapshot.adminBalanceOctas = balance.toString();
          if (balance < 10_000_000n) {
            missing.push({
              key: "admin_account_funded",
              message: `${adminAddr} balance ${balance} octas < 0.1 APT (10_000_000)`,
              remediation: `aptos account fund-with-faucet --account ${adminProfile} --amount 100000000`,
              priority: "m6d-cli",
            });
          }
        }
      }
    }
  }

  // ----- 4. Bridge package published -----
  if (nodeUrl && bridgeAddress) {
    const modulesRes = await getModules(nodeUrl, bridgeAddress);
    if (!modulesRes.ok) {
      missing.push({
        key: "bridge_modules",
        message: `Aptos /v1/accounts/${bridgeAddress}/modules -> ${modulesRes.status}`,
        remediation:
          "Publish the bridge: `aptos move publish --package-dir move --profile $ADMIN_PROFILE` (see M6_OPERATOR_RUNBOOK.md Step 2).",
        priority: "m6d-chain",
      });
    } else {
      const mods = Array.isArray(modulesRes.body) ? modulesRes.body : [];
      const hasBridge = mods.some(
        (m) => m && m.abi && typeof m.abi.name === "string" && m.abi.name === "eunoma_bridge",
      );
      if (!hasBridge) {
        missing.push({
          key: "bridge_modules",
          message: `module 'eunoma_bridge' not published at ${bridgeAddress}`,
          remediation:
            "Publish the bridge: `aptos move publish --package-dir move --profile $ADMIN_PROFILE`.",
          priority: "m6d-chain",
        });
      }
    }
  }

  // ----- 5. PreparedWithdrawProofVK resource present -----
  if (nodeUrl && bridgeAddress) {
    const vkType = `${bridgeAddress}::eunoma_bridge::PreparedWithdrawProofVK`;
    const vkRes = await getResource(nodeUrl, bridgeAddress, vkType);
    if (!vkRes.ok) {
      missing.push({
        key: "prepared_withdraw_proof_vk",
        message: `${vkType} resource not present at ${bridgeAddress} (status=${vkRes.status})`,
        remediation:
          "Publish the prepared withdraw VK via aptos move run ...::publish_prepared_withdraw_proof_vk_v2 (see M6_OPERATOR_RUNBOOK.md Step 3).",
        priority: "m6d-chain",
      });
    }
  }

  // ----- 6. Vault init tx -----
  // Resolve from env, else from the persisted vault-init artifact at
  // <stateRoot>/coordinator/testnet_vault_init/<dkgEpoch>__init.json.
  let vaultInitTxHash = env.EUNOMA_TESTNET_VAULT_INIT_TX_HASH;
  if ((!vaultInitTxHash || !isTxHash(vaultInitTxHash)) && dkgEpoch && serviceRoot) {
    const path = stateRootJoin(
      serviceRoot,
      stateRoot,
      "coordinator",
      "testnet_vault_init",
      `${dkgEpoch}__init.json`,
    );
    const artifact = readJsonIfExists(path);
    if (artifact && typeof artifact.txHash === "string") {
      vaultInitTxHash = artifact.txHash;
      snapshot.vaultInitArtifactPath = path;
    }
  }
  if (!vaultInitTxHash || !isTxHash(vaultInitTxHash)) {
    missing.push({
      key: "vault_init_tx_hash",
      message:
        "EUNOMA_TESTNET_VAULT_INIT_TX_HASH is not set and no persisted artifact at " +
        "<stateRoot>/coordinator/testnet_vault_init/<dkgEpoch>__init.json carries a tx hash",
      remediation:
        "Run `npm run testnet:vault:init -- --submit --ca-registration-artifact ... --snapshot ... --roster ... --frost-roster ...` (see M6_OPERATOR_RUNBOOK.md Step 4) and capture the tx hash.",
      priority: "m6d-artifact",
    });
  } else if (nodeUrl) {
    const txRes = await getTransactionByHash(nodeUrl, vaultInitTxHash);
    if (!txRes.ok) {
      missing.push({
        key: "vault_init_tx_hash",
        message: `Aptos /v1/transactions/by_hash/${vaultInitTxHash} -> ${txRes.status}: ${txRes.text?.slice(0, 120) ?? ""}`,
        remediation:
          "Re-submit the vault init tx and supply the resulting tx hash via EUNOMA_TESTNET_VAULT_INIT_TX_HASH.",
        priority: "m6d-chain",
      });
    } else if (txRes.body?.success !== true || txRes.body?.vm_status !== "Executed successfully") {
      missing.push({
        key: "vault_init_tx_hash",
        message: `Vault init tx ${vaultInitTxHash} on chain but success=${txRes.body?.success}, vm_status=${txRes.body?.vm_status}`,
        remediation: "Investigate the vault init failure and re-submit before retrying.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.vaultInitTx = {
        hash: vaultInitTxHash,
        version: txRes.body.version ?? null,
      };
    }
  }

  // ----- 7. BridgeVault resource at EUNOMA_TESTNET_VAULT_ADDRESS -----
  if (nodeUrl && bridgeAddress && vaultAddress) {
    const vaultType = `${bridgeAddress}::eunoma_bridge::BridgeVault`;
    const vaultRes = await getResource(nodeUrl, vaultAddress, vaultType);
    if (!vaultRes.ok) {
      missing.push({
        key: "bridge_vault_resource",
        message: `${vaultType} not present at ${vaultAddress} (status=${vaultRes.status})`,
        remediation:
          "Run `npm run testnet:vault:init -- --submit ...` to publish the BridgeVault resource.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.bridgeVault = vaultRes.body?.data ?? null;
      // Asset-type cross-check (defense-in-depth — observer also re-checks).
      if (
        assetType &&
        vaultRes.body?.data?.asset_type?.inner &&
        !eqHexLoose(vaultRes.body.data.asset_type.inner, assetType)
      ) {
        missing.push({
          key: "vault_asset_type_mismatch",
          message: `BridgeVault.asset_type=${vaultRes.body.data.asset_type.inner} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
          remediation:
            "Fix EUNOMA_TESTNET_ASSET_TYPE to match the vault's actual asset_type, OR initialize the correct vault.",
          priority: "m6c-env",
        });
      }
    }
  }

  // ----- 8. DeoperatorConfigV2 resource matches per-run roster -----
  if (nodeUrl && bridgeAddress && vaultAddress) {
    const cfgType = `${bridgeAddress}::eunoma_bridge::DeoperatorConfigV2`;
    const cfgRes = await getResource(nodeUrl, vaultAddress, cfgType);
    if (!cfgRes.ok) {
      missing.push({
        key: "deoperator_config_v2",
        message: `${cfgType} not present at ${vaultAddress} (status=${cfgRes.status})`,
        remediation:
          "Run `npm run testnet:vault:init -- --submit ...` — DeoperatorConfigV2 is published as part of vault init.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.deoperatorConfig = cfgRes.body?.data ?? null;
      if (dkgEpoch && snapshot.deoperatorConfig?.dkg_epoch !== undefined) {
        const onChain = String(snapshot.deoperatorConfig.dkg_epoch);
        if (onChain !== dkgEpoch) {
          missing.push({
            key: "dkg_epoch_mismatch",
            message: `DeoperatorConfigV2.dkg_epoch=${onChain} != EUNOMA_TESTNET_DKG_EPOCH=${dkgEpoch}`,
            remediation:
              "Use the dkg_epoch that's actually on chain, OR rotate the config to the desired epoch.",
            priority: "m6c-env",
          });
        }
      }
      if (snapshot.deoperatorConfig?.threshold !== undefined) {
        const threshold = Number(snapshot.deoperatorConfig.threshold);
        if (threshold !== 5) {
          missing.push({
            key: "threshold_violation",
            message: `DeoperatorConfigV2.threshold=${threshold} != 5 (strict 5-of-7 invariant)`,
            remediation:
              "This violates a goal.md hard invariant. Investigate the on-chain config before proceeding.",
            priority: "m6d-chain",
          });
        }
      }
    }
  }

  // ----- 9. Deposit tx -----
  const depositTxHash = env.EUNOMA_TESTNET_DEPOSIT_TX_HASH;
  if (!depositTxHash || !isTxHash(depositTxHash)) {
    missing.push({
      key: "deposit_tx_hash",
      message: "EUNOMA_TESTNET_DEPOSIT_TX_HASH is required (a real, chain-confirmed deposit tx)",
      remediation:
        "Submit a deposit via `aptos move run --function-id $BRIDGE::eunoma_bridge::deposit_with_commitment_v2 --args ...` (see M6_OPERATOR_RUNBOOK.md Step 5) and capture the tx hash.",
      priority: "m6c-env",
    });
  } else if (nodeUrl) {
    const dtxRes = await getTransactionByHash(nodeUrl, depositTxHash);
    if (!dtxRes.ok) {
      missing.push({
        key: "deposit_tx_hash",
        message: `Aptos /v1/transactions/by_hash/${depositTxHash} -> ${dtxRes.status}`,
        remediation:
          "Re-submit the deposit and supply the new tx hash via EUNOMA_TESTNET_DEPOSIT_TX_HASH.",
        priority: "m6d-chain",
      });
    } else if (dtxRes.body?.success !== true || dtxRes.body?.vm_status !== "Executed successfully") {
      missing.push({
        key: "deposit_tx_hash",
        message: `Deposit tx ${depositTxHash}: success=${dtxRes.body?.success} vm_status=${dtxRes.body?.vm_status}`,
        remediation: "Investigate the deposit failure and re-submit before retrying.",
        priority: "m6d-chain",
      });
    } else {
      // ----- 10. DepositConfirmedV2 event present -----
      const events = Array.isArray(dtxRes.body?.events) ? dtxRes.body.events : [];
      const wantType = bridgeAddress
        ? `${bridgeAddress}::eunoma_bridge::DepositConfirmedV2`
        : null;
      const ev = wantType ? events.find((e) => e?.type === wantType) : null;
      if (!ev) {
        missing.push({
          key: "deposit_confirmed_v2_event",
          message: `Deposit tx ${depositTxHash} has no event of type ${wantType ?? "DepositConfirmedV2"}`,
          remediation:
            "Confirm the deposit was made via deposit_with_commitment_v2 (NOT a legacy deposit entry). Re-submit if necessary.",
          priority: "m6d-chain",
        });
      } else {
        // Bind-check fields. asset_type may be a struct { inner: hex } or a hex string
        // depending on the fullnode version.
        const evAssetType =
          typeof ev.data?.asset_type === "string"
            ? ev.data.asset_type
            : ev.data?.asset_type?.inner;
        const evVaultAddr =
          typeof ev.data?.vault_addr === "string"
            ? ev.data.vault_addr
            : ev.data?.vault_addr?.inner ?? null;
        const evDepositCount = ev.data?.deposit_count;

        if (assetType && evAssetType && !eqHexLoose(evAssetType, assetType)) {
          missing.push({
            key: "deposit_event_asset_mismatch",
            message: `DepositConfirmedV2.asset_type=${evAssetType} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
            remediation: "Use the asset_type that the deposit actually targeted.",
            priority: "m6c-env",
          });
        }
        if (vaultAddress && evVaultAddr && !eqHexLoose(evVaultAddr, vaultAddress)) {
          missing.push({
            key: "deposit_event_vault_mismatch",
            message: `DepositConfirmedV2.vault_addr=${evVaultAddr} != EUNOMA_TESTNET_VAULT_ADDRESS=${vaultAddress}`,
            remediation: "Use the vault_addr that the deposit actually targeted.",
            priority: "m6c-env",
          });
        }
        if (env.EUNOMA_TESTNET_DEPOSIT_COUNT) {
          if (String(evDepositCount) !== String(env.EUNOMA_TESTNET_DEPOSIT_COUNT)) {
            missing.push({
              key: "deposit_event_count_mismatch",
              message: `DepositConfirmedV2.deposit_count=${evDepositCount} != EUNOMA_TESTNET_DEPOSIT_COUNT=${env.EUNOMA_TESTNET_DEPOSIT_COUNT}`,
              remediation:
                "Use the chain-authoritative deposit_count from the DepositConfirmedV2 event.",
              priority: "m6c-env",
            });
          }
        } else {
          missing.push({
            key: "deposit_count_env",
            message: "EUNOMA_TESTNET_DEPOSIT_COUNT is required (chain-authoritative deposit_count)",
            remediation: `Set EUNOMA_TESTNET_DEPOSIT_COUNT=${evDepositCount} from the on-chain DepositConfirmedV2 event.`,
            priority: "m6c-env",
          });
        }
        snapshot.depositTx = {
          hash: depositTxHash,
          version: dtxRes.body.version ?? null,
        };
        snapshot.depositEvent = {
          type: ev.type,
          sequence_number: ev.sequence_number,
          version: dtxRes.body.version ?? null,
          data: ev.data,
        };
      }
    }
  }

  // ----- 11. MP-SPDZ runtime check -----
  // We avoid invoking mpc:check synchronously here (it can be slow). Instead surface a hint
  // that the operator should run it separately; mpc_spdz_check.mjs has its own exit codes.
  // If the bootstrap dir is missing entirely, that's a hard miss.
  if (serviceRoot) {
    const mpspdzDir = stateRootJoin(serviceRoot, stateRoot, "..", "mp-spdz");
    // Note: .agent-local/mp-spdz lives ABOVE .agent-local/eunoma-v2.
    const altMpspdzDir = resolve(serviceRoot, ".agent-local", "mp-spdz");
    if (!existsSync(mpspdzDir) && !existsSync(altMpspdzDir)) {
      missing.push({
        key: "mp_spdz_bootstrap",
        message: `MP-SPDZ runtime not bootstrapped (no .agent-local/mp-spdz directory)`,
        remediation: "Run `npm run mpc:bootstrap` then `npm run mpc:check` to verify.",
        priority: "m6d-cli",
      });
    }
  }

  // ----- 12. M6-b prover output -----
  // The orchestrator (testnet_e2e_v2.mjs) already validates EUNOMA_TESTNET_WITHDRAW_PROOF /
  // EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON before invoking us, so we just sanity-check the
  // env value is present.
  if (
    !env.EUNOMA_TESTNET_WITHDRAW_PROOF ||
    !/^(0x)?[0-9a-fA-F]+$/.test(env.EUNOMA_TESTNET_WITHDRAW_PROOF)
  ) {
    missing.push({
      key: "withdraw_proof",
      message:
        "EUNOMA_TESTNET_WITHDRAW_PROOF (hex) is missing or malformed at the pre-flight stage — " +
        "if you supplied EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON the orchestrator should have populated this earlier",
      remediation:
        "Set EUNOMA_TESTNET_WITHDRAW_PROOF (hex) directly, or supply a witness JSON via EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON.",
      priority: "m6b",
    });
  }

  // ----- 13. Worker state cursor sync -----
  // Read per-slot vault_state_v2 cursor files; each slot must show
  // deposit_count_observed >= EUNOMA_TESTNET_DEPOSIT_COUNT.
  // Cursor files live at .agent-local/eunoma-v2/slot-{N}/vault_state_v2/<dkgEpoch>.json
  // (this is the cluster layout — slot-0..6 each have their own vault_state_v2 dir).
  // If any slot lags AND auto-observe is OFF, surface as missing.
  if (dkgEpoch && env.EUNOMA_TESTNET_DEPOSIT_COUNT && serviceRoot) {
    const wantCount = BigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
    const laggingSlots = [];
    const observedBySlot = {};
    for (let slot = 0; slot < 7; slot += 1) {
      const slotDir = resolve(
        serviceRoot,
        stateRoot ?? ".agent-local/eunoma-v2",
        `slot-${slot}`,
        "vault_state_v2",
      );
      let observed = null;
      if (existsSync(slotDir)) {
        const entries = readdirSync(slotDir).filter((f) => f.endsWith(".json"));
        for (const entry of entries) {
          const a = readJsonIfExists(join(slotDir, entry));
          if (a && typeof a.depositCountObserved === "number") {
            const v = BigInt(a.depositCountObserved);
            if (observed === null || v > observed) observed = v;
          } else if (a && typeof a.deposit_count_observed === "number") {
            const v = BigInt(a.deposit_count_observed);
            if (observed === null || v > observed) observed = v;
          }
        }
      }
      observedBySlot[slot] = observed === null ? null : observed.toString();
      if (observed === null || observed < wantCount) {
        laggingSlots.push(slot);
      }
    }
    snapshot.workerCursors = observedBySlot;
    if (laggingSlots.length > 0 && env.EUNOMA_TESTNET_AUTO_OBSERVE_DEPOSIT !== "1") {
      missing.push({
        key: "worker_state_cursor",
        message: `Worker slots ${laggingSlots.join(",")} have deposit_count_observed < ${wantCount} (cursor stale)`,
        remediation:
          "Run `npm run local:vault-state:observe-deposit -- --bridge-address $BRIDGE_PACKAGE_ADDRESS " +
          "--aptos-node-url $APTOS_TESTNET_NODE_URL --dkg-epoch $EUNOMA_TESTNET_DKG_EPOCH " +
          "--vault-ek $EUNOMA_TESTNET_VAULT_EK --sender-address $EUNOMA_TESTNET_SENDER_ADDRESS " +
          "--asset-type $EUNOMA_TESTNET_ASSET_TYPE --chain-id $EUNOMA_TESTNET_CHAIN_ID " +
          "--ca-dkg-transcript-hash $EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH` — OR set " +
          "EUNOMA_TESTNET_AUTO_OBSERVE_DEPOSIT=1 to let testnet:e2e invoke it for you.",
        priority: "m6d-artifact",
      });
    }
  }

  if (missing.length > 0) return { ok: false, missing };
  return { ok: true, snapshot };
}

function resolveProfileAddress(profileName) {
  // Best-effort: aptos config show-profiles emits YAML-ish blocks. We don't need the address
  // for correctness — only for the optional admin-balance check. Return null on any failure.
  const r = spawnSync("aptos", ["config", "show-profiles", "--profile", profileName], {
    encoding: "utf8",
  });
  if (r.status !== 0 || r.error) return null;
  const m = (r.stdout || "").match(/account:\s*(?:")?(0x?[0-9a-fA-F]+)(?:")?/);
  if (!m) return null;
  return add0x(m[1]);
}

// =============================================================================================
// buildFinalReport — reads all required artifacts and assembles the per-run evidence JSON.
// Returns { ok: true, report } | { ok: false, missingArtifacts: [{path, reason}] }.
// =============================================================================================

export async function buildFinalReport(snapshot, env, serviceRoot, stateRoot) {
  const missingArtifacts = [];

  const dkgEpoch = env.EUNOMA_TESTNET_DKG_EPOCH;
  const requestId = env.EUNOMA_TESTNET_REQUEST_ID;

  // ---- Submit artifact (M5b result) ----
  const submitPath = stateRootJoin(
    serviceRoot,
    stateRoot,
    "coordinator",
    "mpcca_withdraw_submit",
    `${dkgEpoch}__${requestId}.json`,
  );
  const submit = readJsonIfExists(submitPath);
  if (!submit) {
    missingArtifacts.push({
      path: submitPath,
      reason: "M5b submit-transcript artifact not found on disk after submit returned success",
    });
  } else if (submit.completed !== true) {
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact present but completed=${submit.completed}`,
    });
  } else if (!isTxHash(submit.txHash)) {
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact has no valid txHash (${submit.txHash})`,
    });
  }

  // ---- Finalize transcript (where transcript hashes live) ----
  const finalizePath = stateRootJoin(
    serviceRoot,
    stateRoot,
    "coordinator",
    "mpcca_withdraw",
    `${dkgEpoch}__${requestId}__finalize.json`,
  );
  const finalize = readJsonIfExists(finalizePath);
  if (!finalize) {
    missingArtifacts.push({
      path: finalizePath,
      reason: "MPCCA finalize transcript not found on disk",
    });
  }

  // ---- CA DKG V2 transcript ----
  let caDkgArtifact = null;
  if (dkgEpoch) {
    const candidates = [
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "ca_dkg_v2", `${dkgEpoch}__phase2.json`),
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "ca_dkg_v2", `${dkgEpoch}.json`),
    ];
    for (const c of candidates) {
      const a = readJsonIfExists(c);
      if (a) {
        caDkgArtifact = { path: c, data: a };
        break;
      }
    }
    if (!caDkgArtifact) {
      missingArtifacts.push({
        path: candidates[0],
        reason: "CA DKG V2 Phase-2 transcript not found",
      });
    }
  }

  // ---- FROST DKG V2 transcript ----
  let frostDkgArtifact = null;
  if (dkgEpoch) {
    const frostCandidates = [
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "frost_dkg_v2", `${dkgEpoch}.json`),
      stateRootJoin(
        serviceRoot,
        stateRoot,
        "coordinator",
        "frost_dkg_v2",
        `${dkgEpoch}__final.json`,
      ),
    ];
    for (const c of frostCandidates) {
      const a = readJsonIfExists(c);
      if (a) {
        frostDkgArtifact = { path: c, data: a };
        break;
      }
    }
    if (!frostDkgArtifact) {
      missingArtifacts.push({
        path: frostCandidates[0],
        reason: "FROST DKG V2 transcript not found",
      });
    }
  }

  // ---- Worker state per-slot transcripts ----
  const workerStateTranscripts = [];
  if (dkgEpoch && env.EUNOMA_TESTNET_DEPOSIT_COUNT) {
    for (let slot = 0; slot < 7; slot += 1) {
      const slotDir = resolve(
        serviceRoot,
        stateRoot ?? ".agent-local/eunoma-v2",
        `slot-${slot}`,
        "vault_state_v2",
      );
      let chosen = null;
      if (existsSync(slotDir)) {
        const entries = readdirSync(slotDir).filter((f) => f.endsWith(".json"));
        // Prefer files that match the dkgEpoch.
        const matching = entries.filter((f) => f.includes(`${dkgEpoch}`));
        for (const e of matching.length > 0 ? matching : entries) {
          const a = readJsonIfExists(join(slotDir, e));
          if (a && (a.transcriptHash || a.transcript_hash)) {
            chosen = { slot, path: join(slotDir, e), data: a };
            break;
          }
        }
      }
      if (!chosen) {
        missingArtifacts.push({
          path: `${slotDir}/<dkgEpoch>__*.json`,
          reason: `Worker slot ${slot} vault_state_v2 transcript not found`,
        });
      } else {
        workerStateTranscripts.push({
          slot: chosen.slot,
          path: chosen.path,
          transcriptHash: chosen.data.transcriptHash ?? chosen.data.transcript_hash,
        });
      }
    }
  }

  // ---- If anything missing, return the structured failure ----
  if (missingArtifacts.length > 0) {
    return { ok: false, missingArtifacts };
  }

  // ---- All artifacts present. Pull every required hash. ----
  const submitArtifact = submit;
  const finalizeArtifact = finalize;

  const caPayloadHash =
    finalizeArtifact?.callArgs?.caPayloadHash ??
    finalizeArtifact?.ca_payload_hash ??
    finalizeArtifact?.caPayloadHash ??
    null;
  const rosterHash =
    finalizeArtifact?.rosterHash ?? finalizeArtifact?.roster_hash ?? null;
  const quorumTranscriptHash =
    finalizeArtifact?.quorumTranscriptHash ?? finalizeArtifact?.quorum_transcript_hash ?? null;
  const mpccaTranscriptHash =
    finalizeArtifact?.mpccaWithdrawFinalTranscriptHash ??
    finalizeArtifact?.transcriptHash ??
    submitArtifact?.finalizeTranscriptHash ??
    null;

  const caDkgV2RosterHash =
    caDkgArtifact?.data?.rosterHash ??
    caDkgArtifact?.data?.caDkgV2RosterHash ??
    caDkgArtifact?.data?.transcript?.rosterHash ??
    null;
  const frostDkgV2RosterHash =
    frostDkgArtifact?.data?.rosterHash ??
    frostDkgArtifact?.data?.frostDkgV2RosterHash ??
    frostDkgArtifact?.data?.transcript?.rosterHash ??
    null;

  // Vault state init transcript (separate from per-slot post-deposit transcripts) — best-effort.
  let vaultStateInitHash = null;
  if (dkgEpoch) {
    const initPath = stateRootJoin(
      serviceRoot,
      stateRoot,
      "coordinator",
      "vault_state_init",
      `${dkgEpoch}.json`,
    );
    const a = readJsonIfExists(initPath);
    if (a) vaultStateInitHash = a.transcriptHash ?? a.transcript_hash ?? null;
  }

  const report = {
    txHashes: {
      vaultInit: snapshot?.vaultInitTx?.hash ?? null,
      deposit: snapshot?.depositTx?.hash ?? null,
      relayerSubmit: submitArtifact.txHash,
      chainConfirmedWithdraw: submitArtifact.txHash, // same value — chain-confirmed after waitForTx
    },
    chainVersions: {
      vaultInit: snapshot?.vaultInitTx?.version ?? null,
      deposit: snapshot?.depositTx?.version ?? null,
    },
    depositEventProof: snapshot?.depositEvent ?? null,
    transcriptHashes: {
      caPayload: caPayloadHash,
      caDkgV2Roster: caDkgV2RosterHash,
      frostDkgV2Roster: frostDkgV2RosterHash,
      deoperatorRoster: rosterHash,
      quorum: quorumTranscriptHash,
      vaultStateInit: vaultStateInitHash,
      vaultStatePerSlot: workerStateTranscripts.map((w) => w.transcriptHash),
      mpcca: mpccaTranscriptHash,
      submit: submitArtifact.transcriptHash ?? null,
    },
    sources: {
      submitArtifactPath: submitPath,
      finalizeTranscriptPath: finalizePath,
      vaultInitArtifactPath: snapshot?.vaultInitArtifactPath ?? null,
      caDkgV2Path: caDkgArtifact?.path ?? null,
      frostDkgV2Path: frostDkgArtifact?.path ?? null,
      workerStatePaths: workerStateTranscripts.map((w) => w.path),
    },
    invariants: {
      threshold: snapshot?.deoperatorConfig?.threshold ?? null,
      operatorSetVersion: snapshot?.deoperatorConfig?.operator_set_version ?? null,
      dkgEpoch: snapshot?.deoperatorConfig?.dkg_epoch ?? null,
      simulated: submitArtifact.simulated === true,
      chainSuccess: submitArtifact.chainSuccess ?? null,
    },
  };

  // Hard cross-check: if any required hash is null, report it as a missing artifact instead of
  // declaring V2 complete with holes. This catches the "submit succeeded but transcripts are stubs"
  // race.
  const required = [
    ["txHashes.vaultInit", report.txHashes.vaultInit],
    ["txHashes.deposit", report.txHashes.deposit],
    ["txHashes.relayerSubmit", report.txHashes.relayerSubmit],
    ["txHashes.chainConfirmedWithdraw", report.txHashes.chainConfirmedWithdraw],
    ["transcriptHashes.caPayload", report.transcriptHashes.caPayload],
    ["transcriptHashes.caDkgV2Roster", report.transcriptHashes.caDkgV2Roster],
    ["transcriptHashes.frostDkgV2Roster", report.transcriptHashes.frostDkgV2Roster],
    ["transcriptHashes.deoperatorRoster", report.transcriptHashes.deoperatorRoster],
    ["transcriptHashes.quorum", report.transcriptHashes.quorum],
    ["transcriptHashes.mpcca", report.transcriptHashes.mpcca],
    ["transcriptHashes.submit", report.transcriptHashes.submit],
  ];
  const nullFields = required.filter(([_, v]) => v === null || v === undefined).map(([k]) => k);
  if (nullFields.length > 0) {
    return {
      ok: false,
      missingArtifacts: nullFields.map((k) => ({
        path: submitPath,
        reason: `Report field ${k} is null/undefined — artifact contents incomplete`,
      })),
    };
  }
  if (report.transcriptHashes.vaultStatePerSlot.length !== 7) {
    return {
      ok: false,
      missingArtifacts: [
        {
          path: "<stateRoot>/slot-*/vault_state_v2/*",
          reason: `Expected 7 per-slot transcript hashes, got ${report.transcriptHashes.vaultStatePerSlot.length}`,
        },
      ],
    };
  }

  return { ok: true, report };
}
