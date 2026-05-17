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
import { existsSync, readFileSync } from "node:fs";
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

// Aptos addresses are 32-byte values. Short forms (`0xabcd`) are equivalent to the
// 64-hex-char left-zero-padded canonical form (`0x000...0abcd`). REST responses always
// emit the canonical form; env values from operators often use short forms. Normalize
// both sides before comparison.
export function normalizeAptosAddress(s) {
  if (typeof s !== "string") return s;
  const stripped = strip0x(s).toLowerCase();
  if (stripped.length > 64) return `0x${stripped}`; // already long; return as-is + prefix
  return `0x${stripped.padStart(64, "0")}`;
}

export function eqAptosAddress(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return normalizeAptosAddress(a) === normalizeAptosAddress(b);
}

// Safe BigInt — never throws. Returns null on malformed input.
export function safeBigInt(s) {
  if (s === null || s === undefined) return null;
  const str = String(s).trim();
  if (!/^[0-9]+$/.test(str)) return null;
  try {
    return BigInt(str);
  } catch {
    return null;
  }
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
          const balance = safeBigInt(coinRes.body.data.coin.value);
          if (balance === null) {
            missing.push({
              key: "admin_balance_unparseable",
              message: `${adminAddr} CoinStore.coin.value is not a non-negative integer (got ${coinRes.body.data.coin.value})`,
              remediation:
                "Aptos returned an unexpected CoinStore shape. Investigate the admin account manually.",
              priority: "m6d-cli",
            });
          } else {
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
      // Aptos returns asset_type either as { inner: hex } or as a plain hex string.
      const vaultAssetType =
        typeof vaultRes.body?.data?.asset_type === "string"
          ? vaultRes.body.data.asset_type
          : vaultRes.body?.data?.asset_type?.inner ?? null;
      if (assetType && vaultAssetType && !eqAptosAddress(vaultAssetType, assetType)) {
        missing.push({
          key: "vault_asset_type_mismatch",
          message: `BridgeVault.asset_type=${vaultAssetType} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
          remediation:
            "Fix EUNOMA_TESTNET_ASSET_TYPE to match the vault's actual asset_type, OR initialize the correct vault.",
          priority: "m6c-env",
        });
      } else if (assetType && !vaultAssetType) {
        missing.push({
          key: "vault_asset_type_unparseable",
          message: `BridgeVault.asset_type shape unrecognized (data=${JSON.stringify(vaultRes.body?.data?.asset_type)})`,
          remediation: "Aptos returned an unexpected BridgeVault.asset_type shape.",
          priority: "m6d-chain",
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
      // Match by event-type suffix so short-form bridge addresses (`0xabcd`) still match
      // chain-canonical padded forms (`0x000...0abcd::eunoma_bridge::DepositConfirmedV2`).
      const events = Array.isArray(dtxRes.body?.events) ? dtxRes.body.events : [];
      const ev = events.find(
        (e) => typeof e?.type === "string" && e.type.endsWith("::eunoma_bridge::DepositConfirmedV2"),
      );
      if (!ev) {
        missing.push({
          key: "deposit_confirmed_v2_event",
          message: `Deposit tx ${depositTxHash} has no event of type ...::eunoma_bridge::DepositConfirmedV2`,
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
            : ev.data?.asset_type?.inner ?? null;
        const evVaultAddr =
          typeof ev.data?.vault_addr === "string"
            ? ev.data.vault_addr
            : ev.data?.vault_addr?.inner ?? null;
        const evDepositCount = ev.data?.deposit_count;

        // Also cross-check the event type's bridge prefix matches our env.
        if (bridgeAddress) {
          const evBridgePrefix = ev.type.split("::")[0];
          if (evBridgePrefix && !eqAptosAddress(evBridgePrefix, bridgeAddress)) {
            missing.push({
              key: "deposit_event_bridge_mismatch",
              message: `DepositConfirmedV2 emitted by ${evBridgePrefix} != BRIDGE_PACKAGE_ADDRESS=${bridgeAddress}`,
              remediation: "Use the BRIDGE_PACKAGE_ADDRESS that emitted this event.",
              priority: "m6c-env",
            });
          }
        }
        if (assetType && evAssetType && !eqAptosAddress(evAssetType, assetType)) {
          missing.push({
            key: "deposit_event_asset_mismatch",
            message: `DepositConfirmedV2.asset_type=${evAssetType} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
            remediation: "Use the asset_type that the deposit actually targeted.",
            priority: "m6c-env",
          });
        } else if (assetType && !evAssetType) {
          missing.push({
            key: "deposit_event_asset_unparseable",
            message: `DepositConfirmedV2.asset_type field shape unrecognized (data=${JSON.stringify(ev.data?.asset_type)})`,
            remediation:
              "Aptos returned an unexpected asset_type shape. Inspect the deposit tx event payload manually.",
            priority: "m6d-chain",
          });
        }
        if (vaultAddress && evVaultAddr && !eqAptosAddress(evVaultAddr, vaultAddress)) {
          missing.push({
            key: "deposit_event_vault_mismatch",
            message: `DepositConfirmedV2.vault_addr=${evVaultAddr} != EUNOMA_TESTNET_VAULT_ADDRESS=${vaultAddress}`,
            remediation: "Use the vault_addr that the deposit actually targeted.",
            priority: "m6c-env",
          });
        }
        // deposit_count cross-check (BigInt-safe).
        const evCountBI = safeBigInt(evDepositCount);
        const envCountBI = safeBigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
        if (env.EUNOMA_TESTNET_DEPOSIT_COUNT) {
          if (evCountBI === null) {
            missing.push({
              key: "deposit_event_count_unparseable",
              message: `DepositConfirmedV2.deposit_count is not a non-negative integer (got ${evDepositCount})`,
              remediation:
                "Aptos returned an unexpected deposit_count shape. Inspect the deposit tx event payload manually.",
              priority: "m6d-chain",
            });
          } else if (envCountBI === null) {
            missing.push({
              key: "deposit_count_env",
              message: `EUNOMA_TESTNET_DEPOSIT_COUNT=${env.EUNOMA_TESTNET_DEPOSIT_COUNT} is not a non-negative decimal string`,
              remediation: `Set EUNOMA_TESTNET_DEPOSIT_COUNT=${evDepositCount} from the on-chain DepositConfirmedV2 event.`,
              priority: "m6c-env",
            });
          } else if (evCountBI !== envCountBI) {
            missing.push({
              key: "deposit_event_count_mismatch",
              message: `DepositConfirmedV2.deposit_count=${evCountBI} != EUNOMA_TESTNET_DEPOSIT_COUNT=${envCountBI}`,
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
        // Cross-check the deposit tx's `sender` matches EUNOMA_TESTNET_SENDER_ADDRESS.
        if (
          env.EUNOMA_TESTNET_SENDER_ADDRESS &&
          dtxRes.body?.sender &&
          !eqAptosAddress(dtxRes.body.sender, env.EUNOMA_TESTNET_SENDER_ADDRESS)
        ) {
          missing.push({
            key: "deposit_tx_sender_mismatch",
            message: `Deposit tx sender=${dtxRes.body.sender} != EUNOMA_TESTNET_SENDER_ADDRESS=${env.EUNOMA_TESTNET_SENDER_ADDRESS}`,
            remediation:
              "Use the depositor address that actually signed the deposit tx. The observer payload depends on this.",
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

  // ----- 13. Worker state — per-slot binding + cursor sync -----
  // Each worker slot persists a single `slot-{N}/vault_state_v2.json` that the M3 observer
  // updates in-place. The file binds the worker's state to the operator's intended
  // (bridge, vault, asset, sender, chain_id, dkg_epoch, vault_ek, roster_hash,
  // ca_dkg_transcript_hash) configuration AND records the chain-authoritative
  // deposit_count_observed.
  //
  // Goal.md item 4 requires fail-closed on: wrong hash, replay, stale sequence, wrong
  // bridge, wrong vault, wrong asset. We enforce this by reading every slot artifact and
  // confirming each field matches the operator's env + chain-snapshot.
  if (dkgEpoch && env.EUNOMA_TESTNET_DEPOSIT_COUNT && serviceRoot) {
    const wantCount = safeBigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
    if (wantCount === null) {
      missing.push({
        key: "deposit_count_env",
        message: `EUNOMA_TESTNET_DEPOSIT_COUNT=${env.EUNOMA_TESTNET_DEPOSIT_COUNT} is not a non-negative decimal string`,
        remediation: "Use the chain-authoritative deposit_count from DepositConfirmedV2 (a decimal integer).",
        priority: "m6c-env",
      });
    } else {
      const observedBySlot = {};
      const transcriptHashBySlot = {};
      const initTranscriptHashBySlot = {};
      for (let slot = 0; slot < 7; slot += 1) {
        const slotFile = resolve(
          serviceRoot,
          stateRoot ?? ".agent-local/eunoma-v2",
          `slot-${slot}`,
          "vault_state_v2.json",
        );
        const a = readJsonIfExists(slotFile);
        if (!a) {
          missing.push({
            key: `worker_state_slot_${slot}_missing`,
            message: `slot-${slot}/vault_state_v2.json not found at ${slotFile}`,
            remediation:
              "Run the local cluster + `npm run local:vault-state:init` to materialize the per-slot vault_state_v2 artifacts.",
            priority: "m6d-artifact",
          });
          observedBySlot[slot] = null;
          continue;
        }
        // ---- Bind-checks: every slot artifact must reference the same op intent. ----
        // dkg_epoch
        if (String(a.dkg_epoch) !== String(dkgEpoch)) {
          missing.push({
            key: `worker_state_slot_${slot}_dkg_epoch`,
            message: `slot-${slot} vault_state_v2.dkg_epoch=${a.dkg_epoch} != EUNOMA_TESTNET_DKG_EPOCH=${dkgEpoch}`,
            remediation:
              "The slot artifact was produced for a different dkg_epoch. Re-init the cluster for the current epoch, or use the matching dkg_epoch.",
            priority: "m6d-artifact",
          });
        }
        // sender_address
        if (
          env.EUNOMA_TESTNET_SENDER_ADDRESS &&
          !eqAptosAddress(a.sender_address ?? "", env.EUNOMA_TESTNET_SENDER_ADDRESS)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_sender_address`,
            message: `slot-${slot} vault_state_v2.sender_address=${a.sender_address} != EUNOMA_TESTNET_SENDER_ADDRESS=${env.EUNOMA_TESTNET_SENDER_ADDRESS}`,
            remediation:
              "Re-run `npm run local:vault-state:init` with the correct sender, or update EUNOMA_TESTNET_SENDER_ADDRESS.",
            priority: "m6d-artifact",
          });
        }
        // asset_type
        if (assetType && !eqAptosAddress(a.asset_type ?? "", assetType)) {
          missing.push({
            key: `worker_state_slot_${slot}_asset_type`,
            message: `slot-${slot} vault_state_v2.asset_type=${a.asset_type} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
            remediation:
              "Re-run `npm run local:vault-state:init` with the correct asset_type, or update EUNOMA_TESTNET_ASSET_TYPE.",
            priority: "m6d-artifact",
          });
        }
        // chain_id
        if (env.EUNOMA_TESTNET_CHAIN_ID) {
          const wantChainId = Number(env.EUNOMA_TESTNET_CHAIN_ID);
          if (Number(a.chain_id) !== wantChainId) {
            missing.push({
              key: `worker_state_slot_${slot}_chain_id`,
              message: `slot-${slot} vault_state_v2.chain_id=${a.chain_id} != EUNOMA_TESTNET_CHAIN_ID=${wantChainId}`,
              remediation:
                "Re-run `npm run local:vault-state:init` with the correct chain_id, or update EUNOMA_TESTNET_CHAIN_ID.",
              priority: "m6d-artifact",
            });
          }
        }
        // vault_ek
        if (
          env.EUNOMA_TESTNET_VAULT_EK &&
          a.vault_ek_hex &&
          !eqHexLoose(a.vault_ek_hex, env.EUNOMA_TESTNET_VAULT_EK)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_vault_ek`,
            message: `slot-${slot} vault_state_v2.vault_ek_hex differs from EUNOMA_TESTNET_VAULT_EK`,
            remediation:
              "The slot artifact's vault_ek does not match the operator's expected vault EK. Investigate before retrying.",
            priority: "m6d-artifact",
          });
        }
        // ca_dkg_transcript_hash — optional cross-check (env may not set it)
        if (
          env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH &&
          a.ca_dkg_transcript_hash &&
          !eqHexLoose(a.ca_dkg_transcript_hash, env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_ca_dkg_transcript_hash`,
            message: `slot-${slot} vault_state_v2.ca_dkg_transcript_hash differs from env`,
            remediation:
              "The slot artifact's CA DKG V2 transcript hash does not match the operator's expected one. Investigate.",
            priority: "m6d-artifact",
          });
        }
        // ---- Cursor check ----
        const observed = safeBigInt(a.deposit_count_observed);
        observedBySlot[slot] = observed === null ? null : observed.toString();
        if (observed === null) {
          missing.push({
            key: `worker_state_slot_${slot}_cursor`,
            message: `slot-${slot} vault_state_v2.deposit_count_observed is not a non-negative integer (got ${a.deposit_count_observed})`,
            remediation:
              "Slot artifact is malformed; investigate before retrying.",
            priority: "m6d-artifact",
          });
        } else if (observed < wantCount) {
          missing.push({
            key: `worker_state_slot_${slot}_cursor`,
            message: `slot-${slot} vault_state_v2.deposit_count_observed=${observed} < EUNOMA_TESTNET_DEPOSIT_COUNT=${wantCount}`,
            remediation:
              "Run `npm run local:vault-state:observe-deposit -- --aptos-node-url $APTOS_TESTNET_NODE_URL --bridge-address $BRIDGE_PACKAGE_ADDRESS --dkg-epoch $EUNOMA_TESTNET_DKG_EPOCH --vault-ek $EUNOMA_TESTNET_VAULT_EK --sender-address $EUNOMA_TESTNET_SENDER_ADDRESS --asset-type $EUNOMA_TESTNET_ASSET_TYPE --chain-id $EUNOMA_TESTNET_CHAIN_ID --ca-dkg-transcript-hash $EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH` until every slot's cursor reaches the expected count.",
            priority: "m6d-artifact",
          });
        }
        transcriptHashBySlot[slot] = a.worker_transcript_hash ?? null;
        initTranscriptHashBySlot[slot] = a.init_transcript_hash ?? null;
      }
      snapshot.workerCursors = observedBySlot;
      snapshot.workerTranscriptHashes = transcriptHashBySlot;
      snapshot.workerInitTranscriptHashes = initTranscriptHashBySlot;
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
  } else if (submit.simulated === true) {
    // goal.md item 7 requires "Chain-confirmed withdraw tx hash" — a `--simulate`
    // pass-through is not a chain-confirmed withdraw. Refuse to declare V2 complete.
    missingArtifacts.push({
      path: submitPath,
      reason:
        "Submit artifact records simulated=true (relayer ran `aptos --simulate`). goal.md item 7 requires a chain-confirmed withdraw, not a simulation. Re-run after restarting the relayer with RELAYER_SUBMIT_ENABLED=1 so the relayer actually broadcasts.",
    });
  } else if (submit.chainSuccess !== true) {
    // The coordinator's submit route fails-closed on chainSuccess=false; if we see anything
    // other than true here, the submit was not chain-confirmed.
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact records chainSuccess=${submit.chainSuccess} (expected true). Not a chain-confirmed withdraw.`,
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
  // Each slot persists a single `slot-{N}/vault_state_v2.json` with `worker_transcript_hash`
  // and `init_transcript_hash` fields. The pre-flight snapshot already validated bindings;
  // here we just confirm each file's transcript hashes are non-empty.
  const workerStateTranscripts = [];
  const workerInitTranscripts = [];
  if (dkgEpoch) {
    for (let slot = 0; slot < 7; slot += 1) {
      const slotFile = resolve(
        serviceRoot,
        stateRoot ?? ".agent-local/eunoma-v2",
        `slot-${slot}`,
        "vault_state_v2.json",
      );
      const a = readJsonIfExists(slotFile);
      if (!a) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} vault_state_v2.json not found`,
        });
        continue;
      }
      const workerHash = a.worker_transcript_hash ?? null;
      const initHash = a.init_transcript_hash ?? null;
      if (!isHex64(workerHash)) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} vault_state_v2.worker_transcript_hash is missing or malformed (${workerHash})`,
        });
      } else {
        workerStateTranscripts.push({ slot, path: slotFile, transcriptHash: workerHash });
      }
      if (!isHex64(initHash)) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} vault_state_v2.init_transcript_hash is missing or malformed (${initHash})`,
        });
      } else {
        workerInitTranscripts.push({ slot, path: slotFile, initTranscriptHash: initHash });
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

  // Vault state init transcript hash — use the per-slot init_transcript_hash. All 7 slots
  // must agree (the worker code pins init_transcript_hash to the canonical final hash via
  // vault_state_v2_init_finalize). If they disagree, that's a hard miss.
  let vaultStateInitHash = null;
  if (workerInitTranscripts.length > 0) {
    const set = new Set(workerInitTranscripts.map((w) => w.initTranscriptHash));
    if (set.size !== 1) {
      missingArtifacts.push({
        path: "<stateRoot>/slot-*/vault_state_v2.json",
        reason: `Per-slot init_transcript_hash values disagree across slots: ${[...set].join(", ")}. All 7 workers must agree on the canonical init transcript hash.`,
      });
    } else {
      vaultStateInitHash = [...set][0];
    }
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
    ["depositEventProof", report.depositEventProof],
    ["transcriptHashes.caPayload", report.transcriptHashes.caPayload],
    ["transcriptHashes.caDkgV2Roster", report.transcriptHashes.caDkgV2Roster],
    ["transcriptHashes.frostDkgV2Roster", report.transcriptHashes.frostDkgV2Roster],
    ["transcriptHashes.deoperatorRoster", report.transcriptHashes.deoperatorRoster],
    ["transcriptHashes.quorum", report.transcriptHashes.quorum],
    ["transcriptHashes.vaultStateInit", report.transcriptHashes.vaultStateInit],
    ["transcriptHashes.mpcca", report.transcriptHashes.mpcca],
    ["transcriptHashes.submit", report.transcriptHashes.submit],
    ["invariants.chainSuccess", report.invariants.chainSuccess],
  ];
  // Reject null/undefined. Also reject invariants.chainSuccess !== true explicitly
  // (false would otherwise sneak through the null-only check).
  const badFields = required
    .filter(([k, v]) => {
      if (v === null || v === undefined) return true;
      if (k === "invariants.chainSuccess" && v !== true) return true;
      return false;
    })
    .map(([k, v]) => [k, v]);
  if (badFields.length > 0) {
    return {
      ok: false,
      missingArtifacts: badFields.map(([k, v]) => ({
        path: submitPath,
        reason: `Report field ${k} is ${v === null ? "null" : v === undefined ? "undefined" : String(v)} — required value missing or wrong`,
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
