import { configFromEnv, type RelayerConfig } from "../config.js";
import { buildRelayerServer, createAptosCliSubmitter, type RelayerServerOptions } from "../server.js";
import { createDepositV3Submitter } from "../deposit_v3_submitter.js";
import { createGasGuard } from "../gas_guard.js";
import { FileSubmitJournal } from "../submit_journal.js";
import { VaultSequencer } from "../vault_sequencer.js";
import { DEFAULT_WITHDRAW_V3_MAX_FEE_OCTAS, createWithdrawV3Submitter } from "../withdraw_v3_submitter.js";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

let cfg: RelayerConfig;
try {
  cfg = configFromEnv();
} catch (err) {
  // RELAYER_BEARER_TOKEN missing (or other config rejection). Surface the
  // message verbatim — it tells the operator EXACTLY what env var to set.
  console.error(`relayer config error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
}

if (!cfg.bridgePackageAddress) {
  console.error(
    "BRIDGE_PACKAGE_ADDRESS env var is not set — relayer cannot encode the --function-id for `aptos move run`.",
  );
  process.exit(2);
}
const bridgePackageAddress = cfg.bridgePackageAddress;

const submitter = createAptosCliSubmitter(bridgePackageAddress, cfg.adminProfile, {
  submit: cfg.submitEnabled,
});

const v3Options = buildV3Options(cfg);

const server = buildRelayerServer({
  bearerToken: cfg.bearerToken,
  submitter,
  ...v3Options,
});

await server.listen({ host: cfg.host, port: cfg.port });

if (cfg.allowNoAuth) {
  // Loud warning: the operator opted out of bearer-token auth via
  // RELAYER_ALLOW_NO_AUTH=1. Only valid for local-dev smoke scripts.
  console.warn(
    "[relayer] WARNING: RELAYER_ALLOW_NO_AUTH=1 — submit route is UNAUTHENTICATED. Local-dev only.",
  );
}

console.log(
  `relayer listening on ${cfg.host}:${cfg.port} (submitEnabled=${cfg.submitEnabled} bearerAuth=${
    cfg.bearerToken ? "on" : "off"
  } adminProfile=${cfg.adminProfile ?? "(unset)"} relayerProfile=${cfg.relayerProfile ?? "(unset)"} v3=${
    v3Options.withdrawV3Submitter !== undefined && v3Options.depositV3Submitter !== undefined ? "on" : "off"
  } bridgePackage=${bridgePackageAddress})`,
);

function buildV3Options(
  config: RelayerConfig,
): Pick<
  RelayerServerOptions,
  "withdrawV3Submitter" | "depositV3Submitter" | "gasGuard" | "sequencer" | "journal"
> {
  if (!config.relayerProfile) {
    console.warn("[relayer] RELAYER_PROFILE unset; split-v3 relayer routes are disabled.");
    return {};
  }

  const missing: string[] = [];
  if (!config.aptosNodeUrl) missing.push("APTOS_NODE_URL");
  if (!config.reserveAccountAddress) missing.push("RESERVE_ACCOUNT_ADDRESS");
  if (config.maxGasPriceOctas === undefined) missing.push("RELAYER_MAX_GAS_PRICE_OCTAS");
  if (config.reserveMinBalanceOctas === undefined) missing.push("RELAYER_RESERVE_MIN_BALANCE_OCTAS");
  if (missing.length > 0) {
    throw new Error(
      `split-v3 relayer routes require ${missing.join(", ")} when RELAYER_PROFILE is set`,
    );
  }

  const stateRoot = process.env.EUNOMA_STATE_ROOT || process.env.EUNOMA_LOCAL_STATE_ROOT || ".agent-local/eunoma-v2";
  const journalPath = resolve(process.cwd(), stateRoot, "relayer", "submit_journal.jsonl");
  const cliFailureLogPath = resolve(process.cwd(), stateRoot, "relayer", "aptos_cli_failures.log");
  mkdirSync(dirname(journalPath), { recursive: true });
  const cliFailureSink = {
    write: (chunk: string) => {
      process.stderr.write(chunk);
      appendFileSync(cliFailureLogPath, chunk);
    },
  };
  const reserveMinBalanceOctas =
    config.reserveMinBalanceOctas! > DEFAULT_WITHDRAW_V3_MAX_FEE_OCTAS
      ? config.reserveMinBalanceOctas!
      : DEFAULT_WITHDRAW_V3_MAX_FEE_OCTAS;

  return {
    withdrawV3Submitter: createWithdrawV3Submitter(bridgePackageAddress, config.relayerProfile, {
      submit: config.submitEnabled,
      stderrSink: cliFailureSink,
    }),
    depositV3Submitter: createDepositV3Submitter(bridgePackageAddress, config.relayerProfile, {
      submit: config.submitEnabled,
    }),
    gasGuard: createGasGuard({
      aptosNodeUrl: config.aptosNodeUrl!,
      reserveAccountAddress: config.reserveAccountAddress!,
      maxGasPriceOctas: config.maxGasPriceOctas!,
      reserveMinBalanceOctas,
    }),
    // CP5 RC5: ONE GLOBAL VaultSequencer, constructed exactly once and shared across every
    // /v3/relayer/submit/withdraw request regardless of asset. `vault_sequence` is a single
    // global counter on VaultCoreV4 (preserves withdraw public[7] FROST layout = 5-of-7), so
    // all assets must serialize through this one instance. Per-asset sharding is FORBIDDEN
    // (V4.1 deferral) — see vault_sequencer.ts header.
    sequencer: new VaultSequencer(),
    journal: new FileSubmitJournal({ filePath: journalPath }),
  };
}
