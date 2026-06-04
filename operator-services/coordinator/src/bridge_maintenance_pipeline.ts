/**
 * Bridge maintenance pipeline — NORMALIZE plan (2026-05-27), Agent D scope.
 *
 * The post-observe fan-out: after `/v2/vault_state/observe_deposit` ships its 200 reply,
 * the coordinator kicks off `ops/scripts/refresh_known_root_cycle.sh` so that
 *
 *   normalize current route → fetch_deposit_tx_hashes → build staged tree
 *     → if staged root is new: rollover → normalize
 *     → record_known_root → publish staged tree
 *
 * runs as an event-driven pipeline instead of waiting on the systemd timer. The shell wrapper
 * is idempotent (each step checks chain state first), so triggering it on every deposit is
 * cheap when there's no work to do. The public `commitment_tree_v2.json` is replaced only
 * after the staged root is route-ready; on failure the old public root remains visible.
 *
 * Concurrency model: **single-flight with queued rerun**. If a previous deposit's pipeline is
 * still running when a new deposit arrives, the new trigger is coalesced into one pending rerun
 * instead of starting a second concurrent shell script. The active run finishes, then the pending
 * rerun starts immediately and picks up any leaves observed after the active run staged its tree.
 *
 * Error handling: this runs after the HTTP reply has flushed, so there is
 * no caller to bubble errors to. ALL failure modes are caught and logged; the function NEVER
 * throws. A queued rerun, the next pipeline trigger, or the systemd timer is the retry mechanism.
 *
 * The triggering deposit tx hash is forwarded into the wrapper when available. This closes
 * the REST-vs-indexer race: observe_deposit proves the concrete tx by REST before GraphQL
 * account_transactions may list it, so the first event-driven refresh can ingest it directly.
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { FastifyBaseLogger } from "fastify";

export interface BridgeMaintenanceContext {
  /**
   * Repo root containing `ops/scripts/refresh_known_root_cycle.sh`. The shell script uses
   * this as `EUNOMA_REPO_ROOT` when the coordinator process provides it, while retaining
   * the alpha-box default path for systemd/manual runs.
   */
  repoRoot: string;
  /**
   * Logger instance from the request that triggered this pipeline. The pipeline's output
   * (rollover/normalize/known_root progress) is streamed through this logger so deploy
   * supervisors can correlate pipeline runs with the originating deposit request.
   */
  logger: FastifyBaseLogger;
  /**
   * Concrete deposit tx hashes already validated by the observe-deposit caller. The wrapper
   * persists them into a retry queue before staging so a failed publication run does not lose
   * the just-confirmed deposit while waiting for indexer catch-up.
   */
  extraDepositTxHashes?: string[];
  /**
   * CP5 RC4: state root holding the init_v4 asset registry
   * (`<stateRoot>/coordinator/asset_registry.json`). The rollover/normalize loop filters this
   * registry to `status==ACTIVE` so a DORMANT stablecoin can never abort the batch. Defaults to
   * `EUNOMA_STATE_ROOT` when omitted (production wiring); tests inject an explicit path.
   */
  stateRoot?: string;
}

/**
 * CP5 RC4: one registry row as persisted by the init_v4 artifact. Only the routing fields the
 * rollover/normalize loop needs (asset_addr + lifecycle status); no secrets.
 */
interface MaintenanceAssetRow {
  metadata: string; // asset_addr (FA Metadata object-address)
  status: "DORMANT" | "ACTIVE" | "PAUSED";
}

/**
 * CP5 RC4: load the init_v4 asset registry and return ONLY the ACTIVE asset addresses. Returns:
 *   - `string[]` (possibly empty) when the registry artifact is present + parseable;
 *   - `null` when the registry is absent / unreadable / malformed (caller falls back to the
 *     legacy single-asset behavior — spawn the wrapper without an ACTIVE-asset filter — so a
 *     not-yet-seeded registry never bricks maintenance).
 *
 * The filter is the load-bearing RC4 invariant: a DORMANT (or PAUSED) stablecoin is dropped from
 * the rollover/normalize batch, so its un-activated CA store can't make the whole cycle abort.
 */
export function loadActiveAssetAddrs(stateRoot: string | undefined): string[] | null {
  if (!stateRoot) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(stateRoot, "coordinator", "asset_registry.json"), "utf8"));
  } catch {
    return null;
  }
  const rows = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { assets?: unknown }).assets)
      ? (raw as { assets: unknown[] }).assets
      : null;
  if (!rows) return null;
  const active: string[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return null;
    const r = row as Record<string, unknown>;
    if (typeof r.metadata !== "string") return null;
    const s = r.status;
    // Early-return-on-non-ACTIVE: only status===ACTIVE (1 / "ACTIVE") rows enter the batch.
    if (s === 1 || s === "ACTIVE") active.push(r.metadata);
  }
  return active;
}

/**
 * In-flight tracker for single-flight semantics. A single Promise per server instance prevents
 * concurrent shell-script runs. New triggers received while the script is active are merged into
 * `pipelineRerunPending` and drained after the active run exits.
 */
let pipelineInFlight: Promise<void> | null = null;
let pipelineRerunPending: BridgeMaintenanceContext | null = null;

/**
 * Trigger the bridge maintenance pipeline asynchronously. Returns immediately. If a pipeline is
 * already in flight, the call schedules one follow-up rerun instead of starting a concurrent job.
 *
 * Safe to call from a response `finish` handler — never throws, never blocks,
 * always logs.
 */
export function triggerBridgeMaintenance(ctx: BridgeMaintenanceContext): void {
  if (pipelineInFlight) {
    pipelineRerunPending = mergeRerunContext(pipelineRerunPending, ctx);
    ctx.logger.info(
      {
        module: "bridge_maintenance_pipeline",
        pendingExtraDepositTxHashCount: normalizeTxHashes(
          pipelineRerunPending.extraDepositTxHashes ?? [],
        ).length,
      },
      "bridge maintenance pipeline already in flight — queued rerun",
    );
    return;
  }
  pipelineInFlight = drainPipelineRuns(ctx)
    .catch((err) => {
      // Defense in depth — `runPipeline` should never reject because it catches its own
      // errors and logs them, but an async response-finish trigger can still surface
      // an unhandledRejection in Node. Swallow + log here so we can't take the process down.
      ctx.logger.error(
        { module: "bridge_maintenance_pipeline", err: serializeError(err) },
        "bridge maintenance pipeline rejected unexpectedly (suppressed)",
      );
    })
    .finally(() => {
      pipelineInFlight = null;
      pipelineRerunPending = null;
    });
}

/**
 * Test-only: reset the in-flight tracker. Production code MUST NOT call this — the
 * tracker exists specifically to prevent concurrent shell-script runs.
 */
export function __resetPipelineInFlightForTests(): void {
  pipelineInFlight = null;
  pipelineRerunPending = null;
}

async function drainPipelineRuns(initialCtx: BridgeMaintenanceContext): Promise<void> {
  let nextCtx: BridgeMaintenanceContext | null = initialCtx;
  while (nextCtx) {
    const currentCtx = nextCtx;
    pipelineRerunPending = null;
    await runPipeline(currentCtx);
    const pendingCtx = consumePendingRerun();
    if (pendingCtx) {
      pendingCtx.logger.info(
        {
          module: "bridge_maintenance_pipeline",
          extraDepositTxHashCount: normalizeTxHashes(
            pendingCtx.extraDepositTxHashes ?? [],
          ).length,
        },
        "bridge maintenance pipeline draining queued rerun",
      );
    }
    nextCtx = pendingCtx;
  }
}

function consumePendingRerun(): BridgeMaintenanceContext | null {
  const pendingCtx = pipelineRerunPending;
  pipelineRerunPending = null;
  return pendingCtx;
}

function mergeRerunContext(
  existing: BridgeMaintenanceContext | null,
  incoming: BridgeMaintenanceContext,
): BridgeMaintenanceContext {
  if (!existing) return incoming;
  return {
    ...existing,
    repoRoot: incoming.repoRoot || existing.repoRoot,
    logger: incoming.logger,
    stateRoot: incoming.stateRoot ?? existing.stateRoot,
    extraDepositTxHashes: normalizeTxHashes([
      ...(existing.extraDepositTxHashes ?? []),
      ...(incoming.extraDepositTxHashes ?? []),
    ]),
  };
}

/**
 * Run the shell wrapper once. Catches all errors and logs them. Resolves on script exit
 * (status 0 or non-zero) and on spawn failure.
 */
async function runPipeline(ctx: BridgeMaintenanceContext): Promise<void> {
  const scriptPath = "ops/scripts/refresh_known_root_cycle.sh";
  const repoRoot = resolveRepoRoot(ctx.repoRoot, scriptPath);
  const absoluteScriptPath = resolve(repoRoot, scriptPath);
  const logger = ctx.logger;
  const extraDepositTxHashes = normalizeTxHashes(ctx.extraDepositTxHashes ?? []);

  // CP5 RC4: filter the asset registry to status==ACTIVE BEFORE spawning the rollover/normalize
  // wrapper. A DORMANT (or PAUSED) stablecoin must NOT be able to abort the batch — only ACTIVE
  // assets enter the loop. Three cases:
  //   - registry present + has ACTIVE assets → forward EUNOMA_ACTIVE_ASSET_ADDRS to the wrapper.
  //   - registry present + ZERO ACTIVE assets → EARLY-RETURN (nothing to roll over; skip spawn).
  //   - registry absent/malformed (null) → legacy single-asset behavior: spawn without the filter
  //     (a not-yet-seeded registry must never brick maintenance).
  const stateRoot = ctx.stateRoot ?? process.env.EUNOMA_STATE_ROOT ?? undefined;
  const activeAssetAddrs = loadActiveAssetAddrs(stateRoot);
  if (activeAssetAddrs !== null && activeAssetAddrs.length === 0) {
    emitJournalLine(
      "bridge maintenance pipeline skipped — registry has no ACTIVE assets (early-return)",
      { stateRoot },
    );
    logger.info(
      { module: "bridge_maintenance_pipeline", stateRoot },
      "bridge maintenance pipeline skipped — registry has no ACTIVE assets (early-return)",
    );
    return;
  }
  const activeAssetCount = activeAssetAddrs?.length ?? null;

  emitJournalLine("bridge maintenance pipeline spawning refresh_known_root_cycle.sh", {
    scriptPath: absoluteScriptPath,
    cwd: repoRoot,
    extraDepositTxHashCount: extraDepositTxHashes.length,
    activeAssetCount,
  });
  logger.info(
    {
      module: "bridge_maintenance_pipeline",
      scriptPath: absoluteScriptPath,
      cwd: repoRoot,
      extraDepositTxHashCount: extraDepositTxHashes.length,
      activeAssetCount,
    },
    "bridge maintenance pipeline spawning refresh_known_root_cycle.sh",
  );
  return new Promise<void>((resolve) => {
    let child;
    try {
      child = spawn("bash", [absoluteScriptPath], {
        cwd: repoRoot,
        // Forward env so APTOS_NODE_URL / CA_DKG_V2_ROSTER_JSON_PATH / coordinator
        // bearer tokens flow through to the orchestrator scripts.
        env: {
          ...process.env,
          EUNOMA_REPO_ROOT: repoRoot,
          ...(extraDepositTxHashes.length > 0
            ? { EUNOMA_EXTRA_DEPOSIT_TX_HASHES: extraDepositTxHashes.join(",") }
            : {}),
          // CP5 RC4: the ACTIVE-only asset routing keys the rollover/normalize loop must iterate.
          // Empty/absent only when the registry is missing (legacy single-asset fallback above).
          ...(activeAssetAddrs && activeAssetAddrs.length > 0
            ? { EUNOMA_ACTIVE_ASSET_ADDRS: activeAssetAddrs.join(",") }
            : {}),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      emitJournalLine("failed to spawn refresh_known_root_cycle.sh", {
        err: serializeError(err),
      });
      logger.error(
        { module: "bridge_maintenance_pipeline", err: serializeError(err) },
        "failed to spawn refresh_known_root_cycle.sh",
      );
      resolve();
      return;
    }

    let stdoutBuf = "";
    let stderrBuf = "";

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");

    child.stdout?.on("data", (chunk: string) => {
      stdoutBuf = drainLines(stdoutBuf + chunk, (line) => {
        emitJournalLine(line, { stream: "stdout" });
        logger.info({ module: "bridge_maintenance_pipeline", stream: "stdout" }, line);
      });
    });
    child.stderr?.on("data", (chunk: string) => {
      stderrBuf = drainLines(stderrBuf + chunk, (line) => {
        // Treat script stderr as informational, not error — the wrapper deliberately uses
        // stderr for progress messages (echo to >&2 in some sub-steps).
        emitJournalLine(line, { stream: "stderr" });
        logger.info({ module: "bridge_maintenance_pipeline", stream: "stderr" }, line);
      });
    });

    child.on("error", (err) => {
      emitJournalLine("refresh_known_root_cycle.sh child emitted error event", {
        err: serializeError(err),
      });
      logger.error(
        { module: "bridge_maintenance_pipeline", err: serializeError(err) },
        "refresh_known_root_cycle.sh child emitted error event",
      );
      // resolve() is wired through 'exit' below; if 'error' fires before 'exit', resolve
      // here so we don't hang the pipelineInFlight tracker.
      resolve();
    });

    child.on("exit", (code, signal) => {
      // Flush any trailing line fragments without a newline.
      if (stdoutBuf.length > 0) {
        emitJournalLine(stdoutBuf, { stream: "stdout" });
        logger.info({ module: "bridge_maintenance_pipeline", stream: "stdout" }, stdoutBuf);
        stdoutBuf = "";
      }
      if (stderrBuf.length > 0) {
        emitJournalLine(stderrBuf, { stream: "stderr" });
        logger.info({ module: "bridge_maintenance_pipeline", stream: "stderr" }, stderrBuf);
        stderrBuf = "";
      }
      if (code === 0) {
        emitJournalLine("refresh_known_root_cycle.sh completed successfully", { code });
        logger.info(
          { module: "bridge_maintenance_pipeline", code },
          "refresh_known_root_cycle.sh completed successfully",
        );
      } else {
        emitJournalLine("refresh_known_root_cycle.sh exited non-zero (next deposit or timer will retry)", {
          code,
          signal,
        });
        logger.warn(
          { module: "bridge_maintenance_pipeline", code, signal },
          "refresh_known_root_cycle.sh exited non-zero (next deposit or timer will retry)",
        );
      }
      resolve();
    });
  });
}

function emitJournalLine(message: string, fields: Record<string, unknown> = {}): void {
  const suffix = Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : "";
  console.log(`[bridge_maintenance_pipeline] ${new Date().toISOString()} ${message}${suffix}`);
}

function resolveRepoRoot(repoRoot: string, scriptPath: string): string {
  const normalized = resolve(repoRoot);
  for (const candidate of [normalized, resolve(normalized, "..")]) {
    if (existsSync(resolve(candidate, scriptPath))) {
      return candidate;
    }
  }
  return normalized;
}

function normalizeTxHashes(input: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of input) {
    const normalized = value.trim().toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(normalized) || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

/**
 * Pull complete lines out of `buf` and dispatch each via `emit`. Return the trailing
 * fragment that has no terminating newline (or the empty string).
 */
function drainLines(buf: string, emit: (line: string) => void): string {
  let rest = buf;
  while (true) {
    const idx = rest.indexOf("\n");
    if (idx < 0) return rest;
    const line = rest.slice(0, idx).replace(/\r$/, "");
    if (line.length > 0) emit(line);
    rest = rest.slice(idx + 1);
  }
}

/**
 * Serialize an unknown error for structured logging. `pino` won't recurse into class
 * instances that aren't Error subclasses, so we flatten to a plain object first.
 */
function serializeError(err: unknown): Record<string, unknown> {
  if (err instanceof Error) {
    return { name: err.name, message: err.message, stack: err.stack };
  }
  return { message: String(err) };
}
