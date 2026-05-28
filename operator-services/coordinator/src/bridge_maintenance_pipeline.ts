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
 * Concurrency model: **coalesce-on-contention**. If a previous deposit's pipeline is still
 * running when a new deposit arrives, `triggerBridgeMaintenance` is a no-op for the new
 * deposit. Rationale: the in-flight pipeline will see the new deposit when it rebuilds the
 * commitment tree from chain events (the tree builder reads chain DepositConfirmedV2 events,
 * not a queue). Worst case the systemd timer's next cycle picks up any deposit that
 * arrived after both the most recent triggered pipeline started AND the most recent
 * commitment-tree build completed — which is exactly the failure mode the timer was
 * designed to backstop.
 *
 * Error handling: this runs after the HTTP reply has flushed, so there is
 * no caller to bubble errors to. ALL failure modes are caught and logged; the function NEVER
 * throws. The next pipeline trigger (or the systemd timer) is the retry mechanism.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
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
}

/**
 * In-flight tracker for coalesce-on-contention semantics. A single Promise per server
 * instance — if a pipeline is already running, new triggers no-op.
 */
let pipelineInFlight: Promise<void> | null = null;

/**
 * Trigger the bridge maintenance pipeline asynchronously. Returns immediately. If a pipeline
 * is already in flight, the call is a no-op (coalesce-on-contention).
 *
 * Safe to call from a response `finish` handler — never throws, never blocks,
 * always logs.
 */
export function triggerBridgeMaintenance(ctx: BridgeMaintenanceContext): void {
  if (pipelineInFlight) {
    ctx.logger.info(
      { module: "bridge_maintenance_pipeline" },
      "bridge maintenance pipeline already in flight — coalescing trigger (no-op)",
    );
    return;
  }
  pipelineInFlight = runPipeline(ctx)
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
    });
}

/**
 * Test-only: reset the in-flight tracker. Production code MUST NOT call this — the
 * tracker exists specifically to prevent concurrent shell-script runs.
 */
export function __resetPipelineInFlightForTests(): void {
  pipelineInFlight = null;
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
  emitJournalLine("bridge maintenance pipeline spawning refresh_known_root_cycle.sh", {
    scriptPath: absoluteScriptPath,
    cwd: repoRoot,
  });
  logger.info(
    { module: "bridge_maintenance_pipeline", scriptPath: absoluteScriptPath, cwd: repoRoot },
    "bridge maintenance pipeline spawning refresh_known_root_cycle.sh",
  );
  return new Promise<void>((resolve) => {
    let child;
    try {
      child = spawn("bash", [absoluteScriptPath], {
        cwd: repoRoot,
        // Forward env so APTOS_NODE_URL / CA_DKG_V2_ROSTER_JSON_PATH / coordinator
        // bearer tokens flow through to the orchestrator scripts.
        env: { ...process.env, EUNOMA_REPO_ROOT: repoRoot },
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
