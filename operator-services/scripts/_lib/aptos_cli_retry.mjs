import { spawnSync } from "node:child_process";

export function extractTxHashFromAptosCli(text) {
  const m =
    String(text || "").match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/) ??
    String(text || "").match(/\/txn\/(0x[0-9a-fA-F]+)(?:\?|$)/);
  return m ? m[1].toLowerCase() : null;
}

export function isRetryableAptosCliTransportFailure(stdoutText, stderrText) {
  const text = `${stdoutText || ""}\n${stderrText || ""}`.toLowerCase();
  if (text.includes("move abort") || text.includes("simulation failed with status")) return false;
  return (
    text.includes("rate limit") ||
    text.includes("ratelimit") ||
    text.includes("too many requests") ||
    text.includes("http 429") ||
    text.includes("bad_status:429") ||
    text.includes("status 429") ||
    text.includes(" 429 ") ||
    text.includes("5xx") ||
    text.includes("http 500") ||
    text.includes("http 502") ||
    text.includes("http 503") ||
    text.includes("http 504")
  );
}

export async function runAptosCliWithRetry(cliArgs, options = {}) {
  const env = options.env ?? process.env;
  const retryAttempts = parsePositiveInt(
    env.EUNOMA_APTOS_CLI_RETRY_ATTEMPTS ?? env.APTOS_CLI_RETRY_ATTEMPTS,
    12,
  );
  const retryDelayMs = parseNonNegativeInt(
    env.EUNOMA_APTOS_CLI_RETRY_DELAY_MS ?? env.APTOS_CLI_RETRY_DELAY_MS,
    5000,
  );
  const label = options.label ?? "aptos";
  const stderrSink = options.stderrSink ?? process.stderr;

  let last = null;
  for (let attempt = 1; attempt <= retryAttempts; attempt += 1) {
    const run = spawnSync(options.aptosBin ?? "aptos", cliArgs, {
      cwd: options.cwd,
      encoding: options.encoding ?? "utf8",
      maxBuffer: options.maxBuffer ?? 10 * 1024 * 1024,
      env,
    });
    const stdoutText = run.stdout || "";
    const stderrText = run.stderr || "";
    const combinedOutput = `${stdoutText}\n${stderrText}`;
    const txHash = extractTxHashFromAptosCli(combinedOutput);
    last = { run, stdoutText, stderrText, combinedOutput, txHash, attempt };

    if (run.error) return last;
    if (run.status === 0 && txHash) return last;

    const retryable = isRetryableAptosCliTransportFailure(stdoutText, stderrText);
    if (!retryable || attempt >= retryAttempts) return last;

    if (stderrText) stderrSink.write(stderrText);
    stderrSink.write(
      `[${label}] retryable Aptos CLI transport failure ` +
        `(attempt ${attempt}/${retryAttempts}); backing off ${retryDelayMs * attempt}ms\n`,
    );
    await sleep(retryDelayMs * attempt);
  }
  return last;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
