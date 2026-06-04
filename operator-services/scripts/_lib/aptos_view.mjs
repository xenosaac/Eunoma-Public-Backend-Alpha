// Helper for Aptos /v1/view queries. Used by the testnet rotation script to
// read on-chain DeoperatorConfigV2 state before submitting a rotation tx.

export async function aptosView(nodeUrl, functionId, typeArgs, args) {
  const url = new URL("/v1/view", nodeUrl).toString();
  const attempts = positiveInt(
    process.env.EUNOMA_APTOS_VIEW_RETRY_ATTEMPTS ?? process.env.APTOS_VIEW_RETRY_ATTEMPTS,
    8,
  );
  const delayMs = positiveInt(
    process.env.EUNOMA_APTOS_VIEW_RETRY_DELAY_MS ?? process.env.APTOS_VIEW_RETRY_DELAY_MS,
    5_000,
  );
  const maxDelayMs = positiveInt(
    process.env.EUNOMA_APTOS_VIEW_RETRY_MAX_DELAY_MS ?? process.env.APTOS_VIEW_RETRY_MAX_DELAY_MS,
    60_000,
  );
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          function: functionId,
          type_arguments: typeArgs ?? [],
          arguments: args ?? [],
        }),
      });
      const text = await res.text();
      if (!res.ok) {
        lastError = new Error(`aptos /v1/view ${functionId} -> ${res.status}: ${text}`);
        if (isRetryableStatus(res.status) && attempt < attempts) {
          await sleep(Math.min(delayMs * attempt, maxDelayMs));
          continue;
        }
        throw lastError;
      }
      try {
        return JSON.parse(text);
      } catch (err) {
        throw new Error(`aptos /v1/view ${functionId} returned non-JSON: ${text}`);
      }
    } catch (err) {
      lastError = err;
      if (attempt < attempts && isRetryableFetchError(err)) {
        await sleep(Math.min(delayMs * attempt, maxDelayMs));
        continue;
      }
      throw err;
    }
  }
  throw lastError ?? new Error(`aptos /v1/view ${functionId} failed`);
}

function isRetryableStatus(status) {
  return status === 429 || status >= 500;
}

function isRetryableFetchError(err) {
  const text = String(err?.message ?? err).toLowerCase();
  return (
    text.includes("429") ||
    text.includes("rate limit") ||
    text.includes("ratelimit") ||
    text.includes("too many requests") ||
    text.includes("fetch failed") ||
    text.includes("econnreset") ||
    text.includes("etimedout")
  );
}

function positiveInt(raw, fallback) {
  const n = Number.parseInt(String(raw ?? ""), 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
