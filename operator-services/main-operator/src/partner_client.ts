// HTTP fan-out from main-op to N partner ops.
//
// Production path uses native fetch / undici. Result handling:
//   - successful 200 with sig → record in result vector
//   - 4xx / 5xx / network error → record null (slot stays empty)
//   - timeout enforced via AbortController

import { CoSignRequestBody } from "@eunoma/partner-operator/src/verify/cosign_request.js";
import { WithdrawCoSignRequestBody } from "@eunoma/partner-operator/src/verify/withdraw_cosign_request.js";

export interface PartnerCoSignResult {
  slot: number;
  signature_bytes: Uint8Array | null;
  pubkey_hex?: string;
  message_bytes_hash_hex?: string;
  error?: string;
}

export async function callPartnerCoSign(
  url: string,
  body: CoSignRequestBody,
  timeout_ms: number,
  bearer_token: string,
): Promise<PartnerCoSignResult> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout_ms);
  try {
    const res = await fetch(`${url}/v1/cosign/deposit`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bearer_token}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (res.status !== 200) {
      const txt = await res.text().catch(() => "");
      return { slot: -1, signature_bytes: null, error: `http_${res.status}:${txt.slice(0, 200)}` };
    }
    const j = (await res.json()) as {
      slot: number;
      signature_hex: string;
      pubkey_hex: string;
      message_bytes_hash_hex: string;
    };
    return {
      slot: j.slot,
      signature_bytes: new Uint8Array(Buffer.from(j.signature_hex, "hex")),
      pubkey_hex: j.pubkey_hex,
      message_bytes_hash_hex: j.message_bytes_hash_hex,
    };
  } catch (err: any) {
    return { slot: -1, signature_bytes: null, error: err?.message ?? "fetch_failed" };
  } finally {
    clearTimeout(t);
  }
}

export async function fanOutCoSignRequests(
  partner_urls: string[],
  partner_bearer_tokens: string[],
  body: CoSignRequestBody,
  timeout_ms: number,
): Promise<PartnerCoSignResult[]> {
  if (partner_urls.length !== partner_bearer_tokens.length) {
    throw new Error(
      `partner_urls (${partner_urls.length}) and partner_bearer_tokens (${partner_bearer_tokens.length}) length mismatch`,
    );
  }
  return Promise.all(
    partner_urls.map((url, i) =>
      callPartnerCoSign(url, body, timeout_ms, partner_bearer_tokens[i]),
    ),
  );
}

export async function callPartnerWithdrawCoSign(
  url: string,
  body: WithdrawCoSignRequestBody,
  timeout_ms: number,
  bearer_token: string,
): Promise<PartnerCoSignResult> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout_ms);
  try {
    const res = await fetch(`${url}/v1/cosign/withdraw`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bearer_token}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (res.status !== 200) {
      const txt = await res.text().catch(() => "");
      return { slot: -1, signature_bytes: null, error: `http_${res.status}:${txt.slice(0, 200)}` };
    }
    const j = (await res.json()) as {
      slot: number;
      signature_hex: string;
      pubkey_hex: string;
      message_bytes_hash_hex: string;
    };
    return {
      slot: j.slot,
      signature_bytes: new Uint8Array(Buffer.from(j.signature_hex, "hex")),
      pubkey_hex: j.pubkey_hex,
      message_bytes_hash_hex: j.message_bytes_hash_hex,
    };
  } catch (err: any) {
    return { slot: -1, signature_bytes: null, error: err?.message ?? "fetch_failed" };
  } finally {
    clearTimeout(t);
  }
}

export async function fanOutWithdrawCoSignRequests(
  partner_urls: string[],
  partner_bearer_tokens: string[],
  body: WithdrawCoSignRequestBody,
  timeout_ms: number,
): Promise<PartnerCoSignResult[]> {
  if (partner_urls.length !== partner_bearer_tokens.length) {
    throw new Error(
      `partner_urls (${partner_urls.length}) and partner_bearer_tokens (${partner_bearer_tokens.length}) length mismatch`,
    );
  }
  return Promise.all(
    partner_urls.map((url, i) =>
      callPartnerWithdrawCoSign(url, body, timeout_ms, partner_bearer_tokens[i]),
    ),
  );
}
