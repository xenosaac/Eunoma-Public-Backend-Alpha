/**
 * M10-c — POST /v2/balance/decrypt.
 *
 * Coordinator fan-out + Lagrange-coefficient helper for the balance-decryption
 * surface. Steps:
 *   1. Parse the orchestrator's request (`dkgEpoch`, `vaultAddress`, `assetType`,
 *      `oldBalanceDHex`, `requestId`). The body MUST NOT carry `aptosNodeUrl`
 *      or `caDkgV2Roster` — both come from coordinator config only (M10-l
 *      codex P1 — a request-controlled URL becomes a chosen-D oracle for
 *      `dk_share · D'`, and a request-controlled roster is SSRF that breaks
 *      the 5-of-7 invariant).
 *   2. Run the forbidden-key regex guard on the inbound body BEFORE any worker
 *      dispatch — any plaintext amount/blind/secret/dk/merkle/sender key fails
 *      400 immediately.
 *   3. Select the lowest-5-of-7 quorum from the CA DKG V2 roster (same
 *      `lowestEligibleSlots` selector used by `/v2/derive/vault_ek/start`
 *      and `/v2/derive/ca_registration/start` MPCCA fan-out). Source: the
 *      coordinator's configured roster via `opts.getDefaultRoster()`.
 *   4. Fan out in parallel to each selected worker's `/v2/balance/decrypt_partial`
 *      endpoint via the injected `SingleNodeForwarder`.
 *   5. For each worker response: re-derive the M10-b canonical bytes from the
 *      coordinator's known inputs + the worker's returned partials and
 *      recompute SHA-256. Reject any slot whose returned `signature` doesn't
 *      match byte-for-byte, OR whose `transcriptDomain` is wrong.
 *   6. Compute Lagrange coefficients at x=0 over the selected quorum's slot
 *      ids (`lagrangeCoefficientsAtZero` from deop-protocol, encoded with
 *      `scalarHexFromBigint`).
 *   7. Run the forbidden-key guard on the assembled outbound response
 *      (defense-in-depth — guards against a worker emitting a forbidden
 *      key in a future protocol revision).
 *   8. Return 200 with `{ slots: [...], lagrangeCoeffs: [...] }`.
 *
 * Failure modes (HTTP status):
 *   - 400 `forbidden_field:<path>`           — guard triggered (inbound or outbound)
 *   - 400 `invalid_request:<reason>`         — shape validation
 *   - 400 `stale_dkg_epoch` / `under_quorum` — roster mismatch
 *   - 502 `worker_forward_rejected`          — network error talking to a worker
 *   - 502 `worker_unexpected_status`         — non-200 from a worker
 *   - 502 `signature_verification_failed`    — SHA-256 transcript mismatch
 *   - 500 `internal_error`                   — anything else
 *
 * The route is stateless (no disk writes); the workers persist their own
 * transcripts via the M10-b zeroize path.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { createHash } from "node:crypto";
import {
  type CaDkgV2Roster,
  lagrangeCoefficientsAtZero,
  scalarHexFromBigint,
  DEOPERATOR_THRESHOLD,
} from "@eunoma/deop-protocol";
import {
  type BalanceDecryptPartialFromWorker,
  type BalanceDecryptRequest,
  type BalanceDecryptResponse,
  BALANCE_DECRYPT_TRANSCRIPT_DOMAIN,
  assertNoForbiddenKeys,
} from "@eunoma/shared";

/**
 * Minimal subset of the coordinator's per-worker forwarder shape that
 * `/v2/balance/decrypt` needs. Mirrors `SingleNodeForwarder` from `server.ts`
 * without taking on the full type-import cycle.
 */
export interface RoutableRosterNode {
  slot: number;
  endpoint: string;
}
export interface RoutableRoster {
  nodes: RoutableRosterNode[];
}
export interface ForwarderResult {
  slot: number;
  ok: boolean;
  statusCode?: number;
  error?: string;
  body?: unknown;
}
export type BalanceDecryptForwarder = (
  path: string,
  body: unknown,
  roster: RoutableRoster,
  slot: number,
  signal?: AbortSignal,
) => Promise<ForwarderResult>;

/** Per-slot timeout for the worker fan-out. */
const DEFAULT_WORKER_TIMEOUT_MS = 30_000;

/** Lowest-N selector — mirrors `lowestEligibleSlots` in `server.ts:7021`. */
function lowestEligibleSlots(roster: CaDkgV2Roster, n: number): number[] {
  return roster.nodes
    .map((node) => node.slot)
    .sort((a, b) => a - b)
    .slice(0, n);
}

/** Shape-validate the inbound request. Throws `invalid_request:<reason>`. */
function parseRequest(raw: unknown): BalanceDecryptRequest {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("invalid_request:body_must_be_object");
  }
  const obj = raw as Record<string, unknown>;
  const requireString = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(`invalid_request:${key}_must_be_nonempty_string`);
    }
    return v;
  };
  const oldBalanceDHexRaw = obj.oldBalanceDHex;
  if (!Array.isArray(oldBalanceDHexRaw) || oldBalanceDHexRaw.length === 0) {
    throw new Error("invalid_request:oldBalanceDHex_must_be_nonempty_array");
  }
  const oldBalanceDHex = oldBalanceDHexRaw.map((v, i) => {
    if (typeof v !== "string" || !/^[0-9a-fA-F]{64}$/.test(v)) {
      throw new Error(
        `invalid_request:oldBalanceDHex[${i}]_must_be_64_hex_chars`,
      );
    }
    return v.toLowerCase();
  });
  // M10-l (codex P1): the request MUST NOT carry `aptosNodeUrl` or
  // `caDkgV2Roster`. Trust for both lives at the coordinator (chainNodeUrl +
  // configured CA DKG V2 roster) and at the worker (its own APTOS_NODE_URL).
  // A request-controlled URL is a threshold decryption oracle (worker would
  // return `dk_share · D'` for attacker-chosen D'); a request-controlled
  // roster is SSRF + breaks 5-of-7. Reject early, defense-in-depth, before
  // any forwarder dispatch.
  if ("aptosNodeUrl" in obj) {
    throw new Error("invalid_request:aptosNodeUrl_not_allowed_in_body");
  }
  if ("caDkgV2Roster" in obj) {
    throw new Error("invalid_request:caDkgV2Roster_not_allowed_in_body");
  }
  return {
    dkgEpoch: requireString("dkgEpoch"),
    vaultAddress: requireString("vaultAddress"),
    assetType: requireString("assetType"),
    oldBalanceDHex,
    requestId: requireString("requestId"),
  };
}

/**
 * Re-derive the M10-b canonical transcript bytes from the coordinator's known
 * inputs + the worker's returned partials, mirroring
 * `canonical_transcript_bytes` in `crypto-worker-rust/src/balance_decrypt.rs`.
 *
 * Layout (every separator is the single ASCII byte 0x3a):
 *
 *   DOMAIN:dkgEpoch:vaultAddress:assetType:slot:requestId:ell:partial[0]:…:partial[ell-1]
 */
function canonicalTranscriptBytes(args: {
  domain: string;
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  slot: number;
  requestId: string;
  partialHex: readonly string[];
}): Uint8Array {
  const parts: string[] = [
    args.domain,
    args.dkgEpoch,
    args.vaultAddress,
    args.assetType,
    String(args.slot),
    args.requestId,
    String(args.partialHex.length),
    ...args.partialHex,
  ];
  return new TextEncoder().encode(parts.join(":"));
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Shape-validate a worker's response and re-verify its SHA-256 signature.
 * Throws on any deviation — caller maps to 502.
 */
function verifyWorkerPartial(args: {
  body: unknown;
  expectedSlot: number;
  expectedEll: number;
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  requestId: string;
}): BalanceDecryptPartialFromWorker {
  const {
    body,
    expectedSlot,
    expectedEll,
    dkgEpoch,
    vaultAddress,
    assetType,
    requestId,
  } = args;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("worker_response_not_object");
  }
  const b = body as Record<string, unknown>;
  if (typeof b.slot !== "number" || !Number.isInteger(b.slot) || b.slot !== expectedSlot) {
    throw new Error(`worker_slot_mismatch:expected=${expectedSlot}:got=${String(b.slot)}`);
  }
  // M10-c-fix: Rust worker emits camelCase JSON (struct has
  // #[serde(rename_all = "camelCase")]), so reads must be camelCase.
  if (!Array.isArray(b.partialHex) || b.partialHex.length !== expectedEll) {
    throw new Error(
      `worker_partial_hex_length_mismatch:expected=${expectedEll}:got=${
        Array.isArray(b.partialHex) ? b.partialHex.length : "non_array"
      }`,
    );
  }
  const partialHex = (b.partialHex as unknown[]).map((v, i) => {
    if (typeof v !== "string" || !/^[0-9a-fA-F]{64}$/.test(v)) {
      throw new Error(`worker_partial_hex[${i}]_not_64_hex`);
    }
    return v.toLowerCase();
  });
  if (typeof b.signature !== "string" || !/^[0-9a-fA-F]{64}$/.test(b.signature)) {
    throw new Error("worker_signature_not_64_hex");
  }
  if (typeof b.transcriptDomain !== "string") {
    throw new Error("worker_transcript_domain_missing");
  }
  if (b.transcriptDomain !== BALANCE_DECRYPT_TRANSCRIPT_DOMAIN) {
    throw new Error(
      `worker_transcript_domain_mismatch:expected=${BALANCE_DECRYPT_TRANSCRIPT_DOMAIN}:got=${b.transcriptDomain}`,
    );
  }
  // Re-derive the canonical bytes from the coordinator's known inputs + the
  // worker's returned partials. Tampered partial -> different bytes -> different
  // hash -> rejection.
  const canonicalBytes = canonicalTranscriptBytes({
    domain: BALANCE_DECRYPT_TRANSCRIPT_DOMAIN,
    dkgEpoch,
    vaultAddress,
    assetType,
    slot: expectedSlot,
    requestId,
    partialHex,
  });
  const recomputed = sha256Hex(canonicalBytes);
  const claimed = b.signature.toLowerCase();
  if (recomputed !== claimed) {
    throw new Error(
      `signature_verification_failed:expected=${recomputed}:got=${claimed}`,
    );
  }
  return {
    slot: expectedSlot,
    partial_hex: partialHex,
    signature: claimed,
    transcript_domain: BALANCE_DECRYPT_TRANSCRIPT_DOMAIN,
  };
}

export interface RegisterBalanceDecryptOptions {
  /**
   * Coordinator-configured CA DKG V2 roster (passed via `getDefaultRoster`).
   * The route uses ONLY this roster — request bodies are rejected if they
   * carry a `caDkgV2Roster` field (M10-l codex P1 — a request-controlled
   * roster would allow SSRF and break the 5-of-7 invariant for partial
   * decrypt).
   */
  getDefaultRoster: () => CaDkgV2Roster | undefined;
  /**
   * M10-l (codex iter-6 P1-13): coordinator-configured bridge vault address.
   * Sourced from `BRIDGE_VAULT_ADDRESS` env. The route rejects requests
   * whose `vaultAddress` doesn't match — preventing a caller with a valid
   * coordinator bearer from asking the threshold to decrypt any non-bridge
   * confidential balance under the same DKG.
   */
  getBridgeVaultAddress: () => string | undefined;
  /**
   * M10-l (codex iter-6 P1-13): coordinator-configured bridge asset type.
   * Sourced from `BRIDGE_ASSET_TYPE` env. Same rationale as
   * `getBridgeVaultAddress` — narrows the threshold-decrypt surface to a
   * single configured (vault, asset) pair.
   */
  getBridgeAssetType: () => string | undefined;
  /** Per-worker fan-out forwarder. */
  forwarder: BalanceDecryptForwarder;
  /** Optional override for the per-worker timeout (default 30_000ms). */
  workerTimeoutMs?: number;
}

/**
 * Register the M10-c balance-decrypt route on the supplied Fastify instance.
 * The bearer-token guard is applied at the server's global `onRequest` hook;
 * this registrar adds no per-route auth.
 */
export function registerBalanceDecryptRoute(
  app: FastifyInstance,
  opts: RegisterBalanceDecryptOptions,
): void {
  const workerTimeoutMs = opts.workerTimeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS;

  app.post(
    "/v2/balance/decrypt",
    async (req: FastifyRequest, reply: FastifyReply) => {
      const raw = req.body ?? {};

      // 1. Inbound forbidden-key guard FIRST — before any parsing or roster
      //    work — so a body with `amount`/`merklePath`/`leafIndex` fails fast.
      try {
        assertNoForbiddenKeys(raw);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "forbidden_field";
        return reply
          .code(400)
          .send({ error: msg.split(":")[0], field: msg.split(":").slice(1).join(":") });
      }

      // 2. Shape-validate.
      let parsed: BalanceDecryptRequest;
      try {
        parsed = parseRequest(raw);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "invalid_request:unknown";
        const [code, ...rest] = msg.split(":");
        return reply.code(400).send({
          error: code ?? "invalid_request",
          message: rest.join(":"),
        });
      }

      // 3a. M10-l (codex iter-6 P1-13): require the request's `vaultAddress`
      //     and `assetType` to match the coordinator-configured bridge values.
      //     Without this gate, a caller with a valid coordinator bearer can
      //     point the threshold-decrypt fan-out at any chain confidential
      //     balance under the same DKG and recover its plaintext.
      const normalizeAptosAddr = (raw: string | undefined): string | null => {
        if (typeof raw !== "string" || raw.length === 0) return null;
        const stripped = raw.toLowerCase().replace(/^0x/, "");
        if (!/^[0-9a-f]{1,64}$/.test(stripped)) return null;
        return stripped.padStart(64, "0");
      };
      const configuredVault = opts.getBridgeVaultAddress();
      const configuredAsset = opts.getBridgeAssetType();
      if (!configuredVault || !configuredAsset) {
        return reply.code(500).send({
          error: "internal_error",
          message:
            "coordinator missing BRIDGE_VAULT_ADDRESS or BRIDGE_ASSET_TYPE config — refusing to fan out threshold-decrypt",
        });
      }
      const cfgVaultNorm = normalizeAptosAddr(configuredVault);
      const reqVaultNorm = normalizeAptosAddr(parsed.vaultAddress);
      if (!cfgVaultNorm || !reqVaultNorm || cfgVaultNorm !== reqVaultNorm) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "vaultAddress does not match the configured bridge vault",
        });
      }
      // Asset types are not always 32-byte addresses (e.g. Move struct tags
      // like `0x1::aptos_coin::AptosCoin`). Try address-normalization first;
      // if either side fails to parse as an address, fall back to a strict
      // case-insensitive string equality (still leading-0x stripped).
      const stripPrefix = (s: string): string => s.toLowerCase().replace(/^0x/, "");
      const cfgAssetNorm = normalizeAptosAddr(configuredAsset);
      const reqAssetNorm = normalizeAptosAddr(parsed.assetType);
      const assetMatches =
        cfgAssetNorm && reqAssetNorm
          ? cfgAssetNorm === reqAssetNorm
          : stripPrefix(configuredAsset) === stripPrefix(parsed.assetType);
      if (!assetMatches) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "assetType does not match the configured bridge asset",
        });
      }

      // 3b. Roster + slot selection — coordinator-configured only.
      // M10-l (codex P1): the request body MUST NOT supply caDkgV2Roster (the
      // parseRequest step above already rejected it). Trust comes from the
      // coordinator's configured roster (`getDefaultRoster`), whose hash is
      // bound into every downstream call (round1/round2/finalize) at config
      // load time.
      const dkgRoster: CaDkgV2Roster | undefined = opts.getDefaultRoster();
      if (!dkgRoster) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "CA_DKG_V2_ROSTER_JSON is required for /v2/balance/decrypt",
        });
      }
      if (parsed.dkgEpoch !== dkgRoster.dkgEpoch) {
        return reply.code(400).send({
          error: "stale_dkg_epoch",
          message: `request.dkgEpoch=${parsed.dkgEpoch} roster.dkgEpoch=${dkgRoster.dkgEpoch}`,
        });
      }
      if (dkgRoster.nodes.length < DEOPERATOR_THRESHOLD) {
        return reply.code(400).send({
          error: "under_quorum",
          message: `roster has ${dkgRoster.nodes.length} nodes < threshold ${DEOPERATOR_THRESHOLD}`,
        });
      }
      const sortedSelectedSlots = lowestEligibleSlots(
        dkgRoster,
        DEOPERATOR_THRESHOLD,
      );

      // 4. Fan-out.
      const ell = parsed.oldBalanceDHex.length;
      const forwarder = opts.forwarder;
      const dkgRosterFinal = dkgRoster;
      type SlotResult =
        | { kind: "ok"; partial: BalanceDecryptPartialFromWorker }
        | { kind: "err"; slot: number; status: number; reason: string };
      const slotResults: SlotResult[] = await Promise.all(
        sortedSelectedSlots.map<Promise<SlotResult>>(async (slot) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), workerTimeoutMs);
          try {
            // M10-l (codex P1): no `aptosNodeUrl` in the worker body. The
            // worker uses its own configured APTOS_NODE_URL for the chain
            // re-fetch. Request-supplied URLs would let a caller point the
            // worker at an attacker-hosted Aptos REST view endpoint and
            // turn `dk_share · D` into an oracle for chosen D.
            const workerBody = {
              dkgEpoch: parsed.dkgEpoch,
              vaultAddress: parsed.vaultAddress,
              assetType: parsed.assetType,
              oldBalanceDHex: parsed.oldBalanceDHex,
              requestId: parsed.requestId,
              slot,
            };
            let res: ForwarderResult;
            try {
              res = await forwarder(
                "/v2/balance/decrypt_partial",
                workerBody,
                dkgRosterFinal,
                slot,
                controller.signal,
              );
            } catch (err) {
              return {
                kind: "err",
                slot,
                status: 502,
                reason:
                  err instanceof Error
                    ? `worker_forward_rejected:${err.message}`
                    : "worker_forward_rejected",
              };
            }
            if (!res.ok || res.statusCode !== 200) {
              return {
                kind: "err",
                slot,
                status: 502,
                reason: `worker_unexpected_status:${res.statusCode ?? "n/a"}:${
                  res.error ?? "no_error"
                }`,
              };
            }
            try {
              const partial = verifyWorkerPartial({
                body: res.body,
                expectedSlot: slot,
                expectedEll: ell,
                dkgEpoch: parsed.dkgEpoch,
                vaultAddress: parsed.vaultAddress,
                assetType: parsed.assetType,
                requestId: parsed.requestId,
              });
              return { kind: "ok", partial };
            } catch (err) {
              return {
                kind: "err",
                slot,
                status: 502,
                reason:
                  err instanceof Error
                    ? err.message
                    : "signature_verification_failed",
              };
            }
          } finally {
            clearTimeout(timer);
          }
        }),
      );

      // 5. Fail closed on any slot error.
      for (const r of slotResults) {
        if (r.kind === "err") {
          const [errCode, ...rest] = r.reason.split(":");
          return reply.code(r.status).send({
            error: errCode ?? "worker_failed",
            slot: r.slot,
            requestId: parsed.requestId,
            message: rest.join(":") || r.reason,
          });
        }
      }
      const partials = slotResults.map((r) => {
        if (r.kind !== "ok") throw new Error("unreachable"); // guarded above
        return r.partial;
      });

      // 6. Compute Lagrange coefficients in the SAME order as
      //    `sortedSelectedSlots` (and therefore the same order as the
      //    `partials` array, since the fan-out preserved order).
      let lagrangeCoeffs: string[];
      try {
        const coeffs = lagrangeCoefficientsAtZero(sortedSelectedSlots);
        lagrangeCoeffs = coeffs.map(scalarHexFromBigint);
      } catch (err) {
        return reply.code(500).send({
          error: "internal_error",
          requestId: parsed.requestId,
          message:
            err instanceof Error ? err.message : "lagrange_compute_failed",
        });
      }

      const resp: BalanceDecryptResponse = {
        slots: partials,
        lagrangeCoeffs,
      };

      // 7. Outbound guard.
      try {
        assertNoForbiddenKeys(resp);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "forbidden_field";
        return reply.code(500).send({
          error: "outbound_forbidden_field",
          requestId: parsed.requestId,
          message: msg,
        });
      }

      return reply.code(200).send(resp);
    },
  );
}
