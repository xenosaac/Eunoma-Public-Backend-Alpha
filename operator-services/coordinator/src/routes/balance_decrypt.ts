/**
 * M10-c — POST /v2/balance/decrypt.
 *
 * Coordinator fan-out + Lagrange-coefficient helper for the balance-decryption
 * surface. Steps:
 *   1. Parse the orchestrator's request (`dkgEpoch`, `vaultAddress`, `assetType`,
 *      `oldBalanceDHex`, `requestId`, `aptosNodeUrl`).
 *   2. Run the forbidden-key regex guard on the inbound body BEFORE any worker
 *      dispatch — any plaintext amount/blind/secret/dk/merkle/sender key fails
 *      400 immediately.
 *   3. Select the lowest-5-of-7 quorum from the CA DKG V2 roster (same
 *      `lowestEligibleSlots` selector used by `/v2/derive/vault_ek/start`
 *      and `/v2/derive/ca_registration/start` MPCCA fan-out).
 *   4. Fan out in parallel to each selected worker's `/v2/balance/decrypt_partial`
 *      endpoint via the injected `SingleNodeForwarder`.
 *   5. For each worker response: re-derive the M10-b canonical bytes from the
 *      coordinator's known inputs + the worker's returned partials and
 *      recompute SHA-256. Reject any slot whose returned `signature` doesn't
 *      match byte-for-byte, OR whose `transcript_domain` is wrong.
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
  caDkgV2RosterHash,
  lagrangeCoefficientsAtZero,
  scalarHexFromBigint,
  validateCaDkgV2Roster,
  parseCaDkgV2Roster,
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
  return {
    dkgEpoch: requireString("dkgEpoch"),
    vaultAddress: requireString("vaultAddress"),
    assetType: requireString("assetType"),
    oldBalanceDHex,
    requestId: requireString("requestId"),
    aptosNodeUrl: requireString("aptosNodeUrl"),
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
  if (!Array.isArray(b.partial_hex) || b.partial_hex.length !== expectedEll) {
    throw new Error(
      `worker_partial_hex_length_mismatch:expected=${expectedEll}:got=${
        Array.isArray(b.partial_hex) ? b.partial_hex.length : "non_array"
      }`,
    );
  }
  const partialHex = (b.partial_hex as unknown[]).map((v, i) => {
    if (typeof v !== "string" || !/^[0-9a-fA-F]{64}$/.test(v)) {
      throw new Error(`worker_partial_hex[${i}]_not_64_hex`);
    }
    return v.toLowerCase();
  });
  if (typeof b.signature !== "string" || !/^[0-9a-fA-F]{64}$/.test(b.signature)) {
    throw new Error("worker_signature_not_64_hex");
  }
  if (typeof b.transcript_domain !== "string") {
    throw new Error("worker_transcript_domain_missing");
  }
  if (b.transcript_domain !== BALANCE_DECRYPT_TRANSCRIPT_DOMAIN) {
    throw new Error(
      `worker_transcript_domain_mismatch:expected=${BALANCE_DECRYPT_TRANSCRIPT_DOMAIN}:got=${b.transcript_domain}`,
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
   * Optional caDkgV2Roster to use for slot selection + endpoint resolution.
   * If absent, the route falls back to the coordinator-configured roster
   * (passed via `getDefaultRoster`).
   */
  getDefaultRoster: () => CaDkgV2Roster | undefined;
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

      // 3. Roster + slot selection.
      let dkgRoster: CaDkgV2Roster | undefined;
      const rawBody = raw as Record<string, unknown>;
      if (rawBody.caDkgV2Roster !== undefined) {
        try {
          dkgRoster = parseCaDkgV2Roster(rawBody.caDkgV2Roster);
          validateCaDkgV2Roster(dkgRoster);
        } catch (err) {
          return reply.code(400).send({
            error: "invalid_request",
            message: err instanceof Error ? err.message : "bad_roster",
          });
        }
      } else {
        dkgRoster = opts.getDefaultRoster();
      }
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
      const rosterHashHex = caDkgV2RosterHash(dkgRoster);
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
            const workerBody = {
              dkgEpoch: parsed.dkgEpoch,
              vaultAddress: parsed.vaultAddress,
              assetType: parsed.assetType,
              oldBalanceDHex: parsed.oldBalanceDHex,
              requestId: parsed.requestId,
              slot,
              aptosNodeUrl: parsed.aptosNodeUrl,
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

      void rosterHashHex; // logged-or-future-use; currently informational only
      return reply.code(200).send(resp);
    },
  );
}
