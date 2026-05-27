/**
 * Normalize ceremony — POST /v2/normalize/sigma/s0.
 *
 * Coordinator fan-out + additive aggregation route that reconstructs the
 * σ-position-0 threshold response `s[0]_threshold = α[0] + e · dk_REAL` for
 * the Aptos CA WithdrawalV1 σ-proof (== "normalize_raw") when the vault's
 * decryption key `dk_REAL` is sharded across the 5-of-7 CA DKG V2 quorum and
 * no single party (including the user, including the coordinator, including
 * any individual worker) holds it.
 *
 * ## Finding — "is α[0] sharded or shared whole?"
 *
 * Three-sentence summary of the existing transfer-finalize convention
 * (mpcca_withdraw_v2 finalize round, crypto-worker-rust/src/lib.rs:9604) vs.
 * this normalize route:
 *
 *   1. The existing transfer-finalize threshold path SHARDS α[0] via additive
 *      shares the user HPKE-seals to each worker; the worker decrypts its
 *      α_share at finalize and returns `s_share_j = α_share_j + e · (λ_j ·
 *      dk_share_j)`, with Lagrange APPLIED INSIDE the worker and the
 *      coordinator simply summing the 5 shares. The α[0] never appears
 *      plaintext at the coordinator.
 *   2. This normalize route now follows that convention: α[0] is split into
 *      additive shares and HPKE-sealed to the selected workers with info string
 *      `EUNOMA_NORMALIZE_ALPHA_SHARE_V1`.
 *   3. Each worker applies its own Lagrange coefficient locally and returns
 *      `α_share_j + e · λ_j · dk_share_j`; the coordinator only sums the five
 *      public partial responses.
 *
 * ## Steps
 *
 *   1. Parse the request: `dkgEpoch`, `vaultAddress`, `assetType`, `e`
 *      (32 hex bytes), `rosterHash`, `selectedSlots`, `alphaShareEnvelopes`,
 *      `requestId`. No
 *      `aptosNodeUrl`, no `caDkgV2Roster` (M10-l codex P1 closure mirrored
 *      from balance_decrypt — request-controlled URLs / rosters are oracle
 *      and SSRF surfaces).
 *   2. Forbidden-key regex guard on the inbound body plus a strict top-level
 *      allowlist; any extra `amount` / `merklePath` / `leafIndex` /
 *      `commitmentHex` / `*dk*` keys fail-closed at 400.
 *   3. Require the request's `vaultAddress` + `assetType` to match the
 *      coordinator-configured bridge values (same M10-l iter-6 P1-13 gate as
 *      balance_decrypt). Without this gate, a caller with a valid bearer
 *      could ask the threshold to operate on any vault under the same DKG.
 *   4. Select the lowest 5-of-7 slots from the configured CA DKG V2 roster
 *      (mirror balance_decrypt.ts:93 `lowestEligibleSlots`).
 *   5. Fan out in parallel to each selected worker's
 *      `/worker/v2/normalize/sigma/s0_partial` endpoint via the injected
 *      `SingleNodeForwarder`.
 *   6. For each worker response: verify slot id matches (502 on mismatch),
 *      verify `partialS0Hex` is 64-hex.
 *   7. Aggregate in the Ed25519 scalar field:
 *        `s[0]_threshold = Σ_i partial_i  (mod q)`.
 *      Math: `Σ_i α_share_i = α[0]` and
 *      `Σ_i e · λ_i · dk_share_i = e · dk_REAL`.
 *   9. Outbound forbidden-key guard. Return 200 with
 *      `{ sigmaResponseS0Hex, slots: sortedSelectedSlots }`.
 *
 * ## Failure modes (HTTP status)
 *
 *   - 400 `forbidden_field:<path>`           — guard triggered (inbound or outbound)
 *   - 400 `invalid_request:<reason>`         — shape validation
 *   - 400 `stale_dkg_epoch` / `under_quorum` — roster mismatch
 *   - 502 `worker_forward_rejected`          — network error talking to a worker
 *   - 502 `worker_unexpected_status`         — non-200 from a worker
 *   - 502 `worker_slot_mismatch`             — worker returned a slot that wasn't asked
 *   - 500 `internal_error`                   — anything else
 *
 * ## Security caveat (DO NOT LOG)
 *
 * Operators MUST configure the deployment to:
 *   (a) NOT include `/v2/normalize/sigma/s0` request/response bodies in any
 *       structured log sink (Fastify logger is disabled at the server-level
 *       in coordinator/src/server.ts:495 `Fastify({ logger: false })`, which
 *       is the load-bearing default).
 *   (b) NOT mirror the route to any monitoring/replay subsystem.
 *   (c) NOT operate the coordinator on a host whose request memory is
 *       inspectable by the bridge admin (the same threat model that already
 *       applies to vault EK derivation).
 *
 * The route itself emits no logs and is stateless (no disk writes).
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import {
  type CaDkgV2Roster,
  ED25519_SCALAR_Q,
  caDkgV2RosterHash,
  scalarHexFromBigint,
  DEOPERATOR_THRESHOLD,
} from "@eunoma/deop-protocol";
import { assertNoForbiddenKeys } from "@eunoma/shared";

/**
 * Minimal subset of the coordinator's per-worker forwarder shape. Mirrors the
 * `BalanceDecryptForwarder` interface in `balance_decrypt.ts:81` so this
 * route plugs into the same `singleNodeForwarder` wired in `server.ts`.
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
export type NormalizeSigmaS0Forwarder = (
  path: string,
  body: unknown,
  roster: RoutableRoster,
  slot: number,
  signal?: AbortSignal,
) => Promise<ForwarderResult>;

/** Per-slot timeout for the worker fan-out. Mirrors balance_decrypt's default. */
const DEFAULT_WORKER_TIMEOUT_MS = 30_000;

/** Worker route the coordinator fans out to. */
const WORKER_PARTIAL_PATH = "/worker/v2/normalize/sigma/s0_partial";

/** Lowest-N selector — mirrors `lowestEligibleSlots` in balance_decrypt.ts:93. */
function lowestEligibleSlots(roster: CaDkgV2Roster, n: number): number[] {
  return roster.nodes
    .map((node) => node.slot)
    .sort((a, b) => a - b)
    .slice(0, n);
}

/** Parsed normalize request — shape-validated; throws `invalid_request:<reason>`. */
interface HpkeEnvelopeBody {
  kem: string;
  kdf: string;
  aead: string;
  enc: string;
  ciphertext: string;
  aadHash: string;
}

interface AlphaShareEnvelopeBody {
  slot: number;
  hpke: HpkeEnvelopeBody;
}

interface NormalizeSigmaS0Request {
  dkgEpoch: string;
  vaultAddress: string;
  assetType: string;
  fiatShamirChallengeHex: string;
  rosterHash: string;
  selectedSlots: number[];
  alphaShareEnvelopes: AlphaShareEnvelopeBody[];
  requestId: string;
}

function assertAllowedKeys(
  obj: Record<string, unknown>,
  allowed: Set<string>,
  label: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`invalid_request:unknown_key:${label}.${key}`);
    }
  }
}

function parseRequest(raw: unknown): NormalizeSigmaS0Request {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("invalid_request:body_must_be_object");
  }
  const obj = raw as Record<string, unknown>;
  assertAllowedKeys(
    obj,
    new Set([
      "dkgEpoch",
      "vaultAddress",
      "assetType",
      "fiatShamirChallengeHex",
      "rosterHash",
      "selectedSlots",
      "alphaShareEnvelopes",
      "requestId",
    ]),
    "$",
  );
  const requireString = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(`invalid_request:${key}_must_be_nonempty_string`);
    }
    return v;
  };
  const requireHex32 = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || !/^[0-9a-fA-F]{64}$/.test(v)) {
      throw new Error(`invalid_request:${key}_must_be_64_hex_chars`);
    }
    return v.toLowerCase();
  };
  const selectedSlotsRaw = obj.selectedSlots;
  if (!Array.isArray(selectedSlotsRaw)) {
    throw new Error("invalid_request:selectedSlots_must_be_array");
  }
  const selectedSlots = selectedSlotsRaw.map((slot, idx) => {
    if (!Number.isInteger(slot) || slot < 0) {
      throw new Error(`invalid_request:selectedSlots_${idx}_must_be_nonnegative_integer`);
    }
    return slot;
  });
  for (let i = 1; i < selectedSlots.length; i += 1) {
    if (selectedSlots[i - 1] >= selectedSlots[i]) {
      throw new Error("invalid_request:selectedSlots_must_be_strictly_ascending");
    }
  }
  const alphaShareEnvelopesRaw = obj.alphaShareEnvelopes;
  if (!Array.isArray(alphaShareEnvelopesRaw)) {
    throw new Error("invalid_request:alphaShareEnvelopes_must_be_array");
  }
  const alphaShareEnvelopes = alphaShareEnvelopesRaw.map((entry, idx) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_must_be_object`);
    }
    const e = entry as Record<string, unknown>;
    assertAllowedKeys(e, new Set(["slot", "hpke"]), `alphaShareEnvelopes[${idx}]`);
    if (!Number.isInteger(e.slot) || (e.slot as number) < 0) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_slot_invalid`);
    }
    if (e.hpke === null || typeof e.hpke !== "object" || Array.isArray(e.hpke)) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_hpke_must_be_object`);
    }
    const hpke = e.hpke as Record<string, unknown>;
    assertAllowedKeys(
      hpke,
      new Set(["kem", "kdf", "aead", "enc", "ciphertext", "aadHash"]),
      `alphaShareEnvelopes[${idx}].hpke`,
    );
    const requireHpkeString = (key: string): string => {
      const v = hpke[key];
      if (typeof v !== "string" || v.length === 0) {
        throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_hpke_${key}_invalid`);
      }
      return v;
    };
    const env = {
      kem: requireHpkeString("kem"),
      kdf: requireHpkeString("kdf"),
      aead: requireHpkeString("aead"),
      enc: requireHpkeString("enc"),
      ciphertext: requireHpkeString("ciphertext"),
      aadHash: requireHpkeString("aadHash"),
    };
    if (
      env.kem !== "DHKEM_X25519_HKDF_SHA256" ||
      env.kdf !== "HKDF_SHA256" ||
      env.aead !== "AES_256_GCM"
    ) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_unsupported_hpke_suite`);
    }
    if (!/^[0-9a-fA-F]{64}$/.test(env.enc) || !/^[0-9a-fA-F]{64}$/.test(env.aadHash)) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_hpke_enc_or_aadHash_invalid`);
    }
    if (!/^[0-9a-fA-F]+$/.test(env.ciphertext) || env.ciphertext.length % 2 !== 0) {
      throw new Error(`invalid_request:alphaShareEnvelopes_${idx}_hpke_ciphertext_invalid`);
    }
    return { slot: e.slot as number, hpke: env };
  });
  // Mirror the M10-l (codex P1) closure from balance_decrypt: request body
  // MUST NOT carry aptosNodeUrl or caDkgV2Roster. Trust comes from the
  // coordinator's configured roster.
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
    fiatShamirChallengeHex: requireHex32("fiatShamirChallengeHex"),
    rosterHash: requireHex32("rosterHash"),
    selectedSlots,
    alphaShareEnvelopes,
    requestId: requireString("requestId"),
  };
}

/** Decode a 64-hex little-endian scalar to a positive bigint mod q. */
function scalarBigintFromHex(hex: string): bigint {
  const raw = hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(raw)) {
    throw new Error("scalar_hex_must_be_64_hex");
  }
  let v = 0n;
  // 32 bytes, little-endian.
  for (let i = 31; i >= 0; i -= 1) {
    const byte = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    v = (v << 8n) | BigInt(byte);
  }
  return v % ED25519_SCALAR_Q;
}

/** Shape-validate a worker partial response. Returns the slot-paired partial bigint. */
function parseWorkerPartial(args: {
  body: unknown;
  expectedSlot: number;
}): { slot: number; partial: bigint } {
  if (args.body === null || typeof args.body !== "object" || Array.isArray(args.body)) {
    throw new Error("worker_response_not_object");
  }
  const b = args.body as Record<string, unknown>;
  // Rust worker emits camelCase JSON (matches balance_decrypt convention).
  if (typeof b.slot !== "number" || !Number.isInteger(b.slot) || b.slot !== args.expectedSlot) {
    throw new Error(
      `worker_slot_mismatch:expected=${args.expectedSlot}:got=${String(b.slot)}`,
    );
  }
  if (typeof b.partialS0Hex !== "string" || !/^[0-9a-fA-F]{64}$/.test(b.partialS0Hex)) {
    throw new Error("worker_partial_s0_hex_not_64_hex");
  }
  return {
    slot: args.expectedSlot,
    partial: scalarBigintFromHex(b.partialS0Hex),
  };
}

export interface RegisterNormalizeSigmaS0Options {
  /**
   * Coordinator-configured CA DKG V2 roster (passed via `getDefaultRoster`).
   * The route uses ONLY this roster — request bodies are rejected if they
   * carry a `caDkgV2Roster` field (M10-l codex P1 — a request-controlled
   * roster would allow SSRF and break the 5-of-7 invariant).
   */
  getDefaultRoster: () => CaDkgV2Roster | undefined;
  /** Bridge vault address (mirrors balance_decrypt M10-l iter-6 P1-13 gate). */
  getBridgeVaultAddress: () => string | undefined;
  /** Bridge asset type tag (mirrors balance_decrypt M10-l iter-6 P1-13 gate). */
  getBridgeAssetType: () => string | undefined;
  /** Per-worker fan-out forwarder. */
  forwarder: NormalizeSigmaS0Forwarder;
  /** Optional override for the per-worker timeout (default 30_000ms). */
  workerTimeoutMs?: number;
}

/**
 * Register the normalize-σ-s0 route on the supplied Fastify instance. The
 * bearer-token guard is applied at the server's global `onRequest` hook;
 * this registrar adds no per-route auth.
 *
 * Exported so `server.ts` (Agent D will wire) can call:
 *   `registerNormalizeSigmaS0Route(server, { getDefaultRoster, getBridgeVaultAddress,
 *     getBridgeAssetType, forwarder: singleNodeForwarder })`.
 */
export function registerNormalizeSigmaS0Route(
  app: FastifyInstance,
  opts: RegisterNormalizeSigmaS0Options,
): void {
  const workerTimeoutMs = opts.workerTimeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS;

  app.post(
    "/v2/normalize/sigma/s0",
    async (req: FastifyRequest, reply: FastifyReply) => {
      const raw = req.body ?? {};

      // 1. Inbound forbidden-key guard.
      try {
        assertNoForbiddenKeys(raw);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "forbidden_field";
        return reply
          .code(400)
          .send({ error: msg.split(":")[0], field: msg.split(":").slice(1).join(":") });
      }

      // 2. Shape-validate.
      let parsed: NormalizeSigmaS0Request;
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

      // 3. Bridge vault/asset match (M10-l iter-6 P1-13 mirror).
      const normalizeAptosAddr = (s: string | undefined): string | null => {
        if (typeof s !== "string" || s.length === 0) return null;
        const stripped = s.toLowerCase().replace(/^0x/, "");
        if (!/^[0-9a-f]{1,64}$/.test(stripped)) return null;
        return stripped.padStart(64, "0");
      };
      const configuredVault = opts.getBridgeVaultAddress();
      const configuredAsset = opts.getBridgeAssetType();
      if (!configuredVault || !configuredAsset) {
        return reply.code(500).send({
          error: "internal_error",
          message:
            "coordinator missing BRIDGE_VAULT_ADDRESS or BRIDGE_ASSET_TYPE config — refusing to fan out normalize",
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

      // 4. Roster + slot selection.
      const dkgRoster: CaDkgV2Roster | undefined = opts.getDefaultRoster();
      if (!dkgRoster) {
        return reply.code(400).send({
          error: "invalid_request",
          message:
            "CA_DKG_V2_ROSTER_JSON is required for /v2/normalize/sigma/s0",
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
      const computedRosterHash = caDkgV2RosterHash(dkgRoster).toLowerCase();
      if (parsed.rosterHash !== computedRosterHash) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "rosterHash does not match the configured CA DKG V2 roster",
        });
      }
      if (
        parsed.selectedSlots.length !== sortedSelectedSlots.length ||
        parsed.selectedSlots.some((slot, idx) => slot !== sortedSelectedSlots[idx])
      ) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "selectedSlots does not match coordinator-selected quorum",
        });
      }
      const alphaEnvelopeBySlot = new Map<number, HpkeEnvelopeBody>();
      for (const envelope of parsed.alphaShareEnvelopes) {
        if (!sortedSelectedSlots.includes(envelope.slot)) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `alphaShareEnvelopes contains unselected slot ${envelope.slot}`,
          });
        }
        if (alphaEnvelopeBySlot.has(envelope.slot)) {
          return reply.code(400).send({
            error: "invalid_request",
            message: `duplicate alphaShareEnvelopes slot ${envelope.slot}`,
          });
        }
        alphaEnvelopeBySlot.set(envelope.slot, envelope.hpke);
      }
      if (alphaEnvelopeBySlot.size !== sortedSelectedSlots.length) {
        return reply.code(400).send({
          error: "invalid_request",
          message: "alphaShareEnvelopes must include exactly one envelope per selected slot",
        });
      }

      // 5. Fan-out.
      const forwarder = opts.forwarder;
      const dkgRosterFinal = dkgRoster;
      type SlotResult =
        | { kind: "ok"; slot: number; partial: bigint }
        | { kind: "err"; slot: number; status: number; reason: string };
      const slotResults: SlotResult[] = await Promise.all(
        sortedSelectedSlots.map<Promise<SlotResult>>(async (slot) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), workerTimeoutMs);
          try {
            const alphaShareHpke = alphaEnvelopeBySlot.get(slot);
            if (!alphaShareHpke) {
              return {
                kind: "err",
                slot,
                status: 500,
                reason: "internal_error:missing_alpha_share_envelope_after_validation",
              };
            }
            const workerBody = {
              dkgEpoch: parsed.dkgEpoch,
              vaultAddress: parsed.vaultAddress,
              assetType: parsed.assetType,
              slot,
              rosterHash: parsed.rosterHash,
              selectedSlots: sortedSelectedSlots,
              fiatShamirChallengeHex: parsed.fiatShamirChallengeHex,
              alphaShareHpke,
              requestId: parsed.requestId,
            };
            let res: ForwarderResult;
            try {
              res = await forwarder(
                WORKER_PARTIAL_PATH,
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
              const parsedPartial = parseWorkerPartial({
                body: res.body,
                expectedSlot: slot,
              });
              return { kind: "ok", slot: parsedPartial.slot, partial: parsedPartial.partial };
            } catch (err) {
              return {
                kind: "err",
                slot,
                status: 502,
                reason: err instanceof Error ? err.message : "worker_parse_failed",
              };
            }
          } finally {
            clearTimeout(timer);
          }
        }),
      );

      // 6. Fail closed on any slot error.
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
        return r;
      });

      // 7. Aggregate: s[0]_threshold = Σ_i partial_i  (mod q).
      // Each worker already applied its local Lagrange coefficient and its
      // HPKE-decrypted additive alpha share.
      const q = ED25519_SCALAR_Q;
      let s0 = 0n;
      for (let i = 0; i < partials.length; i += 1) {
        s0 = (s0 + partials[i].partial) % q;
      }
      const sigmaResponseS0Hex = scalarHexFromBigint(s0);

      const resp = {
        sigmaResponseS0Hex,
        slots: sortedSelectedSlots,
      };

      // 8. Outbound guard.
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
