/**
 * M11 — POST /v2/vault/resync_after_withdraw  and  /v2/vault/resync_before_round1.
 *
 * Coordinator fan-out for the post-withdraw vault-state resync. After a
 * chain-confirmed `WithdrawEventV2`, the on-chain `BridgeVault.vault_sequence`
 * advances but the per-worker `vault_state_v2.json` does not. This route fans
 * the resync out to every roster node's `/v2/vault/resync` worker endpoint; each
 * worker independently re-fetches the tx from ITS OWN trusted node URL, verifies
 * the event binds to its trusted (package, vault) + the claimed sequence, then
 * advances its persisted `vault_sequence`.
 *
 * Two paths, identical behavior, distinguished only for telemetry/audit (the
 * persisted transcript filename records which trigger fired):
 *   - `/v2/vault/resync_after_withdraw`  — orchestrator's post-submit fan-out.
 *   - `/v2/vault/resync_before_round1`   — orchestrator's pre-round1 catch-up.
 *
 * Trust model: the request's `bridgePackage` / `vault` / `assetType` are NOT
 * load-bearing here — the WORKER re-checks them against its own env config and
 * builds the event type from its trusted package. The coordinator additionally
 * cross-checks `vault` / `assetType` against its own configured bridge values
 * (defense-in-depth, mirroring `/v2/balance/decrypt`), and rejects request
 * bodies carrying a `caDkgV2Roster` (SSRF) or any forbidden plaintext key.
 *
 * Success criterion: >= DEOPERATOR_THRESHOLD (5) workers return HTTP 200
 * (idempotent and fresh-advance both count). Slots that are uninitialized for
 * this vault (e.g. non-quorum slots) return 404 and are reported as failed; the
 * fan-out still succeeds as long as the threshold of initialized slots resync.
 *
 * The response reports the EXACT ok/failed slot sets so the orchestrator can
 * confirm its selected round1 signing quorum is fully synced — a bare count is
 * not sufficient.
 *
 * Failure modes (HTTP status):
 *   - 400 `forbidden_field:<path>`     — inbound guard
 *   - 400 `invalid_request:<reason>`   — shape / sequence-binding validation
 *   - 400 `stale_dkg_epoch`            — request epoch != roster epoch
 *   - 400 `under_quorum`               — roster smaller than threshold
 *   - 502 `resync_subthreshold`        — fewer than threshold workers resynced
 *   - 500 `internal_error`             — missing config / persistence failure
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { mkdir, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { type CaDkgV2Roster, DEOPERATOR_THRESHOLD } from "@eunoma/deop-protocol";
import { assertNoForbiddenKeys } from "@eunoma/shared";

/** Minimal forwarder shape (mirrors `SingleNodeForwarder` from server.ts). */
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
export type VaultResyncForwarder = (
  path: string,
  body: unknown,
  roster: RoutableRoster,
  slot: number,
  signal?: AbortSignal,
) => Promise<ForwarderResult>;

const DEFAULT_WORKER_TIMEOUT_MS = 30_000;
const WORKER_RESYNC_PATH = "/v2/vault/resync";

export type VaultResyncTrigger = "after_withdraw" | "before_round1";

interface ParsedResyncRequest {
  dkgEpoch: string;
  requestId: string;
  txHash: string;
  bridgePackage: string;
  vault: string;
  assetType: string;
  root: string;
  nullifierHash: string;
  recipientHash: string;
  requestHash: string;
  eventVaultSequence: number;
  expectedNextSequence: number;
}

const HEX64_RE = /^(0x)?[0-9a-fA-F]{64}$/;
const ADDR_RE = /^(0x)?[0-9a-fA-F]{1,64}$/;

function parseRequest(raw: unknown): ParsedResyncRequest {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("invalid_request:body_must_be_object");
  }
  const obj = raw as Record<string, unknown>;
  // M10-l/M11 (codex P1): a request-controlled roster is SSRF + breaks the
  // threshold invariant. The roster is coordinator config only.
  if ("caDkgV2Roster" in obj) {
    throw new Error("invalid_request:caDkgV2Roster_not_allowed_in_body");
  }
  const reqString = (key: string): string => {
    const v = obj[key];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(`invalid_request:${key}_must_be_nonempty_string`);
    }
    return v;
  };
  const reqHex64 = (key: string): string => {
    const v = reqString(key);
    if (!HEX64_RE.test(v)) {
      throw new Error(`invalid_request:${key}_must_be_64_hex`);
    }
    return v;
  };
  const reqAddr = (key: string): string => {
    const v = reqString(key);
    if (!ADDR_RE.test(v)) {
      throw new Error(`invalid_request:${key}_must_be_hex_address`);
    }
    return v;
  };
  const reqU53 = (key: string): number => {
    const v = obj[key];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || !Number.isSafeInteger(v)) {
      throw new Error(`invalid_request:${key}_must_be_nonneg_safe_integer`);
    }
    return v;
  };
  const eventVaultSequence = reqU53("eventVaultSequence");
  const expectedNextSequence = reqU53("expectedNextSequence");
  if (expectedNextSequence !== eventVaultSequence + 1) {
    throw new Error("invalid_request:expectedNextSequence_must_be_eventVaultSequence_plus_one");
  }
  return {
    dkgEpoch: reqString("dkgEpoch"),
    requestId: reqString("requestId"),
    txHash: reqAddr("txHash"),
    bridgePackage: reqAddr("bridgePackage"),
    vault: reqAddr("vault"),
    assetType: reqString("assetType"),
    root: reqHex64("root"),
    nullifierHash: reqHex64("nullifierHash"),
    recipientHash: reqHex64("recipientHash"),
    requestHash: reqHex64("requestHash"),
    eventVaultSequence,
    expectedNextSequence,
  };
}

function normalizeAptosAddr(raw: string | undefined): string | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const stripped = raw.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{1,64}$/.test(stripped)) return null;
  return stripped.padStart(64, "0");
}

export interface RegisterVaultResyncOptions {
  getDefaultRoster: () => CaDkgV2Roster | undefined;
  getBridgeVaultAddress: () => string | undefined;
  getBridgeAssetType: () => string | undefined;
  forwarder: VaultResyncForwarder;
  stateRoot?: string;
  workerTimeoutMs?: number;
}

/**
 * Register one resync route. Call once per trigger path. Bearer auth is applied
 * by the server's global onRequest hook; this registrar adds no per-route auth.
 */
export function registerVaultResyncRoute(
  app: FastifyInstance,
  opts: RegisterVaultResyncOptions,
  routePath: string,
  trigger: VaultResyncTrigger,
): void {
  const workerTimeoutMs = opts.workerTimeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS;

  app.post(routePath, async (req: FastifyRequest, reply: FastifyReply) => {
    const raw = req.body ?? {};

    // 1. Inbound forbidden-key guard FIRST.
    try {
      assertNoForbiddenKeys(raw);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "forbidden_field";
      return reply
        .code(400)
        .send({ error: msg.split(":")[0], field: msg.split(":").slice(1).join(":") });
    }

    // 2. Shape + sequence-binding validation.
    let parsed: ParsedResyncRequest;
    try {
      parsed = parseRequest(raw);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "invalid_request:unknown";
      const [code, ...rest] = msg.split(":");
      return reply.code(400).send({ error: code ?? "invalid_request", message: rest.join(":") });
    }

    // 3. Defense-in-depth: cross-check vault / asset against coordinator config
    //    (the worker is authoritative, but reject obviously-wrong targets early).
    const configuredVault = opts.getBridgeVaultAddress();
    const configuredAsset = opts.getBridgeAssetType();
    if (!configuredVault || !configuredAsset) {
      return reply.code(500).send({
        error: "internal_error",
        message:
          "coordinator missing BRIDGE_VAULT_ADDRESS or BRIDGE_ASSET_TYPE config — refusing to fan out vault resync",
      });
    }
    const cfgVaultNorm = normalizeAptosAddr(configuredVault);
    const reqVaultNorm = normalizeAptosAddr(parsed.vault);
    if (!cfgVaultNorm || !reqVaultNorm || cfgVaultNorm !== reqVaultNorm) {
      return reply
        .code(400)
        .send({ error: "invalid_request", message: "vault does not match the configured bridge vault" });
    }
    const stripPrefix = (s: string): string => s.toLowerCase().replace(/^0x/, "");
    const cfgAssetNorm = normalizeAptosAddr(configuredAsset);
    const reqAssetNorm = normalizeAptosAddr(parsed.assetType);
    const assetMatches =
      cfgAssetNorm && reqAssetNorm
        ? cfgAssetNorm === reqAssetNorm
        : stripPrefix(configuredAsset) === stripPrefix(parsed.assetType);
    if (!assetMatches) {
      return reply
        .code(400)
        .send({ error: "invalid_request", message: "assetType does not match the configured bridge asset" });
    }

    // 4. Roster — coordinator config only.
    const dkgRoster = opts.getDefaultRoster();
    if (!dkgRoster) {
      return reply
        .code(400)
        .send({ error: "invalid_request", message: "CA_DKG_V2_ROSTER_JSON is required for vault resync" });
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

    // 5. Fan out to EVERY roster node (not just the lowest quorum) so as many
    //    workers as possible advance. `trigger` is coordinator-only metadata and
    //    is NOT forwarded.
    const workerBody = {
      dkgEpoch: parsed.dkgEpoch,
      requestId: parsed.requestId,
      txHash: parsed.txHash,
      bridgePackage: parsed.bridgePackage,
      vault: parsed.vault,
      assetType: parsed.assetType,
      root: parsed.root,
      nullifierHash: parsed.nullifierHash,
      recipientHash: parsed.recipientHash,
      requestHash: parsed.requestHash,
      eventVaultSequence: parsed.eventVaultSequence,
      expectedNextSequence: parsed.expectedNextSequence,
    };
    const allSlots = dkgRoster.nodes.map((n) => n.slot).sort((a, b) => a - b);
    const results: ForwarderResult[] = await Promise.all(
      allSlots.map<Promise<ForwarderResult>>(async (slot) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), workerTimeoutMs);
        try {
          return await opts.forwarder(
            WORKER_RESYNC_PATH,
            workerBody,
            dkgRoster,
            slot,
            controller.signal,
          );
        } catch (err) {
          return {
            slot,
            ok: false,
            error: err instanceof Error ? err.message : "worker_forward_rejected",
          };
        } finally {
          clearTimeout(timer);
        }
      }),
    );

    const okSlots = results.filter((r) => r.ok && r.statusCode === 200).map((r) => r.slot).sort((a, b) => a - b);
    const failedSlots = allSlots.filter((s) => !okSlots.includes(s));
    const thresholdMet = okSlots.length >= DEOPERATOR_THRESHOLD;

    const summary = {
      okSlots,
      failedSlots,
      total: allSlots.length,
      threshold: DEOPERATOR_THRESHOLD,
      thresholdMet,
    };
    const responseBody = { ok: thresholdMet, trigger, requestId: parsed.requestId, summary, results };

    // 6. Persist an audit transcript (public fields only).
    if (opts.stateRoot) {
      try {
        const dir = join(opts.stateRoot, "coordinator", "vault_resync");
        await mkdir(dir, { recursive: true, mode: 0o700 });
        const finalPath = join(dir, `${parsed.dkgEpoch}__${parsed.requestId}__${trigger}.json`);
        const tmpPath = `${finalPath}.tmp.${process.pid}`;
        await writeFile(
          tmpPath,
          JSON.stringify(
            {
              trigger,
              request: workerBody,
              summary,
              results,
              writtenAtMs: Date.now(),
            },
            null,
            2,
          ),
          { mode: 0o600 },
        );
        await rename(tmpPath, finalPath);
      } catch (err) {
        return reply.code(500).send({
          error: "internal_error",
          requestId: parsed.requestId,
          message: `vault_resync transcript persist failed: ${
            err instanceof Error ? err.message : "unknown"
          }`,
        });
      }
    }

    // 7. Outbound forbidden-key guard (defense-in-depth).
    try {
      assertNoForbiddenKeys(responseBody);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "forbidden_field";
      return reply.code(500).send({ error: "outbound_forbidden_field", message: msg });
    }

    return reply.code(thresholdMet ? 200 : 502).send(responseBody);
  });
}
