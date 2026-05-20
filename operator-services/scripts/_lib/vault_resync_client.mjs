// =============================================================================================
// M11 — pure client helpers for the orchestrator's vault-state resync wiring.
//
// These functions hold the NON-I/O logic so they can be unit-tested without a chain or a
// running cluster (the orchestrator does the fetch / fs around them). They mirror the worker's
// trusted-config + sequence semantics:
//   - the WithdrawEventV2 event type is matched against the TRUSTED bridge package only;
//   - vault_sequence in the event is the PRE-increment value (chain becomes event_seq + 1);
//   - resync request bodies carry public hashes only (no forbidden plaintext keys).
// =============================================================================================

export const WITHDRAW_EVENT_V2_TYPE_SUFFIX = "eunoma_bridge::WithdrawEventV2";

/** Normalize an Aptos address to 64-hex lowercase (no 0x), left-padded. Returns null if invalid. */
export function normAddr(addr) {
  if (typeof addr !== "string") return null;
  const s = addr.toLowerCase().replace(/^0x/, "");
  if (s.length === 0 || s.length > 64 || !/^[0-9a-f]+$/.test(s)) return null;
  return s.padStart(64, "0");
}

/** Lowercase + strip 0x for hash value comparison (no length enforcement). */
export function normHex(h) {
  return typeof h === "string" ? h.toLowerCase().replace(/^0x/, "") : "";
}

/**
 * Parse the `WithdrawEventV2` module event out of an Aptos tx-by-hash JSON, matching ONLY the
 * trusted bridge package's event type. Returns the binding + tx success flag, or throws.
 * `vault_sequence` (Aptos u64-as-string) is parsed to a Number.
 */
export function parseWithdrawEventV2FromTx(tx, bridgePackage) {
  const wantAddr = normAddr(bridgePackage);
  if (!wantAddr) throw new Error(`bad bridge package address: ${bridgePackage}`);
  const events = Array.isArray(tx?.events) ? tx.events : null;
  if (!events) throw new Error("tx has no events array");
  for (const ev of events) {
    const type = String(ev?.type ?? "");
    const firstSep = type.indexOf("::");
    if (firstSep < 0) continue;
    const addrSeg = type.slice(0, firstSep);
    const rest = type.slice(firstSep + 2);
    if (rest !== WITHDRAW_EVENT_V2_TYPE_SUFFIX) continue;
    if (normAddr(addrSeg) !== wantAddr) continue; // event from a non-trusted package — ignore
    const d = ev.data ?? {};
    const seqRaw = d.vault_sequence;
    const eventVaultSequence =
      typeof seqRaw === "string" ? Number(seqRaw) : typeof seqRaw === "number" ? seqRaw : NaN;
    if (!Number.isInteger(eventVaultSequence) || eventVaultSequence < 0) {
      throw new Error(`WithdrawEventV2.data.vault_sequence invalid: ${JSON.stringify(seqRaw)}`);
    }
    for (const k of ["root", "nullifier_hash", "recipient_hash", "request_hash"]) {
      if (typeof d[k] !== "string" || d[k].length === 0) {
        throw new Error(`WithdrawEventV2.data.${k} missing`);
      }
    }
    return {
      root: d.root,
      nullifierHash: d.nullifier_hash,
      recipientHash: d.recipient_hash,
      requestHash: d.request_hash,
      eventVaultSequence,
      success: tx?.success === true,
    };
  }
  throw new Error("WithdrawEventV2 not found for trusted package");
}

/**
 * Given a map/object of slot → (sequence | null), return the initialized-slot set and the
 * minimum sequence over initialized slots (null slots are uninitialized and excluded). The
 * lagging set drives catch-up; non-quorum / uninitialized slots are never resync targets.
 */
export function pickInitializedMin(bySlot) {
  const entries = bySlot instanceof Map ? [...bySlot.entries()] : Object.entries(bySlot ?? {});
  const initializedSlots = [];
  let workerMin = null;
  for (const [slot, seq] of entries) {
    if (seq === null || seq === undefined) continue;
    const s = Number(slot);
    const v = Number(seq);
    if (!Number.isFinite(v)) continue;
    initializedSlots.push(s);
    workerMin = workerMin === null ? v : Math.min(workerMin, v);
  }
  initializedSlots.sort((a, b) => a - b);
  return { initializedSlots, workerMin };
}

// Forbidden-key regex (full-token), aligned with @eunoma/shared FORBIDDEN_KEY_RE. The legitimate
// `nullifierHash`/`recipientHash`/`requestHash` are NOT forbidden (only bare `nullifier` etc).
export const FORBIDDEN_RESYNC_KEY_RE =
  /^(amount|secret|nullifier|.*blind|dk|inverse|commitmentHex|leafIndex|merkle.*|.*Path|sender)$/i;

export function assertNoForbiddenResyncKeys(obj, path = "$") {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => assertNoForbiddenResyncKeys(v, `${path}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN_RESYNC_KEY_RE.test(k)) throw new Error(`forbidden_field:${path}.${k}`);
    assertNoForbiddenResyncKeys(v, `${path}.${k}`);
  }
}

/**
 * Build a coordinator resync request body (camelCase, public hashes only). `binding` is the
 * output of `parseWithdrawEventV2FromTx`. Asserts no forbidden plaintext keys before returning.
 */
export function buildResyncBody({
  dkgEpoch,
  requestId,
  txHash,
  bridgePackage,
  vault,
  assetType,
  binding,
  trigger,
}) {
  const eventVaultSequence = binding.eventVaultSequence;
  const body = {
    dkgEpoch: String(dkgEpoch),
    requestId: String(requestId),
    txHash,
    bridgePackage,
    vault,
    assetType,
    root: normHex(binding.root),
    nullifierHash: normHex(binding.nullifierHash),
    recipientHash: normHex(binding.recipientHash),
    requestHash: normHex(binding.requestHash),
    eventVaultSequence,
    expectedNextSequence: eventVaultSequence + 1,
    trigger,
  };
  assertNoForbiddenResyncKeys(body);
  return body;
}
