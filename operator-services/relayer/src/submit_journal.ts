// CP3: submit journal for crash/restart recovery of the 5-tx withdraw sequence.
//
// Before each v3 tx the relayer records an `intent`; after confirmation, a `completed` (with tx
// hash). On restart, `lastCompletedStep(requestHash)` tells the relayer where the sequence got to.
//
// IMPORTANT: the journal is a HINT, not the source of truth. Final resume decisions MUST reconcile
// against ON-CHAIN state (PendingWithdrawFinalizationsV3 + the nullifier set), because a tx can land
// on-chain while the CLI call times out (so a journaled `intent` without `completed` does NOT prove
// the tx did not land). The journal narrows the work; the chain confirms it. Persistence stores only
// PUBLIC identifiers (request_hash, step index, tx hash) — never witnesses/secrets.
import * as fs from "node:fs";

export type JournalPhase = "intent" | "completed";

export interface JournalEntry {
  /** 32-byte hex request_hash identifying the withdraw. */
  requestHash: string;
  /** 0..4 = [proof, attestation, payload, step2a, step2b]. */
  step: number;
  phase: JournalPhase;
  /** Present on `completed` entries. */
  txHash?: string;
  atUnixMs: number;
}

export interface SubmitJournal {
  recordIntent(requestHash: string, step: number): void;
  recordCompleted(requestHash: string, step: number, txHash: string): void;
  /** Highest step index with a `completed` entry for this request, or -1 if none. */
  lastCompletedStep(requestHash: string): number;
  /** All entries for a request, in record order. */
  entries(requestHash: string): JournalEntry[];
}

export interface SubmitJournalOptions {
  /** Append-only JSONL file path. If omitted, the journal is purely in-memory. */
  filePath?: string;
  /** Injectable clock (ms). Defaults to Date.now. */
  now?: () => number;
}

export class FileSubmitJournal implements SubmitJournal {
  private readonly index = new Map<string, JournalEntry[]>();
  private readonly now: () => number;
  private readonly filePath?: string;

  constructor(opts: SubmitJournalOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.filePath = opts.filePath;
    if (this.filePath && fs.existsSync(this.filePath)) {
      this.load(this.filePath);
    }
  }

  private load(filePath: string): void {
    const raw = fs.readFileSync(filePath, "utf8");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const e = JSON.parse(trimmed) as JournalEntry;
        if (typeof e.requestHash === "string" && typeof e.step === "number") {
          this.push(e, /* persist */ false);
        }
      } catch {
        // Skip a malformed/torn trailing line (defensive; a crash mid-append can leave one).
      }
    }
  }

  private push(entry: JournalEntry, persist = true): void {
    const list = this.index.get(entry.requestHash);
    if (list) list.push(entry);
    else this.index.set(entry.requestHash, [entry]);
    if (persist && this.filePath) {
      // POSIX append of a single JSON line is atomic enough for a single-writer journal.
      fs.appendFileSync(this.filePath, `${JSON.stringify(entry)}\n`);
    }
  }

  recordIntent(requestHash: string, step: number): void {
    this.push({ requestHash, step, phase: "intent", atUnixMs: this.now() });
  }

  recordCompleted(requestHash: string, step: number, txHash: string): void {
    this.push({ requestHash, step, phase: "completed", txHash, atUnixMs: this.now() });
  }

  lastCompletedStep(requestHash: string): number {
    const list = this.index.get(requestHash);
    if (!list) return -1;
    let max = -1;
    for (const e of list) {
      if (e.phase === "completed" && e.step > max) max = e.step;
    }
    return max;
  }

  entries(requestHash: string): JournalEntry[] {
    return [...(this.index.get(requestHash) ?? [])];
  }
}
