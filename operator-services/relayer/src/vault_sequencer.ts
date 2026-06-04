// CP3: single-writer serialization for withdraw submission.
//
// withdraw_step2a_eunoma_verify_v3 / withdraw_step2b_invoke_framework_v3 assert
// `vault.vault_sequence == <arg>` and step2b increments the global counter. Two concurrent
// withdraws racing the SAME sequence → only the first step2b lands; the rest abort
// E_VAULT_SEQUENCE_MISMATCH (wasted gas). The relayer therefore serializes the step2a→step2b
// critical section through ONE single-writer async mutex so the relayer never races its own
// submissions. (The 3 prepare_withdraw_*_v3 txs are sender-agnostic, keyed by request_hash, and do
// NOT touch vault_sequence — they may run outside the lock.)
//
// This is a minimal promise-chaining mutex: each task runs strictly after the previous one settles
// (success OR failure), and a task's own rejection propagates to its caller without poisoning the
// queue for subsequent tasks.
//
// CP5 RC5 — GLOBAL, NOT PER-ASSET (V4 multi-asset hard invariant):
//   `vault_sequence` is ONE GLOBAL counter on VaultCoreV4 (the design's S-A decision — it keeps
//   withdraw public[7]'s FROST byte layout identical to V3, preserving 5-of-7). It is NOT
//   per-asset. The relayer MUST therefore serialize ALL withdraws (every asset) through a SINGLE
//   VaultSequencer instance — see relayer/src/bin/start.ts (`sequencer: new VaultSequencer()`,
//   constructed exactly once and shared across all `/v3/relayer/submit/withdraw` requests
//   regardless of `assetAddr`).
//
//   FORBIDDEN: do NOT shard this mutex per-asset (e.g. `Map<assetAddr, VaultSequencer>`). Two
//   different-asset withdraws still race the SAME global vault_sequence; a per-asset-keyed mutex
//   would let them run concurrently and one would abort E_VAULT_SEQUENCE_MISMATCH. Per-asset
//   sequence sharding is an explicit V4.1 deferral (would require a per-asset on-chain counter +
//   a public[7] layout change + a re-derived FROST message — out of scope, and it must not be
//   reintroduced as a "performance optimization"). The withdraw route binds to `opts.sequencer`,
//   never to an asset-keyed lookup, so this stays single-writer-global by construction.
export class VaultSequencer {
  private tail: Promise<unknown> = Promise.resolve();

  /**
   * Run `fn` exclusively: it starts only after every previously-enqueued task has settled. Returns
   * `fn`'s result (or rejection). A rejection does NOT block later tasks.
   */
  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.tail.then(() => fn());
    // Keep the chain alive but swallow this task's outcome so a failure doesn't poison the queue.
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
