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
