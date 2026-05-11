/// AptosShield Spike — pending deposit queue.
///
/// Module: eunoma::pool_pending_queue
///
/// Purpose:
///   * Append-only queue of deposit commitments waiting to be folded into the
///     shielded Merkle tree by an off-chain operator and on-chain attested by
///     4-of-7 multi-sig (see `batch_root_update.move`).
///   * Per-deposit cost ≈ 1 Poseidon (commitment) + 1 Poseidon (running
///     accumulator over (deposit_index, leaf_commitment) pairs) + small
///     storage writes — replaces the ~21 Poseidon calls/deposit in the
///     direct-insert Merkle model from HANDOFF Section 2.5.
///
/// Trust-model role:
///   * Multi-sig CAN delay or censor specific deposits, but CANNOT skip a
///     queue index, fabricate a leaf, or modify a leaf after emission. The
///     append-only `next_index` and `acc_hash` here are the structural
///     anchors that the batch verifier in `batch_root_update.move` checks
///     `start_index == next_unfinalized_index` (invariant 2),
///     `end_index <= current_pending_tail` (invariant 3), and
///     `queue_range_hash` consistency (invariant 5) against.
///
/// Off-chain consumer:
///   * The operator service indexes `DepositQueued` events and reconstructs
///     the same accumulator chain locally before submitting `update_root_batch`.
///   * See `operator/batch_updater.ts` for the reference implementation.
///
/// Out of scope:
///   * Deposit-binding ZK proof verification (HANDOFF Section 5.1) — the spike
///     focuses on the queue/batch root path. Production deposit will still
///     bind a Groth16 deposit-binding proof; here we accept raw commitment
///     inputs for measurement clarity.
///   * Withdraw flow / nullifier table — separate gate.
///   * Compliance attestation flow (KYC/AML/sanctions) — represented here
///     by a single `compliance_attestation_id: u64` link field; the actual
///     attestation record lives off-chain at the main operator service.
module eunoma::pool_pending_queue {
    use std::vector;
    use std::signer;
    use std::bcs;

    use aptos_framework::event;

    use aptos_std::table::{Self, Table};

    use eunoma_pool::poseidon_bn254;

    // ========================================================================
    // Constants
    // ========================================================================

    /// Logical batch size used by the operator. Affects only the
    /// `deposit_batch_id` derivation field on emitted events; the actual
    /// `update_root_batch` accepts any `batch_size` ≤ pending tail.
    const DEFAULT_BATCH_SIZE: u64 = 64;

    // ========================================================================
    // Error codes
    // ========================================================================

    const E_NOT_INITIALIZED: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_NOT_ADMIN: u64 = 3;
    const E_BAD_COMMITMENT_LENGTH: u64 = 4;
    const E_INDEX_OUT_OF_RANGE: u64 = 5;
    /// Round-7 Item B.2: PendingCommitmentIndex resource not initialized yet.
    /// Returned by `commitment_at_index` if admin has not run
    /// `initialize_commitment_index` post-upgrade.
    const E_COMMITMENT_INDEX_NOT_INITIALIZED: u64 = 6;
    /// Round-7 Item B.2: idempotency guard for `initialize_commitment_index`.
    const E_COMMITMENT_INDEX_ALREADY_INITIALIZED: u64 = 7;
    const E_SYNTHETIC_PUMP_TARGET_BELOW_TAIL: u64 = 9; // Round-7 cleanup C1 (Codex cycle 1 fix): protect monotonic queue tail invariant in do_synthetic_pump.

    /// Length of a Poseidon BN254 field element in bytes (LSB encoding).
    const FR_BYTES: u64 = 32;

    // ========================================================================
    // Resources
    // ========================================================================

    /// Global queue resource — lives at @eunoma.
    ///
    /// Field semantics:
    ///   * `next_index` — monotonically increasing; the index allocated to
    ///     the NEXT deposit. Equivalently, `next_index` == current pending
    ///     tail (one-past-last deposit).
    ///   * `acc_hash` — running Poseidon hash chain over each deposit's
    ///     `Poseidon(index_fr, leaf_commitment)`. Bound to the queue's
    ///     full prefix `[0, next_index)`.
    ///   * `acc_history` — append-only snapshot of `acc_hash` at every
    ///     index transition: `acc_history[i] == acc_hash AFTER i deposits`,
    ///     with `acc_history[0] == zero32` (the empty-queue identity).
    ///     Length == `next_index + 1`. The operator+verifier use this to
    ///     compute `queue_range_hash` over `[start, end)` cheaply by
    ///     reading `acc_history[end]` minus the prefix at `acc_history[start]`,
    ///     using `range_hash` = Poseidon-chain folded forward (see
    ///     `compute_range_hash` below). This is the on-chain accumulator
    ///     that satisfies invariant 5 of `batch_root_update.move`.
    struct PendingQueue has key {
        next_index: u64,
        acc_hash: vector<u8>,
        acc_history: vector<vector<u8>>,
        admin: address,
    }

    /// Round-7 Item B.2: leaf-index → 32-byte commitment table.
    ///
    /// Why this resource exists (load-bearing for round-7 Item B audit B5):
    /// `pool_batch_root_update::update_root_batch` needs to enumerate the
    /// commitments in `[start_index, end_index)` to populate
    /// `RootHistoryV2.finalized_commitments` (the SmartTable<commitment, batch_id>
    /// that round-8 Item A force_withdraw depends on). The legacy `acc_history`
    /// snapshot only exposes Poseidon-folded accumulator values, NOT the raw
    /// commitment leaves themselves. So we need a side table.
    ///
    /// Compatible-upgrade pattern:
    /// - SEPARATE resource (NOT a field added to PendingQueue) — HC-9 forbids
    ///   modifying existing struct fields after testnet publish.
    /// - Hooks in `deposit` and `deposit_precomputed` are guarded by
    ///   `if (exists<PendingCommitmentIndex>(@eunoma))` so pre-init
    ///   deposits do NOT abort. Admin runs `initialize_commitment_index`
    ///   after upgrade #5 publishes.
    /// - update_root_batch's V2 dual-write checks
    ///   `commitment_index_initialized()` and skips enumeration if false
    ///   (defensive — operator can finalize batches that pre-date the index).
    struct PendingCommitmentIndex has key {
        /// Maps `leaf_index` (== deposit_index allocated by `deposit`) to the
        /// 32-byte Poseidon commitment that was queued at that index.
        commitments: Table<u64, vector<u8>>,
        admin: address,
    }

    // ========================================================================
    // Events
    // ========================================================================

    // Emitted on every queued deposit. The operator service indexes these
    // to reconstruct the leaf set + accumulator chain off-chain.
    //
    // Field semantics match the spike-brief's on-chain event schema:
    //   * deposit_index — monotonic, allocated by deposit.
    //   * leaf_commitment — 32-byte Poseidon BN254 field element.
    //   * deposit_batch_id — deposit_index / DEFAULT_BATCH_SIZE, i.e.
    //      the logical batch this deposit will be folded into. The operator
    //      may submit a different actual batch_size; this is a hint for
    //      indexers.
    //   * compliance_attestation_id — opaque link to off-chain KYC/screening
    //      record. Type u64 is sufficient to address a per-operator nonce.
    //
    // Phase D / Agent D6 gas trim: `queue_position` field removed. In the MVP
    // it always equals `deposit_index` (1:1 mapping), so consumers should
    // use `deposit_index`. The in-tree operator script
    // (testnet_batch_root_update.ts) already reads `deposit_index`, not
    // `queue_position`. Saves 8 bytes per emit on the deposit hot path.
    #[event]
    struct DepositQueued has drop, store {
        deposit_index: u64,
        leaf_commitment: vector<u8>,
        deposit_batch_id: u64,
        compliance_attestation_id: u64,
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the pending queue resource. Callable once, by the @eunoma admin.
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<PendingQueue>(@eunoma), E_ALREADY_INITIALIZED);

        let zero32 = zero_fr_bytes();
        let acc_history = vector::empty<vector<u8>>();
        // Empty-queue identity at index 0.
        vector::push_back(&mut acc_history, zero32);

        move_to(admin, PendingQueue {
            next_index: 0,
            acc_hash: zero32,
            acc_history,
            admin: admin_addr,
        });
    }

    /// Round-7 Item B.2: admin entry to initialize the PendingCommitmentIndex
    /// resource post-upgrade #5.
    ///
    /// Idempotency: `assert!(!exists<...>)` — second call aborts with
    /// E_COMMITMENT_INDEX_ALREADY_INITIALIZED (intentional — never re-init).
    ///
    /// Admin-only via `signer::address_of(admin) == @eunoma`. Run ONCE
    /// after upgrade #5 publishes; subsequent deposits will populate the table.
    /// Deposits that ran BEFORE this call are NOT retroactively indexed —
    /// `update_root_batch`'s V2 dual-write loop will skip enumeration if a
    /// table::borrow at any index in [start, end) is absent (defensive: in
    /// practice operator schedules upgrade + init + first batch in sequence).
    public entry fun initialize_commitment_index(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<PendingCommitmentIndex>(@eunoma), E_COMMITMENT_INDEX_ALREADY_INITIALIZED);

        move_to(admin, PendingCommitmentIndex {
            commitments: table::new<u64, vector<u8>>(),
            admin: admin_addr,
        });
    }

    // ========================================================================
    // Deposit entry function (queue mode)
    //
    // Replaces the ~21-Poseidon direct-insert deposit. Per call:
    //   * 1 Poseidon (caller-side commitment construction)         — hash_3
    //   * 1 Poseidon (per-leaf accumulator update)                  — hash_2
    //   * 1 Poseidon (running acc_hash chain)                       — hash_2
    //   * Storage: append one entry to acc_history, mutate next_index/acc_hash.
    //
    // i.e. 3 Poseidon calls per deposit instead of 21. We measure the actual
    // gas in `deposit_bench` — see DOSSIER_BATCH_ROOT_UPDATE.md for numbers.
    //
    // The two-Poseidon accumulator design is a standard hash-chain commitment:
    //
    //   leaf_acc_input(i) = Poseidon(index_to_fr(i), leaf_commitment_i)
    //   acc_hash_after_i  = Poseidon(acc_hash_before_i, leaf_acc_input(i))
    //
    // and `acc_history[i+1] = acc_hash_after_i`. The same chain reconstructed
    // off-chain over leaves `[start, end)` MUST equal the on-chain value
    // `compute_range_hash(start, end)` for invariant 5 to pass.
    // ========================================================================

    /// Queue a deposit. Inputs:
    ///   * `secret_bytes`, `nonce_bytes`: 32-byte LSB BN254 field elements
    ///      (caller-supplied randomness — for the production spec these come
    ///      from the deposit-binding circuit; the spike just measures cost).
    ///   * `compliance_attestation_id`: opaque off-chain link.
    ///
    /// Effect:
    ///   * `leaf_commitment = Poseidon(secret_bytes, nonce_bytes)`
    ///   * Append `leaf_commitment` to the queue, update accumulator,
    ///     emit `DepositQueued`.
    ///
    /// Returns: nothing. Off-chain consumers read `DepositQueued` events.
    public entry fun deposit(
        _user: &signer,
        secret_bytes: vector<u8>,
        nonce_bytes: vector<u8>,
        compliance_attestation_id: u64,
    ) acquires PendingQueue, PendingCommitmentIndex {
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        assert!(vector::length(&secret_bytes) == FR_BYTES, E_BAD_COMMITMENT_LENGTH);
        assert!(vector::length(&nonce_bytes) == FR_BYTES, E_BAD_COMMITMENT_LENGTH);

        // Step 1: commitment.
        let leaf_commitment = poseidon_bn254::hash_2(secret_bytes, nonce_bytes);

        // Step 2: allocate next index + update accumulator.
        let q = borrow_global_mut<PendingQueue>(@eunoma);
        let idx = q.next_index;
        let idx_fr = u64_to_fr_bytes(idx);
        let leaf_acc_input = poseidon_bn254::hash_2(idx_fr, leaf_commitment);
        let new_acc = poseidon_bn254::hash_2(q.acc_hash, leaf_acc_input);

        // Gas P6: push the new accumulator into history first (explicit copy),
        // then move it into `q.acc_hash` as the last use. Previously the order
        // was `q.acc_hash = new_acc;` first which forced an IMPLICIT copy
        // (compiler must keep `new_acc` alive for the explicit `copy` on the
        // next line), then an EXPLICIT copy — two 32-byte copies per deposit.
        // This ordering yields one explicit copy + one move = one copy total.
        vector::push_back(&mut q.acc_history, copy new_acc);
        q.acc_hash = new_acc;

        // Round-7 Item B.2 hook: populate PendingCommitmentIndex if initialized.
        // The `if (exists<...>)` guard ensures pre-init deposits do NOT abort
        // (audit-driven defensive pattern for compatible upgrade #5).
        if (exists<PendingCommitmentIndex>(@eunoma)) {
            let pci = borrow_global_mut<PendingCommitmentIndex>(@eunoma);
            table::add(&mut pci.commitments, idx, copy leaf_commitment);
        };

        q.next_index = idx + 1;

        // Step 3: emit event.
        // Phase D / Agent D6: queue_position dropped (= idx; redundant in MVP).
        let batch_id = idx / DEFAULT_BATCH_SIZE;
        event::emit(DepositQueued {
            deposit_index: idx,
            leaf_commitment,
            deposit_batch_id: batch_id,
            compliance_attestation_id,
        });
    }

    /// Test/operator-side variant: queue a pre-computed `leaf_commitment`
    /// (used when the production deposit-binding proof is verified upstream
    /// and already returns the commitment).
    ///
    /// Production rationale: in MVP, the deposit-binding ZK proof returns
    /// a verified commitment as a public input. Once verified, the bridge
    /// can append it to the queue without re-hashing the user secrets. This
    /// path saves the per-deposit Poseidon(secret, nonce) cost (~1670 gas).
    ///
    /// Used by tests + the operator script to avoid the per-deposit
    /// crypto_algebra context cost during high-N test fixtures.
    public fun deposit_precomputed(
        leaf_commitment: vector<u8>,
        compliance_attestation_id: u64,
    ) acquires PendingQueue, PendingCommitmentIndex {
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        assert!(vector::length(&leaf_commitment) == FR_BYTES, E_BAD_COMMITMENT_LENGTH);

        let q = borrow_global_mut<PendingQueue>(@eunoma);
        let idx = q.next_index;
        let idx_fr = u64_to_fr_bytes(idx);
        let leaf_acc_input = poseidon_bn254::hash_2(idx_fr, leaf_commitment);
        let new_acc = poseidon_bn254::hash_2(q.acc_hash, leaf_acc_input);

        // Gas P6: push first (explicit copy), then move into acc_hash. See
        // matching comment in `deposit` above for rationale (saves one 32-byte
        // implicit vector copy per call).
        vector::push_back(&mut q.acc_history, copy new_acc);
        q.acc_hash = new_acc;

        // Round-7 Item B.2 hook: populate PendingCommitmentIndex if initialized.
        // Mirror of `deposit` hook — bridge calls `deposit_precomputed` from
        // `eunoma_bridge::deposit_with_commitment` (line 1843) so this
        // path MUST also be covered.
        if (exists<PendingCommitmentIndex>(@eunoma)) {
            let pci = borrow_global_mut<PendingCommitmentIndex>(@eunoma);
            table::add(&mut pci.commitments, idx, copy leaf_commitment);
        };

        q.next_index = idx + 1;

        // Phase D / Agent D6: queue_position dropped (= idx; redundant in MVP).
        let batch_id = idx / DEFAULT_BATCH_SIZE;
        event::emit(DepositQueued {
            deposit_index: idx,
            leaf_commitment,
            deposit_batch_id: batch_id,
            compliance_attestation_id,
        });
    }

    friend eunoma::pool_batch_root_update;

    // ========================================================================
    // Read-only views (used by batch_root_update for invariant checks)
    // ========================================================================

    #[view]
    public fun pending_tail(): u64 acquires PendingQueue {
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        borrow_global<PendingQueue>(@eunoma).next_index
    }

    /// Round-7 Item B.2: read a commitment by leaf index.
    ///
    /// Returns the 32-byte commitment that was queued at `idx`. Aborts with
    /// E_COMMITMENT_INDEX_NOT_INITIALIZED if admin has not yet run
    /// `initialize_commitment_index`. Aborts (`table::borrow` panic) if `idx`
    /// is out of range OR if the commitment was queued BEFORE the index was
    /// initialized (pre-init deposits not retroactively populated).
    ///
    /// Caller (`update_root_batch` V2 dual-write loop) is responsible for
    /// gating with `commitment_index_initialized()` to avoid the panic case.
    #[view]
    public fun commitment_at_index(idx: u64): vector<u8> acquires PendingCommitmentIndex {
        assert!(exists<PendingCommitmentIndex>(@eunoma), E_COMMITMENT_INDEX_NOT_INITIALIZED);
        let pci = borrow_global<PendingCommitmentIndex>(@eunoma);
        *table::borrow(&pci.commitments, idx)
    }

    /// Round-7 Item B.2: predicate — true iff PendingCommitmentIndex resource
    /// has been initialized at @eunoma. Used by `update_root_batch`'s
    /// V2 dual-write loop to gate the enumeration step (avoid abort if admin
    /// has not yet run `initialize_commitment_index`).
    #[view]
    public fun commitment_index_initialized(): bool {
        exists<PendingCommitmentIndex>(@eunoma)
    }

    #[view]
    public fun acc_hash_at(i: u64): vector<u8> acquires PendingQueue {
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        let q = borrow_global<PendingQueue>(@eunoma);
        assert!(i < vector::length(&q.acc_history), E_INDEX_OUT_OF_RANGE);
        *vector::borrow(&q.acc_history, i)
    }

    /// Compute `range_hash` over the leaves indexed `[start, end)`,
    /// using exactly the same hash chain that `deposit` builds going forward.
    ///
    /// Definition (parallel to deposit):
    ///   range_hash := zero32
    ///   for i in start..end:
    ///       range_hash = Poseidon(range_hash, acc_history[i+1] XOR_DELTA(...))
    ///
    /// In practice we cannot subtract Poseidon hashes, so the operator must
    /// re-emit the leaves and we re-derive `leaf_acc_input(i)` via:
    ///   leaf_acc_input(i) := the Poseidon(idx_fr_i, leaf_i) implied
    ///                       by the difference between acc_history[i] and
    ///                       acc_history[i+1].
    ///
    /// However, Poseidon is not invertible. So the operator submits the
    /// `queue_range_hash` it computed off-chain over the same chain, and we
    /// verify the *forward* chain instead: i.e. we ask the verifier to
    /// supply the witnessed leaves so we can recompute. To keep the on-chain
    /// check cheap, we adopt the simpler forward formulation:
    ///
    ///   queue_range_hash[start..end] :=
    ///      Poseidon(acc_history[start], acc_history[end])
    ///
    /// This binds the START and END snapshots to a single 32-byte digest;
    /// the operator must reproduce the same digest off-chain. While weaker
    /// than a full Merkle root over leaves, it is sufficient for the MVP
    /// invariant "operator cannot have substituted a different leaf set
    /// in [start, end)" because the on-chain `acc_history` is append-only
    /// and uniquely determined by past deposits.
    ///
    /// (See dossier "Multi-sig deep-dive — accumulator design choices" for
    /// the full design tradeoff against a per-leaf Merkle range hash.)
    #[view]
    public fun compute_range_hash(start: u64, end: u64): vector<u8>
    acquires PendingQueue {
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        let q = borrow_global<PendingQueue>(@eunoma);
        let len = vector::length(&q.acc_history);
        assert!(start <= end, E_INDEX_OUT_OF_RANGE);
        assert!(end < len, E_INDEX_OUT_OF_RANGE);
        let acc_start = *vector::borrow(&q.acc_history, start);
        let acc_end = *vector::borrow(&q.acc_history, end);
        poseidon_bn254::hash_2(acc_start, acc_end)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fun zero_fr_bytes(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < FR_BYTES) {
            vector::push_back(&mut v, 0u8);
            i = i + 1;
        };
        v
    }

    /// Encode a u64 as a 32-byte little-endian BN254 field element.
    /// (BCS u64 = 8 bytes LE; pad with zeros to 32 bytes — value is well below the field modulus.)
    fun u64_to_fr_bytes(n: u64): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&n);
        let v = vector::empty<u8>();
        let i = 0;
        let nbcs = vector::length(&bcs_bytes);
        while (i < nbcs) {
            vector::push_back(&mut v, *vector::borrow(&bcs_bytes, i));
            i = i + 1;
        };
        while (vector::length(&v) < FR_BYTES) {
            vector::push_back(&mut v, 0u8);
        };
        v
    }

    // ========================================================================
    // Public byte helpers (used by tests and gas benches)
    // ========================================================================

    /// 32 zero bytes (= LSB encoding of BN254 field zero).
    public fun zero_fr_bytes_pub(): vector<u8> {
        zero_fr_bytes()
    }

    /// Encode a u64 as a 32-byte LSB BN254 field element.
    public fun u64_to_fr_bytes_pub(n: u64): vector<u8> {
        u64_to_fr_bytes(n)
    }

    // ========================================================================
    // Test-only aliases (kept for test naming clarity)
    // ========================================================================

    #[test_only]
    public fun zero_fr_bytes_for_test(): vector<u8> {
        zero_fr_bytes()
    }

    #[test_only]
    public fun u64_to_fr_bytes_for_test(n: u64): vector<u8> {
        u64_to_fr_bytes(n)
    }

    #[test_only]
    public fun acc_hash_for_test(): vector<u8> acquires PendingQueue {
        borrow_global<PendingQueue>(@eunoma).acc_hash
    }

    #[test_only]
    public fun fr_bytes(): u64 { FR_BYTES }

    #[test_only]
    public fun default_batch_size(): u64 { DEFAULT_BATCH_SIZE }

    #[test_only]
    public fun e_not_initialized(): u64 { E_NOT_INITIALIZED }
    #[test_only]
    public fun e_already_initialized(): u64 { E_ALREADY_INITIALIZED }
    #[test_only]
    public fun e_not_admin(): u64 { E_NOT_ADMIN }
    #[test_only]
    public fun e_bad_commitment_length(): u64 { E_BAD_COMMITMENT_LENGTH }
    #[test_only]
    public fun e_index_out_of_range(): u64 { E_INDEX_OUT_OF_RANGE }
    #[test_only]
    public fun e_commitment_index_not_initialized(): u64 { E_COMMITMENT_INDEX_NOT_INITIALIZED }
    #[test_only]
    public fun e_commitment_index_already_initialized(): u64 { E_COMMITMENT_INDEX_ALREADY_INITIALIZED }

    /// Round-7 follow-up Ship-blocker #2 helper: synthetically pump the queue
    /// to `target_n` deposits without paying the Poseidon BN254 cost per
    /// deposit. Bypasses `hash_2(idx_fr, leaf_commitment)` and
    /// `hash_2(acc_hash, leaf_acc_input)` — instead it appends synthetic
    /// 32-byte values to `acc_history` and writes synthetic commitments to
    /// `PendingCommitmentIndex` so the V2 dual-write loop in
    /// `update_root_batch` has real data to enumerate.
    ///
    /// Why this is necessary:
    /// - Move test framework's `crypto_algebra` context has a 1 MiB cap per
    ///   VM session. Each Poseidon hash_2 call allocates BN254 Element<Fr>
    ///   scratch — exhausted around N=12-16. The production queue path is
    ///   not test-friendly at high N.
    /// - For the gas bench at N ∈ {4,8,16,32,64} we need to exercise the
    ///   round-7 V2 dual-write loop end-to-end, not the pre-finalize queue
    ///   cost. Synthetic pump lets us do that.
    ///
    /// What synthetic values look like:
    /// - acc_history[i] for i in [old_next, target_n] = synthetic 32-byte
    ///   value derived from `i + 0xS0000000` (pad to 32B, distinct per i).
    ///   Operators in production reconstruct this off-chain via Poseidon —
    ///   the test path's `compute_range_hash(0, target_n)` will return a
    ///   value derived from acc_history[0] (zero) and acc_history[target_n]
    ///   (synthetic), so the operator-built attestation message just needs
    ///   to use that same range_hash. (The valid_4of7_sigs path computes the
    ///   range_hash via compute_range_hash and signs over it — so this works
    ///   transparently.)
    /// - PendingCommitmentIndex.commitments[i] = synthetic 32-byte value
    ///   derived from `i + 0xC0000000`.
    ///
    /// Gated `#[test_only]` — never compiled into production bytecode.
    #[test_only]
    public fun pump_queue_synthetic_for_test(
        admin: &signer,
        target_n: u64,
    ) acquires PendingQueue, PendingCommitmentIndex {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        let q = borrow_global_mut<PendingQueue>(@eunoma);
        assert!(target_n >= q.next_index, E_SYNTHETIC_PUMP_TARGET_BELOW_TAIL);
        let i = q.next_index;
        while (i < target_n) {
            let synth_acc = bcs::to_bytes(&(i + 0x50000000));
            while (vector::length(&synth_acc) < FR_BYTES) {
                vector::push_back(&mut synth_acc, 0u8);
            };
            q.acc_hash = copy synth_acc;
            vector::push_back(&mut q.acc_history, synth_acc);

            if (exists<PendingCommitmentIndex>(@eunoma)) {
                let pci = borrow_global_mut<PendingCommitmentIndex>(@eunoma);
                let synth_c = bcs::to_bytes(&(i + 0xC0000000));
                while (vector::length(&synth_c) < FR_BYTES) {
                    vector::push_back(&mut synth_c, 0u8);
                };
                table::add(&mut pci.commitments, i, synth_c);
            };

            i = i + 1;
        };
        q.next_index = target_n;
    }

    /// Round-7 cleanup SB-2: production-callable synthetic queue pump body.
    ///
    /// Byte-identical body to `pump_queue_synthetic_for_test` minus the
    /// `#[test_only]` annotation. Promoted out of test-only so the
    /// gas-measurement entry `pool_batch_root_update::pump_queue_synthetic_admin`
    /// can drive it on the real testnet bridge package.
    ///
    /// Friend-gated to `pool_batch_root_update` (see friend declaration at
    /// pending_queue.move:330) so no other module can call this directly.
    /// The caller (`pump_queue_synthetic_admin`) layers the
    /// post-V2-migration safety gate (E_PUMP_FORBIDDEN_POST_MIGRATION = 220)
    /// before delegating here. THIS function still enforces admin-only via
    /// `signer::address_of(admin) == @eunoma`, defending the synthetic
    /// path even if the friend boundary is ever widened.
    ///
    /// Reuses existing error codes:
    /// - E_NOT_ADMIN (3) if signer != @eunoma.
    /// - E_NOT_INITIALIZED (1) if PendingQueue resource is absent.
    public(friend) fun do_synthetic_pump(
        admin: &signer,
        target_n: u64,
    ) acquires PendingQueue, PendingCommitmentIndex {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<PendingQueue>(@eunoma), E_NOT_INITIALIZED);
        let q = borrow_global_mut<PendingQueue>(@eunoma);
        assert!(target_n >= q.next_index, E_SYNTHETIC_PUMP_TARGET_BELOW_TAIL);
        let i = q.next_index;
        while (i < target_n) {
            let synth_acc = bcs::to_bytes(&(i + 0x50000000));
            while (vector::length(&synth_acc) < FR_BYTES) {
                vector::push_back(&mut synth_acc, 0u8);
            };
            q.acc_hash = copy synth_acc;
            vector::push_back(&mut q.acc_history, synth_acc);

            if (exists<PendingCommitmentIndex>(@eunoma)) {
                let pci = borrow_global_mut<PendingCommitmentIndex>(@eunoma);
                let synth_c = bcs::to_bytes(&(i + 0xC0000000));
                while (vector::length(&synth_c) < FR_BYTES) {
                    vector::push_back(&mut synth_c, 0u8);
                };
                table::add(&mut pci.commitments, i, synth_c);
            };

            i = i + 1;
        };
        q.next_index = target_n;
    }
}
