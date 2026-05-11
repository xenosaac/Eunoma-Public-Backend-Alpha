/// AptosShield Spike — multi-sig-attested batch root update.
///
/// Module: eunoma::pool_batch_root_update
///
/// Purpose:
///   * The on-chain half of the Tornado-Trees-style deposit batching path.
///     An off-chain operator (see `operator/batch_updater.ts`) consumes
///     `pending_queue::DepositQueued` events, computes the new Merkle subtree
///     root, gathers 4-of-7 Ed25519 signatures over the canonical batch
///     attestation message, and submits `update_root_batch`.
///   * This module enforces the 9 STRUCTURAL INVARIANTS that bound what the
///     multi-sig committee can and cannot do (see HANDOFF Section 1.1's
///     trust pin and the spike charter's "Multi-sig CAN/CANNOT" matrix).
///
/// The 9 invariants (verbatim from the spike brief, in execution order
/// inside `update_root_batch`):
///
///   1. `old_root == current_finalized_root`        (no rollback / no skip)
///   2. `start_index == next_unfinalized_index`     (queue processed in order)
///   3. `end_index <= current_pending_tail`         (cannot fold leaves not yet deposited)
///   4. `end_index - start_index == batch_size`     (no off-by-one)
///   5. `queue_range_hash` matches the on-chain accumulator restricted
///      to `[start_index, end_index)`               (cannot fabricate leaves)
///   6. `batch_id == last_batch_id + 1`             (no replay, no skip)
///   7. 4-of-7 signatures valid over BCS(canonical message)
///   8. Main operator MUST be in the 4 signing      (HANDOFF Section 1.1 pin)
///   9. Append `new_root` to root_history            (root history append-only;
///                                                    in-flight withdraws keep working)
///
/// Trust model summary (from spike brief):
///   * Multi-sig CAN: delay batches, censor specific deposits,
///     sign a mathematically-wrong `new_root` (accepted MVP-trust risk;
///     mitigated by public auditability + v2 ZK upgrade path + future
///     challenge window).
///   * Multi-sig CANNOT (these are the structural prevents above): skip
///     queue indices, fabricate leaves not in pending events, roll back
///     the root, modify `old_root`, exceed the pending tail, replay a batch.
///
/// Out of scope (design notes only — see DOSSIER):
///   * Challenge-window enforcement (placeholder field present below).
///   * Forced-inclusion / alternate-keeper liveness path.
///   * Full ZK insertion-proof verification (Mode B / Mode C v2).
module eunoma::pool_batch_root_update {
    use std::vector;
    use std::signer;
    use std::bcs;

    use aptos_framework::event;

    use aptos_std::smart_table::{Self, SmartTable};

    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;

    // ========================================================================
    // Constants
    // ========================================================================

    const FR_BYTES: u64 = 32;

    /// Domain separator for the batch root update attestation message.
    /// Mirrors HANDOFF Section 1.5's binding requirements (domain, chain id,
    /// pool id, threshold, ...) — the operator service builds the same
    /// struct in the same order before signing.
    const DOMAIN_BATCH_ROOT_UPDATE_V1: vector<u8> = b"APTOSHIELD_BATCH_ROOT_UPDATE_V1";

    // ========================================================================
    // Error codes  (numbered NOT to collide with pending_queue or multi_sig)
    // ========================================================================

    const E_NOT_INITIALIZED: u64 = 200;
    const E_ALREADY_INITIALIZED: u64 = 201;
    const E_NOT_ADMIN: u64 = 202;

    // INVARIANT-MAPPED ERROR CODES.
    // These are 1-to-1 with the 9 invariants and are referenced by negative
    // tests in `tests/spike_e2e.move`. Keep numbering stable.
    const E_INV1_BAD_OLD_ROOT: u64 = 211;                    // Invariant 1
    const E_INV2_START_INDEX_MISMATCH: u64 = 212;            // Invariant 2
    const E_INV3_END_EXCEEDS_PENDING_TAIL: u64 = 213;        // Invariant 3
    const E_INV4_BATCH_SIZE_MISMATCH: u64 = 214;             // Invariant 4
    const E_INV5_QUEUE_RANGE_HASH_MISMATCH: u64 = 215;       // Invariant 5
    const E_INV6_BATCH_ID_NOT_NEXT: u64 = 216;               // Invariant 6
    // Invariants 7 + 8 reuse the multi_sig_verifier abort codes
    // (E_TOO_FEW_OPERATOR_SIGNATURES = 109, E_MAIN_OPERATOR_SIGNATURE_REQUIRED = 110, etc.)
    // Invariant 9 is constructive (root history append) — no error code path.
    const E_BAD_INPUT_LENGTH: u64 = 217;
    const E_BATCH_SIZE_ZERO: u64 = 218;

    /// Round-7 cleanup SB-2: pump_queue_synthetic_admin called after V2 migration completed.
    /// Synthetic data would corrupt a populated mainnet pool. Pump-side guard fires
    /// from `pool_batch_root_update` only — queue module has no equivalent post-migration
    /// constant (the related queue-side guard `E_SYNTHETIC_PUMP_TARGET_BELOW_TAIL = 9`
    /// at `pending_queue.move:72` defends a different invariant: monotonic queue tail).
    const E_PUMP_FORBIDDEN_POST_MIGRATION: u64 = 220;

    // Round-7 Item B.1 — V2 SmartTable migration error codes.
    /// `migrate_root_history_to_v2` called twice (idempotency guard).
    const E_ALREADY_MIGRATED: u64 = 117;
    /// `migrate_root_history_to_v2` invoked when V1 has > 1000 root entries
    /// (audit B4-2: per-tx storage write cap budget exceeded — must use a
    /// chunked migration if this hits in practice; deferred until we observe
    /// actual root count trajectory on testnet).
    const E_MIGRATION_WINDOW_CLOSED: u64 = 118;
    /// V2 read attempted before V2 initialization (only used by V2-direct view
    /// helpers, NOT by `is_root_in_history` which falls back to V1).
    const E_NOT_INITIALIZED_V2: u64 = 119;

    // ========================================================================
    // Resources
    // ========================================================================

    /// Global root history + batch state. Lives at @eunoma.
    ///
    /// Append-only: `root_history` only grows; `current_finalized_root` always
    /// equals `last(root_history)`. `last_batch_id` is the largest accepted
    /// batch id; the genesis state has `last_batch_id == 0` and
    /// `next_batch_id` is therefore 1 (first batch must use batch_id = 1).
    /// `next_unfinalized_index` is the smallest queue index that has NOT yet
    /// been folded into a finalized root — the first deposit accepted after
    /// the most recent batch.
    ///
    /// `chain_id` and `pool_id` are bound into every attestation message so
    /// signatures cannot be replayed across deployments (HANDOFF Section 1.5).
    /// `operator_set_version` mirrors the same field semantics from
    /// `eunoma_bridge::VaultConfig`. The spike has a static set, so
    /// it is initialized at 0 and never bumped.
    struct RootHistory has key {
        root_history: vector<vector<u8>>,
        current_finalized_root: vector<u8>,
        next_unfinalized_index: u64,
        last_batch_id: u64,
        chain_id: u8,
        pool_id: vector<u8>,
        operator_set_version: u64,
        admin: address,
    }

    /// Round-7 Item B.1 — V2 root history (SmartTable-backed, O(1) lookup).
    ///
    /// Why this resource exists:
    /// - V1 `RootHistory.root_history: vector<vector<u8>>` requires linear
    ///   scan O(N) in `is_root_in_history`. After ~10K batches that's ~10K
    ///   storage reads per withdraw — well above Aptos's 9,200 unit per-tx
    ///   execution gas cap.
    /// - V2 SmartTable<root, batch_id> drops to O(1) bucket lookup.
    /// - Historical Round-8 design context (now superseded by R8-1 drop):
    ///   originally `finalized_commitments: SmartTable<commitment, batch_id>`
    ///   was added as a load-bearing dependency for Round-8 Item A
    ///   `force_withdraw_pending_deposit`. Round-8 was DROPPED per
    ///   LOCAL_ERRATA R8-1 (Codex 2/10 + Tornado/Railgun/Aztec
    ///   industry-precedent decision). The map is retained for: (a) general
    ///   future-feature placeholder governed by R7-9 generalized constraint
    ///   (treat as many-to-one, NOT a deposit-identity oracle); (b) the
    ///   upsert-based duplicate-commitment DoS defense (R7-9) is still
    ///   load-bearing. Populated alongside V2.root_set in
    ///   `update_root_batch`'s dual-write block.
    ///
    /// Compatible-upgrade pattern (HC-9):
    /// - SEPARATE resource alongside V1 — V1 fields untouched.
    /// - V1 push_back continues during dual-write transition window.
    /// - V1 deprecation deferred to a future round (LOCAL_ERRATA R7-2).
    ///
    /// `migration_complete` flag (audit C3 #4 double-spend defense):
    /// - true means V2.root_set has the FULL prefix of V1.root_history at
    ///   the moment migration ran. `is_root_in_history` reads V2 directly.
    /// - false means V2 may have a partial / inconsistent prefix.
    ///   `is_root_in_history` MUST fall back to V1 to avoid double-spend
    ///   (a withdraw using a root that is in V1 but missing from V2 would
    ///   be falsely rejected, OR worse a future race could let a stale
    ///   spent root pass V2's contains check).
    /// - Set true in the migration entry's single tx (atomic — no partial
    ///   state visible across blocks).
    struct RootHistoryV2 has key {
        /// 32-byte root → batch_id at which it was finalized.
        /// `i==0` is the empty-tree root with batch_id=0; `i>=1` is batch i.
        root_set: SmartTable<vector<u8>, u64>,
        /// 32-byte commitment → batch_id at which it was finalized into the
        /// Merkle root. Round-8 Item A force_withdraw uses this to verify the
        /// commitment lives in the finalized state.
        finalized_commitments: SmartTable<vector<u8>, u64>,
        last_batch_id: u64,
        current_finalized_root: vector<u8>,
        pool_id: vector<u8>,
        chain_id: u8,
        next_unfinalized_index: u64,
        migration_complete: bool,
        admin: address,
    }

    // ========================================================================
    // Events
    // ========================================================================

    #[event]
    struct BatchRootUpdated has drop, store {
        batch_id: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
    }

    // ========================================================================
    // Canonical attestation message
    //
    // BCS field order is part of the wire spec. The off-chain operator
    // service builds the same struct in the SAME order before signing. Do
    // NOT reorder.
    // ========================================================================

    struct BatchUpdateAttestationMessage has drop, store, copy {
        domain: vector<u8>,
        chain_id: u8,
        pool_id: vector<u8>,
        operator_set_version: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
        batch_id: u64,
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize root history with the empty-tree root. Callable once,
    /// by the @eunoma admin. The empty-tree root is supplied
    /// by the caller (rather than recomputed on-chain) so the spike does
    /// not pay 20 Poseidon calls just to publish the genesis root — the
    /// operator computes it off-chain and the on-chain code accepts it
    /// as the starting point. (For production, this would be hard-coded
    /// or computed at deploy time.)
    public entry fun initialize(
        admin: &signer,
        empty_tree_root: vector<u8>,
        chain_id: u8,
        pool_id: vector<u8>,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<RootHistory>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(vector::length(&empty_tree_root) == FR_BYTES, E_BAD_INPUT_LENGTH);

        let history = vector::empty<vector<u8>>();
        vector::push_back(&mut history, copy empty_tree_root);

        move_to(admin, RootHistory {
            root_history: history,
            current_finalized_root: empty_tree_root,
            next_unfinalized_index: 0,
            last_batch_id: 0,
            chain_id,
            pool_id,
            operator_set_version: 0,
            admin: admin_addr,
        });
    }

    // ========================================================================
    // Round-7 Item B.1 — V2 migration entry
    // ========================================================================

    /// Round-7 Item B.1: admin entry to migrate V1 RootHistory snapshot into
    /// V2 SmartTable.
    ///
    /// Idempotency (audit B4-1): `assert!(!exists<RootHistoryV2>)` — second
    /// call aborts with E_ALREADY_MIGRATED. NOT a re-init pattern; admin must
    /// re-publish bridge to retry if this somehow goes wrong (acceptable for
    /// a one-time storage migration).
    ///
    /// Size-bounded (audit B4-2): `assert!(N <= 1000, E_MIGRATION_WINDOW_CLOSED)`.
    /// Exceeded ⇒ admin must publish a future chunked migration entry. 1000 is
    /// chosen to keep total per-tx storage writes (1000 × 32B keys + 32B values
    /// + bucket overhead) well under Aptos's per-tx storage budget.
    ///
    /// Atomicity: `migration_complete: true` set within the same `move_to`,
    /// so no partial state is observable across blocks. `is_root_in_history`
    /// becomes V2-direct as soon as this tx commits.
    ///
    /// V2 fields populated:
    /// - `root_set` ← every entry in V1.root_history (mapped to its index as
    ///   batch_id; index 0 is genesis empty-tree root with batch_id 0).
    /// - `finalized_commitments` ← starts EMPTY. Past batches' commitments
    ///   are NOT retroactively backfilled (the commitment data lives in
    ///   `pool_pending_queue::PendingCommitmentIndex` which itself only
    ///   populates from `initialize_commitment_index` forward).
    ///   Historical Round-8 design context (now superseded by R8-1 drop):
    ///   originally this was acceptable because Round-8 Item A force_withdraw
    ///   only needed forward-going commitments, with legacy users handled via
    ///   a future "explicit pre-batch index" path. Round-8 was DROPPED per
    ///   LOCAL_ERRATA R8-1 (Codex 2/10 + Tornado/Railgun/Aztec
    ///   industry-precedent decision); the map is retained for: (a) general
    ///   future-feature placeholder governed by R7-9 generalized constraint;
    ///   (b) the upsert-based duplicate-commitment DoS defense is still
    ///   load-bearing.
    public entry fun migrate_root_history_to_v2(admin: &signer) acquires RootHistory {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<RootHistoryV2>(@eunoma), E_ALREADY_MIGRATED);

        let v1 = borrow_global<RootHistory>(@eunoma);
        let n = vector::length(&v1.root_history);
        assert!(n <= 1000, E_MIGRATION_WINDOW_CLOSED);

        let root_set = smart_table::new<vector<u8>, u64>();
        let i = 0;
        while (i < n) {
            let r = *vector::borrow(&v1.root_history, i);
            // batch_id derivation: i==0 is empty_tree_root (batch_id 0);
            // i>=1 is the i-th batch root (batch_id i). Use upsert-equivalent:
            // legacy V1 may contain duplicate entries if a degenerate batch
            // produced the same root twice; we keep the LAST batch_id observed
            // (the i loop walks forward, so latest wins) by branching here.
            if (smart_table::contains(&root_set, r)) {
                smart_table::upsert(&mut root_set, r, i);
            } else {
                smart_table::add(&mut root_set, r, i);
            };
            i = i + 1;
        };

        move_to(admin, RootHistoryV2 {
            root_set,
            finalized_commitments: smart_table::new<vector<u8>, u64>(),
            last_batch_id: v1.last_batch_id,
            current_finalized_root: v1.current_finalized_root,
            pool_id: v1.pool_id,
            chain_id: v1.chain_id,
            next_unfinalized_index: v1.next_unfinalized_index,
            // Single-tx migration with atomic resource publish — flag flips
            // immediately. No partial state observable across blocks.
            migration_complete: true,
            admin: admin_addr,
        });
    }

    // ========================================================================
    // Round-7 cleanup SB-2 — admin-gated synthetic queue pump entry
    // ========================================================================

    /// Round-7 cleanup SB-2: production-callable synthetic queue pump entry.
    ///
    /// Used by the gas-measurement script to populate the queue at N in {4,8,16,32,64}
    /// so update_root_batch can be measured via aptos move simulate (network simulation,
    /// NOT --profile-gas which is local-debugger-only) against the real bridge package
    /// without paying per-deposit Poseidon cost.
    ///
    /// Aborts:
    /// - E_NOT_ADMIN (202) if signer != @eunoma.
    /// - E_PUMP_FORBIDDEN_POST_MIGRATION (220) if V2 migration_complete has been set.
    public entry fun pump_queue_synthetic_admin(
        admin: &signer,
        target_n: u64,
    ) acquires RootHistoryV2 {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        if (exists<RootHistoryV2>(@eunoma)) {
            let v2 = borrow_global<RootHistoryV2>(@eunoma);
            assert!(!v2.migration_complete, E_PUMP_FORBIDDEN_POST_MIGRATION);
        };
        pending_queue::do_synthetic_pump(admin, target_n);
    }

    #[test_only]
    public fun e_pump_forbidden_post_migration(): u64 { E_PUMP_FORBIDDEN_POST_MIGRATION }

    // ========================================================================
    // Entry function: update_root_batch
    //
    // This is the on-chain half of the batch root update flow. It runs the
    // 9 structural-invariant checks in the order documented at module top.
    // ========================================================================

    public entry fun update_root_batch(
        _submitter: &signer,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
        batch_id: u64,
        signatures: vector<vector<u8>>,
    ) acquires RootHistory, RootHistoryV2 {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);

        // Length sanity (defensive — these would also be caught downstream).
        assert!(vector::length(&old_root) == FR_BYTES, E_BAD_INPUT_LENGTH);
        assert!(vector::length(&new_root) == FR_BYTES, E_BAD_INPUT_LENGTH);
        assert!(vector::length(&queue_range_hash) == FR_BYTES, E_BAD_INPUT_LENGTH);
        assert!(vector::length(&frontier_or_meta_hash) == FR_BYTES, E_BAD_INPUT_LENGTH);
        assert!(batch_size > 0, E_BATCH_SIZE_ZERO);

        let h = borrow_global_mut<RootHistory>(@eunoma);

        // ----------------------------------------------------------------
        // Invariant 1: old_root == current_finalized_root (no rollback).
        // ----------------------------------------------------------------
        assert!(old_root == h.current_finalized_root, E_INV1_BAD_OLD_ROOT);

        // ----------------------------------------------------------------
        // Invariant 2: start_index == next_unfinalized_index
        // (queue processed in order).
        // ----------------------------------------------------------------
        assert!(start_index == h.next_unfinalized_index, E_INV2_START_INDEX_MISMATCH);

        // ----------------------------------------------------------------
        // Invariant 3: end_index <= current_pending_tail
        // (cannot fold leaves not yet deposited).
        // ----------------------------------------------------------------
        let pending_tail = pending_queue::pending_tail();
        assert!(end_index <= pending_tail, E_INV3_END_EXCEEDS_PENDING_TAIL);

        // ----------------------------------------------------------------
        // Invariant 4: end_index - start_index == batch_size (no off-by-one).
        // ----------------------------------------------------------------
        assert!(end_index >= start_index, E_INV4_BATCH_SIZE_MISMATCH);
        assert!(end_index - start_index == batch_size, E_INV4_BATCH_SIZE_MISMATCH);

        // ----------------------------------------------------------------
        // Invariant 5: queue_range_hash matches on-chain accumulator over
        // the half-open range [start_index, end_index).
        //
        // The on-chain `pending_queue::compute_range_hash` reads the
        // append-only `acc_history` and folds Poseidon(acc_history[start],
        // acc_history[end]). The off-chain operator must reproduce the
        // SAME 32-byte digest. Mismatch ⇒ leaves were fabricated or
        // substituted, which the multi-sig CANNOT do.
        // ----------------------------------------------------------------
        let expected_range_hash = pending_queue::compute_range_hash(start_index, end_index);
        assert!(queue_range_hash == expected_range_hash, E_INV5_QUEUE_RANGE_HASH_MISMATCH);

        // ----------------------------------------------------------------
        // Invariant 6: batch_id == last_batch_id + 1 (no replay, no skip).
        // ----------------------------------------------------------------
        assert!(batch_id == h.last_batch_id + 1, E_INV6_BATCH_ID_NOT_NEXT);

        // ----------------------------------------------------------------
        // Invariants 7 + 8: 4-of-7 valid signatures with main operator
        // included, over the canonical BCS-encoded message. Aborts with
        // multi_sig_verifier::E_TOO_FEW_OPERATOR_SIGNATURES (109) or
        // E_MAIN_OPERATOR_SIGNATURE_REQUIRED (110) on failure.
        // ----------------------------------------------------------------
        let msg = BatchUpdateAttestationMessage {
            domain: DOMAIN_BATCH_ROOT_UPDATE_V1,
            chain_id: h.chain_id,
            pool_id: h.pool_id,
            operator_set_version: h.operator_set_version,
            old_root: copy old_root,
            new_root: copy new_root,
            start_index,
            end_index,
            batch_size,
            queue_range_hash: copy queue_range_hash,
            frontier_or_meta_hash: copy frontier_or_meta_hash,
            batch_id,
        };
        let msg_bytes = bcs::to_bytes(&msg);
        multi_sig_verifier::assert_valid_attestation_from_resource(msg_bytes, signatures);

        // ----------------------------------------------------------------
        // Invariant 9: append new_root to root_history (append-only).
        // current_finalized_root advances; old roots stay valid for any
        // in-flight withdrawal proofs (root-history semantics for
        // withdraw verification).
        //
        // Phase D Agent D2 — V1 retirement gate. Post-migration, V2 is the
        // canonical read source (is_root_in_history fast-paths through V2
        // when migration_complete=true) and V2 ⊇ V1 by construction at
        // migration time. So V1 only needs to keep growing while it's still
        // the source of truth — i.e. when V2 is absent OR V2 is partial
        // (migration_complete=false). Once migrated, V1 is frozen; V2 alone
        // accumulates new finalized roots. This preserves:
        //   - is_root_in_history correctness (reads V2 post-migration)
        //   - v2_set_equals_v1 invariant (∀r∈V1: r∈V2 — V2 just has more)
        //   - in-flight withdrawal proofs (atomic single-tx migration with
        //     migration_complete=true set in same move_to; no observable
        //     partial state across blocks)
        // Gas: skips one storage write (root_history vector slot) per batch
        // post-migration, plus the copy+push_back instruction cost.
        // ----------------------------------------------------------------
        let v1_still_canonical = if (exists<RootHistoryV2>(@eunoma)) {
            !borrow_global<RootHistoryV2>(@eunoma).migration_complete
        } else {
            true
        };
        if (v1_still_canonical) {
            vector::push_back(&mut h.root_history, copy new_root);
        };

        // Round-7 Item B.4 — V2 dual-write block.
        //
        // Order: V2 writes happen AFTER V1 vector::push_back and BEFORE
        // V1 metadata bumps (next_unfinalized_index, last_batch_id). Why:
        // - V1 vector is the source-of-truth (HC-9 untouched).
        // - V2 is enriched alongside; if V2 update aborts mid-loop, V1 is
        //   already consistent and the whole tx aborts (atomic — no partial
        //   on-chain state). On retry, V2 resumes from the matching V1 state.
        // - Enumeration window [start_index, end_index) reads from
        //   PendingCommitmentIndex against the PRE-advance state — i.e.
        //   start_index == h.next_unfinalized_index (still the OLD value
        //   here, asserted equal earlier) and end_index <= pending_tail.
        //
        // CRITICAL audit B3: smart_table::upsert (NOT add) for root_set.
        // Edge case: a degenerate batch could re-finalize the same root
        // (e.g. batch with zero net leaves). add() would abort; upsert is
        // safe + last-batch-id wins.
        //
        // CRITICAL audit B5 (R7-9 amended): smart_table::upsert for
        // finalized_commitments — same upsert-with-latest-batch_id semantics
        // as root_set above. Originally `add` (under the old "commitments are
        // unique by construction" assumption); R7-9 proved that assumption
        // wrong: two byte-identical (secret, nonce) deposits produce the SAME
        // commitment, so `add` aborts the entire batch finalize and a single
        // user can DoS a 64-deposit batch. Upsert keeps the latest batch_id
        // observed; double-spend safety is enforced UPSTREAM by the
        // nullifier_hash anti-replay check at withdraw time
        // (eunoma_bridge::withdraw_to_recipient gate 4), so
        // finalized_commitments is NOT a deposit-identity oracle.
        // DO NOT revert to add — see R7-9 for DoS rationale (duplicate-
        // commitment DoS via byte-identical (secret, nonce) deposits).
        if (exists<RootHistoryV2>(@eunoma)) {
            let v2 = borrow_global_mut<RootHistoryV2>(@eunoma);
            smart_table::upsert(&mut v2.root_set, copy new_root, batch_id);
            v2.current_finalized_root = copy new_root;
            v2.next_unfinalized_index = end_index;
            v2.last_batch_id = batch_id;

            // Enumerate this batch's commitments [start_index, end_index)
            // into finalized_commitments. Gated on commitment_index_initialized
            // so pre-init batches finalize V2 root_set without aborting; the
            // commitment-index population is a forward-only commitment
            // (legacy commitments stay V1-only — round-8 Item A handles that).
            //
            // Round-7 follow-up R7-9: smart_table::upsert (NOT add) here so
            // that two deposits with identical (secret, nonce) → identical
            // commitment do not abort the entire batch finalize at runtime.
            // Anti-DoS: a single user could otherwise queue 2 deposits with
            // the same commitment and brick a 64-deposit batch. Uniqueness
            // for double-spend is enforced upstream by the nullifier_hash
            // anti-replay check at withdraw time (gate 4 in
            // eunoma_bridge::withdraw_to_recipient), so latest-batch-id
            // wins is the safe semantic here. See LOCAL_ERRATA R7-9.
            if (pending_queue::commitment_index_initialized()) {
                // 5.11 D3 perf: delegate the per-leaf upsert loop to a
                // friend-only batched helper in pool_pending_queue. That
                // helper hoists exists<PCI>+borrow_global<PCI> out of the
                // loop (1× vs N×) and keeps the table::borrow + upsert in a
                // single tight intra-module iteration (eliminates the N
                // cross-module calls to commitment_at_index). Semantics —
                // including the R7-9 latest-batch-id-wins upsert defense —
                // are byte-equivalent. See finalize_commitments_into_v2 in
                // pool_pending_queue.move for the contract.
                pending_queue::finalize_commitments_into_v2(
                    &mut v2.finalized_commitments,
                    start_index,
                    end_index,
                    batch_id,
                );
            };
        };

        h.current_finalized_root = copy new_root;
        h.next_unfinalized_index = end_index;
        h.last_batch_id = batch_id;

        event::emit(BatchRootUpdated {
            batch_id,
            old_root,
            new_root,
            start_index,
            end_index,
            batch_size,
            queue_range_hash,
            frontier_or_meta_hash,
        });
    }

    // ========================================================================
    // Read-only views
    // ========================================================================

    #[view]
    public fun current_finalized_root(): vector<u8> acquires RootHistory {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        borrow_global<RootHistory>(@eunoma).current_finalized_root
    }

    #[view]
    public fun next_unfinalized_index(): u64 acquires RootHistory {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        borrow_global<RootHistory>(@eunoma).next_unfinalized_index
    }

    #[view]
    public fun last_batch_id(): u64 acquires RootHistory {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        borrow_global<RootHistory>(@eunoma).last_batch_id
    }

    #[view]
    public fun root_history_length(): u64 acquires RootHistory {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        vector::length(&borrow_global<RootHistory>(@eunoma).root_history)
    }

    /// Round-7 Item B.3: V2-preferred / V1-fallback root-in-history check.
    ///
    /// Decision tree (audit C3 #4 double-spend defense — explicit branching):
    ///   if RootHistoryV2 exists AND v2.migration_complete:
    ///       return smart_table::contains(v2.root_set, root)   // O(1) fast path
    ///   else (V2 missing OR migration_complete == false):
    ///       linear scan V1.root_history                       // O(N) safe fallback
    ///
    /// Why explicit fallback (NOT silent fallthrough):
    /// - V2 partial state ⇒ a withdraw using a root that exists in V1 but
    ///   not yet in V2 would be falsely rejected (liveness bug). Worse, if
    ///   migration ever loaded a stale spent root into V2 by mistake, V2
    ///   could allow a double-spend.
    /// - Therefore: V2 is consulted IFF migration_complete confirms the V2
    ///   prefix is the FULL prefix at migration time. V1 is the source of
    ///   truth otherwise.
    /// - Post-migration `update_root_batch` dual-writes both, keeping V2
    ///   in sync with V1 going forward.
    ///
    /// Function signature (`public fun is_root_in_history(root: vector<u8>): bool`)
    /// MUST stay byte-equal — eunoma_bridge::withdraw_to_recipient at
    /// line 1929 calls it. Aptos compatible-upgrade rules ALLOW `acquires`
    /// extensions, so we add `RootHistoryV2` to the clause.
    #[view]
    public fun is_root_in_history(root: vector<u8>): bool acquires RootHistory, RootHistoryV2 {
        if (exists<RootHistoryV2>(@eunoma)) {
            let v2 = borrow_global<RootHistoryV2>(@eunoma);
            if (v2.migration_complete) {
                return smart_table::contains(&v2.root_set, root)
            };
            // V2 partial state — fall through to V1 (audit C3 #4 defense).
        };
        // V1 fallback path: linear scan (slow but correct).
        if (!exists<RootHistory>(@eunoma)) {
            return false
        };
        let h = borrow_global<RootHistory>(@eunoma);
        let n = vector::length(&h.root_history);
        let i = 0;
        while (i < n) {
            if (*vector::borrow(&h.root_history, i) == root) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// Helper used by off-chain operator + tests to construct the canonical
    /// message bytes that get signed. Same struct, same field order, same
    /// BCS encoding as inside `update_root_batch`. Exposed so tests and
    /// the operator script can both round-trip the bytes.
    #[view]
    public fun canonical_message_bytes(
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
        batch_id: u64,
    ): vector<u8> acquires RootHistory {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        let h = borrow_global<RootHistory>(@eunoma);
        let msg = BatchUpdateAttestationMessage {
            domain: DOMAIN_BATCH_ROOT_UPDATE_V1,
            chain_id: h.chain_id,
            pool_id: h.pool_id,
            operator_set_version: h.operator_set_version,
            old_root,
            new_root,
            start_index,
            end_index,
            batch_size,
            queue_range_hash,
            frontier_or_meta_hash,
            batch_id,
        };
        bcs::to_bytes(&msg)
    }

    // ========================================================================
    // Test-only error code accessors
    // ========================================================================

    #[test_only]
    public fun e_not_initialized(): u64 { E_NOT_INITIALIZED }
    #[test_only]
    public fun e_already_initialized(): u64 { E_ALREADY_INITIALIZED }
    #[test_only]
    public fun e_not_admin(): u64 { E_NOT_ADMIN }
    #[test_only]
    public fun e_inv1_bad_old_root(): u64 { E_INV1_BAD_OLD_ROOT }
    #[test_only]
    public fun e_inv2_start_index_mismatch(): u64 { E_INV2_START_INDEX_MISMATCH }
    #[test_only]
    public fun e_inv3_end_exceeds_pending_tail(): u64 { E_INV3_END_EXCEEDS_PENDING_TAIL }
    #[test_only]
    public fun e_inv4_batch_size_mismatch(): u64 { E_INV4_BATCH_SIZE_MISMATCH }
    #[test_only]
    public fun e_inv5_queue_range_hash_mismatch(): u64 { E_INV5_QUEUE_RANGE_HASH_MISMATCH }
    #[test_only]
    public fun e_inv6_batch_id_not_next(): u64 { E_INV6_BATCH_ID_NOT_NEXT }
    #[test_only]
    public fun e_bad_input_length(): u64 { E_BAD_INPUT_LENGTH }
    #[test_only]
    public fun e_batch_size_zero(): u64 { E_BATCH_SIZE_ZERO }
    #[test_only]
    public fun e_already_migrated(): u64 { E_ALREADY_MIGRATED }
    #[test_only]
    public fun e_migration_window_closed(): u64 { E_MIGRATION_WINDOW_CLOSED }
    #[test_only]
    public fun e_not_initialized_v2(): u64 { E_NOT_INITIALIZED_V2 }
    #[test_only]
    public fun domain_v1(): vector<u8> { DOMAIN_BATCH_ROOT_UPDATE_V1 }

    // ========================================================================
    // V2 view helpers (test + observability)
    // ========================================================================

    /// Round-7 Item B.1: check whether V2 RootHistoryV2 resource exists.
    /// Used by tests + off-chain monitor to confirm migration ran.
    #[view]
    public fun root_history_v2_exists(): bool {
        exists<RootHistoryV2>(@eunoma)
    }

    /// Round-7 Item B.1: read V2.migration_complete (panics if V2 absent).
    #[view]
    public fun root_history_v2_migration_complete(): bool acquires RootHistoryV2 {
        assert!(exists<RootHistoryV2>(@eunoma), E_NOT_INITIALIZED_V2);
        borrow_global<RootHistoryV2>(@eunoma).migration_complete
    }

    /// Round-7 Item B.1: V2-direct contains check on root_set.
    /// Distinct from `is_root_in_history` which falls back to V1.
    #[view]
    public fun v2_contains_root(root: vector<u8>): bool acquires RootHistoryV2 {
        assert!(exists<RootHistoryV2>(@eunoma), E_NOT_INITIALIZED_V2);
        smart_table::contains(&borrow_global<RootHistoryV2>(@eunoma).root_set, root)
    }

    /// Round-7 Item B.1: V2-direct contains check on finalized_commitments.
    /// Used by round-8 Item A force_withdraw (NOT this sprint).
    #[view]
    public fun v2_contains_commitment(commitment: vector<u8>): bool acquires RootHistoryV2 {
        assert!(exists<RootHistoryV2>(@eunoma), E_NOT_INITIALIZED_V2);
        smart_table::contains(&borrow_global<RootHistoryV2>(@eunoma).finalized_commitments, commitment)
    }

    /// Round-7 follow-up Ship-blocker #1: forall-r set-equality verification
    /// between V1 root_history and V2 root_set.
    ///
    /// Brief criterion #9 (verbatim): `forall r in V1.root_history:
    /// smart_table::contains(V2.root_set, r) == true`. Cardinality-only
    /// equality (the original Round-7 closure) does NOT discharge the forall:
    /// V2 could in principle contain |V1| elements that disagree pointwise.
    /// This view fn closes the gap by walking V1.root_history and probing
    /// V2.root_set for each entry — short-circuit on the first miss.
    ///
    /// Returns true iff every V1 entry has a matching V2 row. Aborts if
    /// either resource is missing (caller must run init + migrate first).
    /// Reads only — no state mutation, safe to expose as a view.
    #[view]
    public fun v2_set_equals_v1(): bool acquires RootHistory, RootHistoryV2 {
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<RootHistoryV2>(@eunoma), E_NOT_INITIALIZED_V2);
        let v1 = borrow_global<RootHistory>(@eunoma);
        let v2 = borrow_global<RootHistoryV2>(@eunoma);
        let n = vector::length(&v1.root_history);
        let i = 0;
        while (i < n) {
            let r = *vector::borrow(&v1.root_history, i);
            if (!smart_table::contains(&v2.root_set, r)) {
                return false
            };
            i = i + 1;
        };
        true
    }

    // ========================================================================
    // Test-only helpers (NOT exposed at runtime — gated behind #[test_only]).
    // ========================================================================

    /// Round-7 Item B.1 / test 3 helper: synthetically pump V1 root_history
    /// with `count` distinct synthetic roots so test_migrate_root_history_size_capped
    /// can exercise the audit-B4-2 size cap without paying full update_root_batch
    /// crypto cost. Bypasses signature verification — purely a test aid for
    /// the `vector::length(&v1.root_history) <= 1000` assertion path.
    ///
    /// NOT exposed at runtime: `#[test_only]` on the function ensures the
    /// production module never has this in compiled bytecode.
    #[test_only]
    public fun test_only_pump_root_history(
        admin: &signer,
        count: u64,
    ) acquires RootHistory {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<RootHistory>(@eunoma), E_NOT_INITIALIZED);
        let h = borrow_global_mut<RootHistory>(@eunoma);
        let i = 0;
        while (i < count) {
            // Distinct synthetic root: 32-byte LE encoding of (i + 0xF000_0000).
            let synthetic_root = bcs::to_bytes(&(i + 0xF0000000));
            // Pad to 32 bytes.
            while (vector::length(&synthetic_root) < FR_BYTES) {
                vector::push_back(&mut synthetic_root, 0u8);
            };
            vector::push_back(&mut h.root_history, synthetic_root);
            i = i + 1;
        };
    }

    /// Round-7 follow-up Ship-blocker #3: test-only setter for the V2
    /// `migration_complete` flag.
    ///
    /// Required because the production migration entry (`migrate_root_history_to_v2`)
    /// always sets `migration_complete=true` atomically, so the V2-partial /
    /// V1-fallback branch in `is_root_in_history` (lines 540-541) is otherwise
    /// dead code from the test harness's point of view. Audit C3 #4 invariant
    /// requires the partial-state fallback to be exercised — this setter lets
    /// `round7_v2_tests::test_is_root_in_history_v2_partial_falls_back_to_v1`
    /// flip the flag back to false after migration so the V1 linear-scan path
    /// is hit deterministically.
    ///
    /// Gated `#[test_only]` — never compiled into production bytecode.
    #[test_only]
    public fun set_migration_complete_for_test(complete: bool) acquires RootHistoryV2 {
        assert!(exists<RootHistoryV2>(@eunoma), E_NOT_INITIALIZED_V2);
        let v2 = borrow_global_mut<RootHistoryV2>(@eunoma);
        v2.migration_complete = complete;
    }
}
