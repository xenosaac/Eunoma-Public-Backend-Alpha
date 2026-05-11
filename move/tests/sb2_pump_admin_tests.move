// Round-7 cleanup SB-2 — production-callable synthetic queue pump tests.
//
// Coverage (3 new tests; brings total from 78 -> 81):
//   1. test_pump_admin_happy_pre_migration
//      Admin calls pump_queue_synthetic_admin(8) BEFORE V2 migration runs;
//      pending_tail() advances to 8; every pumped slot has a 32-byte
//      commitment populated in PendingCommitmentIndex.
//   2. test_pump_admin_rejects_non_admin
//      Non-admin signer calls pump_queue_synthetic_admin -> aborts E_NOT_ADMIN
//      (202) located in pool_batch_root_update.
//   3. test_pump_admin_rejects_after_migration
//      Admin migrates V1 -> V2 (migration_complete = true), then calls
//      pump_queue_synthetic_admin -> aborts E_PUMP_FORBIDDEN_POST_MIGRATION
//      (220) located in pool_batch_root_update.
//
// Hard-constraint compliance:
//   - HC-1: pump_queue_synthetic_admin is the production path (NOT
//     #[test_only]); the friend-gated do_synthetic_pump body it delegates
//     to also runs in published bytecode. These tests verify both halves
//     end-to-end with no test-only shortcuts in the entry path.
//   - HC-3: structured abort_code + location in #[expected_failure].
//   - HC-4: #[view] annotations on the read-only views these tests touch
//     (commitment_at_index, pending_tail) ship in the same upgrade.
//   - HC-7: no cardinality short-circuits — test 1 walks every pumped slot.
#[test_only]
module eunoma::sb2_pump_admin_tests {
    use std::vector;
    use std::signer;

    use aptos_std::crypto_algebra;

    use aptos_framework::account;

    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;
    use eunoma::pool_batch_root_update as batch_root_update;

    // ========================================================================
    // Test fixture (mirrors round7_v2_tests.move::setup_full_pool).
    // ========================================================================

    const TEST_CHAIN_ID: u8 = 42;
    const TEST_POOL_ID: vector<u8> = b"APTOSHIELD_SB2_POOL_V1";

    /// Stand up a minimally-initialized pool that owns:
    ///   - PendingQueue (via pending_queue::initialize)
    ///   - PendingCommitmentIndex (via pending_queue::initialize_commitment_index)
    ///   - RootHistory (via batch_root_update::initialize)
    ///   - MultiSigVerifier (so update_root_batch's downstream invariants are
    ///     satisfied IF a follow-on test wants to call it; the SB-2 tests
    ///     themselves don't need signatures)
    ///
    /// pre_init_commitment_index = true ensures the commitment table is live
    /// BEFORE the synthetic pump runs, so the assert in test 1 that walks
    /// every pumped slot has data to read.
    fun setup_pool_pre_migration(
        framework: &signer,
        admin: &signer,
    ) {
        crypto_algebra::enable_cryptography_algebra_natives(framework);

        let admin_addr = signer::address_of(admin);
        if (!account::exists_at(admin_addr)) {
            account::create_account_for_test(admin_addr);
        };

        // 7 placeholder operator pubkeys (32 zero bytes each). The
        // multi_sig_verifier::initialize signature requires non-empty pks
        // length 7, but tests in this file never invoke update_root_batch
        // so the actual key material is irrelevant.
        let pks = vector::empty<vector<u8>>();
        let i = 0;
        while (i < 7) {
            let pk = vector::empty<u8>();
            let j = 0;
            while (j < 32) {
                vector::push_back(&mut pk, 0u8);
                j = j + 1;
            };
            vector::push_back(&mut pks, pk);
            i = i + 1;
        };
        multi_sig_verifier::initialize(admin, pks, 0, 4);
        pending_queue::initialize(admin);
        pending_queue::initialize_commitment_index(admin);

        let zero32 = pending_queue::zero_fr_bytes_for_test();
        batch_root_update::initialize(admin, zero32, TEST_CHAIN_ID, TEST_POOL_ID);
    }

    // ========================================================================
    // Test 1 — Happy path: admin pumps queue to 8 BEFORE V2 migration.
    //
    // After the call:
    //   - pending_tail() == 8
    //   - commitment_at_index(i) has length 32 for every i in [0, 8)
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_pump_admin_happy_pre_migration(
        framework: &signer,
        admin: &signer,
    ) {
        setup_pool_pre_migration(framework, admin);

        // Pre-condition sanity: queue is empty.
        assert!(pending_queue::pending_tail() == 0, 8001);

        // Production-path entry call (NOT the #[test_only] sibling).
        batch_root_update::pump_queue_synthetic_admin(admin, 8);

        // Post-condition: queue advanced to 8.
        assert!(pending_queue::pending_tail() == 8, 8002);

        // Per-slot check: each pumped commitment is 32 bytes (HC-7 forall,
        // not cardinality).
        let i = 0;
        while (i < 8) {
            let c = pending_queue::commitment_at_index(i);
            assert!(vector::length(&c) == 32, 8010 + i);
            i = i + 1;
        };
    }

    // ========================================================================
    // Test 2 — Non-admin signer is rejected with E_NOT_ADMIN (202) located
    //          in pool_batch_root_update.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, attacker = @0xBADBEEF)]
    #[expected_failure(abort_code = 202, location = eunoma::pool_batch_root_update)]
    fun test_pump_admin_rejects_non_admin(
        framework: &signer,
        admin: &signer,
        attacker: &signer,
    ) {
        setup_pool_pre_migration(framework, admin);

        let attacker_addr = signer::address_of(attacker);
        if (!account::exists_at(attacker_addr)) {
            account::create_account_for_test(attacker_addr);
        };

        // Attacker tries to pump -> aborts E_NOT_ADMIN (202) at the
        // batch_root_update entry's signer check.
        batch_root_update::pump_queue_synthetic_admin(attacker, 4);
    }

    // ========================================================================
    // Test 3 — After migration_complete = true, admin pump is rejected with
    //          E_PUMP_FORBIDDEN_POST_MIGRATION (220) located in
    //          pool_batch_root_update.
    //
    //          Mirrors the on-chain mainnet/testnet safety: synthetic data
    //          would corrupt a populated pool, so the gate hard-locks once
    //          V2 migration finalizes.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 220, location = eunoma::pool_batch_root_update)]
    fun test_pump_admin_rejects_after_migration(
        framework: &signer,
        admin: &signer,
    ) {
        setup_pool_pre_migration(framework, admin);

        // Atomic migration -> V2 exists with migration_complete = true.
        batch_root_update::migrate_root_history_to_v2(admin);

        // Admin pump -> aborts E_PUMP_FORBIDDEN_POST_MIGRATION (220).
        batch_root_update::pump_queue_synthetic_admin(admin, 4);
    }

    // ========================================================================
    // Test 4 — Round-7 cleanup C1 (Codex cycle 1 fix): admin pump with
    //          target_n < current pending_tail aborts
    //          E_SYNTHETIC_PUMP_TARGET_BELOW_TAIL (9) located in
    //          pool_pending_queue.
    //
    //          Protects monotonic queue tail invariant: do_synthetic_pump's
    //          `while (i < target_n)` loop body would silently skip and
    //          truncate next_index = target_n if target_n < q.next_index,
    //          rolling back the queue and corrupting acc_history. The new
    //          assert in pool_pending_queue::do_synthetic_pump enforces
    //          target_n >= q.next_index before entering the loop.
    //
    //          Abort fires from inside do_synthetic_pump itself, NOT from
    //          the pool_batch_root_update entry's pre-loop V2-migration gate
    //          (220) — so location is pool_pending_queue with code 9.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 9, location = eunoma::pool_pending_queue)]
    fun test_pump_admin_rejects_target_below_tail(
        framework: &signer,
        admin: &signer,
    ) {
        setup_pool_pre_migration(framework, admin);

        // Establish baseline: pump to 8.
        batch_root_update::pump_queue_synthetic_admin(admin, 8);
        assert!(pending_queue::pending_tail() == 8, 8100);

        // Attempt to pump backwards to 4 -> aborts inside
        // pool_pending_queue::do_synthetic_pump with code 9.
        batch_root_update::pump_queue_synthetic_admin(admin, 4);
    }
}
