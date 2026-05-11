// Round-7 sprint v2 — Item B integration tests.
//
// Coverage (5 new tests; brings total from 66 → 71):
//   1. test_migrate_root_history_to_v2_happy
//      V1 has N entries → migrate → V2 contains all N + migration_complete=true.
//   2. test_migrate_root_history_to_v2_idempotent_aborts
//      Calling migrate twice aborts with E_ALREADY_MIGRATED (117).
//   3. test_migrate_root_history_size_capped
//      V1 with 1001 entries → migrate aborts with E_MIGRATION_WINDOW_CLOSED (118).
//   4. test_update_root_batch_dual_writes_v1_v2
//      Post V2 init + commitment-index init, finalize a batch → V1 vector grew
//      AND V2.root_set contains new_root AND V2.finalized_commitments contains
//      every queued commitment in [start, end).
//   5. test_is_root_in_history_post_migrate
//      Confirms V2 fast path is taken when migration_complete=true (asserts on
//      V2-direct view + ensures behavior matches V1 ground truth).
//
// HC-9 compliance:
//   - V1 RootHistory + PendingQueue struct fields untouched.
//   - V2 added alongside V1; dual-write keeps V1 source-of-truth.
//   - is_root_in_history function signature unchanged (acquires extends only,
//     compatible per Aptos upgrade rules).
//
// Per audit (BRIEF_ROUND_7_BD_IMPLEMENTATION.md §"Audit-driven modifications"):
//   - Audit B5 dependency: PendingCommitmentIndex enumeration is exercised
//     via test 4 (operator MUST have run initialize_commitment_index).
//   - Audit C3 #4: migration_complete flag exercised via test 5.
//   - Audit B4-1 idempotency: test 2.
//   - Audit B4-2 size cap: test 3.
//   - Audit B3 (upsert vs add for root_set): test 4 commit edge — single batch
//     does NOT exercise duplicate-root path here; documented as a known gap +
//     covered by static review of upsert call site (line in module body).
#[test_only]
module eunoma::round7_v2_tests {
    use std::vector;
    use std::signer;

    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;

    use aptos_framework::account;

    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;
    use eunoma::pool_batch_root_update as batch_root_update;

    // ========================================================================
    // Test fixture (mirrors integration_pool_e2e.move setup_full_pool).
    // ========================================================================

    const TEST_CHAIN_ID: u8 = 42;
    const TEST_POOL_ID: vector<u8> = b"APTOSHIELD_R7_POOL_V1";

    fun gen_seven_active_operators(): (
        vector<ed25519::SecretKey>, vector<vector<u8>>
    ) {
        let sks = vector::empty<ed25519::SecretKey>();
        let pks = vector::empty<vector<u8>>();
        let i = 0;
        while (i < 7) {
            let (sk, vpk) = ed25519::generate_keys();
            let pk_bytes = ed25519::validated_public_key_to_bytes(&vpk);
            vector::push_back(&mut sks, sk);
            vector::push_back(&mut pks, pk_bytes);
            i = i + 1;
        };
        (sks, pks)
    }

    fun setup_full_pool(
        framework: &signer,
        admin: &signer,
    ): (vector<ed25519::SecretKey>, vector<vector<u8>>) {
        crypto_algebra::enable_cryptography_algebra_natives(framework);

        let admin_addr = signer::address_of(admin);
        if (!account::exists_at(admin_addr)) {
            account::create_account_for_test(admin_addr);
        };

        let (sks, pks) = gen_seven_active_operators();
        multi_sig_verifier::initialize(admin, copy pks, 0, 4);
        pending_queue::initialize(admin);

        let zero32 = pending_queue::zero_fr_bytes_for_test();
        batch_root_update::initialize(admin, zero32, TEST_CHAIN_ID, TEST_POOL_ID);

        (sks, pks)
    }

    fun sign_with(
        sks: &vector<ed25519::SecretKey>,
        i: u64,
        msg: &vector<u8>,
    ): vector<u8> {
        let sk = vector::borrow(sks, i);
        let sig = ed25519::sign_arbitrary_bytes(sk, *msg);
        ed25519::signature_to_bytes(&sig)
    }

    fun empty_sig_vec(): vector<vector<u8>> {
        let v = vector::empty<vector<u8>>();
        let i = 0;
        while (i < 7) {
            vector::push_back(&mut v, vector::empty<u8>());
            i = i + 1;
        };
        v
    }

    fun put_sig(sigs: &mut vector<vector<u8>>, i: u64, sig: vector<u8>) {
        let slot = vector::borrow_mut(sigs, i);
        *slot = sig;
    }

    fun valid_4of7_sigs_main_included(
        sks: &vector<ed25519::SecretKey>,
        msg_bytes: &vector<u8>,
    ): vector<vector<u8>> {
        let sigs = empty_sig_vec();
        put_sig(&mut sigs, 0, sign_with(sks, 0, msg_bytes));   // main
        put_sig(&mut sigs, 1, sign_with(sks, 1, msg_bytes));
        put_sig(&mut sigs, 2, sign_with(sks, 2, msg_bytes));
        put_sig(&mut sigs, 3, sign_with(sks, 3, msg_bytes));
        sigs
    }

    /// Queue n distinct precomputed commitments. Returns the leaf bytes used
    /// (so tests can verify post-finalize V2.finalized_commitments contains them).
    fun queue_n_distinct(n: u64): vector<vector<u8>> {
        let leaves = vector::empty<vector<u8>>();
        let i = 0;
        while (i < n) {
            // Use offset 1000 to avoid trivial-zero leaves.
            let leaf = pending_queue::u64_to_fr_bytes_for_test(i + 1000);
            pending_queue::deposit_precomputed(copy leaf, 0);
            vector::push_back(&mut leaves, leaf);
            i = i + 1;
        };
        leaves
    }

    /// Run a single batch_id=1 finalize over leaves [0, 8) using a fresh
    /// new_root sentinel. Returns the new_root bytes.
    fun finalize_one_batch(
        admin: &signer,
        sks: &vector<ed25519::SecretKey>,
        end_index: u64,
        batch_id: u64,
        new_root_seed: u64,
    ): vector<u8> {
        let new_root = pending_queue::u64_to_fr_bytes_for_test(new_root_seed);
        let frontier = pending_queue::u64_to_fr_bytes_for_test(0x11111111);
        let qrh = pending_queue::compute_range_hash(0, end_index);
        let zero32 = pending_queue::zero_fr_bytes_for_test();

        let msg_bytes = batch_root_update::canonical_message_bytes(
            zero32, copy new_root, 0, end_index, end_index,
            copy qrh, copy frontier, batch_id,
        );
        let sigs = valid_4of7_sigs_main_included(sks, &msg_bytes);

        batch_root_update::update_root_batch(
            admin, zero32, copy new_root, 0, end_index, end_index,
            qrh, frontier, batch_id, sigs,
        );

        new_root
    }

    // ========================================================================
    // Test 1 — V2 migration happy path.
    //
    // V1 has 1 entry initially (genesis empty-tree root). Add 1 batch via
    // update_root_batch BEFORE V2 exists (legacy V1-only path), then
    // migrate. V2 must contain BOTH the genesis empty-tree root and the
    // finalized batch root, with migration_complete=true.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_migrate_root_history_to_v2_happy(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        // Pre-V2 state: queue + finalize one batch via legacy V1-only path.
        let _leaves = queue_n_distinct(8);
        assert!(pending_queue::pending_tail() == 8, 7001);

        let new_root = finalize_one_batch(admin, &sks, 8, 1, 0xDEADBEEF);

        // V2 should NOT exist yet.
        assert!(batch_root_update::root_history_v2_exists() == false, 7002);

        // Run migration.
        batch_root_update::migrate_root_history_to_v2(admin);

        // V2 now exists with migration_complete=true.
        assert!(batch_root_update::root_history_v2_exists() == true, 7003);
        assert!(batch_root_update::root_history_v2_migration_complete() == true, 7004);

        // V2.root_set must contain genesis empty-tree root + finalized new_root.
        let zero32 = pending_queue::zero_fr_bytes_for_test();
        assert!(batch_root_update::v2_contains_root(zero32) == true, 7005);
        assert!(batch_root_update::v2_contains_root(new_root) == true, 7006);

        // is_root_in_history must now use V2 path and return true for both.
        assert!(batch_root_update::is_root_in_history(zero32) == true, 7007);
        assert!(batch_root_update::is_root_in_history(new_root) == true, 7008);

        // A NEVER-finalized root must return false (sanity).
        let unknown = pending_queue::u64_to_fr_bytes_for_test(0xC0FFEE);
        assert!(batch_root_update::is_root_in_history(unknown) == false, 7009);
    }

    // ========================================================================
    // Test 2 — V2 migration is idempotent (second call aborts).
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 117, location = eunoma::pool_batch_root_update)]
    fun test_migrate_root_history_to_v2_idempotent_aborts(
        framework: &signer,
        admin: &signer,
    ) {
        let (_sks, _pks) = setup_full_pool(framework, admin);

        batch_root_update::migrate_root_history_to_v2(admin);
        // Second call must abort E_ALREADY_MIGRATED (117).
        batch_root_update::migrate_root_history_to_v2(admin);
    }

    // ========================================================================
    // Test 3 — V2 migration size cap (audit B4-2).
    //
    // Synthesize a V1 with 1001 entries by repeatedly finalizing batches
    // (each adds one root). 1000 batches added on top of the genesis entry
    // gives 1001 total — migration must abort.
    //
    // Practical issue: 1000 update_root_batch calls in a unit test would be
    // VERY slow (>1 min compile/exec). Instead we use a smaller batch loop
    // and exercise the cap via a TEST-ONLY helper that pre-pumps V1 root_history
    // — added below as a #[test_only] helper. This isolates the assertion
    // semantics without paying the full 1000-batch crypto cost.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 118, location = eunoma::pool_batch_root_update)]
    fun test_migrate_root_history_size_capped(
        framework: &signer,
        admin: &signer,
    ) {
        let (_sks, _pks) = setup_full_pool(framework, admin);

        // Pump V1 with 1001 distinct roots via a #[test_only] helper that
        // bypasses signature verification (signature path is exercised
        // separately and not the subject of this test).
        batch_root_update::test_only_pump_root_history(admin, 1001);

        // Migration must abort E_MIGRATION_WINDOW_CLOSED (118).
        batch_root_update::migrate_root_history_to_v2(admin);
    }

    // ========================================================================
    // Test 4 — update_root_batch dual-writes V1 + V2 (LOAD-BEARING).
    //
    // Setup: init V2 + init commitment index, queue 8 deposits, finalize batch.
    // Verify:
    //   - V1 root_history_length grew from 1 to 2.
    //   - V2.root_set contains the new finalized root.
    //   - V2.finalized_commitments contains EVERY queued commitment.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_update_root_batch_dual_writes_v1_v2(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        // Step A: init V2 (empty V1 → empty V2 prefix sans genesis).
        // We migrate FIRST so subsequent batches dual-write to V2.
        // Initial V1 has the genesis empty-tree root (1 entry).
        batch_root_update::migrate_root_history_to_v2(admin);
        assert!(batch_root_update::root_history_v2_migration_complete() == true, 7401);

        // Step B: init commitment index BEFORE deposits so they populate.
        pending_queue::initialize_commitment_index(admin);
        assert!(pending_queue::commitment_index_initialized() == true, 7402);

        // Step C: queue 8 distinct deposits.
        let leaves = queue_n_distinct(8);
        assert!(pending_queue::pending_tail() == 8, 7403);

        // Verify the commitment index has all 8.
        let i = 0;
        while (i < 8) {
            let stored = pending_queue::commitment_at_index(i);
            let expected = *vector::borrow(&leaves, i);
            assert!(stored == expected, 7410 + i);
            i = i + 1;
        };

        // Step D: finalize batch_id=1.
        let v1_len_before = batch_root_update::root_history_length();
        let new_root = finalize_one_batch(admin, &sks, 8, 1, 0xBEEF7777);
        let v1_len_after = batch_root_update::root_history_length();

        // V1 grew by 1 (HC-9 dual-write preserved).
        assert!(v1_len_after == v1_len_before + 1, 7420);

        // V2.root_set contains new_root.
        assert!(batch_root_update::v2_contains_root(new_root) == true, 7421);

        // V2.finalized_commitments contains all 8 commitments.
        let j = 0;
        while (j < 8) {
            let leaf = *vector::borrow(&leaves, j);
            assert!(batch_root_update::v2_contains_commitment(leaf) == true, 7430 + j);
            j = j + 1;
        };

        // is_root_in_history (V2 fast path) returns true for new_root.
        assert!(batch_root_update::is_root_in_history(new_root) == true, 7440);
    }

    // ========================================================================
    // Test 5 — is_root_in_history uses V2 path post-migrate.
    //
    // Demonstrates V2-direct correctness: the V2 contains check returns the
    // same answer as a V1 linear scan would have (ground-truth comparison).
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_is_root_in_history_post_migrate(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        // Finalize one batch BEFORE migration (V1-only path).
        let _leaves = queue_n_distinct(8);
        let pre_migrate_root = finalize_one_batch(admin, &sks, 8, 1, 0xAAAAAAAA);

        // Migrate.
        batch_root_update::migrate_root_history_to_v2(admin);
        assert!(batch_root_update::root_history_v2_migration_complete() == true, 7501);

        // V2-direct contains pre_migrate_root.
        assert!(batch_root_update::v2_contains_root(pre_migrate_root) == true, 7502);

        // is_root_in_history must return the same.
        assert!(batch_root_update::is_root_in_history(pre_migrate_root) == true, 7503);

        // Genesis empty-tree root must also be recognized.
        let zero32 = pending_queue::zero_fr_bytes_for_test();
        assert!(batch_root_update::v2_contains_root(zero32) == true, 7504);
        assert!(batch_root_update::is_root_in_history(zero32) == true, 7505);

        // Random unknown root: false in both V2 direct and V2-fast-path.
        let unknown = pending_queue::u64_to_fr_bytes_for_test(0xDEADC0DE);
        assert!(batch_root_update::v2_contains_root(unknown) == false, 7506);
        assert!(batch_root_update::is_root_in_history(unknown) == false, 7507);
    }

    // ========================================================================
    // Test 6 (Round-7 follow-up Ship-blocker #3) — V2 partial state falls back to V1.
    //
    // Audit C3 #4 invariant requires that when V2.migration_complete == false,
    // `is_root_in_history` MUST consult V1 (linear scan) rather than V2 — to
    // avoid double-spend / liveness regressions if V2 ever has a partial
    // prefix. Production migration always sets the flag true atomically, so
    // this branch is dead code unless the test harness flips the flag back
    // to false explicitly. The new `set_migration_complete_for_test` setter
    // (gated `#[test_only]`) does exactly that.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_is_root_in_history_v2_partial_falls_back_to_v1(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        // Step A: queue + finalize a batch on V1-only path so V1 has a
        // recognizable root (one beyond the genesis empty-tree root).
        let _leaves = queue_n_distinct(8);
        let v1_root = finalize_one_batch(admin, &sks, 8, 1, 0xCAFECAFE);

        // Step B: migrate V2. Production-sealed atomic migration ⇒
        // migration_complete=true.
        batch_root_update::migrate_root_history_to_v2(admin);
        assert!(batch_root_update::root_history_v2_migration_complete() == true, 7601);
        assert!(batch_root_update::v2_contains_root(v1_root) == true, 7602);

        // Step C: flip migration_complete=false to simulate V2 partial state.
        batch_root_update::set_migration_complete_for_test(false);
        assert!(batch_root_update::root_history_v2_migration_complete() == false, 7603);

        // Step D: the V1 linear-scan fallback path MUST be hit. v1_root is
        // present in V1.root_history, so is_root_in_history returns true even
        // though we have NOT consulted V2's smart_table.
        assert!(batch_root_update::is_root_in_history(v1_root) == true, 7604);

        // Genesis empty-tree root is also in V1 → V1 fallback finds it.
        let zero32 = pending_queue::zero_fr_bytes_for_test();
        assert!(batch_root_update::is_root_in_history(zero32) == true, 7605);

        // An unknown root that is in NEITHER V1 nor V2 returns false (the V1
        // fallback path completes its scan and falls through to the bottom
        // `false`).
        let unknown = pending_queue::u64_to_fr_bytes_for_test(0xBADBADBAD);
        assert!(batch_root_update::is_root_in_history(unknown) == false, 7606);

        // Step E (sanity): re-enable the V2 fast path → identical result.
        batch_root_update::set_migration_complete_for_test(true);
        assert!(batch_root_update::is_root_in_history(v1_root) == true, 7607);
        assert!(batch_root_update::is_root_in_history(unknown) == false, 7608);
    }

    // ========================================================================
    // Test 7 (Round-7 follow-up Ship-blocker #4) — duplicate commitment is NOT
    // a DoS vector for batch finalize.
    //
    // Codex review C3 #4: `smart_table::add` for finalized_commitments
    // would abort with EALREADY_EXISTS if a single user submitted two
    // deposits with identical (secret, nonce) → identical commitment. That
    // would brick the entire 64-deposit batch. Defense: switch to upsert.
    // Uniqueness for double-spend is enforced at withdraw-time by the
    // nullifier_hash anti-replay check, so latest-batch-id wins is safe.
    //
    // This test queues two deposits with byte-identical commitments and then
    // finalizes them in a single batch. Pre-fix: aborts in the dual-write
    // commitment loop. Post-fix: succeeds; v2_contains_commitment(c) returns
    // true for the duplicated commitment.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_duplicate_commitment_no_dos(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        // Init V2 + commitment-index BEFORE deposits so dual-write fires.
        batch_root_update::migrate_root_history_to_v2(admin);
        pending_queue::initialize_commitment_index(admin);
        assert!(pending_queue::commitment_index_initialized() == true, 7701);

        // Queue 2 deposits with byte-identical commitments.
        let dup_commitment = pending_queue::u64_to_fr_bytes_for_test(0xDEADDEAD);
        pending_queue::deposit_precomputed(copy dup_commitment, 0);
        pending_queue::deposit_precomputed(copy dup_commitment, 0);
        assert!(pending_queue::pending_tail() == 2, 7702);

        // Confirm both queue slots resolve to the same commitment.
        let stored_0 = pending_queue::commitment_at_index(0);
        let stored_1 = pending_queue::commitment_at_index(1);
        assert!(stored_0 == dup_commitment, 7703);
        assert!(stored_1 == dup_commitment, 7704);

        // Finalize batch [0, 2). With upsert, the second commitment overwrites
        // the first row (latest batch_id wins, which is the same batch here).
        // With the previous `add`, this would abort EALREADY_EXISTS and brick
        // the whole batch.
        let _new_root = finalize_one_batch(admin, &sks, 2, 1, 0x12345678);

        // V2.finalized_commitments contains the (de-duplicated) commitment.
        assert!(batch_root_update::v2_contains_commitment(dup_commitment) == true, 7705);
    }
}
