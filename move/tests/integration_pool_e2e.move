// Gate 5 / Step 4 (2026-05-08): integration tests for the ported pool modules
// (`pool_pending_queue`, `pool_batch_root_update`, `pool_multi_sig_verifier`)
// running under the `@eunoma` namespace inside the ConfidentialAPT bridge
// package.
//
// What this file proves:
//   1. Pool modules work under the `@eunoma` address (port + namespace
//      rename did not break anything semantically).
//   2. The 9-invariant batch update flow runs end-to-end: queue 8 leaves →
//      attest → submit batch → root advances. Mirrors spike's
//      `test_e2e_n8_succeeds` but in the bridge package.
//   3. INV3 abort still originates from `pool_batch_root_update` (NOT
//      `pool_pending_queue`) — FROZEN contract per
//      INTEGRATION_INTERFACE_RECEIVER.md §4. If a future optimization moves
//      the assertion across module boundaries, this test breaks.
//   4. The Option Xb param-form verifier
//      (`pool_multi_sig_verifier::assert_valid_attestation`) is callable as a
//      pure function with operator_pubkeys / threshold / main_index passed
//      in — proving the bridge can use it without depending on the in-pool
//      OperatorSet resource. Three sub-tests cover positive (4-of-7 with
//      main) + main-missing abort (110) + sub-threshold abort (109).
//
// Crypto-algebra context note: the test queues only 8 commitments via
// `deposit_precomputed`, well under the per-test cap. No additional
// per-leaf Poseidon calls are required.
#[test_only]
module eunoma::integration_pool_e2e {
    use std::vector;
    use std::signer;

    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;

    use aptos_framework::account;

    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;
    use eunoma::pool_batch_root_update as batch_root_update;

    // ========================================================================
    // Test fixture builders (mirror spike_e2e.move with namespace rebind).
    // ========================================================================

    const TEST_CHAIN_ID: u8 = 42;
    const TEST_POOL_ID: vector<u8> = b"APTOSHIELD_INTEGRATION_POOL_V1";

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

    fun queue_n_precomputed(n: u64) {
        let i = 0;
        while (i < n) {
            let leaf = pending_queue::u64_to_fr_bytes_for_test(i + 1000);
            pending_queue::deposit_precomputed(leaf, 0);
            i = i + 1;
        };
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

    fun valid_4of7_sigs_main_missing(
        sks: &vector<ed25519::SecretKey>,
        msg_bytes: &vector<u8>,
    ): vector<vector<u8>> {
        let sigs = empty_sig_vec();
        // slot 0 (main) intentionally empty — 4 valid sigs in slots 1-4
        put_sig(&mut sigs, 1, sign_with(sks, 1, msg_bytes));
        put_sig(&mut sigs, 2, sign_with(sks, 2, msg_bytes));
        put_sig(&mut sigs, 3, sign_with(sks, 3, msg_bytes));
        put_sig(&mut sigs, 4, sign_with(sks, 4, msg_bytes));
        sigs
    }

    fun three_sigs_main_included(
        sks: &vector<ed25519::SecretKey>,
        msg_bytes: &vector<u8>,
    ): vector<vector<u8>> {
        let sigs = empty_sig_vec();
        put_sig(&mut sigs, 0, sign_with(sks, 0, msg_bytes));   // main
        put_sig(&mut sigs, 1, sign_with(sks, 1, msg_bytes));
        put_sig(&mut sigs, 2, sign_with(sks, 2, msg_bytes));
        // only 3 valid sigs total — under threshold of 4
        sigs
    }

    // ========================================================================
    // Test 1: positive end-to-end through pool modules in bridge namespace.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_pool_full_e2e_n8_succeeds_in_bridge_namespace(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);

        queue_n_precomputed(8);
        assert!(pending_queue::pending_tail() == 8, 1001);

        let new_root = pending_queue::u64_to_fr_bytes_for_test(0xDEADBEEF);
        let frontier = pending_queue::u64_to_fr_bytes_for_test(0x11111111);
        let qrh = pending_queue::compute_range_hash(0, 8);

        let zero32 = pending_queue::zero_fr_bytes_for_test();
        let msg_bytes = batch_root_update::canonical_message_bytes(
            zero32, copy new_root, 0, 8, 8,
            copy qrh, copy frontier, 1,
        );
        let sigs = valid_4of7_sigs_main_included(&sks, &msg_bytes);

        batch_root_update::update_root_batch(
            admin, zero32, copy new_root, 0, 8, 8,
            qrh, frontier, 1, sigs,
        );

        assert!(batch_root_update::current_finalized_root() == new_root, 1100);
        assert!(batch_root_update::next_unfinalized_index() == 8, 1101);
        assert!(batch_root_update::last_batch_id() == 1, 1102);
        assert!(batch_root_update::root_history_length() == 2, 1103);
        assert!(batch_root_update::is_root_in_history(zero32) == true, 1104);
        assert!(batch_root_update::is_root_in_history(new_root) == true, 1105);
    }

    // ========================================================================
    // Test 2: INV3 abort module location is FROZEN at pool_batch_root_update.
    // FROZEN per Poseidon_Research/dispatch_discipline/INTEGRATION_INTERFACE_RECEIVER.md §4.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 213, location = eunoma::pool_batch_root_update)]
    fun test_inv3_abort_originates_in_pool_batch_module(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, _pks) = setup_full_pool(framework, admin);
        queue_n_precomputed(2);
        // Pending tail is 2. Try end_index = 3 — must abort INV3 (213) from
        // batch_root_update, NOT from pending_queue.

        let zero32 = pending_queue::zero_fr_bytes_for_test();
        let new_root = pending_queue::u64_to_fr_bytes_for_test(0xDEADBEEF);
        let frontier = pending_queue::u64_to_fr_bytes_for_test(0x11);
        let qrh = pending_queue::u64_to_fr_bytes_for_test(0xCAFE);

        let msg = batch_root_update::canonical_message_bytes(
            zero32, copy new_root, 0, 3, 3, copy qrh, copy frontier, 1,
        );
        let sigs = valid_4of7_sigs_main_included(&sks, &msg);

        batch_root_update::update_root_batch(
            admin, zero32, new_root, 0, 3, 3, qrh, frontier, 1, sigs,
        );
    }

    // ========================================================================
    // Test 3: Xb param-form verifier — positive 4-of-7 with main passes.
    // Proves bridge can call assert_valid_attestation as a pure function.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_xb_param_verifier_4of7_with_main_passes(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, pks) = setup_full_pool(framework, admin);

        let msg_bytes = b"APTOSHIELD_XB_PARAM_VERIFIER_TEST_MESSAGE";
        let sigs = valid_4of7_sigs_main_included(&sks, &msg_bytes);

        // Call the param-based verifier directly — no OperatorSet acquisition.
        // This is the path the bridge takes (passing &cfg.operator_pubkeys etc.).
        multi_sig_verifier::assert_valid_attestation(
            msg_bytes,
            sigs,
            &pks,
            4,  // threshold
            0,  // main_operator_index
        );
    }

    // ========================================================================
    // Test 4: Xb param-form verifier — main missing aborts 110.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 110, location = eunoma::pool_multi_sig_verifier)]
    fun test_xb_param_verifier_main_missing_aborts_110(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, pks) = setup_full_pool(framework, admin);

        let msg_bytes = b"APTOSHIELD_XB_PARAM_VERIFIER_TEST_MESSAGE";
        let sigs = valid_4of7_sigs_main_missing(&sks, &msg_bytes);

        multi_sig_verifier::assert_valid_attestation(
            msg_bytes,
            sigs,
            &pks,
            4,
            0,
        );
    }

    // ========================================================================
    // Test 5: Xb param-form verifier — only 3 sigs aborts 109.
    // Confirms threshold floor is enforced when caller passes threshold = 4.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    #[expected_failure(abort_code = 109, location = eunoma::pool_multi_sig_verifier)]
    fun test_xb_param_verifier_three_sigs_aborts_109(
        framework: &signer,
        admin: &signer,
    ) {
        let (sks, pks) = setup_full_pool(framework, admin);

        let msg_bytes = b"APTOSHIELD_XB_PARAM_VERIFIER_TEST_MESSAGE";
        let sigs = three_sigs_main_included(&sks, &msg_bytes);

        multi_sig_verifier::assert_valid_attestation(
            msg_bytes,
            sigs,
            &pks,
            4,
            0,
        );
    }
}
