#[test_only]
/// (CP2 ASP) Tests for the asp-recorder delegate + recent-window logic added in the ASP tree design
/// (asp-tree-design.md §6). Covers:
///   (a) record_asp_root_via_delegate from the delegate succeeds + the recorded root is in-window.
///   (b) a non-delegate signer calling record_asp_root_via_delegate aborts E_NOT_ASP_RECORDER_DELEGATE.
///   (c) asp_root_in_recent_window returns false for an unknown root.
///   (d) after recording > K roots, an old root ages out of the window (returns false), while a
///       recent root stays in-window.
///
/// Setup note: the production init_asp_recorder_delegate gates on assert_admin (needs a full
/// BridgeVault bootstrap). These tests instead use the #[test_only] seeder
/// eunoma_bridge::test_only_seed_asp_delegate to plant ASPRecorderDelegate{addr} + empty
/// KnownASPRoots directly at @eunoma, then drive the REAL record_asp_root_via_delegate entry and the
/// REAL asp_root_in_recent_window helper (via the test_only_* accessors). record_asp_root_via_delegate
/// reads timestamp::now_seconds(), so each test starts the testing clock.
module eunoma::asp_recorder_window_test {
    use std::signer;
    use std::vector;
    use aptos_framework::timestamp;
    use eunoma::eunoma_bridge;

    // 32-byte (HASH_BYTES) roots — record_asp_root_via_delegate asserts assert_hash(&root).
    fun root_a(): vector<u8> { x"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" }
    fun root_b(): vector<u8> { x"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2" }
    fun unknown_root(): vector<u8> { x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }
    fun cid(): vector<u8> { b"bafybeigdyrtestcidplaceholder" }

    // Build a distinct 32-byte root whose first byte encodes `i` (i in 0..255).
    fun root_i(i: u8): vector<u8> {
        let v = vector::empty<u8>();
        vector::push_back(&mut v, i);
        let j = 1;
        while (j < 32) {
            vector::push_back(&mut v, 0x33);
            j = j + 1;
        };
        v
    }

    // (a) delegate records a root -> succeeds and the root is in the recent window.
    #[test(aptos_framework = @aptos_framework, admin = @eunoma, delegate = @0xD)]
    fun test_delegate_record_succeeds_and_is_in_window(
        aptos_framework: &signer,
        admin: &signer,
        delegate: &signer,
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        eunoma_bridge::test_only_seed_asp_delegate(admin, signer::address_of(delegate));

        eunoma_bridge::record_asp_root_via_delegate(delegate, root_a(), cid());

        assert!(eunoma_bridge::test_only_asp_sets_len() == 1, 100);
        assert!(eunoma_bridge::test_only_asp_root_in_recent_window(root_a()), 101);
    }

    // (b) a non-delegate signer is rejected with E_NOT_ASP_RECORDER_DELEGATE.
    #[test(aptos_framework = @aptos_framework, admin = @eunoma, delegate = @0xD, attacker = @0xBAD)]
    #[expected_failure(abort_code = 38, location = eunoma::eunoma_bridge)]
    fun test_non_delegate_record_aborts(
        aptos_framework: &signer,
        admin: &signer,
        delegate: &signer,
        attacker: &signer,
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        eunoma_bridge::test_only_seed_asp_delegate(admin, signer::address_of(delegate));
        // The attacker is not the recorded delegate addr.
        eunoma_bridge::record_asp_root_via_delegate(attacker, root_b(), cid());
    }

    // (c) unknown root is not in the window.
    #[test(aptos_framework = @aptos_framework, admin = @eunoma, delegate = @0xD)]
    fun test_unknown_root_not_in_window(
        aptos_framework: &signer,
        admin: &signer,
        delegate: &signer,
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        eunoma_bridge::test_only_seed_asp_delegate(admin, signer::address_of(delegate));
        // Record one known root so KnownASPRoots is non-empty, then query a different root.
        eunoma_bridge::record_asp_root_via_delegate(delegate, root_a(), cid());
        assert!(!eunoma_bridge::test_only_asp_root_in_recent_window(unknown_root()), 102);
        // Also: empty-log case is exercised in test (b) implicitly; assert the abort const matches.
        assert!(eunoma_bridge::e_not_asp_recorder_delegate() == 38, 103);
    }

    // (d) after recording > K roots, an old root ages out of the window.
    #[test(aptos_framework = @aptos_framework, admin = @eunoma, delegate = @0xD)]
    fun test_old_root_ages_out_of_window(
        aptos_framework: &signer,
        admin: &signer,
        delegate: &signer,
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        eunoma_bridge::test_only_seed_asp_delegate(admin, signer::address_of(delegate));

        let k = eunoma_bridge::asp_root_window_k();
        // Record root_i(0) FIRST (it will become the oldest), then record exactly K more distinct
        // roots. Total = K + 1 entries, so root_i(0) is the (K+1)-th from the end -> outside the
        // last-K window. The most recent root (root_i(K)) must still be in-window.
        eunoma_bridge::record_asp_root_via_delegate(delegate, root_i(0), cid());
        // Sanity: right after recording, the oldest root IS in-window (only 1 entry).
        assert!(eunoma_bridge::test_only_asp_root_in_recent_window(root_i(0)), 200);

        let n = 1;
        while (n <= k) {
            // root_i(n) for n in 1..=K — all distinct from root_i(0) and from each other.
            eunoma_bridge::record_asp_root_via_delegate(delegate, root_i((n as u8)), cid());
            n = n + 1;
        };

        // Total recorded = K + 1. The oldest (root_i(0)) has now aged out of the last-K window.
        assert!(eunoma_bridge::test_only_asp_sets_len() == k + 1, 201);
        assert!(!eunoma_bridge::test_only_asp_root_in_recent_window(root_i(0)), 202);
        // The newest root is still in-window.
        assert!(eunoma_bridge::test_only_asp_root_in_recent_window(root_i((k as u8))), 203);
    }
}
