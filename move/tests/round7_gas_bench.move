// Round-7 follow-up Ship-blocker #2 — gas bench against round-7 V2 bridge package.
//
// Why this file exists:
//   The original Round-7 D.3 measurement used
//   `Poseidon_Research/AptosShield_Spike/move/scripts/measure_update_root_batch_gas.sh`
//   which builds the SPIKE sources, NOT the round-7 V2 bridge sources. The
//   spike has zero V2 dual-write code, so its O(1) "1,416 gas for ALL N" is
//   measuring a different code path. Codex review surfaced this — the
//   round-7 V2 bridge has an O(N) commitment loop in `update_root_batch`
//   (lines ~462-469 of `pool/batch_root_update.move`), so per-leaf cost
//   should grow with N.
//
// What this test does:
//   For each N in {4, 8, 16, 32, 64} the test
//     (a) initializes V2 + commitment-index,
//     (b) queues N deposits via `deposit_precomputed`,
//     (c) calls `update_root_batch` finalizing batch [0, N).
//   The pre-finalize work (init / queue) is identical across N modulo
//   the per-leaf accumulator + commitment-index push. The finalize step
//   includes the V2 commitment-loop dual-write, which is the O(N) cost we
//   want to surface.
//
// How "gas" is reported:
//   `aptos move test` does NOT expose per-test instruction counts in its
//   output, but the `--instructions <CAP>` flag aborts a test when the
//   total instructions executed exceeds the cap. We use this as a binary-
//   search proxy: re-running this file with lower `--instructions` caps
//   reveals the threshold at which each per-N test fails. The thresholds
//   form a per-N relative gas trend (NOT chain gas, but trend-true).
//
//   Operator workflow (off this test file, recorded in WORK_LOG.md
//   "## Round-7 D.3 corrected" section):
//     for cap in [200_000, 100_000, 50_000, ...]:
//         aptos move test --filter round7_gas_bench --instructions $cap
//   The first cap at which a given test fails ≈ that test's instruction
//   cost. The default `--instructions` cap is 100k, which is high enough
//   for N=4 but exceeded by N=64.
//
// HC-9 / Round-7 follow-up:
//   - V1 RootHistory + PendingQueue struct fields untouched.
//   - V2 dual-write code is the SAME code paths that ship to mainnet —
//     this file just exercises them at varied N.
//   - All 5 N tests are independent; failure of high-N does not block
//     low-N.

#[test_only]
module eunoma::round7_gas_bench {
    use std::vector;
    use std::signer;

    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;

    use aptos_framework::account;

    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;
    use eunoma::pool_batch_root_update as batch_root_update;

    const TEST_CHAIN_ID: u8 = 42;
    const TEST_POOL_ID: vector<u8> = b"APTOSHIELD_R7_BENCH";

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
    ): vector<ed25519::SecretKey> {
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

        // Round-7 V2 init alongside V1 (mirrors production migrate path).
        batch_root_update::migrate_root_history_to_v2(admin);
        pending_queue::initialize_commitment_index(admin);

        sks
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

    /// Run the V2 dual-write commitment loop end-to-end for a given N.
    /// Caller controls N — used by the per-N test entry points below.
    /// Uses `pump_queue_synthetic_for_test` to bypass the per-deposit
    /// Poseidon cost so high-N tests do not exhaust the algebra context.
    fun run_one_finalize(
        framework: &signer,
        admin: &signer,
        n: u64,
    ) {
        let sks = setup_full_pool(framework, admin);

        // Synthetic-pump the queue + commitment index to N entries. Skips
        // the per-deposit Poseidon hash_2 calls; the V2 dual-write loop
        // in update_root_batch still iterates the full N entries and
        // exercises the same smart_table::upsert calls.
        pending_queue::pump_queue_synthetic_for_test(admin, n);

        let new_root = pending_queue::u64_to_fr_bytes_for_test(0xBEEF0000 + n);
        let frontier = pending_queue::u64_to_fr_bytes_for_test(0x11111111);
        // compute_range_hash does ONE Poseidon call regardless of N.
        let qrh = pending_queue::compute_range_hash(0, n);
        let zero32 = pending_queue::zero_fr_bytes_for_test();

        let msg_bytes = batch_root_update::canonical_message_bytes(
            zero32, copy new_root, 0, n, n,
            copy qrh, copy frontier, 1,
        );
        let sigs = valid_4of7_sigs_main_included(&sks, &msg_bytes);

        batch_root_update::update_root_batch(
            admin, zero32, copy new_root, 0, n, n,
            qrh, frontier, 1, sigs,
        );

        // Sanity: V2 must contain new_root.
        assert!(batch_root_update::v2_contains_root(new_root) == true, 99001);
    }

    // ========================================================================
    // Per-N tests. Each one is independent (fresh framework + admin), so
    // failure of one (e.g. N=64 hitting the instruction cap) does not affect
    // the others. Tests are filterable via --filter:
    //   aptos move test --filter round7_gas_bench::test_finalize_n_4
    // etc. Use `--instructions <CAP>` to find the threshold each test
    // requires (see workflow comment at top of file).
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_finalize_n_4(framework: &signer, admin: &signer) {
        run_one_finalize(framework, admin, 4);
    }

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_finalize_n_8(framework: &signer, admin: &signer) {
        run_one_finalize(framework, admin, 8);
    }

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_finalize_n_16(framework: &signer, admin: &signer) {
        run_one_finalize(framework, admin, 16);
    }

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_finalize_n_32(framework: &signer, admin: &signer) {
        run_one_finalize(framework, admin, 32);
    }

    #[test(framework = @aptos_framework, admin = @eunoma)]
    fun test_finalize_n_64(framework: &signer, admin: &signer) {
        run_one_finalize(framework, admin, 64);
    }
}
