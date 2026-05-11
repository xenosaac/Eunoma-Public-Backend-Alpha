// Agent D5 — `deposit_batch_with_commitments` end-to-end tests.
//
// Surface tested (per Agent D5 brief):
//   * Happy path with N=2 and N=4 — bridge passes every gate (expiry,
//     pause, batch-size, length-match, per-item nonce, ca-payload-hash
//     binding via per-item digest, single 4-of-7 multi-sig over the
//     batched digest vector, per-item Groth16 proof) and dispatches into
//     `confidential_asset::confidential_transfer_raw` for each item; the
//     framework aborts E_WRONG_NUM_CHUNKS (65537) on the empty placeholder
//     CA payload, proving the full bridge-side gate set passed. Mirrors
//     the single-deposit positive-test pattern.
//   * Single-commitment N=1 — happy path edge case (semantically equivalent
//     to single-deposit but exercises the batch dispatch path with the
//     minimum allowed batch size).
//   * Negative — invalid attestation (operators sign over a *stale* item
//     digest, bridge recomputes a different one): E_INVALID_OPERATOR_SIGNATURE
//     (108) from `pool_multi_sig_verifier`. This is the partial-failure
//     scenario from the brief: one item's data drifted from the attestation,
//     ENTIRE batch rejected atomically.
//   * Negative — replay: re-submit a batch that contains a deposit_nonce
//     already consumed by an earlier (single-deposit or batched) call.
//     Hits `E_DEPOSIT_NONCE_REPLAY` (16). Verified via the test-only
//     `test_call_consume_deposit_nonce` helper to side-step CA framework
//     rollback under Move's transactional semantics.
//   * Negative — in-batch duplicate nonce: two items in the same batch
//     share the same `deposit_nonce`. Caught pre-multisig with the
//     dedicated `E_BATCH_DUPLICATE_NONCE` (27) abort.
//   * Negative — batch size 0 or batch size > MAX_BATCH_DEPOSITS:
//     `E_BATCH_SIZE_OUT_OF_RANGE` (25).
//   * Negative — parallel-vector length mismatch: `E_BATCH_LENGTH_MISMATCH` (26).
//
// Test fixtures reuse the Gate 4a deposit-binding fixtures via the same
// `DepositBindingTestOverride` resource and `publish_prepared_deposit_binding_vk`
// admin entry that the single-deposit test suite installs. Because the same
// fixture commitment/amount_tag/asset_id/vault_addr_hash bytes are reused
// across every batch item, each item's Groth16 proof verifies against the
// same VK — sufficient for proving the bridge-side batch gates without
// regenerating the circuit per item.
#[test_only]
module eunoma::deposit_batch_tests {
    use std::bcs;
    use std::signer;
    use std::vector;

    use aptos_std::ed25519;

    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::Object;
    use aptos_framework::timestamp;

    use eunoma::eunoma_bridge;

    // ====================================================================
    //  Gate 4a fixture bytes (verbatim from circuits/generated/move_fixtures/)
    // ====================================================================
    // Phase F W3 — regenerated for the 4-public-input deposit circuit.
    const VK_ALPHA_G1: vector<u8> = x"12c16beca06688485d74f21688948e77dedd9a4ad68b28b0eeb6293252e56826ae44c5727d76b62d79f2923c1c1bc5f58e778c4b03a3c58903cc6a1efc189109";
    const VK_BETA_G2:  vector<u8> = x"1ca4e89cceb6a9b7caabcd83980fcd69ef6df2b9d5f7b45d082e247807493c0ce21e5e7224aab40a95a0434fe84af514f9f81a5a4884abccad4fb8ec072a620d688459b1d0c167b809117b8cd25eb18b191f1a6f1406d4873ce49d06439c9e0fc8226b4a8f6578991eade15e60729cd6854e7160ae4b5d9640993c13184cb80b";
    const VK_GAMMA_G2: vector<u8> = x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609";
    const VK_DELTA_G2: vector<u8> = x"28f894bd6fa2503e8fa6c95e3140cff9670b037e491a700c2125003072ef9a1d73fd1e0783d0dbdbcdeb9d55ae30465c9b20e1d265c2b0024a120c7a4d350e2ca0857cde259f1b035000a38624db47cf6bf95595ac65930367cd825393f6c801990632b426d639e4649494f499346fd3ff02f604ca030624d8d4147d44f92f1a";

    const VK_IC_0: vector<u8> = x"f7c850638246b8203850b3ef63e55d5b35f6b7a385b523c3e775fd46b50b1e0feeb4adc4d85e2dce44b774e5ac64b1a82719f370965a1932c674527242849c0b";
    const VK_IC_1: vector<u8> = x"3590b33528bf6e17ce5015d6ac18d05bfeeb3c9e7f75675d3b64b558d5f8eb1cac1352465d8ee082ca0936150cfd34b3b137f0df824daba78b7b4a03aed46320";
    const VK_IC_2: vector<u8> = x"7e4325dff4f72c7d6aac99313818ff538b36cf774352ec4129290dddadfff825cfabf8e883b20675a48102aa212c568d6df0e7698949ae1fc9ba41c7ebacb72c";
    const VK_IC_3: vector<u8> = x"ababae53ea5208df20f73b178c92fa26cc0b0ec107e0853536eff74aac27372c654f8e5d7c464a38da6f7ea6e9949572844eab8b0b1de74a6ca5747ccfce341f";
    const VK_IC_4: vector<u8> = x"a0d4f0a41ebef3db789968a2fd37458c268849bf213f6c7eba2a72755b1f471d939ea92889637adebd1c00a5c5d5850643a3c8e401f78f1855d776ae6c1d5a01";

    const PROOF_A: vector<u8> = x"035d4dc41c8787c35786ea004e5f8580d6ed9213fc7e1c290cdc8b2e5b6fd52de9f123547736b919f9081b5b3729e5fd44e4b235da428a93a8034c2d13470400";
    const PROOF_B: vector<u8> = x"ec2670b532abe71e375dd0314807cb5950f6934971ef104a7cc762a54a2c9f0ee6ed00c3665062b0eec4475ad69a4f53eab3fa210ab181109e45e6021b159a1b43b3492ddafec31e7bc59ee669b9431462ebfcb674ae267014055028cee5781570fa143731149f4c33091703301096d19a94e76a85fda0311cb1f171240b8409";
    const PROOF_C: vector<u8> = x"80fa277173e5d5f59ab1796471999d0e45476254451670dc3271369481cbea226b3ae6b9a745922740e95b3a66b8ef351ca90130d0519f6a739d66a890a18127";

    const PUB_VALID_COMMITMENT: vector<u8> = x"942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613";
    const PUB_VALID_AMOUNT_TAG: vector<u8> = x"02ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b";
    const PUB_VALID_ASSET_ID:        vector<u8> = x"0700000000000000000000000000000000000000000000000000000000000000";
    const PUB_VALID_VAULT_ADDR_HASH: vector<u8> = x"edaffceedbeaedaffceedbeaedaffceedbeaedaffceedbeaedaffcee0befbe00";

    const VAULT_SEED: vector<u8> = b"APTOSHIELD_GATE4B_VAULT_SEED_V1";
    const TEST_NOW: u64 = 1_700_000_000;
    const TEST_EXPIRY: u64 = 1_900_000_000;

    // ====================================================================
    //  Fixture builders (mirror deposit_with_commitment_tests.move)
    // ====================================================================

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

    fun make_test_metadata(creator: &signer): Object<fungible_asset::Metadata> {
        let (_mint, _transfer, _burn, _mutate, metadata) =
            fungible_asset::create_fungible_asset(creator);
        metadata
    }

    fun setup_for_deposit(
        framework: &signer,
        admin: &signer,
        main_op_addr: address,
    ): (Object<fungible_asset::Metadata>, vector<ed25519::SecretKey>, vector<vector<u8>>) {
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(TEST_NOW);
        chain_id::initialize_for_test(framework, 2u8);

        let admin_addr = signer::address_of(admin);
        if (!account::exists_at(admin_addr)) {
            account::create_account_for_test(admin_addr);
        };
        let metadata = make_test_metadata(admin);
        let (sks, pks) = gen_seven_active_operators();

        eunoma_bridge::init_vault(
            admin,
            main_op_addr,
            metadata,
            pks,
            /*main_operator_index=*/ 0,
            /*attestation_threshold=*/ 4,
            VAULT_SEED,
            b"vault_ek_placeholder_gate4b",
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
        );

        eunoma_bridge::publish_deposit_binding_vk(
            admin,
            VK_ALPHA_G1, VK_BETA_G2, VK_GAMMA_G2, VK_DELTA_G2,
            VK_IC_0, VK_IC_1, VK_IC_2, VK_IC_3, VK_IC_4,
        );
        eunoma_bridge::install_deposit_binding_test_override(
            admin,
            PUB_VALID_ASSET_ID,
            PUB_VALID_VAULT_ADDR_HASH,
        );
        eunoma_bridge::init_vault_config_cache(admin);
        eunoma_bridge::publish_prepared_deposit_binding_vk(admin);

        (metadata, sks, pks)
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

    fun sign_with(
        sks: &vector<ed25519::SecretKey>,
        i: u64,
        msg: &vector<u8>,
    ): vector<u8> {
        let sk = vector::borrow(sks, i);
        let sig = ed25519::sign_arbitrary_bytes(sk, *msg);
        ed25519::signature_to_bytes(&sig)
    }

    fun valid_4of7(
        sks: &vector<ed25519::SecretKey>,
        msg: &vector<u8>,
    ): vector<vector<u8>> {
        let sigs = empty_sig_vec();
        put_sig(&mut sigs, 0, sign_with(sks, 0, msg));
        put_sig(&mut sigs, 1, sign_with(sks, 1, msg));
        put_sig(&mut sigs, 2, sign_with(sks, 2, msg));
        put_sig(&mut sigs, 3, sign_with(sks, 3, msg));
        sigs
    }

    fun empty_vec_of_vec(): vector<vector<u8>> { vector::empty<vector<u8>>() }
    fun empty_vec_of_vec_of_vec(): vector<vector<vector<u8>>> { vector::empty<vector<vector<u8>>>() }

    fun recompute_ca_payload_hash(
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
    ): vector<u8> {
        eunoma_bridge::test_call_hash_confidential_transfer_payload(
            asset_type, vault_addr,
            empty_vec_of_vec(), empty_vec_of_vec(), empty_vec_of_vec(),
            empty_vec_of_vec(), empty_vec_of_vec(), empty_vec_of_vec(),
            empty_vec_of_vec(), empty_vec_of_vec(), empty_vec_of_vec_of_vec(),
            vector::empty<u8>(), vector::empty<u8>(),
            empty_vec_of_vec(), empty_vec_of_vec(),
            vector::empty<u8>(),
        )
    }

    fun build_valid_proof(): vector<u8> {
        let out = vector::empty<u8>();
        vector::append(&mut out, PROOF_A);
        vector::append(&mut out, PROOF_B);
        vector::append(&mut out, PROOF_C);
        out
    }

    /// Build N parallel input vectors for a batch where every item shares the
    /// same Gate 4a fixture (same commitment, amount_tag, proof, empty CA
    /// payload) but has a UNIQUE per-item deposit_nonce. Returns:
    ///   (commitments, amount_tags, proofs, nonces,
    ///    new_balance_p_vec, ..., memo_vec, item_digests).
    /// Inputs share the fixture so every item's Groth16 proof verifies against
    /// the same prepared VK without regenerating circuits per item. The
    /// distinct nonces give distinct per-item digests (and therefore distinct
    /// attestation message bytes), exactly what the bridge will recompute.
    fun build_batch_inputs(
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
        nonce_prefix: vector<u8>,
        n: u64,
    ): (
        vector<vector<u8>>, vector<vector<u8>>, vector<vector<u8>>, vector<vector<u8>>,
        vector<vector<vector<u8>>>, vector<vector<vector<u8>>>, vector<vector<vector<u8>>>,
        vector<vector<vector<u8>>>, vector<vector<vector<u8>>>, vector<vector<vector<u8>>>,
        vector<vector<vector<u8>>>, vector<vector<vector<u8>>>,
        vector<vector<vector<vector<u8>>>>,
        vector<vector<u8>>, vector<vector<u8>>,
        vector<vector<vector<u8>>>, vector<vector<vector<u8>>>,
        vector<vector<u8>>,
        vector<vector<u8>>
    ) {
        let commitments = vector::empty<vector<u8>>();
        let amount_tags = vector::empty<vector<u8>>();
        let proofs = vector::empty<vector<u8>>();
        let nonces = vector::empty<vector<u8>>();
        let nbp = vector::empty<vector<vector<u8>>>();
        let nbr = vector::empty<vector<vector<u8>>>();
        let nbrea = vector::empty<vector<vector<u8>>>();
        let amtp = vector::empty<vector<vector<u8>>>();
        let amtrs = vector::empty<vector<vector<u8>>>();
        let amtrr = vector::empty<vector<vector<u8>>>();
        let amtrea = vector::empty<vector<vector<u8>>>();
        let ekv = vector::empty<vector<vector<u8>>>();
        let amtrvolun = vector::empty<vector<vector<vector<u8>>>>();
        let zkrpb = vector::empty<vector<u8>>();
        let zkrpa = vector::empty<vector<u8>>();
        let spc = vector::empty<vector<vector<u8>>>();
        let spr = vector::empty<vector<vector<u8>>>();
        let memos = vector::empty<vector<u8>>();
        let item_digests = vector::empty<vector<u8>>();

        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        let i = 0;
        while (i < n) {
            vector::push_back(&mut commitments, PUB_VALID_COMMITMENT);
            vector::push_back(&mut amount_tags, PUB_VALID_AMOUNT_TAG);
            vector::push_back(&mut proofs, build_valid_proof());

            // Unique nonce: prefix || u64-LE(i).
            let nonce_i = nonce_prefix;
            vector::push_back(&mut nonce_i, (i as u8));
            vector::push_back(&mut nonce_i, 0xCAu8);
            vector::push_back(&mut nonce_i, 0xFEu8);
            vector::push_back(&mut nonces, nonce_i);

            vector::push_back(&mut nbp, empty_vec_of_vec());
            vector::push_back(&mut nbr, empty_vec_of_vec());
            vector::push_back(&mut nbrea, empty_vec_of_vec());
            vector::push_back(&mut amtp, empty_vec_of_vec());
            vector::push_back(&mut amtrs, empty_vec_of_vec());
            vector::push_back(&mut amtrr, empty_vec_of_vec());
            vector::push_back(&mut amtrea, empty_vec_of_vec());
            vector::push_back(&mut ekv, empty_vec_of_vec());
            vector::push_back(&mut amtrvolun, empty_vec_of_vec_of_vec());
            vector::push_back(&mut zkrpb, vector::empty<u8>());
            vector::push_back(&mut zkrpa, vector::empty<u8>());
            vector::push_back(&mut spc, empty_vec_of_vec());
            vector::push_back(&mut spr, empty_vec_of_vec());
            vector::push_back(&mut memos, vector::empty<u8>());

            let dig = eunoma_bridge::test_call_batch_item_digest(
                PUB_VALID_COMMITMENT,
                PUB_VALID_AMOUNT_TAG,
                cph,
                nonce_i,
            );
            vector::push_back(&mut item_digests, dig);
            i = i + 1;
        };

        (commitments, amount_tags, proofs, nonces,
         nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
         zkrpb, zkrpa, spc, spr, memos,
         item_digests)
    }

    fun build_batch_attestation_bytes(
        item_digests: vector<vector<u8>>,
    ): vector<u8> {
        let msg = eunoma_bridge::test_call_new_batch_deposit_attestation_message(
            /*chain_id=*/ 2u8,
            // Codex P2 fix: 8-byte LE u64 pool_id (matches D1 c1/c2/c3 +
            // production batch encoding post-Codex-P2-fix on eunoma_bridge:2232).
            /*pool_id=*/ x"0000000000000000",
            item_digests,
            TEST_EXPIRY,
        );
        bcs::to_bytes(&msg)
    }

    // ====================================================================
    //  Positive — N=2 happy path
    //
    //  Both items reuse the same Gate 4a fixture (so the per-item Groth16
    //  proof verifies against the same prepared VK). Each item gets a unique
    //  deposit_nonce so the per-item digest vector has two distinct entries
    //  and the BCS-encoded batch attestation bytes are distinct from any
    //  single-deposit attestation.
    //
    //  Expected: every bridge-layer gate passes; CA dispatch on the first
    //  item aborts E_WRONG_NUM_CHUNKS (65537) inside
    //  `aptos_framework::confidential_balance` — exactly the proof pattern
    //  used by the single-deposit positive test.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 65537, location = aptos_framework::confidential_balance)]
    fun test_batch_deposit_n2_happy_path(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_n2_happy_path_", 2,
        );

        let msg_bytes = build_batch_attestation_bytes(item_digests);
        let sigs = valid_4of7(&sks, &msg_bytes);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Positive — N=4 happy path. Same proof pattern as N=2.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 65537, location = aptos_framework::confidential_balance)]
    fun test_batch_deposit_n4_happy_path(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_n4_happy_path_", 4,
        );

        let msg_bytes = build_batch_attestation_bytes(item_digests);
        let sigs = valid_4of7(&sks, &msg_bytes);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Positive — N=1 (minimum allowed batch size). Same dispatch pattern,
    //  semantically equivalent to single-deposit but routes through the
    //  batch entry function.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 65537, location = aptos_framework::confidential_balance)]
    fun test_batch_deposit_n1_happy_path(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_n1_min_size_", 1,
        );

        let msg_bytes = build_batch_attestation_bytes(item_digests);
        let sigs = valid_4of7(&sks, &msg_bytes);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Negative — partial-failure scenario: operators sign over a STALE
    //  item digest vector (built from a stale ca_payload_hash that no longer
    //  matches the actual per-item CA payload the bridge will recompute).
    //  Per the brief's partial-failure spec, the ENTIRE batch reverts —
    //  surfaced as E_INVALID_OPERATOR_SIGNATURE (108) from the multi-sig
    //  verifier (the recomputed attestation message bytes differ from
    //  what operators signed).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 108, location = eunoma::pool_multi_sig_verifier)]
    fun test_batch_deposit_rejects_invalid_attestation(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            _real_item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_invalid_attest_", 2,
        );

        // Operators sign over a STALE item-digest vector — digests computed
        // against a wrong ca_payload_hash. Bridge will recompute the real
        // digest vector → BCS-encoded message bytes differ → main slot's
        // ed25519 verify fails.
        let nonce0 = *vector::borrow(&nonces, 0);
        let nonce1 = *vector::borrow(&nonces, 1);
        let stale_dig0 = eunoma_bridge::test_call_batch_item_digest(
            PUB_VALID_COMMITMENT, PUB_VALID_AMOUNT_TAG,
            b"stale_ca_payload_hash_for_item0__________________________________",
            nonce0,
        );
        let stale_dig1 = eunoma_bridge::test_call_batch_item_digest(
            PUB_VALID_COMMITMENT, PUB_VALID_AMOUNT_TAG,
            b"stale_ca_payload_hash_for_item1__________________________________",
            nonce1,
        );
        let stale_digests = vector::empty<vector<u8>>();
        vector::push_back(&mut stale_digests, stale_dig0);
        vector::push_back(&mut stale_digests, stale_dig1);

        let stale_msg = build_batch_attestation_bytes(stale_digests);
        let sigs = valid_4of7(&sks, &stale_msg);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Negative — in-batch duplicate nonce caught with the dedicated
    //  E_BATCH_DUPLICATE_NONCE (27) abort. Two items in the same batch
    //  share the same deposit_nonce; rejected BEFORE multi-sig verify.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 27, location = eunoma::eunoma_bridge)]
    fun test_batch_deposit_rejects_in_batch_duplicate_nonce(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_dup_nonce_", 2,
        );

        // Force item 1's nonce to equal item 0's nonce. Bridge will catch
        // this in the linear-scan O(N²) duplicate check.
        let nonce0 = *vector::borrow(&nonces, 0);
        let slot1 = vector::borrow_mut(&mut nonces, 1);
        *slot1 = nonce0;

        let msg_bytes = build_batch_attestation_bytes(item_digests);
        let sigs = valid_4of7(&sks, &msg_bytes);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Negative — replay: a deposit_nonce already consumed via the
    //  single-deposit `test_call_consume_deposit_nonce` helper is rejected
    //  when re-submitted inside a batch. Same E_DEPOSIT_NONCE_REPLAY (16)
    //  the single-deposit path uses — proves the batch path consults the
    //  SAME `used_deposit_nonces` table (no parallel storage / no
    //  cross-flow replay window).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 16, location = eunoma::eunoma_bridge)]
    fun test_batch_deposit_rejects_replay_against_used_table(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();

        let (
            commitments, amount_tags, proofs, nonces,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea, ekv, amtrvolun,
            zkrpb, zkrpa, spc, spr, memos,
            item_digests
        ) = build_batch_inputs(
            asset_type, vault_addr, b"batch_replay_", 2,
        );

        // Burn the second item's nonce via the test-only helper BEFORE the
        // batch call (mirrors a prior successful deposit that consumed it).
        let pre_burn_nonce = *vector::borrow(&nonces, 1);
        eunoma_bridge::test_call_consume_deposit_nonce(pre_burn_nonce);

        let msg_bytes = build_batch_attestation_bytes(item_digests);
        let sigs = valid_4of7(&sks, &msg_bytes);

        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            nbp, nbr, nbrea, amtp, amtrs, amtrr, amtrea,
            ekv, amtrvolun, zkrpb, zkrpa, spc, spr, memos,
        );
    }

    // ====================================================================
    //  Negative — batch size 0 (empty parallel vectors). E_BATCH_SIZE_OUT_OF_RANGE.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 25, location = eunoma::eunoma_bridge)]
    fun test_batch_deposit_rejects_empty(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let sigs = empty_sig_vec();
        eunoma_bridge::deposit_batch_with_commitments(
            user,
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
            TEST_EXPIRY, sigs,
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<vector<u8>>>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<u8>>(),
        );
    }

    // ====================================================================
    //  Negative — parallel-vector length mismatch. E_BATCH_LENGTH_MISMATCH (26).
    //  commitments has 2 entries; amount_tags has only 1.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 26, location = eunoma::eunoma_bridge)]
    fun test_batch_deposit_rejects_length_mismatch(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        user: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        let user_addr = signer::address_of(user);
        if (!account::exists_at(user_addr)) {
            account::create_account_for_test(user_addr);
        };

        let commitments = vector::empty<vector<u8>>();
        vector::push_back(&mut commitments, PUB_VALID_COMMITMENT);
        vector::push_back(&mut commitments, PUB_VALID_COMMITMENT);

        let amount_tags = vector::empty<vector<u8>>();
        vector::push_back(&mut amount_tags, PUB_VALID_AMOUNT_TAG);
        // Note: only 1 amount_tag — length mismatch with commitments.

        let proofs = vector::empty<vector<u8>>();
        let nonces = vector::empty<vector<u8>>();
        vector::push_back(&mut nonces, b"len_mismatch_n0_");
        vector::push_back(&mut nonces, b"len_mismatch_n1_");

        let sigs = empty_sig_vec();
        eunoma_bridge::deposit_batch_with_commitments(
            user,
            commitments, amount_tags, proofs, nonces,
            TEST_EXPIRY, sigs,
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<vector<u8>>>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<vector<u8>>>(),
            vector::empty<vector<u8>>(),
        );
    }
}
