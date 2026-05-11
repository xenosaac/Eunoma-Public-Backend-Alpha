// Gate 4b — `deposit_with_commitment` end-to-end tests.
//
// Surface tested (per BRIEF_GATE_4B_DEPOSIT_MOVE.md acceptance table):
//   * 7 negative tests covering each error gate the bridge layer enforces:
//       1. wrong amount_tag         -> E_INVALID_DEPOSIT_BINDING_PROOF (18)
//       2. wrong proof bytes        -> E_INVALID_DEPOSIT_BINDING_PROOF (18)
//       3. mutated CA payload       -> E_INVALID_OPERATOR_SIGNATURE   (12)
//          (subagent decision: bridge does NOT add a separate
//          E_PAYLOAD_HASH_MISMATCH check; the binding is enforced
//          indirectly because the recomputed ca_payload_hash flows
//          into the attestation message body and therefore breaks
//          operator signature verification when CA fields are mutated.
//          See REPORT_GATE_4B_DEPOSIT_MOVE.md for rationale.)
//       4. 3-of-7 sigs              -> E_TOO_FEW_OPERATOR_SIGNATURES   (10)
//       5. 4-of-7 without main      -> E_MAIN_OPERATOR_SIGNATURE_REQUIRED (11)
//       6. expired attestation      -> E_EXPIRED_ATTESTATION           (15)
//       7. nonce replay             -> E_DEPOSIT_NONCE_REPLAY          (16)
//   * 1 positive test that runs the full deposit flow with a valid 4-of-7
//     attestation + a valid Gate 4a Groth16 proof; expected to abort INSIDE
//     `aptos_framework::confidential_balance` (chunk-count check on placeholder
//     CA bytes) — proving every bridge-layer gate passed before reaching the
//     framework, exactly per Gate 3 prototype Test 4 pattern.
//
// Test fixtures:
//   * VK / proof / public-input bytes copied from
//     `circuits/generated/move_fixtures/move_constants.move` (Gate 4a).
//   * The Gate 4a fixture used placeholder asset_id = 7 and
//     vault_addr_hash = `edaffceedbeaedaffceedbeaedaffceedbeaedaffceedbeaedaffcee0befbe00`.
//     Real Move-side `derive_asset_id` / `derive_vault_addr_hash` would yield
//     different Fr values, so the fixture proof would NOT verify against the
//     bridge's recomputed asset_id / vault_addr_hash from the actual test
//     `Object<Metadata>` address and vault resource-account address.
//
//     Subagent decision (REPORT_GATE_4B): the positive test uses a
//     test-only override `set_asset_id_override_for_test` /
//     `set_vault_addr_hash_override_for_test` that the bridge consults when
//     a `DepositBindingTestOverride` resource exists at @eunoma. Production
//     code path (no override) calls the real Poseidon-of-address derivation;
//     test path (override exists) returns the fixed placeholder bytes. This
//     keeps the production assert_valid_deposit_binding_proof call site
//     unchanged AND keeps the Gate 4a fixture re-usable without regenerating
//     the circuit. The override resource is `#[test_only]` and never compiles
//     into a published module.
//
//   * Operator pubkey set: 7 fresh ed25519 keys generated per test
//     (`gen_seven_active_operators`), main_operator_index = 0, threshold = 4.
//     Operator signatures are re-signed inside each test over the canonical
//     attestation message; the bridge then re-derives the same message via
//     `new_deposit_attestation_message` and verifies the sigs.
//
//   * `chain_id` is initialized to 2u8 to match the Gate 4a fixture's
//     `chain_id = 2` public input.
#[test_only]
module eunoma::deposit_with_commitment_tests {
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
    // Phase F W3 — regenerated for the 4-public-input circuit
    // (chain_id + pool_id baked as compile-time constants CHAIN_ID=2, POOL_ID=0).
    // Source: circuits/generated/move_fixtures/vk_bytes.json + proof_valid_bytes.json
    // + public_valid_bytes.json. The deterministic VK pieces (alpha, beta, gamma)
    // match the previous fixture (they come from the ptau); delta + IC + proof
    // differ because the random contribution + new circuit shape change them.
    const VK_ALPHA_G1: vector<u8> = x"12c16beca06688485d74f21688948e77dedd9a4ad68b28b0eeb6293252e56826ae44c5727d76b62d79f2923c1c1bc5f58e778c4b03a3c58903cc6a1efc189109";
    const VK_BETA_G2:  vector<u8> = x"1ca4e89cceb6a9b7caabcd83980fcd69ef6df2b9d5f7b45d082e247807493c0ce21e5e7224aab40a95a0434fe84af514f9f81a5a4884abccad4fb8ec072a620d688459b1d0c167b809117b8cd25eb18b191f1a6f1406d4873ce49d06439c9e0fc8226b4a8f6578991eade15e60729cd6854e7160ae4b5d9640993c13184cb80b";
    const VK_GAMMA_G2: vector<u8> = x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609";
    const VK_DELTA_G2: vector<u8> = x"28f894bd6fa2503e8fa6c95e3140cff9670b037e491a700c2125003072ef9a1d73fd1e0783d0dbdbcdeb9d55ae30465c9b20e1d265c2b0024a120c7a4d350e2ca0857cde259f1b035000a38624db47cf6bf95595ac65930367cd825393f6c801990632b426d639e4649494f499346fd3ff02f604ca030624d8d4147d44f92f1a";

    const VK_IC_0: vector<u8> = x"f7c850638246b8203850b3ef63e55d5b35f6b7a385b523c3e775fd46b50b1e0feeb4adc4d85e2dce44b774e5ac64b1a82719f370965a1932c674527242849c0b";
    const VK_IC_1: vector<u8> = x"3590b33528bf6e17ce5015d6ac18d05bfeeb3c9e7f75675d3b64b558d5f8eb1cac1352465d8ee082ca0936150cfd34b3b137f0df824daba78b7b4a03aed46320";
    const VK_IC_2: vector<u8> = x"7e4325dff4f72c7d6aac99313818ff538b36cf774352ec4129290dddadfff825cfabf8e883b20675a48102aa212c568d6df0e7698949ae1fc9ba41c7ebacb72c";
    const VK_IC_3: vector<u8> = x"ababae53ea5208df20f73b178c92fa26cc0b0ec107e0853536eff74aac27372c654f8e5d7c464a38da6f7ea6e9949572844eab8b0b1de74a6ca5747ccfce341f";
    const VK_IC_4: vector<u8> = x"a0d4f0a41ebef3db789968a2fd37458c268849bf213f6c7eba2a72755b1f471d939ea92889637adebd1c00a5c5d5850643a3c8e401f78f1855d776ae6c1d5a01";

    // Valid proof (uncompressed bytes; auto-generated by Phase F W3 setup).
    const PROOF_A: vector<u8> = x"035d4dc41c8787c35786ea004e5f8580d6ed9213fc7e1c290cdc8b2e5b6fd52de9f123547736b919f9081b5b3729e5fd44e4b235da428a93a8034c2d13470400";
    const PROOF_B: vector<u8> = x"ec2670b532abe71e375dd0314807cb5950f6934971ef104a7cc762a54a2c9f0ee6ed00c3665062b0eec4475ad69a4f53eab3fa210ab181109e45e6021b159a1b43b3492ddafec31e7bc59ee669b9431462ebfcb674ae267014055028cee5781570fa143731149f4c33091703301096d19a94e76a85fda0311cb1f171240b8409";
    const PROOF_C: vector<u8> = x"80fa277173e5d5f59ab1796471999d0e45476254451670dc3271369481cbea226b3ae6b9a745922740e95b3a66b8ef351ca90130d0519f6a739d66a890a18127";

    // Public inputs (Fr 32-byte LE, in snarkjs declaration order):
    //   [0] commitment, [1] amount_tag, [2] asset_id, [3] vault_addr_hash
    // (Phase F W3: chain_id + pool_id removed from publics, baked as circuit constants.)
    const PUB_VALID_COMMITMENT: vector<u8> = x"942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613";
    const PUB_VALID_AMOUNT_TAG: vector<u8> = x"02ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b";
    const PUB_VALID_ASSET_ID:        vector<u8> = x"0700000000000000000000000000000000000000000000000000000000000000";
    const PUB_VALID_VAULT_ADDR_HASH: vector<u8> = x"edaffceedbeaedaffceedbeaedaffceedbeaedaffceedbeaedaffcee0befbe00";

    // Mutated public inputs — used by the negative tests that need a *different*
    // commitment / amount_tag than the proof was generated for.
    const PUB_NEG_AMOUNT_TAG: vector<u8> = x"03ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b";

    // ====================================================================
    //  Test fixture builders
    // ====================================================================

    const VAULT_SEED: vector<u8> = b"APTOSHIELD_GATE4B_VAULT_SEED_V1";
    const TEST_NOW: u64 = 1_700_000_000;
    const TEST_EXPIRY: u64 = 1_900_000_000;

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

    /// Standard happy-path setup for Gate 4b tests:
    ///   * timestamp set to TEST_NOW
    ///   * chain_id set to 2 (matches Gate 4a fixture's chain_id = 2)
    ///   * asset metadata + 7 operators
    ///   * `init_vault` with main = 0, threshold = 4
    ///   * `publish_deposit_binding_vk` populated from Gate 4a fixture VK
    ///   * test override resource installed so derive_asset_id /
    ///     derive_vault_addr_hash return the Gate 4a fixture's placeholder
    ///     Fr bytes (asset_id = 0x07 padded, vault_addr_hash = the magic
    ///     edaff... pattern from the fixture).
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

        // Publish Phase F W3 VK fixture (5 IC slots, 4 publics).
        eunoma_bridge::publish_deposit_binding_vk(
            admin,
            VK_ALPHA_G1,
            VK_BETA_G2,
            VK_GAMMA_G2,
            VK_DELTA_G2,
            VK_IC_0, VK_IC_1, VK_IC_2, VK_IC_3, VK_IC_4,
        );

        // Install test-only Fr override so derive_asset_id /
        // derive_vault_addr_hash return Gate 4a fixture's placeholder
        // bytes instead of the real Poseidon-of-address derivation.
        eunoma_bridge::install_deposit_binding_test_override(
            admin,
            PUB_VALID_ASSET_ID,
            PUB_VALID_VAULT_ADDR_HASH,
        );

        // Phase B L-α — initialize VaultConfigCache so deposits can read the
        // cached asset_id / vault_addr_hash instead of recomputing hash_3.
        // Must be called AFTER install_deposit_binding_test_override so the
        // cache picks up the Gate 4a fixture's placeholder Fr values.
        eunoma_bridge::init_vault_config_cache(admin);

        // Phase B L-δ — publish the prepared VK so deposits can dispatch to
        // verify_proof_prepared_fq12 (1 multi_pairing + skip Gt deserialization)
        // instead of the slow verify_proof (4 separate pairings).
        eunoma_bridge::publish_prepared_deposit_binding_vk(admin);

        (metadata, sks, pks)
    }

    /// Build a 7-slot empty-signature vector.
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

    /// Empty placeholder CA payload — every byte vector empty. The CA framework
    /// rejects this at the chunk-count check (E_WRONG_NUM_CHUNKS, abort code
    /// 65537 inside `aptos_framework::confidential_balance`); see Gate 3
    /// prototype Test 4 for the canonical pattern.
    struct EmptyCaPayload has drop {}

    /// Build the canonical valid-fixture deposit attestation message bytes.
    /// Every field matches the Gate 4a fixture's public inputs (commitment,
    /// amount_tag, asset_id, vault_addr_hash, chain_id, pool_id) so the
    /// Groth16 proof will verify when the bridge runs through assert_valid_deposit_binding_proof.
    fun build_valid_attestation_msg(
        deposit_nonce: vector<u8>,
        ca_payload_hash: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
    ): vector<u8> {
        let msg = eunoma_bridge::test_call_new_deposit_attestation_message(
            /*chain_id=*/ 2u8,
            // Phase D Agent D1: production deposit path now passes 8-byte LE u64
            // pool_id into the attestation message (matches TS encoder + saves
            // 24 BCS bytes on the signed message). Test fixture must mirror so
            // signatures the test produces match the bytes the bridge recomputes.
            /*pool_id=*/ x"0000000000000000",
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            TEST_EXPIRY,
        );
        bcs::to_bytes(&msg)
    }

    /// Concatenate Gate 4a's proof_a || proof_b || proof_c into a single
    /// 256-byte uncompressed proof blob.
    fun build_valid_proof(): vector<u8> {
        let out = vector::empty<u8>();
        vector::append(&mut out, PROOF_A);
        vector::append(&mut out, PROOF_B);
        vector::append(&mut out, PROOF_C);
        out
    }

    fun empty_vec_of_vec(): vector<vector<u8>> {
        vector::empty<vector<u8>>()
    }

    fun empty_vec_of_vec_of_vec(): vector<vector<vector<u8>>> {
        vector::empty<vector<vector<u8>>>()
    }

    /// Recompute the same ca_payload_hash the bridge will recompute. We
    /// pass empty placeholders for every CA payload field; the bridge will
    /// hash the same struct, get the same digest, and the operators sign
    /// over an attestation message containing that digest.
    fun recompute_ca_payload_hash(
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
    ): vector<u8> {
        eunoma_bridge::test_call_hash_confidential_transfer_payload(
            asset_type,
            vault_addr,
            empty_vec_of_vec(),  // new_balance_p
            empty_vec_of_vec(),  // new_balance_r
            empty_vec_of_vec(),  // new_balance_r_eff_aud
            empty_vec_of_vec(),  // amount_p
            empty_vec_of_vec(),  // amount_r_sender
            empty_vec_of_vec(),  // amount_r_recip
            empty_vec_of_vec(),  // amount_r_eff_aud
            empty_vec_of_vec(),  // ek_volun_auds
            empty_vec_of_vec_of_vec(),  // amount_r_volun_auds
            vector::empty<u8>(), // zkrp_new_balance
            vector::empty<u8>(), // zkrp_amount
            empty_vec_of_vec(),  // sigma_proto_comm
            empty_vec_of_vec(),  // sigma_proto_resp
            vector::empty<u8>(), // memo
        )
    }

    /// Run a deposit with *valid* attestation + proof + commitment + amount_tag,
    /// 4 sigs (slots 0,1,2,3) over the canonical attestation message.
    /// Returns the attestation message bytes for caller-side test assertions.
    /// Does NOT call `deposit_with_commitment` itself — caller invokes that.
    fun build_valid_sigs_and_msg(
        sks: &vector<ed25519::SecretKey>,
        deposit_nonce: vector<u8>,
        ca_payload_hash: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
    ): (vector<u8>, vector<vector<u8>>) {
        let msg = build_valid_attestation_msg(
            deposit_nonce,
            ca_payload_hash,
            commitment,
            amount_tag,
        );
        let sigs = empty_sig_vec();
        put_sig(&mut sigs, 0, sign_with(sks, 0, &msg));
        put_sig(&mut sigs, 1, sign_with(sks, 1, &msg));
        put_sig(&mut sigs, 2, sign_with(sks, 2, &msg));
        put_sig(&mut sigs, 3, sign_with(sks, 3, &msg));
        (msg, sigs)
    }

    // ====================================================================
    //  Negative test 1 — wrong amount_tag
    //
    //  We pass an amount_tag that doesn't match the proof's commitment circuit
    //  (mutated 1st byte). Operators sign over the (commitment, mutated
    //  amount_tag) so attestation passes; the Groth16 verifier rejects because
    //  the public-input vector pairs the mutated amount_tag against the same
    //  proof bytes -> pairing equation fails.
    //  Expected: E_INVALID_DEPOSIT_BINDING_PROOF (18).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 18, location = eunoma::eunoma_bridge)]
    fun test_deposit_rejects_wrong_amount_tag(
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

        let nonce = b"deposit_nonce_wrong_amount_tag_v1";
        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();
        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        // Operators sign over the (commitment, MUTATED amount_tag) attestation
        // — multi-sig PASSES. Then proof verification fails because public[1]
        // (amount_tag) doesn't match the proof's witness.
        let (_msg, sigs) = build_valid_sigs_and_msg(
            &sks,
            nonce,
            cph,
            PUB_VALID_COMMITMENT,
            PUB_NEG_AMOUNT_TAG,
        );

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_NEG_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 2 — wrong proof bytes
    //
    //  Pass 256 bytes of 0xAA as the proof. Deserialization will fail (bytes
    //  do not encode valid G1/G2 affine points), aborting in
    //  assert_valid_deposit_binding_proof's `de_g1`/`de_g2` calls.
    //  Expected: E_INVALID_DEPOSIT_BINDING_PROOF (18).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 18, location = eunoma::eunoma_bridge)]
    fun test_deposit_rejects_wrong_proof(
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

        let nonce = b"deposit_nonce_wrong_proof_v1";
        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();
        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        // Operators sign valid attestation; only the proof bytes are garbage.
        let (_msg, sigs) = build_valid_sigs_and_msg(
            &sks,
            nonce,
            cph,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
        );

        // 256 bytes of 0xAA — wrong size? No, exactly 256. But fails to
        // decode as valid G1/G2 affine points, so de_g1 aborts.
        let garbage_proof = vector::empty<u8>();
        let i = 0;
        while (i < 256) {
            vector::push_back(&mut garbage_proof, 0xAAu8);
            i = i + 1;
        };

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            garbage_proof,
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 3 — wrong CA payload hash (mutated payload field)
    //
    //  Operators sign over an attestation built against ca_payload_hash A
    //  (computed from the original CA payload). Then we call
    //  deposit_with_commitment with a MUTATED CA payload: the bridge
    //  recomputes ca_payload_hash B, builds a different attestation message,
    //  and operator signatures (which signed message-with-hash-A) won't
    //  verify against message-with-hash-B.
    //
    //  Subagent decision (REPORT_GATE_4B): this surfaces as
    //  E_INVALID_OPERATOR_SIGNATURE (12) — the main-slot sig fails strict
    //  signature_verify_strict against the mutated message bytes — rather than
    //  E_PAYLOAD_HASH_MISMATCH. The bridge intentionally does NOT carry a
    //  user-provided ca_payload_hash; it only uses the recomputed one in the
    //  attestation message body. Brief test #3 row allows this code path.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 108, location = eunoma::pool_multi_sig_verifier)]
    fun test_deposit_rejects_wrong_payload_hash(
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

        let nonce = b"deposit_nonce_wrong_payload_v1";

        // Step 1: Operators sign over a "stale" ca_payload_hash that does NOT
        // match what the bridge will recompute on the actual CA payload below.
        let stale_hash = b"stale_ca_payload_hash_signed_by_operators_____";
        let (_msg, sigs) = build_valid_sigs_and_msg(
            &sks,
            nonce,
            stale_hash,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
        );

        // Step 2: Bridge recomputes ca_payload_hash from the actual (empty)
        // CA payload — yields a digest that doesn't match the stale_hash the
        // operators signed over. Result: main-slot sig fails verify ->
        // E_INVALID_OPERATOR_SIGNATURE (12).
        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 4 — 3-of-7 attestation (threshold not met)
    //
    //  Slots 0, 1, 2 sign — main IS slot 0 so main_signed = true, but
    //  valid_count = 3 < threshold = 4 -> E_TOO_FEW_OPERATOR_SIGNATURES (10).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 109, location = eunoma::pool_multi_sig_verifier)]
    fun test_deposit_rejects_3_of_7(
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

        let nonce = b"deposit_nonce_3_of_7_v1";
        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();
        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        let msg = build_valid_attestation_msg(
            nonce, cph, PUB_VALID_COMMITMENT, PUB_VALID_AMOUNT_TAG,
        );
        let sigs = empty_sig_vec();
        // Only 3 signatures — slots 0 (main), 1, 2.
        put_sig(&mut sigs, 0, sign_with(&sks, 0, &msg));
        put_sig(&mut sigs, 1, sign_with(&sks, 1, &msg));
        put_sig(&mut sigs, 2, sign_with(&sks, 2, &msg));

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 5 — 4-of-7 without main
    //
    //  Slots 1, 2, 3, 4 sign; main (slot 0) does NOT.
    //  valid_count = 4 meets threshold, but main_signed = false ->
    //  E_MAIN_OPERATOR_SIGNATURE_REQUIRED (11).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 110, location = eunoma::pool_multi_sig_verifier)]
    fun test_deposit_rejects_4_of_7_without_main(
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

        let nonce = b"deposit_nonce_4_of_7_no_main_v1";
        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();
        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        let msg = build_valid_attestation_msg(
            nonce, cph, PUB_VALID_COMMITMENT, PUB_VALID_AMOUNT_TAG,
        );
        let sigs = empty_sig_vec();
        // 4 signatures, but main (slot 0) is missing.
        put_sig(&mut sigs, 1, sign_with(&sks, 1, &msg));
        put_sig(&mut sigs, 2, sign_with(&sks, 2, &msg));
        put_sig(&mut sigs, 3, sign_with(&sks, 3, &msg));
        put_sig(&mut sigs, 4, sign_with(&sks, 4, &msg));

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 6 — expired attestation
    //
    //  TEST_NOW = 1_700_000_000; pass expiry = 1_500_000_000 (in past) ->
    //  E_EXPIRED_ATTESTATION (15).
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 15, location = eunoma::eunoma_bridge)]
    fun test_deposit_rejects_expired_attestation(
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

        // Past expiry — bridge aborts before attestation/proof checks.
        let past_expiry: u64 = 1_500_000_000;
        let nonce = b"deposit_nonce_expired_v1";
        let sigs = empty_sig_vec(); // sigs unused; expiry check is FIRST after pause.

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            past_expiry,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    //  Negative test 7 — nonce replay
    //
    //  Run a valid deposit twice with the same nonce. First call reaches
    //  the CA framework dispatch (and aborts inside the framework on
    //  E_WRONG_NUM_CHUNKS / abort code 65537 in confidential_balance) —
    //  but at that point the nonce has already been added to the table
    //  per the bridge's "mark nonce consumed before CA dispatch" guarantee.
    //  Retrying with the same nonce must hit E_DEPOSIT_NONCE_REPLAY (16).
    //
    //  Implementation note: because the first call panics inside the
    //  framework (placeholder CA bytes are invalid), Move's test runtime
    //  rolls back state — meaning the nonce-table insert is also reverted.
    //  To still exercise replay protection deterministically, this test
    //  uses a parallel test-only entry that performs ONLY the nonce-check +
    //  insert (`test_call_consume_deposit_nonce`) and verifies that the
    //  second insert aborts E_DEPOSIT_NONCE_REPLAY (16). This isolates the
    //  nonce-replay gate from the CA dispatch failure that would otherwise
    //  mask it under Move's transactional rollback semantics.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    #[expected_failure(abort_code = 16, location = eunoma::eunoma_bridge)]
    fun test_deposit_rejects_nonce_replay(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);

        let nonce = b"deposit_nonce_replay_v1";
        // First insert succeeds.
        eunoma_bridge::test_call_consume_deposit_nonce(nonce);
        // Second insert with same nonce -> E_DEPOSIT_NONCE_REPLAY (16).
        eunoma_bridge::test_call_consume_deposit_nonce(nonce);
    }

    // ====================================================================
    //  Positive test — full happy path reaches CA framework dispatch
    //
    //  Runs deposit_with_commitment with:
    //    * valid 4-of-7 attestation (slots 0 main, 1, 2, 3)
    //    * valid Gate 4a Groth16 proof + valid public inputs (commitment,
    //      amount_tag) + override-installed asset_id/vault_addr_hash matching
    //      Gate 4a fixture
    //    * valid expiry, fresh nonce
    //    * EMPTY CA payload (every byte vector empty)
    //
    //  Every bridge-side gate passes (pause, expiry, nonce, payload-hash
    //  binding via attestation, 4-of-7 multi-sig, Groth16 proof, nonce table
    //  insert). The bridge dispatches into
    //  `aptos_framework::confidential_asset::confidential_transfer_raw`,
    //  which delegates to `confidential_balance::new_compressed_balance`,
    //  which aborts E_WRONG_NUM_CHUNKS (abort code 65537) on the empty
    //  byte-vector chunks.
    //
    //  Same pattern as Gate 3 prototype Test 4 — the framework-internal abort
    //  EMPIRICALLY proves every bridge-side gate passed AND the cross-module
    //  dispatch reached the framework.
    // ====================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, user = @0xCA11)]
    #[expected_failure(abort_code = 65537, location = aptos_framework::confidential_balance)]
    fun test_deposit_with_commitment_succeeds_to_ca_dispatch(
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

        let nonce = b"deposit_nonce_positive_v1";
        let vault_addr = eunoma_bridge::get_vault_addr();
        let asset_type = eunoma_bridge::get_asset_type();
        let cph = recompute_ca_payload_hash(asset_type, vault_addr);

        let (_msg, sigs) = build_valid_sigs_and_msg(
            &sks,
            nonce,
            cph,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
        );

        eunoma_bridge::deposit_with_commitment(
            user,
            PUB_VALID_COMMITMENT,
            PUB_VALID_AMOUNT_TAG,
            build_valid_proof(),
            nonce,
            TEST_EXPIRY,
            sigs,
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            empty_vec_of_vec_of_vec(),
            vector::empty<u8>(),
            vector::empty<u8>(),
            empty_vec_of_vec(),
            empty_vec_of_vec(),
            vector::empty<u8>(),
        );
    }

    // ====================================================================
    // Phase B B.1 — VaultConfigCache (L-α) admin-entry tests
    // ====================================================================

    /// init_vault_config_cache must reject non-admin callers (E_NOT_ADMIN = 1).
    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, attacker = @0xBAD)]
    #[expected_failure(abort_code = 1, location = eunoma::eunoma_bridge)]
    fun test_init_vault_config_cache_rejects_non_admin(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        attacker: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        // setup_for_deposit already initializes VaultConfigCache once via admin.
        // Drop that and re-test with attacker-as-signer below.
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        // Second call by attacker must abort E_NOT_ADMIN.
        eunoma_bridge::init_vault_config_cache(attacker);
    }

    /// init_vault_config_cache must be idempotent (E_ALREADY_INITIALIZED = 5).
    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    #[expected_failure(abort_code = 5, location = eunoma::eunoma_bridge)]
    fun test_init_vault_config_cache_rejects_double_init(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        // setup_for_deposit already calls init_vault_config_cache once.
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        // Second call by admin must abort E_ALREADY_INITIALIZED.
        eunoma_bridge::init_vault_config_cache(admin);
    }

    // ====================================================================
    // Phase B B.2 — PreparedDepositBindingVK (L-δ) admin-entry tests
    // ====================================================================

    // publish_prepared_deposit_binding_vk must reject non-admin callers (E_NOT_ADMIN = 1).
    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, attacker = @0xBAD)]
    #[expected_failure(abort_code = 1, location = eunoma::eunoma_bridge)]
    fun test_publish_prepared_vk_rejects_non_admin(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        attacker: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        // setup_for_deposit already published prepared VK once. Attempt by attacker must fail E_NOT_ADMIN.
        eunoma_bridge::publish_prepared_deposit_binding_vk(attacker);
    }

    // publish_prepared_deposit_binding_vk must be idempotent (E_ALREADY_INITIALIZED = 5).
    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    #[expected_failure(abort_code = 5, location = eunoma::eunoma_bridge)]
    fun test_publish_prepared_vk_rejects_double_publish(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        let main_addr = signer::address_of(main_op);
        let (_metadata, _sks, _pks) = setup_for_deposit(framework, admin, main_addr);
        // setup_for_deposit already published once; second admin call must abort E_ALREADY_INITIALIZED.
        eunoma_bridge::publish_prepared_deposit_binding_vk(admin);
    }
}
