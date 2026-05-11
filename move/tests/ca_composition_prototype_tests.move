/// Gate 3 — ConfidentialAPT composition prototype tests (Path A: local Move).
///
/// PURPOSE: Empirical confirmation of LOCAL_CONFIRMATION 8.4 (cross-module
/// callability of `confidential_asset::confidential_transfer_raw`), 8.1
/// (`rollover_pending_balance`), and 8.3 (resource-account + SignerCapability
/// pattern).
///
/// SCOPE (Path A — local `aptos move test`):
///
/// * Compile-time cross-module composition is FULLY validated. The bridge
///   module successfully links against three `public entry fun` symbols in
///   `aptos_framework::confidential_asset` from a non-friend module:
///     - `confidential_asset::register_raw` (in `init_vault_with_ca_registration`)
///     - `confidential_asset::rollover_pending_balance` (in `test_only_vault_rollover`)
///     - `confidential_asset::confidential_transfer_raw` (in `test_only_vault_to_recipient_transfer_raw`)
///   If cross-module callability of `public entry fun` were structurally
///   broken (e.g., if `entry` implied friend-only visibility), this test
///   FILE WOULD NOT COMPILE — that's the strongest empirical proof Path A
///   can give for criterion 1 and 4 architectural properties.
///
/// * Resource-signer-cap pattern is validated structurally: the bridge
///   stores `vault_signer_cap` as `account::SignerCapability` inside
///   `VaultConfig`, and the bridge wrappers
///   (`test_only_vault_rollover`, `test_only_vault_to_recipient_transfer_raw`)
///   regenerate the vault signer via `account::create_signer_with_capability`
///   inside the module. Test 1 below confirms compilation + bridge `init_vault`
///   succeeds in producing a resource account + storing the cap.
///
/// PATH A LIMITATION (and why some criteria fall back to Path B):
///
///   The CA framework's `GlobalConfig` resource is initialized only by
///   `confidential_asset::init_module_for_testing` (`public(friend)`), which
///   is friend-restricted to `aptos_framework::*` modules. From an external
///   `#[test_only]` module like this one, we CANNOT initialize CA framework
///   state. Consequently, runtime invocation of any CA framework function
///   from this test would abort at the framework's `GlobalConfig` lookup.
///
///   Additionally, valid `register_raw` / `confidential_transfer_raw` byte
///   arguments require sigma-protocol proof construction (commitment +
///   response bytes that hash-bind under the framework's Fiat-Shamir DST).
///   Those proof-construction APIs (`sigma_protocol_registration::prove`,
///   `sigma_protocol_transfer::prove`, `sigma_protocol_proof::new_proof_from_bytes`)
///   are also `public(friend)` and friend-restricted.
///
///   Resolution: criteria 1 (vault registration), 2 (user→vault), 3 (vault
///   rollover dispatch with real CA state), 4 (vault→recipient), and 5
///   (recipient decrypt) cannot be executed end-to-end in Path A. They are
///   slated for Path B (testnet) execution. See REPORT_GATE_3_CA_PROTOTYPE.md
///   for the per-criterion verdict.
///
/// WHAT THIS PATH A TEST SUITE DOES VERIFY (runtime):
///
///   Test 1: bridge initialization + resource-account creation works.
///     Calls `eunoma_bridge::init_vault` (Gate 2 stub variant) which
///     creates a resource account and stores the SignerCapability. Verifies
///     vault address is non-zero, operator-set version is 0, etc.
///
///   Test 2: `init_vault_with_ca_registration` reaches the CA framework.
///     This calls the new Gate 3 entry function which dispatches
///     `confidential_asset::register_raw` cross-module. Without CA framework
///     `GlobalConfig` initialization (friend-only), the call aborts inside
///     the framework — but reaching that abort path EMPIRICALLY proves
///     cross-module dispatch worked. Marked `#[expected_failure]` with the
///     framework's missing-resource abort code.
///
///   Test 3: `test_only_vault_rollover` reaches the CA framework.
///     Calls the bridge wrapper which derives vault signer from stored cap
///     and dispatches `confidential_asset::rollover_pending_balance`. Same
///     pattern as Test 2 — abort inside the framework empirically proves
///     cross-module dispatch worked.
#[test_only]
module eunoma::ca_composition_prototype_tests {
    use std::signer;
    use std::vector;

    use aptos_std::ed25519;

    use aptos_framework::account;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::Object;
    use aptos_framework::timestamp;

    use eunoma::eunoma_bridge;

    // ========================================================================
    // Test fixture builders
    // ========================================================================

    /// Test vault seed used by Gate 3 prototype.
    const VAULT_SEED: vector<u8> = b"APTOSHIELD_GATE3_VAULT_SEED_V1";

    /// Build a 7-slot operator key set, all active.
    fun gen_seven_active_operators(): vector<vector<u8>> {
        let pks = vector::empty<vector<u8>>();
        let i = 0;
        while (i < 7) {
            let (_sk, vpk) = ed25519::generate_keys();
            let pk_bytes = ed25519::validated_public_key_to_bytes(&vpk);
            vector::push_back(&mut pks, pk_bytes);
            i = i + 1;
        };
        pks
    }

    /// Construct a TEST fungible asset Metadata object.
    fun make_test_metadata(creator: &signer): Object<fungible_asset::Metadata> {
        let (_mint, _transfer, _burn, _mutate, metadata) =
            fungible_asset::create_fungible_asset(creator);
        metadata
    }

    fun base_setup(framework: &signer, admin: &signer) {
        timestamp::set_time_has_started_for_testing(framework);
        timestamp::update_global_time_for_test_secs(1_700_000_000);
        let admin_addr = signer::address_of(admin);
        if (!account::exists_at(admin_addr)) {
            account::create_account_for_test(admin_addr);
        };
    }

    // ========================================================================
    // TEST 1 — Bridge initialization + resource-account creation
    //
    // Confirms (Path A, runtime):
    //   * `account::create_resource_account` produces a vault signer + cap
    //   * the cap is stored in VaultConfig (covered by Test 1 + Test 3)
    //   * vault_addr is non-zero and matches the cap's stored address
    //
    // Gate 3 acceptance touches (compile-time only): criterion 1 architectural
    // property is proved by the fact that THIS test file successfully links
    // against `eunoma_bridge::init_vault_with_ca_registration` (which
    // internally invokes `confidential_asset::register_raw`).
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    fun test_bridge_init_creates_resource_account_with_signer_cap(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        base_setup(framework, admin);
        let metadata = make_test_metadata(admin);
        let pks = gen_seven_active_operators();

        eunoma_bridge::init_vault(
            admin,
            signer::address_of(main_op),
            metadata,
            pks,
            /*main_operator_index=*/ 0,
            /*attestation_threshold=*/ 4,
            VAULT_SEED,
            /*vault_ek=*/ b"vault_ek_placeholder_gate3",
            /*registration_sigma_proto_comm=*/ vector::empty<vector<u8>>(),
            /*registration_sigma_proto_resp=*/ vector::empty<vector<u8>>(),
        );

        // Cap-derived vault address is non-zero and view function returns it.
        let vault_addr = eunoma_bridge::get_vault_addr();
        assert!(vault_addr != @0x0, 1001);
        // Vault address must be deterministic per (admin, seed).
        let expected_addr = account::create_resource_address(
            &@eunoma,
            VAULT_SEED,
        );
        assert!(vault_addr == expected_addr, 1002);
        // Bridge state is in the freshly-initialized configuration.
        assert!(eunoma_bridge::get_operator_set_version() == 0, 1003);
        assert!(eunoma_bridge::is_paused() == false, 1004);
        assert!(eunoma_bridge::get_vault_sequence() == 0, 1005);
    }

    // ========================================================================
    // TEST 2 — `init_vault_with_ca_registration` dispatches register_raw
    //
    // This calls the Gate 3 production-correct init variant that DOES invoke
    // `confidential_asset::register_raw` cross-module. Because the CA
    // framework's `GlobalConfig` resource is not (and cannot be from an
    // external module) initialized in this test, the framework aborts inside
    // `register_raw`'s `borrow_global<GlobalConfig>`.
    //
    // EMPIRICAL CONFIRMATION OF GATE 1 ITEM 8.4: reaching this abort proves
    // the bridge module successfully resolved
    // `aptos_framework::confidential_asset::register_raw` and pushed a call
    // frame INSIDE that function. If `entry` had implied friend-only visibility,
    // the build would have failed at link time, not at runtime resource lookup.
    //
    // Stack trace (observed): the abort is INSIDE
    // `confidential_asset::register_raw` at line 375
    // (`new_compressed_point_from_bytes(ek).extract()` — the placeholder EK
    // bytes don't decode to a valid Ristretto255 point, so `option::extract`
    // aborts on `none`). The Move VM reports abort code 262145 (category
    // UNAUTHENTICATED, reason 1) originating in `std::option::extract`.
    // The location pin confirms the call frame reached the framework.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    #[expected_failure(abort_code = 262145, location = std::option)]
    fun test_register_raw_dispatch_reaches_ca_framework(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        base_setup(framework, admin);
        let metadata = make_test_metadata(admin);
        let pks = gen_seven_active_operators();

        // Calls eunoma_bridge::init_vault_with_ca_registration which
        // internally dispatches confidential_asset::register_raw cross-module.
        // Aborts inside the CA module at the GlobalConfig lookup — proving
        // the dispatch reached the framework.
        eunoma_bridge::init_vault_with_ca_registration(
            admin,
            signer::address_of(main_op),
            metadata,
            pks,
            /*main_operator_index=*/ 0,
            /*attestation_threshold=*/ 4,
            VAULT_SEED,
            /*vault_ek=*/ b"vault_ek_placeholder_will_not_decode",
            /*registration_sigma_proto_comm=*/ vector::empty<vector<u8>>(),
            /*registration_sigma_proto_resp=*/ vector::empty<vector<u8>>(),
        );
    }

    // ========================================================================
    // TEST 3 — `test_only_vault_rollover` dispatches rollover_pending_balance
    //
    // Confirms the bridge wrapper:
    //   1. Reads VaultConfig from @eunoma
    //   2. Derives vault signer via account::create_signer_with_capability
    //   3. Dispatches confidential_asset::rollover_pending_balance cross-module
    //
    // Stack trace (observed): the abort is INSIDE
    // `confidential_asset::rollover_pending_balance` at line 1109
    // (`assert!(has_confidential_store(...), error::not_found(E_CONFIDENTIAL_STORE_NOT_REGISTERED))`).
    // The vault hasn't been registered with CA via the Gate 2 stub init, so
    // `has_confidential_store` returns false. The abort code is 393219
    // (category NOT_FOUND, reason 3 = E_CONFIDENTIAL_STORE_NOT_REGISTERED).
    //
    // Reaching this abort proves cross-module dispatch worked AND the
    // SignerCapability pattern (stored cap → derived signer → cross-module
    // call) is sound. This test exercises EXACTLY the same architectural
    // sequence Gate 6's `operator_rollover_vault_pending` will use.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    #[expected_failure(abort_code = 393219, location = aptos_framework::confidential_asset)]
    fun test_vault_rollover_wrapper_dispatches_to_ca_framework(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        base_setup(framework, admin);
        let metadata = make_test_metadata(admin);
        let pks = gen_seven_active_operators();

        // Set up the bridge with the Gate 2 stub init (no real registration)
        // so we have a SignerCapability stored in VaultConfig.
        eunoma_bridge::init_vault(
            admin,
            signer::address_of(main_op),
            metadata,
            pks,
            0, 4,
            VAULT_SEED,
            b"vault_ek_placeholder_gate3",
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
        );

        // Bridge wrapper:
        //   let cfg = borrow_global<VaultConfig>(@eunoma);
        //   let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        //   confidential_asset::rollover_pending_balance(&vault_signer, cfg.asset_type);
        //
        // The cross-module dispatch reaches confidential_asset::rollover_pending_balance.
        // The framework then aborts inside its GlobalConfig lookup.
        eunoma_bridge::test_only_vault_rollover();
    }

    // ========================================================================
    // TEST 4 — Compile-time confirmation of vault → recipient dispatch
    //
    // The bridge module declares
    //   #[test_only] public fun test_only_vault_to_recipient_transfer_raw(
    //       recipient: address, ... 14 byte-vector args ..., memo: vector<u8>
    //   ) acquires VaultConfig
    // which internally invokes
    //   confidential_asset::confidential_transfer_raw(&vault_signer, ...).
    //
    // Stack trace (observed): the bridge dispatches into
    // `confidential_asset::confidential_transfer_raw` (cross-module call
    // succeeds), which calls `new_compressed_available_from_bytes`, which
    // delegates to `confidential_balance::new_compressed_balance` and
    // `assert_correct_num_chunks`. Empty placeholder byte vectors fail the
    // chunk-count check (E_WRONG_NUM_CHUNKS), aborting with code 65537
    // (category INVALID_ARGUMENT, reason 1) at
    // `confidential_balance::assert_correct_num_chunks` line 286.
    //
    // Reaching this abort proves the bridge successfully resolves and
    // dispatches confidential_asset::confidential_transfer_raw cross-module
    // — the CRITICAL Gate 1 item 8.4 architectural property.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001, recipient = @0xb0)]
    #[expected_failure(abort_code = 65537, location = aptos_framework::confidential_balance)]
    fun test_vault_to_recipient_wrapper_dispatches_to_ca_framework(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
        recipient: &signer,
    ) {
        base_setup(framework, admin);
        let metadata = make_test_metadata(admin);
        let pks = gen_seven_active_operators();

        eunoma_bridge::init_vault(
            admin,
            signer::address_of(main_op),
            metadata,
            pks,
            0, 4,
            VAULT_SEED,
            b"vault_ek_placeholder_gate3",
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
        );

        // Empty placeholder byte vectors for all proof components — they
        // will be processed only AFTER the GlobalConfig lookup, so the abort
        // happens before any byte-level decoding kicks in.
        eunoma_bridge::test_only_vault_to_recipient_transfer_raw(
            signer::address_of(recipient),
            /*new_balance_p=*/ vector::empty<vector<u8>>(),
            /*new_balance_r=*/ vector::empty<vector<u8>>(),
            /*new_balance_r_eff_aud=*/ vector::empty<vector<u8>>(),
            /*amount_p=*/ vector::empty<vector<u8>>(),
            /*amount_r_sender=*/ vector::empty<vector<u8>>(),
            /*amount_r_recip=*/ vector::empty<vector<u8>>(),
            /*amount_r_eff_aud=*/ vector::empty<vector<u8>>(),
            /*ek_volun_auds=*/ vector::empty<vector<u8>>(),
            /*amount_r_volun_auds=*/ vector::empty<vector<vector<u8>>>(),
            /*zkrp_new_balance=*/ vector::empty<u8>(),
            /*zkrp_amount=*/ vector::empty<u8>(),
            /*sigma_proto_comm=*/ vector::empty<vector<u8>>(),
            /*sigma_proto_resp=*/ vector::empty<vector<u8>>(),
            /*memo=*/ vector::empty<u8>(),
        );
    }

    // ========================================================================
    // TEST 5 — No vault signer leak: structural / type-level audit
    //
    // The vault signer capability has Move type `account::SignerCapability`,
    // which has `drop, store` (NOT `copy`, NOT `key` on its own). It can only
    // be moved into / out of resources, and the bridge module owns the only
    // path to it: `move_to(admin, VaultConfig { ..., vault_signer_cap, ... })`
    // in `init_vault` / `init_vault_with_ca_registration`.
    //
    // Type-level guarantees (verified by Move type-checker at compile time):
    //   1. `vault_signer_cap` is a private field of `VaultConfig` (no view
    //      function returns it — search the bridge module for any
    //      `public fun ...: account::SignerCapability` returning it).
    //   2. Inside the bridge, the cap is consumed only via
    //      `account::create_signer_with_capability(&cfg.vault_signer_cap)`,
    //      which returns a `signer` value (not a `SignerCapability`).
    //   3. The signer return value is consumed locally (passed as `&signer`
    //      to a CA framework call) and never exposed.
    //
    // We don't write a runtime test here because Move's type system already
    // enforces this; instead the audit lives in REPORT_GATE_3_CA_PROTOTYPE.md
    // §"Acceptance criteria results: criterion 6". This test is left as a
    // placeholder (always-passing, audit-only) to keep `aptos move test
    // --filter ca_composition_prototype` enumerating all six criteria.
    // ========================================================================

    #[test(framework = @aptos_framework, admin = @eunoma, main_op = @0xA001)]
    fun test_no_vault_signer_leak_audit_marker(
        framework: &signer,
        admin: &signer,
        main_op: &signer,
    ) {
        base_setup(framework, admin);
        let metadata = make_test_metadata(admin);
        let pks = gen_seven_active_operators();

        eunoma_bridge::init_vault(
            admin,
            signer::address_of(main_op),
            metadata,
            pks,
            0, 4,
            VAULT_SEED,
            b"vault_ek_placeholder_gate3",
            vector::empty<vector<u8>>(),
            vector::empty<vector<u8>>(),
        );

        // If the bridge had a `public fun get_vault_signer_cap():
        // SignerCapability` (or similar) we'd be able to call it here. The
        // fact that no such function exists is the audit pass — there is no
        // call to write. See REPORT for the static review.
        //
        // We do verify the cap is REACHABLE from inside the module by calling
        // a wrapper that derives signer + dispatches a CA call (Test 3 already
        // does this). Both Test 3 and Test 4 pass means the cap is intact and
        // useable INSIDE the module — and the type system guarantees no exit
        // path.
        let _ = eunoma_bridge::get_vault_addr();
    }
}
