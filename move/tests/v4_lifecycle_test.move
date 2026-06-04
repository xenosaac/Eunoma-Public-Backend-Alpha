#[test_only]
/// V4 multi-asset onboarding lifecycle (CP2 MB-1, dormant-lifecycle-VERIFIED §2 + §4, cross-asset
/// doc FIX-3/FIX-5). Drives the REAL register_asset_metadata_v4 entry + the REAL derive_asset_id /
/// status / append-only / uniqueness logic against a test-seeded GLOBAL VaultCoreV4 + AssetRegistryV4
/// (planted via test_only_seed_v4_core_and_registry — identical row shape to init_v4, but WITHOUT
/// the confidential_asset::register_raw + 5-of-7 FROST machinery, which is E2E on testnet).
///
/// Covered (design is FINAL — these pin behavior, they do not redesign):
///   (a) register_asset_metadata_v4 inserts status == DORMANT and computes asset_id_fr ON-CHAIN
///       via derive_asset_id(asset_type) — NOT a caller arg (register has no asset_id_fr parameter;
///       the stored row byte-equals test_only_derive_asset_id(asset_type)).
///   (b) two distinct asset_types get two distinct on-chain-derived asset_id_fr (Poseidon is
///       per-address) — the uniqueness premise for the append-only registry.
///   (c) register is APPEND-ONLY: re-registering the same asset_addr aborts E_ASSET_ID_MISMATCH (42).
///   (d) activate requires DORMANT: the REAL activate idempotency gate aborts E_ASSET_ALREADY_ACTIVE
///       (41) once a row is ACTIVE (production ACTIVE is reachable ONLY through the register_raw-
///       bearing activate_asset_ca_v4; here the ACTIVE flip is the test_only_set_asset_status shim).
///   (e) a non-admin caller cannot register — E_NOT_ADMIN (1) (assert_admin_v4 over VaultCoreV4.admin).
///   (f) init_v4 asserts !exists<DepositBindingTestOverride> (FIX-5): with the override installed,
///       init_v4 aborts E_ASSET_ID_MISMATCH (42) at the FIX-5 guard, BEFORE any resource-account /
///       register_raw work (so derive_asset_id stays honest on the live module).
module eunoma::v4_lifecycle_test {
    use std::vector;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use eunoma::eunoma_bridge;

    // 32-byte vault_addr_hash_fr placeholder (register asserts assert_hash on it).
    fun vault_addr_hash(): vector<u8> { x"5151515151515151515151515151515151515151515151515151515151515151" }

    // (a) register inserts DORMANT + computes asset_id_fr on-chain (NOT a caller arg).
    #[test(admin = @eunoma, apt_creator = @0xA1)]
    fun test_register_metadata_dormant_derives_asset_id_on_chain(
        admin: &signer,
        apt_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_vault_seed_lifecycle_a");
        let (_m, _t, _b, _mm, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let apt_addr = object::object_address(&apt);

        // register_asset_metadata_v4 has NO asset_id_fr parameter — it derives on-chain.
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);

        // Row exists, status == DORMANT (not yet CA-activated).
        assert!(eunoma_bridge::test_only_registry_contains(apt_addr), 100);
        assert!(eunoma_bridge::test_only_asset_status(apt_addr) == eunoma_bridge::asset_status_dormant(), 101);
        // Stored asset_id_fr byte-equals the on-chain derive_asset_id(asset_type) — proof it was
        // computed, never caller-supplied.
        let derived = eunoma_bridge::test_only_derive_asset_id(apt);
        assert!(eunoma_bridge::test_only_asset_id_fr(apt_addr) == derived, 102);
        assert!(vector::length(&derived) == 32, 103);
    }

    // (b) two distinct asset_types derive two distinct asset_id_fr (per-address Poseidon).
    #[test(admin = @eunoma, apt_creator = @0xA1, usdc_creator = @0xC1)]
    fun test_two_assets_distinct_derived_asset_ids(
        admin: &signer,
        apt_creator: &signer,
        usdc_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_vault_seed_lifecycle_b");
        let (_m1, _t1, _b1, _mm1, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let (_m2, _t2, _b2, _mm2, usdc) = fungible_asset::create_fungible_asset(usdc_creator);
        let apt_addr = object::object_address(&apt);
        let usdc_addr = object::object_address(&usdc);

        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        eunoma_bridge::register_asset_metadata_v4(admin, usdc_addr, vault_addr_hash(), 6);

        let id_apt = eunoma_bridge::test_only_asset_id_fr(apt_addr);
        let id_usdc = eunoma_bridge::test_only_asset_id_fr(usdc_addr);
        // Distinct asset object-addresses -> distinct Poseidon images.
        assert!(id_apt != id_usdc, 110);
        // Both DORMANT at register (only APT goes ACTIVE at init in production; both dormant here).
        assert!(eunoma_bridge::test_only_asset_status(usdc_addr) == eunoma_bridge::asset_status_dormant(), 111);
    }

    // (c) register is APPEND-ONLY — re-registering the same asset_addr aborts E_ASSET_ID_MISMATCH.
    #[test(admin = @eunoma, apt_creator = @0xA1)]
    #[expected_failure(abort_code = 42, location = eunoma::eunoma_bridge)]
    fun test_register_same_asset_twice_aborts(
        admin: &signer,
        apt_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_vault_seed_lifecycle_c");
        let (_m, _t, _b, _mm, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let apt_addr = object::object_address(&apt);
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        // APPEND-ONLY violation: second register of the same asset_addr.
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
    }

    // (d) activate requires DORMANT — the REAL idempotency gate aborts E_ASSET_ALREADY_ACTIVE once
    // ACTIVE. (Production ACTIVE is set ONLY by the register_raw-bearing activate; the ACTIVE flip
    // here is the test shim, then we drive the REAL DORMANT gate.)
    #[test(admin = @eunoma, apt_creator = @0xA1)]
    #[expected_failure(abort_code = 41, location = eunoma::eunoma_bridge)]
    fun test_activate_requires_dormant_aborts_when_active(
        admin: &signer,
        apt_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_vault_seed_lifecycle_d");
        let (_m, _t, _b, _mm, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let apt_addr = object::object_address(&apt);
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        // While DORMANT the activate gate passes (no abort).
        eunoma_bridge::test_only_assert_activate_requires_dormant(apt_addr);
        // Flip ACTIVE (simulating a completed activate_asset_ca_v4), then a second activate must brick.
        eunoma_bridge::test_only_set_asset_status(apt_addr, eunoma_bridge::asset_status_active());
        eunoma_bridge::test_only_assert_activate_requires_dormant(apt_addr);
    }

    // (e) a non-admin signer cannot register — assert_admin_v4 aborts E_NOT_ADMIN (1).
    #[test(admin = @eunoma, attacker = @0xBAD, apt_creator = @0xA1)]
    #[expected_failure(abort_code = 1, location = eunoma::eunoma_bridge)]
    fun test_non_admin_register_aborts(
        admin: &signer,
        attacker: &signer,
        apt_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_vault_seed_lifecycle_e");
        let (_m, _t, _b, _mm, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let apt_addr = object::object_address(&apt);
        // attacker is not VaultCoreV4.admin.
        eunoma_bridge::register_asset_metadata_v4(attacker, apt_addr, vault_addr_hash(), 8);
    }

    // (f) init_v4 asserts !exists<DepositBindingTestOverride> (FIX-5). With the override installed,
    // init_v4 aborts E_ASSET_ID_MISMATCH (42) at the FIX-5 guard BEFORE any resource-account /
    // register_raw work — so derive_asset_id can never be collapsed to a constant on a live init.
    #[test(admin = @eunoma, apt_creator = @0xA1)]
    #[expected_failure(abort_code = 42, location = eunoma::eunoma_bridge)]
    fun test_init_v4_aborts_when_test_override_present(
        admin: &signer,
        apt_creator: &signer,
    ) {
        // Install the deposit-binding test override (collapses derive_asset_id to a constant).
        eunoma_bridge::install_deposit_binding_test_override_v2(
            admin,
            x"3333333333333333333333333333333333333333333333333333333333333333",
            x"4444444444444444444444444444444444444444444444444444444444444444",
        );
        let (_m, _t, _b, _mm, apt) = fungible_asset::create_fungible_asset(apt_creator);
        // init_v4 must brick at the FIX-5 guard (line :1000) before touching the resource account.
        // The remaining args are placeholders — the FIX-5 abort precedes their use.
        eunoma_bridge::init_v4(
            admin,
            b"v4_vault_seed_lifecycle_f",
            apt,
            1,                                  // operator_set_version
            1,                                  // dkg_epoch
            x"7777777777777777777777777777777777777777777777777777777777777777", // roster_hash (32B)
            x"8888888888888888888888888888888888888888888888888888888888888888", // frost_group_pubkey (32B)
            x"9999999999999999999999999999999999999999999999999999999999999999", // vault_ek (32B)
            vector::empty<vector<u8>>(),        // registration_sigma_comm
            vector::empty<vector<u8>>(),        // registration_sigma_resp
            b"dep_v1",                          // deposit_circuit_version
            b"wd_v1",                           // withdraw_circuit_version
            b"ca_v1",                           // ca_payload_circuit_version
            empty_fallback_pubkeys(),           // fallback_pubkeys (7 × 32B)
            8,                                  // apt_decimals
        );
    }

    // 7 × 32-byte fallback pubkeys (assert_valid_fallback_pubkeys requires MAX_DEOPERATORS = 7).
    // Only reached if FIX-5 did NOT fire — it does, so these are never validated; supplied for
    // call-shape completeness.
    fun empty_fallback_pubkeys(): vector<vector<u8>> {
        let v = vector::empty<vector<u8>>();
        let i = 0;
        while (i < 7) {
            vector::push_back(&mut v, x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            i = i + 1;
        };
        v
    }
}
