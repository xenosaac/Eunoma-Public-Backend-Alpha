#[test_only]
/// V4 MA-1 cross-asset routing soundness (CP2, cross-asset-atomicity doc §1.3/§1.6 gate (3) +
/// HOLE-1/FIX-1, dormant-lifecycle-VERIFIED §8 release-gate "M2"). The single load-bearing line that
/// makes the attacker-chosen `asset_addr` non-redirectable is, at every spend resolution site
/// (TX0/TX2/TX3/TX4):
///
///     assert!(derive_asset_id(st.asset_type) == proven_asset_id, E_ASSET_ID_MISMATCH)
///
/// where st.asset_type is read from the REAL registry row keyed by the attacker-chosen asset_addr,
/// and proven_asset_id is the value fed to the Groth16 withdraw publics[2]. This test drives that
/// EXACT assert via test_only_assert_ma1_route.
///
/// Covered (release gate M2):
///   (M2) a cUSDC inclusion proof (proven_asset_id == derive_asset_id(cUSDC)) ROUTED THROUGH the APT
///        asset_addr -> derive_asset_id(APT) != cUSDC proven_asset_id -> abort E_ASSET_ID_MISMATCH (42).
///   (positive) the honest route (cUSDC proof through the cUSDC asset_addr) passes the assert.
///   (sanity) derive_asset_id is per-address: the two registered assets have distinct images, so the
///            cross-route is detectable; and routing an APT proof through cUSDC also bricks (symmetry).
module eunoma::v4_ma1_soundness_test {
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use eunoma::eunoma_bridge;

    fun vault_addr_hash(): vector<u8> { x"5151515151515151515151515151515151515151515151515151515151515151" }

    // (M2) cUSDC inclusion proof + APT route -> abort E_ASSET_ID_MISMATCH (42).
    #[test(admin = @eunoma, apt_creator = @0xA1, usdc_creator = @0xC1)]
    #[expected_failure(abort_code = 42, location = eunoma::eunoma_bridge)]
    fun test_cusdc_proof_apt_route_aborts_id_mismatch(
        admin: &signer,
        apt_creator: &signer,
        usdc_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_seed_ma1_a");
        let (_m1, _t1, _b1, _mm1, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let (_m2, _t2, _b2, _mm2, usdc) = fungible_asset::create_fungible_asset(usdc_creator);
        let apt_addr = object::object_address(&apt);
        let usdc_addr = object::object_address(&usdc);
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        eunoma_bridge::register_asset_metadata_v4(admin, usdc_addr, vault_addr_hash(), 6);

        // The proof binds the cUSDC asset_id (publics[2] = derive_asset_id(cUSDC)).
        let cusdc_proven_asset_id = eunoma_bridge::test_only_asset_id_fr(usdc_addr);
        // Attacker routes that cUSDC proof through the APT asset_addr: the MA-1 Poseidon-link assert
        // recomputes derive_asset_id(st.asset_type)=derive_asset_id(APT) and compares to the cUSDC
        // proven_asset_id -> mismatch -> abort.
        eunoma_bridge::test_only_assert_ma1_route(apt_addr, cusdc_proven_asset_id);
    }

    // (positive) the honest cUSDC proof through the cUSDC route passes the MA-1 assert (no abort).
    #[test(admin = @eunoma, apt_creator = @0xA1, usdc_creator = @0xC1)]
    fun test_honest_cusdc_route_passes(
        admin: &signer,
        apt_creator: &signer,
        usdc_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_seed_ma1_b");
        let (_m1, _t1, _b1, _mm1, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let (_m2, _t2, _b2, _mm2, usdc) = fungible_asset::create_fungible_asset(usdc_creator);
        let apt_addr = object::object_address(&apt);
        let usdc_addr = object::object_address(&usdc);
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        eunoma_bridge::register_asset_metadata_v4(admin, usdc_addr, vault_addr_hash(), 6);

        let cusdc_proven_asset_id = eunoma_bridge::test_only_asset_id_fr(usdc_addr);
        // Honest route: proof's asset_id matches derive_asset_id(cUSDC) -> assert holds.
        eunoma_bridge::test_only_assert_ma1_route(usdc_addr, cusdc_proven_asset_id);
        // The error const is the CP2-allocated 42.
        assert!(eunoma_bridge::e_asset_id_mismatch() == 42, 200);
    }

    // (symmetry) an APT proof routed through the cUSDC asset_addr also bricks E_ASSET_ID_MISMATCH.
    #[test(admin = @eunoma, apt_creator = @0xA1, usdc_creator = @0xC1)]
    #[expected_failure(abort_code = 42, location = eunoma::eunoma_bridge)]
    fun test_apt_proof_cusdc_route_aborts(
        admin: &signer,
        apt_creator: &signer,
        usdc_creator: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_seed_ma1_c");
        let (_m1, _t1, _b1, _mm1, apt) = fungible_asset::create_fungible_asset(apt_creator);
        let (_m2, _t2, _b2, _mm2, usdc) = fungible_asset::create_fungible_asset(usdc_creator);
        let apt_addr = object::object_address(&apt);
        let usdc_addr = object::object_address(&usdc);
        eunoma_bridge::register_asset_metadata_v4(admin, apt_addr, vault_addr_hash(), 8);
        eunoma_bridge::register_asset_metadata_v4(admin, usdc_addr, vault_addr_hash(), 6);

        let apt_proven_asset_id = eunoma_bridge::test_only_asset_id_fr(apt_addr);
        // APT proof through the cUSDC route -> derive_asset_id(cUSDC) != APT proven_asset_id -> abort.
        eunoma_bridge::test_only_assert_ma1_route(usdc_addr, apt_proven_asset_id);
    }
}
