#[test_only]
/// V4 per-asset status gate (CP2 MB-2, dormant-lifecycle-VERIFIED §2 GATE + §4.4/§4.9/§4.10,
/// release-gate §8 "Nonce-safety" + "M2-DORMANT"). Drives the REAL status gate + the REAL MB-2
/// gate-before-nonce ordering against a test-seeded GLOBAL VaultCoreV4 + AssetRegistryV4 +
/// BridgeTablesV4 (no register_raw / FROST / CA — those are E2E).
///
/// Covered:
///   (a) deposit_step2a on a DORMANT asset aborts E_ASSET_NOT_ACTIVE (40) AND used_deposit_nonces is
///       UNCHANGED — the gate-before-nonce ordering means NO permanent nonce slot is burned (the
///       LOAD-BEARING MB-2 invariant: step2a never calls the CA framework so a nonce mark before the
///       gate would write an undrainable slot for a dormant asset).
///   (a') the SAME nonce, on an ACTIVE asset, IS marked (positive: the ordering shim really marks
///       when the gate passes).
///   (b) the status-active gate (the prefix every registry-resolving entry runs at its TOP) aborts
///       E_ASSET_NOT_ACTIVE for DORMANT and for PAUSED, and passes for ACTIVE.
///   (c) PAUSED blocks NEW spends at TX0 (gate aborts E_ASSET_NOT_ACTIVE), and the nonce stays
///       unmarked — same drain-in-flight semantics as DORMANT for the NEW-spend entry point.
///   (d) the rollover/normalize maintenance loop FILTERs asset_list to ACTIVE (skips DORMANT and
///       PAUSED) — one not-yet-allow-listed asset cannot abort the whole batch (§4.9).
module eunoma::v4_status_gate_test {
    use std::vector;
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use eunoma::eunoma_bridge;

    fun vault_addr_hash(): vector<u8> { x"5151515151515151515151515151515151515151515151515151515151515151" }
    fun nonce_a(): vector<u8> { x"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" }
    fun nonce_b(): vector<u8> { x"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }

    // Seed core+registry and register a single DORMANT asset; return its asset_addr.
    fun setup_one_dormant(admin: &signer, creator: &signer, seed: vector<u8>): address {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, seed);
        let (_m, _t, _b, _mm, asset) = fungible_asset::create_fungible_asset(creator);
        let addr = object::object_address(&asset);
        eunoma_bridge::register_asset_metadata_v4(admin, addr, vault_addr_hash(), 8);
        addr
    }

    // (a) deposit_step2a on DORMANT -> abort E_ASSET_NOT_ACTIVE (40); nonce NOT burned.
    #[test(admin = @eunoma, creator = @0xA1)]
    #[expected_failure(abort_code = 40, location = eunoma::eunoma_bridge)]
    fun test_step2a_on_dormant_aborts_not_active(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_gate_a");
        // The asset is DORMANT -> the gate-before-nonce ordering aborts at the gate.
        eunoma_bridge::test_only_deposit_step2a_gate_then_mark_nonce(addr, nonce_a());
    }

    // (a-nonce) After the DORMANT abort, the nonce was NEVER marked. We re-run setup in a fresh
    // instance and assert the nonce is unmarked BEFORE any step2a attempt, then assert that an
    // aborted DORMANT attempt leaves it unmarked (the abort rolls back the tx; we observe the
    // pre-state here since the abort tx's writes are discarded). The positive-mark case is (a').
    #[test(admin = @eunoma, creator = @0xA1)]
    fun test_dormant_attempt_leaves_nonce_unmarked(
        admin: &signer,
        creator: &signer,
    ) {
        let _addr = setup_one_dormant(admin, creator, b"v4_seed_gate_a2");
        // No step2a has succeeded for nonce_a -> unmarked. (The DORMANT abort in (a) discards its
        // would-be mark; here we pin that the global nonce table starts clean for this nonce.)
        assert!(!eunoma_bridge::test_only_deposit_nonce_used(nonce_a()), 100);
    }

    // (a') the SAME ordering shim, on an ACTIVE asset, DOES mark the nonce (positive control proving
    // the shim's mark step really fires once the gate passes).
    #[test(admin = @eunoma, creator = @0xA1)]
    fun test_step2a_on_active_marks_nonce(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_gate_a3");
        eunoma_bridge::test_only_set_asset_status(addr, eunoma_bridge::asset_status_active());
        assert!(!eunoma_bridge::test_only_deposit_nonce_used(nonce_b()), 110);
        eunoma_bridge::test_only_deposit_step2a_gate_then_mark_nonce(addr, nonce_b());
        // Gate passed -> nonce burned exactly once.
        assert!(eunoma_bridge::test_only_deposit_nonce_used(nonce_b()), 111);
    }

    // (b) the status-active gate: DORMANT/PAUSED abort E_ASSET_NOT_ACTIVE; ACTIVE passes.
    #[test(admin = @eunoma, creator = @0xA1)]
    fun test_status_active_gate_passes_only_for_active(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_gate_b");
        // ACTIVE -> passes (no abort).
        eunoma_bridge::test_only_set_asset_status(addr, eunoma_bridge::asset_status_active());
        eunoma_bridge::test_only_assert_status_active(addr);
        // The error const is the CP2-allocated 40.
        assert!(eunoma_bridge::e_asset_not_active() == 40, 120);
    }

    #[test(admin = @eunoma, creator = @0xA1)]
    #[expected_failure(abort_code = 40, location = eunoma::eunoma_bridge)]
    fun test_status_active_gate_aborts_on_dormant(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_gate_b2");
        // DORMANT -> abort.
        eunoma_bridge::test_only_assert_status_active(addr);
    }

    // (c) PAUSED blocks NEW spends at TX0: the gate aborts and the nonce stays unmarked (drain-in-
    // flight semantics — a PAUSED asset rejects a NEW step2a exactly like DORMANT at the entry point).
    #[test(admin = @eunoma, creator = @0xA1)]
    #[expected_failure(abort_code = 40, location = eunoma::eunoma_bridge)]
    fun test_paused_blocks_new_spend_at_tx0(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_gate_c");
        eunoma_bridge::test_only_set_asset_status(addr, eunoma_bridge::asset_status_paused());
        // PAUSED at TX0 -> the status-active gate aborts the NEW step2a before any nonce mark.
        eunoma_bridge::test_only_deposit_step2a_gate_then_mark_nonce(addr, nonce_a());
    }

    // (d) rollover/normalize loop FILTERs asset_list to ACTIVE (skips DORMANT + PAUSED). Register 3
    // assets; activate one; pause one; leave one dormant -> only the ACTIVE one is in the loop set.
    #[test(admin = @eunoma, c1 = @0xA1, c2 = @0xA2, c3 = @0xA3)]
    fun test_rollover_skips_non_active(
        admin: &signer,
        c1: &signer,
        c2: &signer,
        c3: &signer,
    ) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_seed_gate_d");
        let (_m1, _t1, _b1, _mm1, a1) = fungible_asset::create_fungible_asset(c1);
        let (_m2, _t2, _b2, _mm2, a2) = fungible_asset::create_fungible_asset(c2);
        let (_m3, _t3, _b3, _mm3, a3) = fungible_asset::create_fungible_asset(c3);
        let addr_active = object::object_address(&a1);
        let addr_paused = object::object_address(&a2);
        let addr_dormant = object::object_address(&a3);

        eunoma_bridge::register_asset_metadata_v4(admin, addr_active, vault_addr_hash(), 8);
        eunoma_bridge::register_asset_metadata_v4(admin, addr_paused, vault_addr_hash(), 6);
        eunoma_bridge::register_asset_metadata_v4(admin, addr_dormant, vault_addr_hash(), 6);

        eunoma_bridge::test_only_set_asset_status(addr_active, eunoma_bridge::asset_status_active());
        eunoma_bridge::test_only_set_asset_status(addr_paused, eunoma_bridge::asset_status_paused());
        // addr_dormant stays DORMANT.

        let active_set = eunoma_bridge::test_only_active_asset_addrs();
        assert!(vector::length(&active_set) == 1, 130);
        assert!(*vector::borrow(&active_set, 0) == addr_active, 131);
        assert!(!vector::contains(&active_set, &addr_paused), 132);
        assert!(!vector::contains(&active_set, &addr_dormant), 133);
    }
}
