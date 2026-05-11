// Item 8.8 NEEDS_TESTING resolution — compile-time check that the bridge can
// reach `confidential_asset::is_normalized` and `confidential_asset::get_num_transfers_received`
// from a sibling test module without struct-visibility surprises.
//
// We don't run the body (the test would need a real registered ConfidentialStore
// at the queried address); we only need the file to COMPILE. The cross-module
// call inside `get_vault_balance_metadata` (in confidential_bridge.move) is the
// real proof — this file just provides an extra explicit check.
#[test_only]
module eunoma::ca_view_compile_test {
    use aptos_framework::confidential_asset;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::Object;

    // Compile-only function. References the four CA view APIs we need.
    // If any of these change signature or visibility upstream, this fails.
    #[test_only]
    public fun referenced_ca_apis_compile_check(
        addr: address,
        asset_type: Object<fungible_asset::Metadata>,
    ): (bool, u64, bool, bool) {
        (
            confidential_asset::is_normalized(addr, asset_type),
            confidential_asset::get_num_transfers_received(addr, asset_type),
            confidential_asset::has_confidential_store(addr, asset_type),
            confidential_asset::incoming_transfers_paused(addr, asset_type),
        )
    }
}
