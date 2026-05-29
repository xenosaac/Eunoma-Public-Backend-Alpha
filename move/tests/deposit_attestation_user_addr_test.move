#[test_only]
/// (CP1 sub-5) Guards the deposit-attestation byte format after binding `user_addr` (deposit re-key).
/// Asserts (1) the production hand-rolled `serialize_deposit_attestation_v3_msg` is byte-identical to
/// the canonical `DepositAttestationV3Message` BCS — with `user_addr` appended last — and (2) the exact
/// golden bytes. The golden = the pre-`user_addr` deposit fixture (see
/// `frost_attestation_strict_verify_test::test_message_bcs_byte_parity`) with the 32-byte `user_addr`
/// (0x..eeeeeee4) appended at the end. The off-chain TS `bcsEncodeDepositAttestationV2` (CP2) MUST
/// reproduce these golden bytes exactly (writeAddress for user_addr — raw 32B, no length prefix).
module eunoma::deposit_attestation_user_addr_test {
    use eunoma::eunoma_bridge;

    #[test]
    fun test_deposit_attestation_serializer_matches_struct_with_user_addr() {
        let domain = b"EUNOMA_DEPOSIT_BIND_V3";
        let chain_id = 2u8;
        let bridge = @0x00000000000000000000000000000000000000000000000000000000eeeeeee1;
        let vault = @0x00000000000000000000000000000000000000000000000000000000eeeeeee2;
        let asset_type = @0x00000000000000000000000000000000000000000000000000000000eeeeeee3;
        let operator_set_version = 1u64;
        let dkg_epoch = 9u64;
        let roster_hash = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let frost_group_pubkey = x"0e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa";
        let commitment = x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let amount_tag = x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let ca_payload_hash = x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let deposit_nonce = x"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let expiry_secs = 1800000000u64;
        let circuit_versions_hash = x"1111111111111111111111111111111111111111111111111111111111111111";
        let user_addr = @0x00000000000000000000000000000000000000000000000000000000eeeeeee4;

        let hand = eunoma_bridge::test_only_serialize_deposit_attestation_v3_msg(
            domain, chain_id, bridge, vault, asset_type, operator_set_version, dkg_epoch,
            roster_hash, frost_group_pubkey, commitment, amount_tag, ca_payload_hash,
            deposit_nonce, expiry_secs, circuit_versions_hash, user_addr,
        );
        let strukt = eunoma_bridge::test_only_struct_bcs_deposit_attestation_v3_msg(
            domain, chain_id, bridge, vault, asset_type, operator_set_version, dkg_epoch,
            roster_hash, frost_group_pubkey, commitment, amount_tag, ca_payload_hash,
            deposit_nonce, expiry_secs, circuit_versions_hash, user_addr,
        );
        // (1) Production serializer is byte-identical to the canonical struct BCS (transcription-free).
        assert!(hand == strukt, 1);

        // (2) Golden bytes = the pre-user_addr deposit fixture + the 32-byte user_addr appended.
        let golden = x"1645554e4f4d415f4445504f5349545f42494e445f56330200000000000000000000000000000000000000000000000000000000eeeeeee100000000000000000000000000000000000000000000000000000000eeeeeee200000000000000000000000000000000000000000000000000000000eeeeeee30100000000000000090000000000000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa200e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc20dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd20eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00d2496b0000000020111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000eeeeeee4";
        assert!(hand == golden, 2);
    }
}
