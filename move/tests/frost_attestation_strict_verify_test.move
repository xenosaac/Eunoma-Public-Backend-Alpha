#[test_only]
module eunoma::frost_attestation_strict_verify_test {
    use std::bcs;
    use std::vector;
    use aptos_std::ed25519;

    struct DepositAttestationV2Message has drop, store {
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    fun build_message(): DepositAttestationV2Message {
        DepositAttestationV2Message {
            domain: b"EUNOMA_DEPOSIT_BIND_V2",
            chain_id: 2,
            bridge: @0x00000000000000000000000000000000000000000000000000000000eeeeeee1,
            vault: @0x00000000000000000000000000000000000000000000000000000000eeeeeee2,
            asset_type: @0x00000000000000000000000000000000000000000000000000000000eeeeeee3,
            operator_set_version: 1,
            dkg_epoch: 9,
            roster_hash: x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            frost_group_pubkey: x"0e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa",
            commitment: x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            amount_tag: x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ca_payload_hash: x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            deposit_nonce: x"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            expiry_secs: 1800000000,
            circuit_versions_hash: x"1111111111111111111111111111111111111111111111111111111111111111",
        }
    }

    #[test]
    fun test_message_bcs_byte_parity() {
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        assert!(bytes == x"1645554e4f4d415f4445504f5349545f42494e445f56320200000000000000000000000000000000000000000000000000000000eeeeeee100000000000000000000000000000000000000000000000000000000eeeeeee200000000000000000000000000000000000000000000000000000000eeeeeee30100000000000000090000000000000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa200e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc20dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd20eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00d2496b00000000201111111111111111111111111111111111111111111111111111111111111111", 1);
    }

    #[test]
    fun test_frost_group_signature_passes_strict_verify() {
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        let sig = ed25519::new_signature_from_bytes(x"61ece7f596431a19b0a65cca8a03976ca1b81d6cf809a0a0441c3efecd98fa66484dcc282dba903e59ec8b7c52dbe8f97fa596dc943bb3b2bf56520228827401");
        let pubkey = ed25519::new_unvalidated_public_key_from_bytes(x"0e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa");
        assert!(ed25519::signature_verify_strict(&sig, &pubkey, bytes), 2);
    }

    #[test]
    fun test_flipped_signature_byte_fails() {
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        let raw = x"61ece7f596431a19b0a65cca8a03976ca1b81d6cf809a0a0441c3efecd98fa66484dcc282dba903e59ec8b7c52dbe8f97fa596dc943bb3b2bf56520228827401";
        let first = *vector::borrow(&raw, 0);
        let mutated_first = first ^ 0xff;
        let mutated = vector::empty<u8>();
        vector::push_back(&mut mutated, mutated_first);
        let i = 1;
        let len = vector::length(&raw);
        while (i < len) {
            vector::push_back(&mut mutated, *vector::borrow(&raw, i));
            i = i + 1;
        };
        let sig = ed25519::new_signature_from_bytes(mutated);
        let pubkey = ed25519::new_unvalidated_public_key_from_bytes(x"0e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa");
        assert!(!ed25519::signature_verify_strict(&sig, &pubkey, bytes), 3);
    }
}
