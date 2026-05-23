module eunoma::eunoma_bridge {
    use std::bcs;
    use std::option;
    use std::signer;
    use std::vector;

    use aptos_std::aptos_hash;
    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;
    use aptos_std::table::{Self, Table};

    use std::bn254_algebra::{
        Fq12,
        FormatFq12LscLsb,
        FormatFrLsb,
        FormatG1Uncompr,
        FormatG2Uncompr,
        Fr,
        G1,
        G2,
        Gt,
    };

    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::confidential_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::timestamp;

    use eunoma::groth16_bn254;
    use eunoma_pool::poseidon_bn254;

    const MAX_DEOPERATORS: u64 = 7;
    const THRESHOLD_V2: u64 = 5;
    const ED25519_PUBLIC_KEY_BYTES: u64 = 32;
    const ED25519_SIGNATURE_BYTES: u64 = 64;
    const HASH_BYTES: u64 = 32;
    const FR_BYTES: u64 = 32;

    const G1_UNCOMPRESSED_BYTES: u64 = 64;
    const G2_UNCOMPRESSED_BYTES: u64 = 128;
    const FQ12_BYTES: u64 = 384;
    const PROOF_BYTES: u64 = 256;
    // Stage 3 A6: bumped to add amount_p_digest as additional public input.
    // Deposit publics: commitment, amount_tag, asset_id, vault_addr_hash, amount_p_digest (5) + 1 const term = 6.
    // Withdraw publics: root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
    //   request_hash, vault_sequence, amount_p_digest (9) + 1 const term = 10.
    const DEPOSIT_VK_IC_LENGTH: u64 = 6;
    const WITHDRAW_VK_IC_LENGTH: u64 = 10;

    const DOMAIN_DEPOSIT_V2: vector<u8> = b"EUNOMA_DEPOSIT_BIND_V2";
    const DOMAIN_WITHDRAW_V2: vector<u8> = b"EUNOMA_WITHDRAW_ATTESTATION_V2";
    const POSEIDON_DOMAIN_ASSET_ID: vector<u8> = b"EUNOMA_ASSET_ID_V2";
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH: vector<u8> = b"EUNOMA_VAULT_ADDR_V2";
    const POSEIDON_DOMAIN_RECIPIENT_HASH: vector<u8> = b"EUNOMA_RECIPIENT_V2";

    const E_NOT_ADMIN: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_NOT_INITIALIZED: u64 = 3;
    const E_PAUSED: u64 = 4;
    const E_NOT_PAUSED: u64 = 5;
    const E_BAD_THRESHOLD: u64 = 6;
    const E_BAD_ROSTER_HASH: u64 = 7;
    const E_BAD_GROUP_PUBKEY: u64 = 8;
    const E_BAD_VAULT_EK: u64 = 9;
    const E_BAD_FALLBACK_PUBKEYS: u64 = 10;
    const E_EXPIRED: u64 = 11;
    const E_BAD_HASH_LENGTH: u64 = 12;
    const E_PAYLOAD_HASH_MISMATCH: u64 = 13;
    const E_INVALID_DEPOSIT_BINDING_PROOF: u64 = 14;
    const E_INVALID_WITHDRAW_PROOF: u64 = 15;
    const E_INVALID_DEOP_SIGNATURE: u64 = 16;
    const E_TOO_FEW_DEOP_SIGNATURES: u64 = 17;
    const E_DEPOSIT_NONCE_REPLAY: u64 = 18;
    const E_NULLIFIER_ALREADY_SPENT: u64 = 19;
    const E_VAULT_SEQUENCE_MISMATCH: u64 = 20;
    const E_INVALID_ROOT: u64 = 21;
    const E_RECIPIENT_HASH_MISMATCH: u64 = 22;
    /// Stage 3 A6: malformed amount_p (must be exactly 4 entries of 32 bytes each).
    /// See compute_amount_p_digest_v2 + circuits/{deposit_binding,withdrawal_proof}.circom Compose8.
    const E_INVALID_AMOUNT_P_SHAPE: u64 = 23;
    const E_PENDING_DEPOSIT_BINDING: u64 = 24;
    const E_PENDING_WITHDRAW_PROOF: u64 = 25;

    struct BridgeVault has key {
        admin: address,
        vault_addr: address,
        vault_signer_cap: account::SignerCapability,
        asset_type: Object<fungible_asset::Metadata>,
        vault_sequence: u64,
        // Goal.md M3: monotonic deposit counter. Incremented exactly once per successful
        // deposit_with_commitment_v2 (AFTER confidential_transfer_raw succeeds). Workers
        // observe DepositConfirmedV2 events keyed by this counter to advance their own
        // local state-share cursors deterministically.
        deposit_count: u64,
        paused: bool,
        used_deposit_nonces: Table<vector<u8>, bool>,
        used_nullifiers: Table<vector<u8>, bool>,
        known_roots: Table<vector<u8>, bool>,
    }

    struct BridgeVaultTablesV2 has key {
        used_deposit_nonces: Table<vector<u8>, bool>,
        used_nullifiers: Table<vector<u8>, bool>,
        known_roots: Table<vector<u8>, bool>,
    }

    struct PendingDepositBindingsV2 has key {
        by_commitment: Table<vector<u8>, PendingDepositBindingV2>,
    }

    struct PendingDepositBindingV2 has store, drop {
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
    }

    struct PendingWithdrawProofsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV2>,
    }

    struct PendingWithdrawProofV2 has store, drop {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    }

    struct DeoperatorConfigV2 has key {
        operator_set_version: u64,
        dkg_epoch: u64,
        threshold: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    }

    struct DepositBindingVK has key {
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic: vector<vector<u8>>,
    }

    struct PreparedDepositBindingVK has key {
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,
        pvk_gamma_g2_neg: vector<u8>,
        pvk_delta_g2_neg: vector<u8>,
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    struct WithdrawProofVK has key {
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic: vector<vector<u8>>,
    }

    struct PreparedWithdrawProofVK has key {
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,
        pvk_gamma_g2_neg: vector<u8>,
        pvk_delta_g2_neg: vector<u8>,
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    struct DepositBindingTestOverride has key {
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    }

    struct VaultPublicInputsV2 has key {
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    }

    struct CircuitVersionsForHash has drop, store {
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
    }

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

    struct WithdrawAttestationV2Message has drop, store {
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    struct CAPayloadForHashV2 has drop, copy {
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    }

    #[event]
    struct VaultInitializedV2 has drop, store {
        vault_addr: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        threshold: u64,
        roster_hash: vector<u8>,
    }

    #[event]
    struct DepositEventV2 has drop, store {
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    // Goal.md M3: post-success deposit event keyed by the monotonic deposit_count. The
    // worker-side observer reads this event off the chain ledger and advances its local
    // state-share cursor IFF deposit_count == observer's local_cursor + 1. Replay,
    // wrong-sequence, wrong-asset, and stale events fail closed at the observer.
    #[event]
    struct DepositConfirmedV2 has drop, store {
        vault_addr: address,
        asset_type: address,
        deposit_count: u64,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    #[event]
    struct WithdrawEventV2 has drop, store {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
    }

    #[event]
    struct BridgePauseChangedV2 has drop, store {
        paused: bool,
    }

    #[event]
    struct RootRecordedV2 has drop, store {
        root: vector<u8>,
    }

    public entry fun init_vault_with_ca_registration_v2(
        admin: &signer,
        vault_seed: vector<u8>,
        asset_type: Object<fungible_asset::Metadata>,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_comm: vector<vector<u8>>,
        registration_sigma_resp: vector<vector<u8>>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<BridgeVault>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(!exists<DeoperatorConfigV2>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
        let vault_addr = signer::address_of(&vault_signer);
        confidential_asset::register_raw(
            &vault_signer,
            *&asset_type,
            *&vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        move_to(admin, BridgeVault {
            admin: signer::address_of(admin),
            vault_addr,
            vault_signer_cap,
            asset_type,
            vault_sequence: 0,
            deposit_count: 0,
            paused: false,
            used_deposit_nonces: table::new<vector<u8>, bool>(),
            used_nullifiers: table::new<vector<u8>, bool>(),
            known_roots: table::new<vector<u8>, bool>(),
        });
        move_to(admin, new_vault_tables_v2());

        move_to(admin, DeoperatorConfigV2 {
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
            frost_group_pubkey,
            vault_ek,
            deposit_circuit_version,
            withdraw_circuit_version,
            ca_payload_circuit_version,
            fallback_pubkeys,
        });

        event::emit(VaultInitializedV2 {
            vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
        });
    }

    public entry fun rollover_vault_with_ca_registration_v2(
        admin: &signer,
        vault_seed: vector<u8>,
        asset_type: Object<fungible_asset::Metadata>,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_comm: vector<vector<u8>>,
        registration_sigma_resp: vector<vector<u8>>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) acquires BridgeVault, DeoperatorConfigV2, VaultPublicInputsV2, DepositBindingTestOverride {
        assert_initialized();
        assert_admin(admin);
        assert!(!exists<BridgeVaultTablesV2>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
        let vault_addr = signer::address_of(&vault_signer);
        confidential_asset::register_raw(
            &vault_signer,
            *&asset_type,
            *&vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        let asset_id_fr = derive_asset_id(asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault_addr);
        upsert_vault_public_inputs_v2(admin, asset_id_fr, vault_addr_hash_fr);
        move_to(admin, new_vault_tables_v2());

        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        vault.admin = signer::address_of(admin);
        vault.vault_addr = vault_addr;
        vault.vault_signer_cap = vault_signer_cap;
        vault.asset_type = asset_type;
        vault.vault_sequence = 0;
        vault.deposit_count = 0;
        vault.paused = false;

        let cfg = borrow_global_mut<DeoperatorConfigV2>(@eunoma);
        cfg.operator_set_version = operator_set_version;
        cfg.dkg_epoch = dkg_epoch;
        cfg.threshold = THRESHOLD_V2;
        cfg.roster_hash = roster_hash;
        cfg.frost_group_pubkey = frost_group_pubkey;
        cfg.vault_ek = vault_ek;
        cfg.deposit_circuit_version = deposit_circuit_version;
        cfg.withdraw_circuit_version = withdraw_circuit_version;
        cfg.ca_payload_circuit_version = ca_payload_circuit_version;
        cfg.fallback_pubkeys = fallback_pubkeys;

        event::emit(VaultInitializedV2 {
            vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
        });
    }

    public entry fun rotate_deoperator_config_v2(
        admin: &signer,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) acquires BridgeVault, DeoperatorConfigV2 {
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let cfg = borrow_global_mut<DeoperatorConfigV2>(@eunoma);
        cfg.operator_set_version = operator_set_version;
        cfg.dkg_epoch = dkg_epoch;
        cfg.threshold = THRESHOLD_V2;
        cfg.roster_hash = roster_hash;
        cfg.frost_group_pubkey = frost_group_pubkey;
        cfg.vault_ek = vault_ek;
        cfg.deposit_circuit_version = deposit_circuit_version;
        cfg.withdraw_circuit_version = withdraw_circuit_version;
        cfg.ca_payload_circuit_version = ca_payload_circuit_version;
        cfg.fallback_pubkeys = fallback_pubkeys;
    }

    public entry fun publish_vault_public_inputs_v2(
        admin: &signer,
    ) acquires BridgeVault, DepositBindingTestOverride {
        assert_admin(admin);
        assert!(!exists<VaultPublicInputsV2>(@eunoma), E_ALREADY_INITIALIZED);
        let vault = borrow_global<BridgeVault>(@eunoma);
        let asset_id_fr = derive_asset_id(vault.asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault.vault_addr);
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        move_to(admin, VaultPublicInputsV2 { asset_id_fr, vault_addr_hash_fr });
    }

    public entry fun refresh_vault_public_inputs_v2(
        admin: &signer,
    ) acquires BridgeVault, VaultPublicInputsV2, DepositBindingTestOverride {
        assert_admin(admin);
        let vault = borrow_global<BridgeVault>(@eunoma);
        let asset_id_fr = derive_asset_id(vault.asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault.vault_addr);
        upsert_vault_public_inputs_v2(admin, asset_id_fr, vault_addr_hash_fr);
    }

    public entry fun pause_v2(admin: &signer) acquires BridgeVault {
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert!(!vault.paused, E_PAUSED);
        vault.paused = true;
        event::emit(BridgePauseChangedV2 { paused: true });
    }

    public entry fun unpause_v2(admin: &signer) acquires BridgeVault {
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert!(vault.paused, E_NOT_PAUSED);
        vault.paused = false;
        event::emit(BridgePauseChangedV2 { paused: false });
    }

    public entry fun record_known_root_v2(
        admin: &signer,
        root: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2 {
        assert_admin(admin);
        assert_hash(&root);
        record_known_root_internal(*&root);
        event::emit(RootRecordedV2 { root });
    }

    public entry fun deposit_with_commitment_v2(
        sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        deposit_binding_proof: vector<u8>,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingDepositBindingsV2, DeoperatorConfigV2, VaultPublicInputsV2, PreparedDepositBindingVK {
        assert_initialized();
        assert_not_expired(expiry_secs);
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        assert_hash(&ca_payload_hash);

        assert!(!deposit_nonce_used(&deposit_nonce), E_DEPOSIT_NONCE_REPLAY);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let vault_addr = vault.vault_addr;

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            asset_type,
            vault_addr,
            *&new_balance_p,
            *&new_balance_r,
            *&new_balance_r_eff_aud,
            *&amount_p,
            *&amount_r_sender,
            *&amount_r_recip,
            *&amount_r_eff_aud,
            *&ek_volun_auds,
            *&amount_r_volun_auds,
            *&zkrp_new_balance,
            *&zkrp_amount,
            *&sigma_proto_comm,
            *&sigma_proto_resp,
            *&memo,
        );
        let ca_payload_hash_fr = ca_payload_hash_to_fr_safe(ca_payload_hash_raw);
        assert!(ca_payload_hash_fr == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let msg = DepositAttestationV2Message {
            domain: DOMAIN_DEPOSIT_V2,
            chain_id: chain_id::get(),
            bridge: @eunoma,
            vault: vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version: cfg.operator_set_version,
            dkg_epoch: cfg.dkg_epoch,
            roster_hash: *&cfg.roster_hash,
            frost_group_pubkey: *&cfg.frost_group_pubkey,
            commitment: *&commitment,
            amount_tag: *&amount_tag,
            ca_payload_hash: *&ca_payload_hash,
            deposit_nonce: *&deposit_nonce,
            expiry_secs,
            circuit_versions_hash: circuit_versions_hash(cfg),
        };
        assert_deop_attestation_v2(
            bcs::to_bytes(&msg),
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // Stage 3 A6: compute amount_p_digest from the 14-CA-args amount_p (4 × 32B Ristretto
        // compressed Pedersen commits). This binds deposit commitment leaf to the CA framework's
        // amount_p (which framework σ-proto then binds to actual transfer amount via balance
        // equation old = new + transfer). At withdraw, the same digest is recomputed and
        // byte-compared against the Groth16 public input — Pedersen DL binding forces
        // withdraw amount == deposit amount (vote conservation). See plan A6 design.
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        consume_or_verify_deposit_binding(
            *&commitment,
            *&amount_tag,
            amount_p_digest,
            deposit_binding_proof,
        );

        mark_deposit_nonce_used(*&deposit_nonce);

        confidential_asset::confidential_transfer_raw(
            sender,
            asset_type,
            vault_addr,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );

        // Goal.md M3: increment deposit_count AFTER confidential_transfer_raw succeeds.
        // If the CA payload had failed verification or aborted, deposit_count must NOT
        // advance — the observer's strict-monotonic-ordering check would otherwise see a
        // counter gap that no event could explain.
        let vault_for_count = borrow_global_mut<BridgeVault>(@eunoma);
        let new_deposit_count = vault_for_count.deposit_count + 1;
        vault_for_count.deposit_count = new_deposit_count;

        // Legacy event kept for backwards compat with consumers that don't yet read
        // deposit_count. M3 observers MUST read DepositConfirmedV2 (below) instead.
        event::emit(DepositEventV2 {
            commitment: *&commitment,
            amount_tag: *&amount_tag,
            ca_payload_hash: *&ca_payload_hash,
            deposit_nonce: *&deposit_nonce,
        });

        // Goal.md M3: post-success deposit event keyed by deposit_count. Observers use this
        // to advance their local state-share cursor; strictly ordered by deposit_count.
        event::emit(DepositConfirmedV2 {
            vault_addr,
            asset_type: object::object_address(&asset_type),
            deposit_count: new_deposit_count,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
        });
    }

    public entry fun withdraw_to_recipient_v2(
        _relayer: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        withdraw_proof: vector<u8>,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawProofsV2, DeoperatorConfigV2, VaultPublicInputsV2, PreparedWithdrawProofVK {
        assert_initialized();
        assert_not_expired(expiry_secs);
        assert_hash(&root);
        assert_hash(&nullifier_hash);
        assert_hash(&recipient_hash);
        assert_hash(&amount_tag);
        assert_hash(&ca_payload_hash);
        assert_hash(&request_hash);

        assert!(known_root_recorded(&root), E_INVALID_ROOT);
        assert!(!nullifier_used(&nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let asset_type = vault.asset_type;
        let vault_addr = vault.vault_addr;
        let expected_recipient_hash = derive_recipient_hash(recipient);
        assert!(expected_recipient_hash == recipient_hash, E_RECIPIENT_HASH_MISMATCH);

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            asset_type,
            recipient,
            *&new_balance_p,
            *&new_balance_r,
            *&new_balance_r_eff_aud,
            *&amount_p,
            *&amount_r_sender,
            *&amount_r_recip,
            *&amount_r_eff_aud,
            *&ek_volun_auds,
            *&amount_r_volun_auds,
            *&zkrp_new_balance,
            *&zkrp_amount,
            *&sigma_proto_comm,
            *&sigma_proto_resp,
            *&memo,
        );
        let ca_payload_hash_fr = ca_payload_hash_to_fr_safe(ca_payload_hash_raw);
        assert!(ca_payload_hash_fr == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let msg = WithdrawAttestationV2Message {
            domain: DOMAIN_WITHDRAW_V2,
            chain_id: chain_id::get(),
            bridge: @eunoma,
            vault: vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version: cfg.operator_set_version,
            dkg_epoch: cfg.dkg_epoch,
            roster_hash: *&cfg.roster_hash,
            frost_group_pubkey: *&cfg.frost_group_pubkey,
            root: *&root,
            nullifier_hash: *&nullifier_hash,
            recipient,
            recipient_hash: *&recipient_hash,
            amount_tag: *&amount_tag,
            ca_payload_hash: *&ca_payload_hash,
            request_hash: *&request_hash,
            vault_sequence,
            expiry_secs,
            circuit_versions_hash: circuit_versions_hash(cfg),
        };
        assert_deop_attestation_v2(
            bcs::to_bytes(&msg),
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        let cache = borrow_global<VaultPublicInputsV2>(@eunoma);
        // Stage 3 A6: recompute amount_p_digest from the SAME 14-CA-args amount_p that goes
        // into framework's confidential_transfer_raw below. Groth16 public input
        // amount_p_digest MUST byte-equal this — that's the binding that forces withdraw
        // amount = deposit amount (via Pedersen DL binding on the same blind).
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        consume_or_verify_withdraw_proof(
            *&root,
            *&nullifier_hash,
            cache.asset_id_fr,
            *&recipient_hash,
            *&amount_tag,
            *&ca_payload_hash,
            *&request_hash,
            vault_sequence,
            amount_p_digest,
            withdraw_proof,
        );

        let vault_signer = {
            let vault_for_cap = borrow_global<BridgeVault>(@eunoma);
            account::create_signer_with_capability(&vault_for_cap.vault_signer_cap)
        };
        mark_nullifier_used(*&nullifier_hash);
        let vault_mut = borrow_global_mut<BridgeVault>(@eunoma);
        vault_mut.vault_sequence = vault_mut.vault_sequence + 1;

        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            asset_type,
            recipient,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );

        event::emit(WithdrawEventV2 {
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
        });
    }

    public entry fun operator_rollover_vault_pending_v2(
        operator: &signer,
    ) acquires BridgeVault {
        assert_admin(operator);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::rollover_pending_balance(&vault_signer, asset_type);
    }

    public entry fun operator_normalize_vault_balance_v2(
        operator: &signer,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires BridgeVault {
        assert_admin(operator);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::normalize_raw(
            &vault_signer,
            asset_type,
            new_balance_p,
            new_balance_r,
            new_balance_r_aud,
            zkrp_new_balance,
            sigma_proto_comm,
            sigma_proto_resp,
        );
    }

    public entry fun init_pending_deposit_bindings_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingDepositBindingsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositBindingsV2 {
            by_commitment: table::new<vector<u8>, PendingDepositBindingV2>(),
        });
    }

    public entry fun init_pending_withdraw_proofs_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawProofsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV2>(),
        });
    }

    public entry fun prepare_deposit_binding_v2(
        sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires PendingDepositBindingsV2, PreparedDepositBindingVK, VaultPublicInputsV2 {
        assert_initialized();
        let _sender_addr = signer::address_of(sender);
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        assert!(exists<PendingDepositBindingsV2>(@eunoma), E_NOT_INITIALIZED);
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_deposit_binding_proof(
            *&commitment,
            *&amount_tag,
            *&amount_p_digest,
            deposit_binding_proof,
        );
        let pending = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
        assert!(!table::contains(&pending.by_commitment, *&commitment), E_PENDING_DEPOSIT_BINDING);
        table::add(&mut pending.by_commitment, commitment, PendingDepositBindingV2 {
            amount_tag,
            amount_p_digest,
        });
    }

    public entry fun prepare_withdraw_proof_v2(
        sender: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p: vector<vector<u8>>,
        withdraw_proof: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawProofsV2, PreparedWithdrawProofVK, VaultPublicInputsV2 {
        assert_initialized();
        let _sender_addr = signer::address_of(sender);
        assert_hash(&root);
        assert_hash(&nullifier_hash);
        assert_hash(&recipient_hash);
        assert_hash(&amount_tag);
        assert_hash(&ca_payload_hash);
        assert_hash(&request_hash);
        assert!(exists<PendingWithdrawProofsV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(known_root_recorded(&root), E_INVALID_ROOT);
        assert!(!nullifier_used(&nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let cache = borrow_global<VaultPublicInputsV2>(@eunoma);
        let asset_id = cache.asset_id_fr;
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_withdraw_proof(
            *&root,
            *&nullifier_hash,
            asset_id,
            *&recipient_hash,
            *&amount_tag,
            *&ca_payload_hash,
            *&request_hash,
            vault_sequence,
            *&amount_p_digest,
            withdraw_proof,
        );
        let pending = borrow_global_mut<PendingWithdrawProofsV2>(@eunoma);
        assert!(!table::contains(&pending.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV2 {
            root,
            nullifier_hash,
            asset_id,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            vault_sequence,
            amount_p_digest,
        });
    }

    public fun get_vault_sequence_v2(): u64 acquires BridgeVault {
        borrow_global<BridgeVault>(@eunoma).vault_sequence
    }

    public fun get_vault_address_v2(): address acquires BridgeVault {
        borrow_global<BridgeVault>(@eunoma).vault_addr
    }

    public fun get_deoperator_config_v2(): (u64, u64, u64, vector<u8>, vector<u8>, vector<u8>)
    acquires DeoperatorConfigV2 {
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        (
            cfg.operator_set_version,
            cfg.dkg_epoch,
            cfg.threshold,
            *&cfg.roster_hash,
            *&cfg.frost_group_pubkey,
            *&cfg.vault_ek,
        )
    }

    public fun is_nullifier_used_v2(nullifier_hash: vector<u8>): bool acquires BridgeVault, BridgeVaultTablesV2 {
        nullifier_used(&nullifier_hash)
    }

    public entry fun publish_deposit_binding_vk_v2(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4],
        });
    }

    public entry fun publish_deposit_binding_vk_v2_a6(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_5, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5],
        });
    }

    public entry fun publish_prepared_deposit_binding_vk_v2(
        admin: &signer,
    ) acquires DepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<DepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedDepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<DepositBindingVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2 = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);
        move_to(admin, PreparedDepositBindingVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    /// V2 deposit-binding VK rotation. Admin-only. Idempotent over presence of the
    /// existing resource: if a DepositBindingVK is already published, it is dropped
    /// FIRST (along with any cached PreparedDepositBindingVK), and the new VK is moved
    /// in. After this entry runs, the admin MUST call
    /// `rotate_prepared_deposit_binding_vk_v2` to refresh the cached prepared VK.
    /// Required when the trusted-setup zkey is regenerated and the on-chain VK no
    /// longer matches the proving key. Hard invariants unchanged: no plaintext
    /// witness, no centralized dk/inverse, no 5-of-7 weakening.
    public entry fun rotate_deposit_binding_vk_v2(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        if (exists<DepositBindingVK>(@eunoma)) {
            let DepositBindingVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<DepositBindingVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4],
        });
    }

    /// A6 deposit-binding VK rotation. Added as a compatible sidecar because
    /// the deployed testnet package cannot change existing public signatures.
    public entry fun rotate_deposit_binding_vk_v2_a6(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        if (exists<DepositBindingVK>(@eunoma)) {
            let DepositBindingVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<DepositBindingVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_5, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5],
        });
    }

    /// V2 prepared deposit-binding VK rotation. Admin-only. Drops any cached
    /// PreparedDepositBindingVK and re-derives it from the currently-published
    /// DepositBindingVK. Call this AFTER `rotate_deposit_binding_vk_v2` so
    /// `assert_valid_deposit_binding_proof` consumes the refreshed pairing cache.
    public entry fun rotate_prepared_deposit_binding_vk_v2(
        admin: &signer,
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<DepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        let vk = borrow_global<DepositBindingVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2 = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);
        move_to(admin, PreparedDepositBindingVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    public entry fun publish_withdraw_proof_vk_v2(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
        ic_6: vector<u8>,
        ic_7: vector<u8>,
        ic_8: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8],
        });
    }

    public entry fun publish_withdraw_proof_vk_v2_a6(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
        ic_6: vector<u8>,
        ic_7: vector<u8>,
        ic_8: vector<u8>,
        ic_9: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_9, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8, ic_9],
        });
    }

    public entry fun publish_prepared_withdraw_proof_vk_v2(
        admin: &signer,
    ) acquires WithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedWithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2 = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);
        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    /// V2 withdraw-proof VK rotation. Admin-only. Mirrors
    /// `rotate_deposit_binding_vk_v2`: drop any stale prepared cache first,
    /// replace the raw VK, then call `rotate_prepared_withdraw_proof_vk_v2`.
    public entry fun rotate_withdraw_proof_vk_v2_a6(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
        ic_6: vector<u8>,
        ic_7: vector<u8>,
        ic_8: vector<u8>,
        ic_9: vector<u8>,
    ) acquires WithdrawProofVK, PreparedWithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedWithdrawProofVK>(@eunoma)) {
            let PreparedWithdrawProofVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedWithdrawProofVK>(@eunoma);
        };
        if (exists<WithdrawProofVK>(@eunoma)) {
            let WithdrawProofVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<WithdrawProofVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_9, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8, ic_9],
        });
    }

    /// V2 prepared withdraw-proof VK rotation. Admin-only. Drops only the
    /// prepared cache and re-derives it from the currently-published raw VK.
    public entry fun rotate_prepared_withdraw_proof_vk_v2(
        admin: &signer,
    ) acquires WithdrawProofVK, PreparedWithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        if (exists<PreparedWithdrawProofVK>(@eunoma)) {
            let PreparedWithdrawProofVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedWithdrawProofVK>(@eunoma);
        };
        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2 = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);
        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    fun assert_initialized() {
        assert!(exists<BridgeVault>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<DeoperatorConfigV2>(@eunoma), E_NOT_INITIALIZED);
    }

    fun assert_admin(admin: &signer) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
    }

    fun vault_signer_and_asset_type(): (signer, Object<fungible_asset::Metadata>) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        (
            account::create_signer_with_capability(&vault.vault_signer_cap),
            vault.asset_type,
        )
    }

    fun assert_deop_attestation_v2(
        message_bytes: vector<u8>,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
    ) {
        if (vector::length(&group_signature) > 0) {
            let ok = vector::length(&group_signature) == ED25519_SIGNATURE_BYTES
                && ed25519::signature_verify_strict(
                    &ed25519::new_signature_from_bytes(group_signature),
                    &ed25519::new_unvalidated_public_key_from_bytes(*&cfg.frost_group_pubkey),
                    *&message_bytes,
                );
            assert!(ok, E_INVALID_DEOP_SIGNATURE);
        } else {
            assert_valid_fallback_attestation(
                &message_bytes,
                fallback_bitmap,
                &fallback_signatures,
                cfg,
            );
        }
    }

    fun assert_valid_fallback_attestation(
        message_bytes: &vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: &vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
    ) {
        assert!(vector::length(fallback_signatures) == MAX_DEOPERATORS, E_TOO_FEW_DEOP_SIGNATURES);
        let valid_count = 0;
        let i = 0;
        while (i < MAX_DEOPERATORS) {
            let sig = vector::borrow(fallback_signatures, i);
            if (vector::length(sig) > 0) {
                assert!(bit_is_set(fallback_bitmap, i), E_INVALID_DEOP_SIGNATURE);
                let pubkey = vector::borrow(&cfg.fallback_pubkeys, i);
                let ok = vector::length(pubkey) == ED25519_PUBLIC_KEY_BYTES
                    && vector::length(sig) == ED25519_SIGNATURE_BYTES
                    && ed25519::signature_verify_strict(
                        &ed25519::new_signature_from_bytes(*sig),
                        &ed25519::new_unvalidated_public_key_from_bytes(*pubkey),
                        *message_bytes,
                    );
                assert!(ok, E_INVALID_DEOP_SIGNATURE);
                valid_count = valid_count + 1;
            };
            i = i + 1;
        };
        assert!(valid_count >= cfg.threshold, E_TOO_FEW_DEOP_SIGNATURES);
    }

    fun assert_valid_fallback_pubkeys(pubkeys: &vector<vector<u8>>) {
        assert!(vector::length(pubkeys) == MAX_DEOPERATORS, E_BAD_FALLBACK_PUBKEYS);
        let active = 0;
        let i = 0;
        while (i < MAX_DEOPERATORS) {
            let pubkey = vector::borrow(pubkeys, i);
            let len = vector::length(pubkey);
            assert!(len == 0 || len == ED25519_PUBLIC_KEY_BYTES, E_BAD_FALLBACK_PUBKEYS);
            if (len == ED25519_PUBLIC_KEY_BYTES) {
                active = active + 1;
            };
            i = i + 1;
        };
        assert!(active >= THRESHOLD_V2, E_BAD_FALLBACK_PUBKEYS);
    }

    fun new_vault_tables_v2(): BridgeVaultTablesV2 {
        BridgeVaultTablesV2 {
            used_deposit_nonces: table::new<vector<u8>, bool>(),
            used_nullifiers: table::new<vector<u8>, bool>(),
            known_roots: table::new<vector<u8>, bool>(),
        }
    }

    fun deposit_nonce_used(deposit_nonce: &vector<u8>): bool acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            return table::contains(
                &borrow_global<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
                *deposit_nonce,
            )
        };
        table::contains(&borrow_global<BridgeVault>(@eunoma).used_deposit_nonces, *deposit_nonce)
    }

    fun mark_deposit_nonce_used(deposit_nonce: vector<u8>) acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            table::add(
                &mut borrow_global_mut<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
                deposit_nonce,
                true,
            );
        } else {
            table::add(&mut borrow_global_mut<BridgeVault>(@eunoma).used_deposit_nonces, deposit_nonce, true);
        };
    }

    fun known_root_recorded(root: &vector<u8>): bool acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            return table::contains(&borrow_global<BridgeVaultTablesV2>(@eunoma).known_roots, *root)
        };
        table::contains(&borrow_global<BridgeVault>(@eunoma).known_roots, *root)
    }

    fun record_known_root_internal(root: vector<u8>) acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
            if (!table::contains(&tables.known_roots, *&root)) {
                table::add(&mut tables.known_roots, root, true);
            };
        } else {
            let vault = borrow_global_mut<BridgeVault>(@eunoma);
            if (!table::contains(&vault.known_roots, *&root)) {
                table::add(&mut vault.known_roots, root, true);
            };
        };
    }

    fun nullifier_used(nullifier_hash: &vector<u8>): bool acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            return table::contains(
                &borrow_global<BridgeVaultTablesV2>(@eunoma).used_nullifiers,
                *nullifier_hash,
            )
        };
        table::contains(&borrow_global<BridgeVault>(@eunoma).used_nullifiers, *nullifier_hash)
    }

    fun mark_nullifier_used(nullifier_hash: vector<u8>) acquires BridgeVault, BridgeVaultTablesV2 {
        if (exists<BridgeVaultTablesV2>(@eunoma)) {
            table::add(&mut borrow_global_mut<BridgeVaultTablesV2>(@eunoma).used_nullifiers, nullifier_hash, true);
        } else {
            table::add(&mut borrow_global_mut<BridgeVault>(@eunoma).used_nullifiers, nullifier_hash, true);
        };
    }

    fun upsert_vault_public_inputs_v2(
        admin: &signer,
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    ) acquires VaultPublicInputsV2 {
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        if (exists<VaultPublicInputsV2>(@eunoma)) {
            let cache = borrow_global_mut<VaultPublicInputsV2>(@eunoma);
            cache.asset_id_fr = asset_id_fr;
            cache.vault_addr_hash_fr = vault_addr_hash_fr;
        } else {
            move_to(admin, VaultPublicInputsV2 { asset_id_fr, vault_addr_hash_fr });
        };
    }

    fun hash_confidential_transfer_payload_v2(
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ): vector<u8> {
        aptos_hash::keccak256(bcs::to_bytes(&CAPayloadForHashV2 {
            asset_type,
            to,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        }))
    }

    fun ca_payload_hash_to_fr_safe(raw: vector<u8>): vector<u8> {
        assert!(vector::length(&raw) == FR_BYTES, E_PAYLOAD_HASH_MISMATCH);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < 31) {
            vector::push_back(&mut out, *vector::borrow(&raw, i));
            i = i + 1;
        };
        vector::push_back(&mut out, 0u8);
        out
    }

    fun circuit_versions_hash(cfg: &DeoperatorConfigV2): vector<u8> {
        aptos_hash::keccak256(bcs::to_bytes(&CircuitVersionsForHash {
            deposit_circuit_version: *&cfg.deposit_circuit_version,
            withdraw_circuit_version: *&cfg.withdraw_circuit_version,
            ca_payload_circuit_version: *&cfg.ca_payload_circuit_version,
        }))
    }

    fun consume_or_verify_deposit_binding(
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
        proof: vector<u8>,
    ) acquires PendingDepositBindingsV2, PreparedDepositBindingVK, VaultPublicInputsV2 {
        if (exists<PendingDepositBindingsV2>(@eunoma) && vector::length(&proof) == 0) {
            let pending = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
            assert!(table::contains(&pending.by_commitment, *&commitment), E_INVALID_DEPOSIT_BINDING_PROOF);
            let cached = table::remove(&mut pending.by_commitment, *&commitment);
            assert!(cached.amount_tag == amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF);
            assert!(cached.amount_p_digest == amount_p_digest, E_INVALID_DEPOSIT_BINDING_PROOF);
        } else {
            assert_valid_deposit_binding_proof(
                commitment,
                amount_tag,
                amount_p_digest,
                proof,
            );
        }
    }

    fun consume_or_verify_withdraw_proof(
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        proof: vector<u8>,
    ) acquires PendingWithdrawProofsV2, PreparedWithdrawProofVK {
        if (exists<PendingWithdrawProofsV2>(@eunoma) && vector::length(&proof) == 0) {
            let pending = borrow_global_mut<PendingWithdrawProofsV2>(@eunoma);
            assert!(table::contains(&pending.by_request_hash, *&request_hash), E_INVALID_WITHDRAW_PROOF);
            let cached = table::remove(&mut pending.by_request_hash, *&request_hash);
            assert!(cached.root == root, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.nullifier_hash == nullifier_hash, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.asset_id == asset_id, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.recipient_hash == recipient_hash, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.amount_tag == amount_tag, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.ca_payload_hash == ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.vault_sequence == vault_sequence, E_INVALID_WITHDRAW_PROOF);
            assert!(cached.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
        } else {
            assert_valid_withdraw_proof(
                root,
                nullifier_hash,
                asset_id,
                recipient_hash,
                amount_tag,
                ca_payload_hash,
                request_hash,
                vault_sequence,
                amount_p_digest,
                proof,
            );
        }
    }

    fun assert_valid_deposit_binding_proof(
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedDepositBindingVK, VaultPublicInputsV2 {
        assert!(exists<PreparedDepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<VaultPublicInputsV2>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedDepositBindingVK>(@eunoma);
        let cache = borrow_global<VaultPublicInputsV2>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == DEPOSIT_VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_prepared_vk_shape(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            E_INVALID_DEPOSIT_BINDING_PROOF,
        );
        // Stage 3 A6: amount_p_digest is the 5th public input (after commitment, amount_tag,
        // asset_id, vault_addr_hash). Circuit publics order MUST match this vector exactly.
        let publics = vector[
            de_fr_with_error(commitment, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(cache.asset_id_fr, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(cache.vault_addr_hash_fr, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(amount_p_digest, E_INVALID_DEPOSIT_BINDING_PROOF),
        ];
        assert_groth16_prepared(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            &pvk.pvk_uvw_gamma_g1,
            &publics,
            proof,
            E_INVALID_DEPOSIT_BINDING_PROOF,
        );
    }

    fun assert_valid_withdraw_proof(
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedWithdrawProofVK {
        assert!(exists<PreparedWithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedWithdrawProofVK>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        assert_prepared_vk_shape(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            E_INVALID_WITHDRAW_PROOF,
        );
        // Stage 3 A6: amount_p_digest is the 9th public input. Circuit publics order:
        // [root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
        //  request_hash, vault_sequence, amount_p_digest] — MUST match exactly.
        let publics = vector[
            de_fr_with_error(root, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(nullifier_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(asset_id, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(recipient_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(amount_tag, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(ca_payload_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(request_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(u64_to_fr_bytes(vault_sequence), E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(amount_p_digest, E_INVALID_WITHDRAW_PROOF),
        ];
        assert_groth16_prepared(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            &pvk.pvk_uvw_gamma_g1,
            &publics,
            proof,
            E_INVALID_WITHDRAW_PROOF,
        );
    }

    fun assert_groth16_prepared(
        pvk_alpha_g1_beta_g2_fq12: &vector<u8>,
        pvk_gamma_g2_neg: &vector<u8>,
        pvk_delta_g2_neg: &vector<u8>,
        pvk_uvw_gamma_g1: &vector<vector<u8>>,
        publics: &vector<crypto_algebra::Element<Fr>>,
        proof: vector<u8>,
        err: u64,
    ) {
        assert!(vector::length(&proof) == PROOF_BYTES, err);
        let pvk_alpha_beta = de_fq12_with_error(*pvk_alpha_g1_beta_g2_fq12, err);
        let pvk_gamma_neg = de_g2_with_error(*pvk_gamma_g2_neg, err);
        let pvk_delta_neg = de_g2_with_error(*pvk_delta_g2_neg, err);
        let vk_ic = vector::empty<crypto_algebra::Element<G1>>();
        let i = 0;
        let n = vector::length(pvk_uvw_gamma_g1);
        while (i < n) {
            let ic_bytes = *vector::borrow(pvk_uvw_gamma_g1, i);
            vector::push_back(&mut vk_ic, de_g1_with_error(ic_bytes, err));
            i = i + 1;
        };
        let proof_a = de_g1_with_error(byte_slice_exact(&proof, 0, G1_UNCOMPRESSED_BYTES, err), err);
        let proof_b = de_g2_with_error(byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            err,
        ), err);
        let proof_c = de_g1_with_error(byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            PROOF_BYTES,
            err,
        ), err);
        let ok = groth16_bn254::verify_proof_prepared_fq12<G1, G2, Gt, Fq12, Fr>(
            &pvk_alpha_beta,
            &pvk_gamma_neg,
            &pvk_delta_neg,
            &vk_ic,
            publics,
            &proof_a,
            &proof_b,
            &proof_c,
        );
        assert!(ok, err);
    }

    fun assert_prepared_vk_shape(
        alpha_beta: &vector<u8>,
        gamma_neg: &vector<u8>,
        delta_neg: &vector<u8>,
        err: u64,
    ) {
        assert!(vector::length(alpha_beta) == FQ12_BYTES, err);
        assert_g2(gamma_neg, err);
        assert_g2(delta_neg, err);
    }

    fun pairing_fq12_bytes(
        alpha_g1: &crypto_algebra::Element<G1>,
        beta_g2: &crypto_algebra::Element<G2>,
    ): vector<u8> {
        let paired = crypto_algebra::pairing<G1, G2, Gt>(alpha_g1, beta_g2);
        let upcasted = crypto_algebra::upcast<Gt, Fq12>(&paired);
        crypto_algebra::serialize<Fq12, FormatFq12LscLsb>(&upcasted)
    }

    fun neg_g2_bytes(g2: &crypto_algebra::Element<G2>): vector<u8> {
        let neg = crypto_algebra::neg<G2>(g2);
        crypto_algebra::serialize<G2, FormatG2Uncompr>(&neg)
    }

    fun de_fr(bytes: vector<u8>): crypto_algebra::Element<Fr> {
        de_fr_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_fr_with_error(bytes: vector<u8>, err: u64): crypto_algebra::Element<Fr> {
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(&bytes);
        assert!(option::is_some(&opt), err);
        option::extract(&mut opt)
    }

    fun de_g1(bytes: vector<u8>): crypto_algebra::Element<G1> {
        de_g1_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g1_with_error(bytes: vector<u8>, err: u64): crypto_algebra::Element<G1> {
        let opt = crypto_algebra::deserialize<G1, FormatG1Uncompr>(&bytes);
        assert!(option::is_some(&opt), err);
        option::extract(&mut opt)
    }

    fun de_g2(bytes: vector<u8>): crypto_algebra::Element<G2> {
        de_g2_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g2_with_error(bytes: vector<u8>, err: u64): crypto_algebra::Element<G2> {
        let opt = crypto_algebra::deserialize<G2, FormatG2Uncompr>(&bytes);
        assert!(option::is_some(&opt), err);
        option::extract(&mut opt)
    }

    fun de_fq12(bytes: vector<u8>): crypto_algebra::Element<Fq12> {
        de_fq12_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_fq12_with_error(bytes: vector<u8>, err: u64): crypto_algebra::Element<Fq12> {
        let opt = crypto_algebra::deserialize<Fq12, FormatFq12LscLsb>(&bytes);
        assert!(option::is_some(&opt), err);
        option::extract(&mut opt)
    }

    fun assert_g1(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G1_UNCOMPRESSED_BYTES, err);
    }

    fun assert_g2(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G2_UNCOMPRESSED_BYTES, err);
    }

    fun u64_to_fr_bytes(n: u64): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&n);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < vector::length(&bcs_bytes)) {
            vector::push_back(&mut out, *vector::borrow(&bcs_bytes, i));
            i = i + 1;
        };
        while (vector::length(&out) < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
        };
        out
    }

    fun byte_slice_exact(src: &vector<u8>, start: u64, end: u64, err: u64): vector<u8> {
        let n = vector::length(src);
        assert!(start <= end && end <= n, err);
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        out
    }

    fun bytes_to_field_le32(src: &vector<u8>): vector<u8> {
        let n = vector::length(src);
        assert!(n <= FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        while (i < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
            i = i + 1;
        };
        out
    }

    fun byte_slice_padded(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let n = vector::length(src);
        assert!(start <= end && end <= n, E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        let padded_len = end - start;
        while (padded_len < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
            padded_len = padded_len + 1;
        };
        out
    }

    fun derive_asset_id(asset_type: Object<fungible_asset::Metadata>): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).asset_id_fr
        };
        derive_address_hash(object::object_address(&asset_type), POSEIDON_DOMAIN_ASSET_ID)
    }

    fun derive_vault_addr_hash(vault_addr: address): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).vault_addr_hash_fr
        };
        derive_address_hash(vault_addr, POSEIDON_DOMAIN_VAULT_ADDR_HASH)
    }

    fun derive_recipient_hash(recipient: address): vector<u8> {
        derive_address_hash(recipient, POSEIDON_DOMAIN_RECIPIENT_HASH)
    }

    fun derive_address_hash(addr: address, domain_bytes: vector<u8>): vector<u8> {
        let addr_bytes = bcs::to_bytes(&addr);
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_BAD_HASH_LENGTH);
        let hi = byte_slice_padded(&addr_bytes, 0, 16);
        let lo = byte_slice_padded(&addr_bytes, 16, 32);
        let domain = bytes_to_field_le32(&domain_bytes);
        poseidon_bn254::hash_3(domain, hi, lo)
    }

    /// Stage 3 A6: compute amount_p_digest from the CA framework's 4 × 32B Ristretto amount_p.
    ///
    /// Mirrors circuits/{deposit_binding,withdrawal_proof}.circom Compose8 template +
    /// circuits/scripts/compute_{deposit,withdraw}_witness.mjs compose8() helper.
    ///
    /// Each 32B compressed Ristretto point p[k] is split into 2 × 16B little-endian limbs:
    ///   p[k]_lo = byte_slice_padded(p[k], 0, 16)   // bytes 0..16, padded right to 32B for Fr
    ///   p[k]_hi = byte_slice_padded(p[k], 16, 32)  // bytes 16..32, padded right to 32B for Fr
    /// Then 8 limbs are hashed in the Compose8 tree (only hash_2 + hash_3 are available in
    /// eunoma_pool::poseidon_bn254; matches circuit Compose8 exactly):
    ///   a = hash_3(p[0]_lo, p[0]_hi, p[1]_lo)
    ///   b = hash_3(p[1]_hi, p[2]_lo, p[2]_hi)
    ///   c = hash_2(p[3]_lo, p[3]_hi)
    ///   digest = hash_3(a, b, c)
    ///
    /// IMPORTANT: limb ORDER must exactly match the circuit / JS witness builder, which is
    /// [p[0]_lo, p[0]_hi, p[1]_lo, p[1]_hi, p[2]_lo, p[2]_hi, p[3]_lo, p[3]_hi]. The
    /// Compose8 tree consumes them in that order: a takes limbs [0,1,2], b takes [3,4,5],
    /// c takes [6,7].
    fun compute_amount_p_digest_v2(amount_p: &vector<vector<u8>>): vector<u8> {
        // CA framework TRANSFER_AMOUNT_CHUNK_COUNT = 4; each chunk is a 32B compressed Ristretto point.
        assert!(vector::length(amount_p) == 4, E_INVALID_AMOUNT_P_SHAPE);

        let p0 = vector::borrow(amount_p, 0);
        let p1 = vector::borrow(amount_p, 1);
        let p2 = vector::borrow(amount_p, 2);
        let p3 = vector::borrow(amount_p, 3);
        assert!(vector::length(p0) == 32, E_INVALID_AMOUNT_P_SHAPE);
        assert!(vector::length(p1) == 32, E_INVALID_AMOUNT_P_SHAPE);
        assert!(vector::length(p2) == 32, E_INVALID_AMOUNT_P_SHAPE);
        assert!(vector::length(p3) == 32, E_INVALID_AMOUNT_P_SHAPE);

        // Compose8 tree (matches circom Compose8 + JS compose8).
        let a = poseidon_bn254::hash_3(
            byte_slice_padded(p0, 0, 16),
            byte_slice_padded(p0, 16, 32),
            byte_slice_padded(p1, 0, 16),
        );
        let b = poseidon_bn254::hash_3(
            byte_slice_padded(p1, 16, 32),
            byte_slice_padded(p2, 0, 16),
            byte_slice_padded(p2, 16, 32),
        );
        let c = poseidon_bn254::hash_2(
            byte_slice_padded(p3, 0, 16),
            byte_slice_padded(p3, 16, 32),
        );
        poseidon_bn254::hash_3(a, b, c)
    }

    fun assert_hash(bytes: &vector<u8>) {
        assert!(vector::length(bytes) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    fun assert_not_expired(expiry_secs: u64) {
        assert!(timestamp::now_seconds() <= expiry_secs, E_EXPIRED);
    }

    fun bit_is_set(bitmap: u8, index: u64): bool {
        let divisor = 1u8;
        let i = 0;
        while (i < index) {
            divisor = divisor * 2;
            i = i + 1;
        };
        ((bitmap / divisor) % 2) == 1
    }

    #[test_only]
    public entry fun install_deposit_binding_test_override_v2(
        admin: &signer,
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingTestOverride>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        move_to(admin, DepositBindingTestOverride { asset_id_fr, vault_addr_hash_fr });
    }

    #[test_only]
    public fun test_call_hash_confidential_transfer_payload_v2(
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ): vector<u8> {
        hash_confidential_transfer_payload_v2(
            asset_type,
            to,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        )
    }

    #[test_only]
    public fun test_call_ca_payload_hash_to_fr_safe_v2(raw: vector<u8>): vector<u8> {
        ca_payload_hash_to_fr_safe(raw)
    }

    public fun e_bad_threshold(): u64 { E_BAD_THRESHOLD }
    public fun e_invalid_deop_signature(): u64 { E_INVALID_DEOP_SIGNATURE }
    public fun e_too_few_deop_signatures(): u64 { E_TOO_FEW_DEOP_SIGNATURES }
    public fun e_payload_hash_mismatch(): u64 { E_PAYLOAD_HASH_MISMATCH }
    public fun e_invalid_deposit_binding_proof(): u64 { E_INVALID_DEPOSIT_BINDING_PROOF }
    public fun e_invalid_withdraw_proof(): u64 { E_INVALID_WITHDRAW_PROOF }
    public fun e_recipient_hash_mismatch(): u64 { E_RECIPIENT_HASH_MISMATCH }
}
