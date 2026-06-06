module eunoma::eunoma_bridge {
    use std::bcs;
    use std::option;
    use std::signer;
    use std::vector;

    use aptos_std::aptos_hash;
    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;
    use aptos_std::ristretto255;
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
    use aptos_framework::aptos_account;
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
    // ASP (2026-05-30, asp-tree-design §5.2/§6): withdraw circuit gains 3 publics
    //   (asp_root, state_tree_depth, asp_tree_depth) so publics 9 -> 12, VK IC 10 -> 13.
    // V4 (2026-06-02): pruned withdraw public vector to stay near deposit-level verifier cost.
    // CANONICAL public order:
    //   [0]root [1]nullifier_hash [2]request_hash [3]amount_p_digest [4]asp_root
    //   [5]change_commitment.
    // Public count = 6; VK IC length = 7. Move recomputes request_hash from public route args
    // before verification, and uses proof-bound amount_p_digest directly instead of recomputing
    // Poseidon8 over amount_p_old on the prepare hot path.
    // EMPTY change_commitment sentinel = 0 (CHANGE_COMMITMENT_EMPTY): a full withdraw binds
    // change_commitment public[12] to the field element 0.
    const DEPOSIT_VK_IC_LENGTH: u64 = 6;
    const WITHDRAW_VK_IC_LENGTH: u64 = 7;
    // V4 (CP1/CP2 MB-5): the EMPTY change_commitment sentinel = the field element 0, encoded as
    // 32 little-endian zero bytes. A full withdraw binds public[12] to this value and emits NO
    // ChangeNoteAppendedV4; a partial withdraw binds a non-zero Compose5 change commitment and
    // emits the change-leaf event (has_change == change_commitment != CHANGE_COMMITMENT_EMPTY).
    const CHANGE_COMMITMENT_EMPTY: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    // CP6 ragequit (asp-tree-design §8 / §5.4): the standalone transparent-exit circuit has 4
    // publics (EXACT order, must match the Move publics vector byte-for-byte):
    //   [0]commitment [1]nullifier_hash [2]root [3]state_tree_depth
    // commitment is REVEALED (transparent link); NO asp_root / no ASP inclusion. 4 publics + 1
    // const term = VK IC length 5.
    const RAGEQUIT_VK_IC_LENGTH: u64 = 5;

    // ASP (2026-05-30, asp-tree-design §6 / D3): withdraw accepts an asp_root that matches any
    // of the LAST K recorded ASP roots. Small window so a periodic re-fork (which pushes a fresh
    // root) does not instantly invalidate in-flight proofs, while revoked commitments age out
    // once their root falls past the window. K is a plan-time parameter (§13).
    const ASP_ROOT_WINDOW_K: u64 = 32;

    const DOMAIN_DEPOSIT_V2: vector<u8> = b"EUNOMA_DEPOSIT_BIND_V2";
    // Deposit re-key: V3 attestation binds user_addr so relayer-submitted step2a cannot be
    // misdirected. Kept additive because Aptos upgrades reject layout/signature changes.
    const DOMAIN_DEPOSIT_V3: vector<u8> = b"EUNOMA_DEPOSIT_BIND_V3";
    const DOMAIN_WITHDRAW_V2: vector<u8> = b"EUNOMA_WITHDRAW_ATTESTATION_V2";
    // V4 (CP2 MB-6, dormant-lifecycle-VERIFIED §3): de-list emergency-exit attestation domain. The
    // 5-of-7 deoperators sign (asset_type, recipient, amount, expiry) to authorize a withdraw_to_raw
    // to plain FA when Aptos has de-listed the asset for CA (normal withdraw + ragequit both brick
    // on is_confidentiality_enabled). Distinct domain so an emergency-exit signature can never be
    // replayed as a normal-withdraw attestation.
    const DOMAIN_EMERGENCY_EXIT_V4: vector<u8> = b"EUNOMA_EMERGENCY_EXIT_V4";
    const POSEIDON_DOMAIN_ASSET_ID: vector<u8> = b"EUNOMA_ASSET_ID_V2";
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH: vector<u8> = b"EUNOMA_VAULT_ADDR_V2";
    const POSEIDON_DOMAIN_RECIPIENT_HASH: vector<u8> = b"EUNOMA_RECIPIENT_V2";
    // Round 4 WB2.E C / FR-1.5b: precomputed Fr-bytes form of the 3 POSEIDON_DOMAIN_* strings
    // = byte sequence of the string + zero-pad to FR_BYTES (32). Equivalent to
    // bytes_to_field_le32(POSEIDON_DOMAIN_*) but computed at compile time, saving the per-call
    // pad work (formerly ~100 gas per derive_address_hash call, hit on every withdraw
    // recipient_hash + every admin asset_id / vault_addr_hash derive). Byte-equality with
    // bytes_to_field_le32 output: src[0..n] || 0u8 × (32-n), where n = string length.
    //
    // ASSET_ID_V2 (18 bytes "EUNOMA_ASSET_ID_V2" + 14 zeros):
    const POSEIDON_DOMAIN_ASSET_ID_FR: vector<u8> = x"45554e4f4d415f41535345545f49445f56320000000000000000000000000000";
    // VAULT_ADDR_V2 (20 bytes "EUNOMA_VAULT_ADDR_V2" + 12 zeros):
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH_FR: vector<u8> = x"45554e4f4d415f5641554c545f414444525f5632000000000000000000000000";
    // RECIPIENT_V2 (19 bytes "EUNOMA_RECIPIENT_V2" + 13 zeros):
    const POSEIDON_DOMAIN_RECIPIENT_HASH_FR: vector<u8> = x"45554e4f4d415f524543495049454e545f563200000000000000000000000000";

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
    const E_PENDING_WITHDRAW_ATTESTATION: u64 = 26;
    const E_PENDING_WITHDRAW_PAYLOAD: u64 = 27;
    // R6-Plan-B (split-tx deposit): step2b authorization + missing-pending errors.
    const E_NOT_DEPOSIT_OWNER: u64 = 28;
    const E_NO_PENDING_FINALIZATION: u64 = 29;
    // R7-OPS-1 (recorder-delegate): delegate-based known_root recording without admin key.
    const E_RECORDER_DELEGATE_NOT_INITIALIZED: u64 = 30;
    const E_NOT_RECORDER_DELEGATE: u64 = 31;
    const E_NOT_WITHDRAW_OWNER: u64 = 32;
    const E_PENDING_WITHDRAW_FINALIZATION: u64 = 33;
    // (C) gas economics: GasFeeConfigV1 not initialized.
    const E_GAS_FEE_NOT_INITIALIZED: u64 = 34;
    // (B) deposit re-key: a (user_addr, commitment) finalization slot already exists at step2a.
    const E_PENDING_DEPOSIT_FINALIZATION: u64 = 35;
    // ASP (2026-05-30, asp-tree-design §6): curated private-exit Association Set Provider errors.
    // asp_root supplied to a withdraw is not in the recent ASP-root window (revoked / unknown root).
    const E_INVALID_ASP_ROOT: u64 = 36;
    // ASP recorder delegate (low-priv, no admin key) errors — mirror E_RECORDER_DELEGATE_*.
    const E_ASP_RECORDER_DELEGATE_NOT_INITIALIZED: u64 = 37;
    const E_NOT_ASP_RECORDER_DELEGATE: u64 = 38;
    // CP6 ragequit (transparent exit): only the original depositor may ragequit a commitment.
    const E_NOT_ORIGINAL_DEPOSITOR: u64 = 39;

    // ============================================================================
    // V4 multi-asset (CP2 MB-1, design 2026-06-01 §4 + dormant-lifecycle-VERIFIED §2-4).
    // Per-asset DORMANT->ACTIVE lifecycle, append-only registry, on-chain-derived asset_id.
    // ============================================================================
    // Asset resolved from the registry is not in the ACTIVE state (DORMANT/PAUSED) — every
    // registry-resolving spend/deposit/prepare/ragequit entry gates on this at the TOP, before
    // any global table write. A DORMANT entry is unspendable by construction.
    const E_ASSET_NOT_ACTIVE: u64 = 40;
    // activate_asset_ca_v4 idempotency gate — st.status must be DORMANT to activate. Belt over
    // the framework's E_CONFIDENTIAL_STORE_ALREADY_REGISTERED suspenders.
    const E_ASSET_ALREADY_ACTIVE: u64 = 41;
    // register_asset_metadata_v4 validation — the asset_addr is already registered, OR the
    // on-chain-derived asset_id_fr collides with an already-registered asset (uniqueness),
    // OR a caller-supplied asset_id_fr disagrees with the on-chain derivation.
    const E_ASSET_ID_MISMATCH: u64 = 42;
    // V4 (CP2 MB-4, design §6 B-prime): aggregate-Pedersen amount-conservation equality failed —
    // point_equals(P_old, P_wd + P_rem) is false, i.e. the partial-withdraw split does not conserve
    // the spent note's amount (A_old != W + A_rem). Raised in the cache-once prepare path.
    const E_AMOUNT_CONSERVATION: u64 = 43;
    // V4 (CP2 MB-6, dormant-lifecycle-VERIFIED §3): de-list emergency exit invoked while the asset
    // is STILL CA-enabled (is_confidentiality_enabled == true). The emergency path is ONLY for a
    // governance-de-listed asset; while CA is live, use the normal withdraw / ragequit paths.
    const E_NOT_DELISTED: u64 = 44;

    // Per-asset lifecycle status (AssetVaultStateV4.status). DORMANT = registered metadata only
    // (no CA store yet, unspendable); ACTIVE = CA-registered + spendable; PAUSED = block-new
    // (drain-in-flight). status + vault_ek are the ONLY mutable fields on a registry row.
    const ASSET_STATUS_DORMANT: u8 = 0;
    const ASSET_STATUS_ACTIVE: u8 = 1;
    const ASSET_STATUS_PAUSED: u8 = 2;

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

    // ============================================================================
    // V4 multi-asset storage (CP2 MB-1). Design: §4.3 (struct sketch) of
    // 2026-06-01-eunoma-v4-multi-asset-partial-withdraw-design.md, refined by §2 of
    // 2026-06-01-eunoma-v4-dormant-lifecycle-and-delist-exit-VERIFIED.md.
    //
    // Topology T1 (D4): ONE shared vault resource account registered for N CA assets. The
    // signer cap is a SINGLE field on VaultCoreV4 (NOT fanned across the Table) — per-asset CA
    // balance isolation is the framework's job (ConfidentialStore is keyed per (account,
    // asset_type)). Per-asset metadata lives in an APPEND-ONLY registry; globals (counters,
    // nonces, nullifiers, known_roots) are single instances across all assets.
    // ============================================================================

    // GLOBAL vault core. vault_sequence is byte-identical to V3 BridgeVault.vault_sequence
    // (still withdraw public[7] + FROST attestation message field — zero blast radius, D5).
    // next_leaf_index is the NEW global unified-tree append index (one monotonic counter across
    // every asset's deposit finalization AND every partial-withdraw change-leaf emission, §10.1).
    struct VaultCoreV4 has key {
        admin: address,
        vault_addr: address,
        vault_signer_cap: account::SignerCapability,   // SignerCapability has drop,store (account.move:57)
        paused: bool,
        next_leaf_index: u64,   // GLOBAL unified-tree append index (deposits + change leaves)
        vault_sequence: u64,    // GLOBAL anti-replay nonce (S-A) — byte-identical to V3 public[7]
    }

    // Per-asset metadata — NO signer cap (one shared account; T1). Legal Table value (store+drop).
    // asset_type / asset_id_fr / decimals are IMMUTABLE after register (MA-1 soundness premise:
    // routing correctness = derive_asset_id(st.asset_type) == proven_asset_id depends only on the
    // immutable asset_type + immutable asset_id_fr). status + vault_ek are the ONLY mutable fields.
    // asset_id_fr is COMPUTED on-chain via derive_asset_id(asset_type) at register, NEVER a caller arg.
    struct AssetVaultStateV4 has store, drop {
        asset_type: Object<fungible_asset::Metadata>,  // feeds confidential_transfer_raw + ca_payload_hash
        asset_id_fr: vector<u8>,                        // derive_asset_id(asset_type) — circuit public[2]
        vault_addr_hash_fr: vector<u8>,                 // constant in T1; stored per-asset for symmetry
        vault_ek: vector<u8>,                           // per-asset CA encryption key (∅ while DORMANT)
        decimals: u8,                                   // 8 APT / 6 cUSDC,cUSDT — IMMUTABLE after register
        deposit_count: u64,                             // PER-ASSET observer cursor (NOT the tree key)
        status: u8,                                     // DORMANT(0)/ACTIVE(1)/PAUSED(2)
    }

    // APPEND-ONLY registry (FIX-3). by_asset keyed by the FA metadata object-address; there is
    // intentionally NO reverse index asset_id_fr -> asset_addr (derive_asset_id is one-way), so
    // spends thread asset_addr as an explicit arg and assert the Poseidon-link (MA-1). asset_list
    // makes the registry enumerable for ops / off-chain config build.
    struct AssetRegistryV4 has key {
        by_asset: Table<address, AssetVaultStateV4>,    // key = object::object_address(metadata)
        asset_list: vector<address>,
    }

    // GLOBAL tables — same shape as BridgeVaultTablesV2, ONE set across all assets. used_nullifiers
    // is global because asset_id is inside the Compose5 preimage, so cross-asset nullifier / leaf
    // collisions are cryptographically impossible. known_roots is the ONE unified state tree's
    // root history.
    struct BridgeTablesV4 has key {
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

    // N1 (gas opt): cache amount_p directly (in addition to digest) so deposit cache-hit
    // can byte-compare amount_p without recomputing compute_amount_p_digest_v2's 4 Poseidon
    // hashes (~700 gas saved). Additive struct + resource — compatible with Aptos upgrade.
    // Frontend writes via new prepare_deposit_binding_v3 entry; consume reads V3 first then
    // V2 fallback then Groth16 fallback.
    struct PendingDepositBindingV3 has store, drop {
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
        amount_p: vector<vector<u8>>,
    }

    struct PendingDepositBindingsV3 has key {
        by_commitment: Table<vector<u8>, PendingDepositBindingV3>,
    }

    // R6-Plan-B (split-tx): step2a writes; step2b drains and invokes CA framework.
    // Stores all fields needed for DepositConfirmedV2 emit at step2b plus anti-drain
    // bindings (sender, ca_payload_hash, expiry_secs). Anti vault-drain critical:
    // step2b recomputes ca_payload_hash from supplied CA args + asserts == stored hash;
    // without this, attacker (= same signer) can submit step2a with args_X then step2b
    // with args_Y and bind commitment_X to deposit_Y (vault binding mismatch -> drain).
    struct PendingDepositFinalizationV3 has store, drop {
        sender: address,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    }

    struct PendingDepositFinalizationsV3 has key {
        by_commitment: Table<vector<u8>, PendingDepositFinalizationV3>,
    }

    // R7-OPS-1: recorder-delegate authorization. Admin one-time init seeds delegate to
    // bridge admin addr; admin_set_recorder_delegate rotates to operator (alpha box relayer
    // addr typically). record_known_root_v2_via_delegate then accepts the delegate's signer
    // without requiring admin key on the operator machine. Strict scope: delegate can ONLY
    // call the via_delegate entry — cannot mint commitments, drain vault, change config,
    // or change roster. Worst-case alpha-box compromise = attacker spams known_roots table
    // with garbage (mitigated by assert_hash length check + table idempotent add).
    struct RecorderDelegate has key {
        addr: address,
    }

    // ASP (2026-05-30, asp-tree-design §4.2 / §6): one recorded Association Set = the ASP-tree
    // root over the curator-approved commitment subset, the IPFS CID of the full plaintext set
    // (published for auditability), and the recording timestamp. associationSets-style append-only
    // log; withdraw verifies asp_root ∈ the recent window (asp_root_in_recent_window).
    struct AssociationSetData has store, drop, copy {
        root: vector<u8>,
        ipfs_cid: vector<u8>,
        timestamp: u64,
    }

    // ASP: append-only log of recorded Association Sets. Seeded empty at init_asp_recorder_delegate
    // time; the asp-recorder delegate appends one entry per re-fork epoch.
    struct KnownASPRoots has key {
        sets: vector<AssociationSetData>,
    }

    // CP6 ragequit (asp-tree-design §8): records the original depositor address keyed by commitment,
    // written at deposit finalization. Used by the (future, CP6) ragequit entry to enforce
    // `recipient == deposit_sender[commitment]` (resources can only exit back to the original
    // depositor — closes the "deposit -> ragequit to a clean address" laundering escape). The
    // map itself is needed now; the ragequit entry is CP6.
    struct DepositSenderMap has key {
        by_commitment: Table<vector<u8>, address>,
    }

    // ASP recorder delegate authorization. Mirrors RecorderDelegate exactly: admin one-time init
    // seeds addr = admin; admin_set_asp_recorder_delegate rotates to a low-priv operator addr.
    // record_asp_root_via_delegate accepts the delegate's signer (no admin key on the operator
    // box). Strict scope: the delegate can ONLY append to KnownASPRoots — cannot touch any other
    // admin-controlled state. ASP roots encode compliance (curator/KYT) decisions, not privacy
    // secrets, and the full set is public on IPFS so a bad root is detectable (asp-tree-design D4).
    struct ASPRecorderDelegate has key {
        addr: address,
    }

    // (C) gas economics: flat plain-APT relayer-gas fee collected at deposit step2b, routed to a
    // communal plain-APT gas-reserve account the withdraw relayer draws gas from. FLAT only (a
    // %-fee in cleartext APT would leak the confidential amount). Admin-settable so the fee can be
    // retuned / the reserve rotated / the fee zeroed (kill-switch) without a redeploy.
    struct GasFeeConfigV1 has key {
        flat_fee_octas: u64,
        reserve_addr: address,
    }

    // C1 (gas opt): cache circuit_versions_hash(cfg) so deposit/withdraw hot paths read a
    // 32B field instead of running keccak256+bcs every tx (~250-800 gas saved per call).
    struct CircuitVersionsHashCacheV2 has key {
        hash: vector<u8>,
    }

    // V4 (CP2 MB-3, 2026-06-01): PendingWithdrawProofsV2 / PendingWithdrawProofV2 PHYSICALLY
    // DELETED (legacy asset_id-blind-at-consume cache; cross-asset bypass under multi-asset).
    // Only the V3b cache (asset_id + change_commitment carrying, re-asserted on cache-hit) ships.

    struct PendingWithdrawAttestationsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV2>,
    }

    struct PendingWithdrawAttestationV2 has store, drop {
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
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    struct PendingWithdrawPayloadsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawPayloadV2>,
    }

    struct PendingWithdrawPayloadV2 has store, drop {
        asset_type: address,
        recipient: address,
        ca_payload_hash: vector<u8>,
        amount_p_digest: vector<u8>,
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

    // V4 (CP2 MB-3, 2026-06-01): PendingWithdrawProofsV3 / PendingWithdrawProofV3 (msg_hash
    // keccak cache) PHYSICALLY DELETED. Its cache-consume branch recomputed an asset_id-bearing
    // msg_hash but the cache row never stored asset_id, so a multi-asset settle could collide it.
    // The V3b cache (below) carries asset_id + change_commitment and is the only survivor.

    // Round 5 Wave E.5 (R5-R) — V3b proof cache: field-by-field equality at consume instead of
    // keccak. Codex constraint (audit 2026-05-25): every Groth16-bound non-key public input MUST
    // be stored and compared. P0 hotfix at prepare_withdraw_payload_v3 + consume_or_compute_
    // withdraw_payload (recompute amount_p_digest + assert ==) MUST remain.
    //
    // V4 (CP2 MB-3, 2026-06-01): asset_id RE-ADDED (the V3 singleton assumption dies under
    // multi-asset — asset_id is now the registry-resolved AssetVaultStateV4.asset_id_fr and is
    // re-asserted on cache-hit). change_commitment ADDED (CP1 public[12]) and re-asserted on
    // cache-hit. This is the ONLY surviving withdraw-proof cache struct; the legacy V2b/V3/V2
    // asset_id-blind cache-consume branches are physically deleted (MA-1 / FIX-2).
    struct PendingWithdrawProofsV3b has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV3b>,
    }

    struct PendingWithdrawProofV3b has store, drop {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,          // V4 MB-3: registry-resolved asset_id_fr (re-asserted on cache-hit)
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        change_commitment: vector<u8>, // V4 CP1: public[12] (EMPTY = 32 zero bytes)
    }

    // V4 (CP2 MB-3, 2026-06-01): PendingWithdrawProofsV2b / PendingWithdrawProofV2b PHYSICALLY
    // DELETED. The V2b cache dropped asset_id and re-read it from the now-dead singleton
    // VaultPublicInputsV2.asset_id_fr at consume — a total cross-asset bypass under multi-asset
    // (MA-1 / FIX-2). The ONLY surviving withdraw-proof cache is V3b (which now CARRIES asset_id
    // + change_commitment and re-asserts both on cache-hit).

    struct PendingWithdrawAttestationsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV3>,
    }

    struct PendingWithdrawAttestationV3 has store, drop {
        msg_hash: vector<u8>,
    }

    // Round 5 Wave E.1 (R5-D) — V2b attestation cache: msg_hash-only (32B vs ~600B V2).
    // Soft migration: prepare_withdraw_attestation_v2 writes V2b going forward;
    // consume_or_verify_withdraw_attestation reads V3 → V2b → V2 → miss. In-flight V2
    // entries (from pre-Round-5 deploys) still drain via the V2 fallthrough branch.
    struct PendingWithdrawAttestationsV2b has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV2b>,
    }

    struct PendingWithdrawAttestationV2b has store, drop {
        msg_hash: vector<u8>,
    }

    struct PendingWithdrawPayloadsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawPayloadV3>,
    }

    struct PendingWithdrawPayloadV3 has store, drop {
        msg_hash: vector<u8>,
        amount_p_digest: vector<u8>,
    }

    // V4 (CP2 MB-4, design §6 B-prime / §6.4): cache-once aggregate-Pedersen conservation result,
    // keyed by request_hash (mirrors the amount_p_digest payload cache). The ~3 multi_scalar_mul +
    // 12 VALIDATING decompressions + point_equals run EXACTLY ONCE in the prepare path
    // (prepare_withdraw_conservation_v4) and the cheap boolean is read on the hot step2b path — the
    // gas-placement requirement of §6.4 (heavy curve math off the already-over-cap settle tx). The
    // cached row also pins the amount_p_digest the conservation was proven against, so a consumer
    // re-asserts the SAME spent-note amount the Groth16 public[8] bound (no rebind to a different
    // amount). A FULL withdraw (no remainder) records conserved=true trivially (A_rem = 0).
    struct PendingWithdrawConservationsV4 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawConservationV4>,
    }

    struct PendingWithdrawConservationV4 has store, drop {
        amount_p_digest: vector<u8>,   // the spent note's amount_p_digest (Groth16 public[8])
        conserved: bool,               // point_equals(P_old, P_wd + P_rem) held
    }

    struct PendingWithdrawFinalizationsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawFinalizationV3>,
    }

    struct PendingWithdrawFinalizationV3 has store, drop {
        sender: address,
        // V4 (CP2 MB-3, 2026-06-01): asset_addr + asset_id stored so TX4 re-resolves the SAME
        // registry entry TX3 validated (FIX-4) — the finalization row is no longer asset-blind.
        asset_addr: address,
        asset_id: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        // V4 (CP2 MB-5): change_commitment public[12], validated at step2a (TX3) via the V3b cache
        // re-assert + the Groth16 binding, carried here so step2b (TX4) emits ChangeNoteAppendedV4
        // (only when has_change) under the GLOBAL next_leaf_index without re-reading the V3b cache.
        change_commitment: vector<u8>,
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

    // CP6 ragequit (asp-tree-design §8): VK for the standalone transparent-exit circuit. Mirrors
    // WithdrawProofVK exactly but the stored ic vector has RAGEQUIT_VK_IC_LENGTH = 5 elements
    // (4 publics + const term), vs 13 for the ASP withdraw circuit.
    struct RagequitProofVK has key {
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic: vector<vector<u8>>,
    }

    struct PreparedRagequitProofVK has key {
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

    struct DepositAttestationV3Message has drop, store {
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
        user_addr: address,
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

    // A1 (Aptos compat fix): struct DepositEventV2 RESTORED — Aptos rejects deletion of
    // #[event] structs at upgrade time (EVENT_METADATA_VALIDATION_ERROR). We keep the
    // struct declaration but NEVER emit it (the emit was deleted in deposit_with_commitment_v2).
    // Gas saved = the emit cost (~700-900 gas), not the struct declaration (zero runtime cost).
    #[event]
    struct DepositEventV2 has drop, store {
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
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

    // R6-Plan-B (split-tx): emitted at step2a so frontend/observer detect partial
    // state. step2b then emits the normal DepositConfirmedV2. Observer cursor does
    // NOT advance on Step2aRecorded — only on DepositConfirmedV2.
    #[event]
    struct DepositStep2aRecorded has drop, store {
        commitment: vector<u8>,
        sender: address,
        expiry_secs: u64,
    }

    // FR-1.1 (Round 4 F): struct retained, emit replaced by WithdrawEventV3.
    // Aptos forbids deleting #[event] fields (EVENT_METADATA_VALIDATION_ERROR); same A1
    // pattern as DepositEventV2:369-372.
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

    // FR-1.1 (Round 4 F): bridge withdraw event no longer emits raw recipient address;
    // amount_tag + ca_payload_hash were unused off-chain. Parsed by the same V2 consumers
    // (chain_fetch::parse_tx_withdraw_event_v2, vault_resync_client::parseWithdrawEventV2FromTx,
    // testnet_e2e_checks event-binding gate) — they accept either V2 or V3 type names.
    #[event]
    struct WithdrawEventV3 has drop, store {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
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

    // ASP (2026-05-30, asp-tree-design §6): emitted when the asp-recorder delegate appends a new
    // Association Set (root + IPFS CID of the full plaintext approved-commitment set).
    #[event]
    struct ASPRootRecorded has drop, store {
        root: vector<u8>,
        ipfs_cid: vector<u8>,
    }

    // CP6 ragequit (asp-tree-design §8): emitted when an original depositor reclaims their deposit
    // via the transparent original-path exit. commitment is REVEALED on purpose (the deposit<->exit
    // link is public by design — that is what blocks the "deposit -> ragequit to a clean address"
    // laundering escape). original_sender == the recorded deposit_sender[commitment] == the signer.
    // The amount stays confidential (the CA transfer hides it); no amount field is emitted.
    #[event]
    struct RagequitEventV1 has drop, store {
        commitment: vector<u8>,
        original_sender: address,
        nullifier_hash: vector<u8>,
        timestamp: u64,
    }

    // V4 (CP2 MB-5, design 2026-06-01 §3.3/§4.4/§10.1): a partial-withdraw change/remainder note
    // commitment appended to the SAME single global state LeanIMT under the GLOBAL next_leaf_index.
    // Emitted ONLY when has_change == 1 (change_commitment != CHANGE_COMMITMENT_EMPTY) — a full
    // withdraw emits NO ChangeNoteAppendedV4. Deliberately a SEPARATE event (not folded into the
    // withdraw event) so the off-chain LeanIMT builder ingests the change leaf as a first-class
    // appendable leaf under one global counter, and so it carries NO co-emitted parent identifier
    // (avoids on-chain parent->change linkage in the event payload). The change leaf's
    // amount_p_digest stays private/in-circuit; NO plaintext amount is emitted.
    #[event]
    struct ChangeNoteAppendedV4 has drop, store {
        leaf_index: u64,             // GLOBAL unified-tree append index (post-increment)
        change_commitment: vector<u8>,
        asset_type: address,         // the partial-withdraw's asset (change is same-asset)
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
        // ASP/CP6 (asp-tree-design §6/§8): deposit_sender[commitment] map for ragequit (CP6).
        move_to(admin, DepositSenderMap { by_commitment: table::new<vector<u8>, address>() });

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

    // ============================================================================
    // V4 multi-asset onboarding lifecycle (CP2 MB-1). DORMANT->ACTIVE two-step register, so a
    // not-yet-allow-listed asset (e.g. a stablecoin behind the CA double wall) can be registered
    // DORMANT now and activated later with one admin tx, zero module upgrade. Design:
    // dormant-lifecycle-VERIFIED §2; main design §4.3.
    // ============================================================================

    // STEP 1 — register asset metadata only. ALWAYS succeeds even for a not-yet-allow-listed asset
    // (does NOT call register_raw). Inserts status=DORMANT into the append-only registry +
    // appends asset_list. asset_id_fr is COMPUTED ON-CHAIN via derive_asset_id(asset_type), never
    // a caller arg (FIX-3). asset_type/asset_id_fr/decimals are immutable after this.
    public entry fun register_asset_metadata_v4(
        admin: &signer,
        asset_addr: address,
        vault_addr_hash_fr: vector<u8>,
        decimals: u8,
    ) acquires VaultCoreV4, AssetRegistryV4, DepositBindingTestOverride {
        assert_admin_v4(admin);
        // FIX-5: the DepositBindingTestOverride short-circuits derive_asset_id to a constant — its
        // presence on a live module would collapse every asset to the same asset_id_fr. Refuse to
        // register while it exists (cutover checklist also verifies absence before flipping active).
        assert!(!exists<DepositBindingTestOverride>(@eunoma), E_ASSET_ID_MISMATCH);
        assert_hash(&vault_addr_hash_fr);

        let registry = borrow_global_mut<AssetRegistryV4>(@eunoma);
        // APPEND-ONLY: asset_addr must not already be present.
        assert!(!table::contains(&registry.by_asset, asset_addr), E_ASSET_ID_MISMATCH);

        let asset_type = object::address_to_object<fungible_asset::Metadata>(asset_addr);
        // Compute asset_id_fr ON-CHAIN. Never a caller arg (MA-1 / FIX-3).
        let asset_id_fr = derive_asset_id(asset_type);
        // Uniqueness: the derived asset_id_fr must not already be used by another registered asset
        // (no two asset_addrs may share an asset_id_fr — would break the Poseidon-link routing).
        assert!(!asset_id_fr_in_use(&registry.asset_list, &registry.by_asset, &asset_id_fr), E_ASSET_ID_MISMATCH);

        table::add(&mut registry.by_asset, asset_addr, AssetVaultStateV4 {
            asset_type,
            asset_id_fr,
            vault_addr_hash_fr,
            vault_ek: vector::empty<u8>(),   // ∅ while DORMANT; filled at activate
            decimals,
            deposit_count: 0,
            status: ASSET_STATUS_DORMANT,
        });
        vector::push_back(&mut registry.asset_list, asset_addr);
    }

    // STEP 2 — CA-register the (already metadata-registered) asset + flip ACTIVE. Succeeds ONLY
    // after Aptos allow-lists the asset (register_raw hard-asserts is_confidentiality_enabled).
    // Reads asset_type FROM THE REGISTRY (never a caller-supplied asset_type) so a remap is
    // impossible. ACTIVE is reachable ONLY through this register_raw-bearing path (no standalone
    // set_status). vault_ek must equal the shared threshold CA EK (chosen default, §7).
    public entry fun activate_asset_ca_v4(
        admin: &signer,
        asset_addr: address,
        vault_ek: vector<u8>,
        registration_sigma_comm: vector<vector<u8>>,
        registration_sigma_resp: vector<vector<u8>>,
    ) acquires VaultCoreV4, AssetRegistryV4, DeoperatorConfigV2 {
        assert_admin_v4(admin);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        // Chosen default (§7): ONE shared threshold CA EK across all assets.
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        assert!(vault_ek == cfg.vault_ek, E_BAD_VAULT_EK);

        let core = borrow_global<VaultCoreV4>(@eunoma);
        let vault_signer = account::create_signer_with_capability(&core.vault_signer_cap);

        // Read the row + assert DORMANT (idempotency belt over the framework store-exists abort).
        // Read st.asset_type from the registry FIRST (never a caller arg), then register_raw.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        assert!(table::contains(&registry.by_asset, asset_addr), E_ASSET_ID_MISMATCH);
        let asset_type = table::borrow(&registry.by_asset, asset_addr).asset_type;
        assert!(table::borrow(&registry.by_asset, asset_addr).status == ASSET_STATUS_DORMANT, E_ASSET_ALREADY_ACTIVE);

        // register_raw FIRST — internally hard-asserts is_confidentiality_enabled_for_asset_type;
        // aborts E_ASSET_TYPE_DISALLOWED until Aptos allow-lists. Any abort rolls back the whole tx.
        confidential_asset::register_raw(
            &vault_signer,
            asset_type,
            *&vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        // ONLY AFTER register_raw returns: set vault_ek + flip ACTIVE. Never touches the immutable
        // asset_type / asset_id_fr / decimals triple.
        let st = table::borrow_mut(&mut borrow_global_mut<AssetRegistryV4>(@eunoma).by_asset, asset_addr);
        st.vault_ek = vault_ek;
        st.status = ASSET_STATUS_ACTIVE;
    }

    // init_v4 — create_resource_account ONCE, seed the global core/tables/registry, and onboard
    // APT (register DORMANT then activate=ACTIVE). Stablecoins ship DORMANT (register only, no
    // activate) — only APT is ACTIVE at init. FIX-5: assert the DepositBindingTestOverride is
    // absent so derive_asset_id is honest on the live module.
    public entry fun init_v4(
        admin: &signer,
        vault_seed: vector<u8>,
        apt_asset_type: Object<fungible_asset::Metadata>,
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
        apt_decimals: u8,
    ) acquires VaultCoreV4, AssetRegistryV4, DeoperatorConfigV2, DepositBindingTestOverride {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<VaultCoreV4>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(!exists<AssetRegistryV4>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(!exists<BridgeTablesV4>(@eunoma), E_ALREADY_INITIALIZED);
        // FIX-5: the override collapses derive_asset_id to a constant — must be absent on a live init.
        assert!(!exists<DepositBindingTestOverride>(@eunoma), E_ASSET_ID_MISMATCH);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        // ONE shared resource account for N CA assets (T1).
        let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
        let vault_addr = signer::address_of(&vault_signer);

        // Seed the global core, registry, and tables.
        move_to(admin, VaultCoreV4 {
            admin: signer::address_of(admin),
            vault_addr,
            vault_signer_cap,
            paused: false,
            next_leaf_index: 0,
            vault_sequence: 0,
        });
        move_to(admin, AssetRegistryV4 {
            by_asset: table::new<address, AssetVaultStateV4>(),
            asset_list: vector::empty<address>(),
        });
        move_to(admin, BridgeTablesV4 {
            used_deposit_nonces: table::new<vector<u8>, bool>(),
            used_nullifiers: table::new<vector<u8>, bool>(),
            known_roots: table::new<vector<u8>, bool>(),
        });

        // Deoperator config (threshold hard-set to THRESHOLD_V2 = 5 — no override path).
        if (!exists<DeoperatorConfigV2>(@eunoma)) {
            move_to(admin, DeoperatorConfigV2 {
                operator_set_version,
                dkg_epoch,
                threshold: THRESHOLD_V2,
                roster_hash,
                frost_group_pubkey,
                vault_ek: *&vault_ek,
                deposit_circuit_version,
                withdraw_circuit_version,
                ca_payload_circuit_version,
                fallback_pubkeys,
            });
        };

        // ASP/CP6: deposit_sender map for ragequit (global, asset-agnostic).
        if (!exists<DepositSenderMap>(@eunoma)) {
            move_to(admin, DepositSenderMap { by_commitment: table::new<vector<u8>, address>() });
        };

        // Onboard APT: register metadata DORMANT then activate=ACTIVE. Only APT is ACTIVE at init;
        // stablecoins ship DORMANT (a later register_asset_metadata_v4 + activate_asset_ca_v4).
        let apt_asset_addr = object::object_address(&apt_asset_type);
        let apt_vault_addr_hash_fr = derive_vault_addr_hash(vault_addr);
        register_asset_metadata_v4(admin, apt_asset_addr, apt_vault_addr_hash_fr, apt_decimals);
        activate_asset_ca_v4(
            admin,
            apt_asset_addr,
            vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        event::emit(VaultInitializedV2 {
            vault_addr,
            asset_type: apt_asset_addr,
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
    ) acquires BridgeVault, DeoperatorConfigV2, VaultPublicInputsV2, DepositBindingTestOverride, CircuitVersionsHashCacheV2 {
        // Codex fix: rollover is the V1→V2 bootstrap that CREATES BridgeVaultTablesV2. The
        // tightened assert_initialized() would falsely abort here because V2 tables don't
        // exist yet. Replace with narrower pre-rollover checks (BridgeVault + cfg only).
        assert!(exists<BridgeVault>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<DeoperatorConfigV2>(@eunoma), E_NOT_INITIALIZED);
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
        // ASP/CP6 (asp-tree-design §6/§8): seed deposit_sender map at the V1->V2 rollover bootstrap.
        // Guarded because rollover may be re-run paths; the map is additive and never reset.
        if (!exists<DepositSenderMap>(@eunoma)) {
            move_to(admin, DepositSenderMap { by_commitment: table::new<vector<u8>, address>() });
        };

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

        // C2 gas opt: refresh circuit_versions_hash cache. Defensive: skip if not yet initialized.
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            let cfg_ref = borrow_global<DeoperatorConfigV2>(@eunoma);
            let new_hash = circuit_versions_hash(cfg_ref);
            borrow_global_mut<CircuitVersionsHashCacheV2>(@eunoma).hash = new_hash;
        };

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
    ) acquires BridgeVault, DeoperatorConfigV2, CircuitVersionsHashCacheV2 {
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

        // C2 gas opt: refresh circuit_versions_hash cache. Defensive: skip if not yet initialized.
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            let cfg_ref = borrow_global<DeoperatorConfigV2>(@eunoma);
            let new_hash = circuit_versions_hash(cfg_ref);
            borrow_global_mut<CircuitVersionsHashCacheV2>(@eunoma).hash = new_hash;
        };
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

    // V4 clean-replace: record roots into BridgeTablesV4. The legacy V2 recorder writes
    // BridgeVaultTablesV2, which does not exist on a fresh V4 package; withdraw V4 checks the
    // unified BridgeTablesV4.known_roots table.
    public entry fun record_known_root_v4(
        admin: &signer,
        root: vector<u8>,
    ) acquires VaultCoreV4, BridgeTablesV4 {
        assert_admin_v4(admin);
        assert_hash(&root);
        record_known_root_internal_v4(*&root);
        event::emit(RootRecordedV2 { root });
    }

    // R7-OPS-1: admin one-time init seeds RecorderDelegate.addr = admin's own address.
    // After init, admin can rotate via admin_set_recorder_delegate. This is required
    // before any record_known_root_v2_via_delegate call.
    public entry fun init_recorder_delegate(admin: &signer) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<RecorderDelegate>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, RecorderDelegate { addr: signer::address_of(admin) });
    }

    // R7-OPS-1: admin rotates the recorder delegate address. Setting to a non-admin
    // operator address (e.g., alpha-box testnet-relayer) lets the operator timer call
    // record_known_root_v2_via_delegate without holding admin keys. Re-callable any time
    // by admin to revoke (set back to admin addr) or rotate to a new operator.
    public entry fun admin_set_recorder_delegate(
        admin: &signer,
        delegate_addr: address,
    ) acquires RecorderDelegate, BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global_mut<RecorderDelegate>(@eunoma);
        rd.addr = delegate_addr;
    }

    // (C) gas economics: one-time init of the flat plain-APT relayer-gas fee + communal reserve
    // address. No-op-safe: until this runs, deposit_step2b collects no fee (exists<> guard there).
    public entry fun init_gas_fee_config_v1(
        admin: &signer,
        flat_fee_octas: u64,
        reserve_addr: address,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<GasFeeConfigV1>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, GasFeeConfigV1 { flat_fee_octas, reserve_addr });
    }

    // (C) gas economics: admin retunes the flat fee / rotates the reserve / zeroes the fee.
    // flat_fee_octas = 0 is the incident kill-switch — disables collection with no redeploy.
    public entry fun admin_set_gas_fee_config_v1(
        admin: &signer,
        flat_fee_octas: u64,
        reserve_addr: address,
    ) acquires GasFeeConfigV1, BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(exists<GasFeeConfigV1>(@eunoma), E_GAS_FEE_NOT_INITIALIZED);
        let c = borrow_global_mut<GasFeeConfigV1>(@eunoma);
        c.flat_fee_octas = flat_fee_octas;
        c.reserve_addr = reserve_addr;
    }

    // R7-OPS-1: delegate-signed root recording. Sender must match RecorderDelegate.addr
    // (set by admin via admin_set_recorder_delegate). Same effect as record_known_root_v2
    // but no admin key required on the operator machine. Strict scope: only writes to
    // known_roots table — cannot touch any other admin-controlled state.
    public entry fun record_known_root_v2_via_delegate(
        delegate: &signer,
        root: vector<u8>,
    ) acquires RecorderDelegate, BridgeVaultTablesV2 {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        assert_hash(&root);
        record_known_root_internal(*&root);
        event::emit(RootRecordedV2 { root });
    }

    public entry fun record_known_root_v4_via_delegate(
        delegate: &signer,
        root: vector<u8>,
    ) acquires RecorderDelegate, BridgeTablesV4 {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        assert_hash(&root);
        record_known_root_internal_v4(*&root);
        event::emit(RootRecordedV2 { root });
    }

    // ASP (2026-05-30, asp-tree-design §6 / D4): admin one-time init seeds ASPRecorderDelegate.addr
    // = admin's own address, and seeds an empty KnownASPRoots log. After init, admin can rotate the
    // delegate via admin_set_asp_recorder_delegate. Required before any record_asp_root_via_delegate.
    // Mirrors init_recorder_delegate exactly (same low-priv, no-admin-key delegate pattern).
    public entry fun init_asp_recorder_delegate(admin: &signer) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<ASPRecorderDelegate>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, ASPRecorderDelegate { addr: signer::address_of(admin) });
        if (!exists<KnownASPRoots>(@eunoma)) {
            move_to(admin, KnownASPRoots { sets: vector::empty<AssociationSetData>() });
        };
    }

    // ASP: admin rotates the asp-recorder delegate address. Setting to a low-priv operator address
    // lets the off-chain re-fork timer push ASP roots without holding admin keys. Re-callable any
    // time by admin to revoke (set back to admin addr) or rotate. Mirrors admin_set_recorder_delegate.
    public entry fun admin_set_asp_recorder_delegate(
        admin: &signer,
        delegate_addr: address,
    ) acquires ASPRecorderDelegate, BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(exists<ASPRecorderDelegate>(@eunoma), E_ASP_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global_mut<ASPRecorderDelegate>(@eunoma);
        rd.addr = delegate_addr;
    }

    // ASP: delegate-signed ASP-root recording. Sender must match ASPRecorderDelegate.addr (set by
    // admin). Appends one AssociationSetData{root, ipfs_cid, now} to the KnownASPRoots log and emits
    // ASPRootRecorded. Strict scope: only appends to KnownASPRoots — cannot touch any other state.
    // No admin key required on the operator box. Mirrors record_known_root_v2_via_delegate.
    public entry fun record_asp_root_via_delegate(
        delegate: &signer,
        root: vector<u8>,
        ipfs_cid: vector<u8>,
    ) acquires ASPRecorderDelegate, KnownASPRoots {
        assert!(exists<ASPRecorderDelegate>(@eunoma), E_ASP_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<ASPRecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_ASP_RECORDER_DELEGATE);
        assert_hash(&root);
        let known = borrow_global_mut<KnownASPRoots>(@eunoma);
        vector::push_back(&mut known.sets, AssociationSetData {
            root: *&root,
            ipfs_cid: *&ipfs_cid,
            timestamp: timestamp::now_seconds(),
        });
        event::emit(ASPRootRecorded { root, ipfs_cid });
    }

    public entry fun deposit_with_commitment_v2(
        sender: &signer,
        // V4 (CP2 MB-2): asset_addr +1 routing key (also bound into the deop attestation as
        // asset_type_addr — a wrong asset_addr fails attestation). Registry resolution adds the
        // per-asset status gate.
        asset_addr: address,
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingDepositBindingsV2, PendingDepositBindingsV3, DeoperatorConfigV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_not_expired(expiry_secs);
        // R6-A.1: inline 3-hash block (mirrors R5-G.2 assert_6_withdraw_hashes idiom).
        assert_3_deposit_hashes(&commitment, &amount_tag, &ca_payload_hash);

        // V4 MB-2 (LOAD-BEARING): STATUS GATE at the TOP, BEFORE the nonce mark + any global write.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        let asset_id_fr = *&st.asset_id_fr;
        let vault_addr_hash_fr = *&st.vault_addr_hash_fr;
        assert!(derive_asset_id(asset_type) == asset_id_fr, E_ASSET_ID_MISMATCH);

        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        let vault_addr = core.vault_addr;

        // Nonce mark AFTER the status gate (MB-2 ordering invariant).
        {
            let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
            check_and_mark_deposit_nonce_v4(tables, &deposit_nonce);
        };

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        // R6-B.4: bool-return in-place compare; avoids 32B alloc + 32-byte `==` loop.
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        // R6-C.2 hoist: cvh local enables ref-pass to R6-C.1 struct-free serializer.
        let cvh = get_or_compute_circuit_versions_hash(cfg);
        // R6-C.1: struct-free BCS serializer (mirrors R5-C withdraw analog at line 1416).
        // Byte-identical to bcs::to_bytes(&DepositAttestationV2Message{...}) per byte-identity
        // tests in round6_wave_d_deposit_msg_byte_identity_tests.move. Saves ~500-800 gas/deposit
        // (struct walker frame + heap alloc + drop + 6 redundant vec32 bcs allocs).
        let msg_bytes = serialize_deposit_attestation_v3_msg(
            &DOMAIN_DEPOSIT_V3,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &commitment,
            &amount_tag,
            &ca_payload_hash,
            &deposit_nonce,
            expiry_secs,
            &cvh,
            // (B) monolith self-deposit: user IS the submitter, so user_addr = sender.
            signer::address_of(sender),
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // B1-v2 gas opt: pass &amount_p directly. consume_or_verify handles digest computation
        // internally only on cache-miss / V2-cache / Groth16 fallback. V3 cache-hit (happy
        // path post-migration) skips 4-Poseidon compute entirely (~700 gas saved per deposit).
        // R7-W1: pass sender_addr for composite (sender, commitment) V3 cache lookup.
        consume_or_verify_deposit_binding(
            signer::address_of(sender),
            &asset_id_fr,
            &vault_addr_hash_fr,
            &commitment,
            &amount_tag,
            &amount_p,
            deposit_binding_proof,
        );

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

        // V4 (§10.1): advance the GLOBAL unified-tree append index AFTER confidential_transfer_raw
        // succeeds (a failed CA payload must NOT advance it, else the off-chain builder sees a
        // dense-index gap). The per-asset deposit_count is a separate observer cursor.
        core.next_leaf_index = core.next_leaf_index + 1;
        let leaf_index = core.next_leaf_index;
        let new_deposit_count = {
            let st_mut = table::borrow_mut(&mut borrow_global_mut<AssetRegistryV4>(@eunoma).by_asset, asset_addr);
            st_mut.deposit_count = st_mut.deposit_count + 1;
            st_mut.deposit_count
        };

        // Post-success deposit event. Observers advance their local state-share cursor strictly
        // ordered by the global leaf_index. (V4 DepositConfirmedV4 event is a separate stage;
        // the retained DepositConfirmedV2 shape is reused here with the global counter as
        // deposit_count for now.)
        let _ = new_deposit_count;
        event::emit(DepositConfirmedV2 {
            vault_addr,
            asset_type: asset_type_addr,
            deposit_count: leaf_index,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
        });
    }

    // ============================================================================
    // R6-Plan-B: split-tx deposit (step2a + step2b) for Petra ~13k execution cap.
    //
    // Single-tx deposit_with_commitment_v2 hits ~14-18k step2 gas (~8-11k CA framework
    // sigma-proof + ~3-7k Eunoma own-verify). Petra rejects at sim time > ~13k.
    // Split: step2a runs Eunoma own-verify (~3-5k); step2b invokes CA framework (~10-13k).
    // Both signed by SAME user (CA framework requires sender's signer to debit balance).
    //
    // Anti vault-drain: step2b RECOMPUTES ca_payload_hash from supplied CA args + asserts
    // == ca_payload_hash stored at step2a. Without this, attacker (= same signer) could
    // submit step2a with args_X (binds commitment_X to amount_X via FROST attest), then
    // step2b with args_Y (CA framework verifies args_Y internally + transfers args_Y to
    // vault), creating commitment_X bound to amount_Y -> withdraw amount_X = vault drain.
    //
    // Re-asserts at step2b (per Plan agent B.0 audit):
    //   1. tx.sender == pending.sender (anti-frontrun, same-user enforcement)
    //   2. assert_not_expired(pending.expiry_secs) (anti delayed-attack past FROST expiry)
    //   3. !vault.paused (admin pause must abort in-flight finalizations)
    //   4. ca_payload_hash recompute + match (anti args-substitution vault drain)
    // ============================================================================

    public entry fun deposit_step2a_eunoma_verify(
        sender: &signer,
        // V4 (CP2 MB-2): asset_addr +1 routing key (forwarded to the v3 entry).
        asset_addr: address,
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingDepositBindingsV2, PendingDepositBindingsV3, PendingDepositFinalizationsV3, DeoperatorConfigV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2, DepositBindingTestOverride {
        deposit_step2a_eunoma_verify_v3(
            sender,
            asset_addr,
            signer::address_of(sender),
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            deposit_binding_proof,
            expiry_secs,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
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
    }

    public entry fun deposit_step2a_eunoma_verify_v3(
        // (B) deposit re-key: tx submitter (relayer OR the user themselves) — UNUSED for auth.
        // Authority = the deop FROST attestation (now binds user_addr) + the deposit-binding proof.
        _relayer: &signer,
        // V4 (CP2 MB-2): asset_addr +1 routing key. The deop attestation already binds
        // asset_type_addr, so a wrong asset_addr fails attestation; the registry resolution here
        // adds the per-asset status gate (DORMANT assets are unspendable).
        asset_addr: address,
        // (B) the depositing user's address; the finalization + binding cache are keyed by this,
        // and it is bound into the signed attestation message so a relayer cannot misdirect it.
        user_addr: address,
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingDepositBindingsV2, PendingDepositBindingsV3, PendingDepositFinalizationsV3, DeoperatorConfigV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2, DepositBindingTestOverride {
        assert_initialized_v4();
        assert!(exists<PendingDepositFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);
        assert_not_expired(expiry_secs);
        assert_3_deposit_hashes(&commitment, &amount_tag, &ca_payload_hash);

        // V4 MB-2 (LOAD-BEARING): STATUS GATE at the TOP, BEFORE check_and_mark_deposit_nonce_v4.
        // step2a never calls the CA framework (no store-existence backstop), so gating after the
        // nonce mark would burn a permanent nonce slot + write an undrainable finalization row for
        // a DORMANT asset. Resolve the registry row first and require ACTIVE.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        // V4: per-asset deposit publics from the registry row (deposit circuit FROZEN; only the
        // SOURCE of asset_id_fr / vault_addr_hash_fr moves singleton -> registry).
        let asset_id_fr = *&st.asset_id_fr;
        let vault_addr_hash_fr = *&st.vault_addr_hash_fr;
        // V4 MA-1: pin the route to the registry's immutable on-chain-derived asset_id_fr.
        assert!(derive_asset_id(asset_type) == asset_id_fr, E_ASSET_ID_MISMATCH);

        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        let vault_addr = core.vault_addr;

        // Nonce mark AFTER the status gate (MB-2 ordering invariant).
        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        check_and_mark_deposit_nonce_v4(tables, &deposit_nonce);

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let cvh = get_or_compute_circuit_versions_hash(cfg);
        let msg_bytes = serialize_deposit_attestation_v3_msg(
            &DOMAIN_DEPOSIT_V3,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &commitment,
            &amount_tag,
            &ca_payload_hash,
            &deposit_nonce,
            expiry_secs,
            &cvh,
            // (B) deposit re-key: bind the depositing user into the deop-signed attestation so a
            // relayer-submitted step2a is authenticated to user_addr and cannot be misdirected.
            user_addr,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // (B) consume the V3 binding cache under (user_addr, commitment) — prepare_deposit_binding_v3
        // wrote it under the same user_addr. The deposit-binding Groth16 proof already binds the
        // commitment to the user's private nullifier/secret, so keying by user_addr does NOT reopen
        // the R7-W1 squat-DoS (an attacker cannot mint a valid binding for a commitment they don't own).
        consume_or_verify_deposit_binding(
            user_addr,
            &asset_id_fr,
            &vault_addr_hash_fr,
            &commitment,
            &amount_tag,
            &amount_p,
            deposit_binding_proof,
        );

        // Record pending finalization keyed by (user_addr, commitment). step2b (signed by the USER)
        // drains it via compose_pending_key(signer::address_of(sender), commitment) + the
        // entry.sender == signer check, so only the user — not the relayer — can finalize + CA-debit.
        let key = compose_pending_key(user_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        // (B sub-4) contains-guard: a pre-existing (user_addr, commitment) finalization slot is
        // rejected with a named error instead of a raw table::add abort. A same-nonce relayer retry
        // is already stopped earlier by check_and_mark_deposit_nonce_v2 (E_DEPOSIT_NONCE_REPLAY).
        assert!(!table::contains(&pending.by_commitment, *&key), E_PENDING_DEPOSIT_FINALIZATION);
        table::add(&mut pending.by_commitment, key, PendingDepositFinalizationV3 {
            sender: user_addr,
            amount_tag: *&amount_tag,
            ca_payload_hash: *&ca_payload_hash,
            deposit_nonce: *&deposit_nonce,
            expiry_secs,
        });

        event::emit(DepositStep2aRecorded {
            commitment,
            sender: user_addr,
            expiry_secs,
        });

        // Owned-by-value args (new_balance_p, etc.) used by-ref above; auto-dropped at
        // scope end (vector<...> has drop). They are re-supplied at step2b for the
        // confidential_transfer_raw call.
    }

    public entry fun deposit_step2b_invoke_framework(
        sender: &signer,
        // V4 (CP2 MB-2): asset_addr +1 routing key.
        asset_addr: address,
        commitment: vector<u8>,
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
    ) acquires VaultCoreV4, AssetRegistryV4, DepositSenderMap, PendingDepositFinalizationsV3, GasFeeConfigV1, DepositBindingTestOverride {
        assert_initialized_v4();
        assert!(exists<PendingDepositFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);

        // R7-W1: composite (sender, commitment) key — table contains() with attacker's
        // address won't collide with victim's slot. entry.sender check below is now
        // structurally enforced by the key itself, but kept as belt-and-suspenders.
        let sender_addr = signer::address_of(sender);
        let key = compose_pending_key(sender_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        assert!(table::contains(&pending.by_commitment, key), E_NO_PENDING_FINALIZATION);
        let entry = table::remove(&mut pending.by_commitment, key);

        // Re-checks (Plan agent B.0 audit): sender, expiry, ca_payload_hash.
        assert!(sender_addr == entry.sender, E_NOT_DEPOSIT_OWNER);
        assert_not_expired(entry.expiry_secs);

        // V4 MB-2: STATUS GATE. PAUSED = drain-in-flight (a post-step2a finalization row settles
        // under ACTIVE or PAUSED; a DORMANT asset is never spendable). MA-1 Poseidon-link the route.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status != ASSET_STATUS_DORMANT, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        assert!(derive_asset_id(asset_type) == st.asset_id_fr, E_ASSET_ID_MISMATCH);

        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        let vault_addr = core.vault_addr;

        // ANTI VAULT-DRAIN: recompute ca_payload_hash from supplied CA args + assert
        // matches entry.ca_payload_hash (verified by step2a's FROST attest binding).
        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &entry.ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

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

        // (C) gas economics — collect a FLAT plain-APT relayer-gas fee from the user (already the
        // signer here) into the communal gas reserve. Zero extra signature. FLAT ONLY: a %-fee paid
        // in cleartext APT would reveal the confidential amount (A = F/p). No-op until admin runs
        // init_gas_fee_config_v1; flat_fee_octas = 0 disables it (incident kill-switch). Atomic with
        // the CA debit above — if the user lacks APT for the fee the whole step2b reverts (no
        // deposit without fee, no fee without deposit). Borrows a different global than `vault`.
        if (exists<GasFeeConfigV1>(@eunoma)) {
            let fee_cfg = borrow_global<GasFeeConfigV1>(@eunoma);
            if (fee_cfg.flat_fee_octas > 0) {
                aptos_account::transfer(sender, fee_cfg.reserve_addr, fee_cfg.flat_fee_octas);
            };
        };

        // V4 (§10.1): advance the GLOBAL unified-tree append index (the leaf ordering key) AFTER
        // the CA transfer succeeds; the per-asset deposit_count is a separate observer cursor.
        core.next_leaf_index = core.next_leaf_index + 1;
        let leaf_index = core.next_leaf_index;
        {
            let st_mut = table::borrow_mut(&mut borrow_global_mut<AssetRegistryV4>(@eunoma).by_asset, asset_addr);
            st_mut.deposit_count = st_mut.deposit_count + 1;
        };

        // ASP/CP6 (asp-tree-design §6/§8): record deposit_sender[commitment] = sender now that the
        // deposit is final (CA transfer succeeded) + commitment known + sender = the signer here.
        // Used by the CP6 ragequit entry to enforce `recipient == deposit_sender[commitment]` so
        // unapproved funds can only exit back to the original depositor. Contains-guard: a duplicate
        // (sender, commitment) finalization cannot reach here (the PendingDepositFinalizationsV3 slot
        // is removed above), but commitment uniqueness across senders is enforced upstream — the
        // guard keeps this idempotent and abort-free. No-op if the map is not yet seeded (a pre-ASP
        // deploy runs init_deposit_sender_map once).
        if (exists<DepositSenderMap>(@eunoma)) {
            let dsm = borrow_global_mut<DepositSenderMap>(@eunoma);
            if (!table::contains(&dsm.by_commitment, *&commitment)) {
                table::add(&mut dsm.by_commitment, *&commitment, sender_addr);
            };
        };

        event::emit(DepositConfirmedV2 {
            vault_addr,
            asset_type: asset_type_addr,
            deposit_count: leaf_index,
            commitment,
            amount_tag: entry.amount_tag,
            ca_payload_hash: entry.ca_payload_hash,
            deposit_nonce: entry.deposit_nonce,
        });
    }

    // ASP/CP6 (asp-tree-design §6/§8): one-time admin seed of the deposit_sender map for deploys
    // that predate this CP (init/rollover seed it for fresh deploys). No-op-safe via exists guard.
    public entry fun init_deposit_sender_map(admin: &signer) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<DepositSenderMap>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, DepositSenderMap { by_commitment: table::new<vector<u8>, address>() });
    }

    // ASP (2026-05-30, asp-tree-design §6): monolith withdraw path. The 3 new publics (asp_root,
    // state_tree_depth, asp_tree_depth) are appended AFTER request_hash (before vault_sequence),
    // the same relative position the relayer uses for prepare_withdraw_proof_v{2,3}. This entry
    // hits the VERIFY branch of consume_or_verify_withdraw_proof, so it both enforces the recent
    // ASP-root window and binds the 3 publics into the Groth16 verify.
    public entry fun withdraw_to_recipient_v2(
        _relayer: &signer,
        // V4 (CP2 MB-3): asset_addr is an explicit +1 positional routing key (attacker-chosen);
        // the registry row is resolved + gated ACTIVE + MA-1 Poseidon-linked to the proof.
        asset_addr: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        asp_root: vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        // V4 (CP1): change_commitment public[12] (EMPTY = 32 zero bytes for a full withdraw).
        change_commitment: vector<u8>,
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, KnownASPRoots, PendingWithdrawProofsV3b, PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3, PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3, DeoperatorConfigV2, PreparedWithdrawProofVK, CircuitVersionsHashCacheV2, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_not_expired(expiry_secs);
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        // ASP: asp_root is a 32B Fr like root.
        assert_hash(&asp_root);
        // V4 CP1: change_commitment is a 32B Fr (EMPTY = 32 zero bytes).
        assert_hash(&change_commitment);

        // V4 MB-2: STATUS GATE at the TOP, before any global table read/write. Resolve the
        // registry row by the attacker-chosen asset_addr and require ACTIVE. V4 MA-1: bind the
        // route to the proof via derive_asset_id(st.asset_type) == st.asset_id_fr (proven_asset_id
        // fed to publics[2]).
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_id = *&st.asset_id_fr;
        assert!(derive_asset_id(asset_type) == asset_id, E_ASSET_ID_MISMATCH);

        // Hold ONE mut borrow on BridgeTablesV4 (global) across known_root check + nullifier check
        // + nullifier mark.
        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        // ASP (asp-tree-design §6): asp_root must be in the recent ASP-root window, parallel to the
        // state-root check above. Reads KnownASPRoots (a different global than `tables`).
        assert!(asp_root_in_recent_window(&asp_root), E_INVALID_ASP_ROOT);

        // V4: hold a single mut borrow on VaultCoreV4 (global signer cap + vault_addr +
        // vault_sequence) across the whole withdraw body.
        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        assert!(core.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = core.vault_addr;
        let asset_type_addr = object::object_address(&asset_type);
        let expected_recipient_hash = derive_recipient_hash(recipient);
        assert!(expected_recipient_hash == recipient_hash, E_RECIPIENT_HASH_MISMATCH);

        let (_, amount_p_digest) = consume_or_compute_withdraw_payload(
            recipient,
            asset_type,
            &request_hash,
            &ca_payload_hash,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        // R5-J (Round 5 A.5): compute circuit_versions_hash once outside the inner fn (which
        // calls into 3 sub-branches all using it). Eliminates inner CircuitVersionsHashCacheV2
        // borrow + 32B clone per call. Saves ~150-300 gas/withdraw.
        let circuit_versions_hash = get_or_compute_circuit_versions_hash(cfg);
        // FR-1.3: 6 `*&` hash clones eliminated; consume_or_verify_withdraw_attestation now &refs.
        consume_or_verify_withdraw_attestation(
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
            vault_addr,
            asset_type_addr,
            &circuit_versions_hash,
        );
        // V4 MA-1: asset_id is the registry-resolved asset_id_fr (Poseidon-linked above), NOT a
        // dead singleton read.
        // ASP: monolith hits the VERIFY branch — pass the real asp_root + depths so they are bound
        // into the Groth16 publics. V4 CP1: change_commitment public[12] also bound here.
        consume_or_verify_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            &asp_root,
            state_tree_depth,
            asp_tree_depth,
            &change_commitment,
            withdraw_proof,
        );

        // V4: derive signer from the held VaultCoreV4 mut borrow, then bump the GLOBAL
        // vault_sequence on the same borrow. nullifier marked in the held BridgeTablesV4 borrow.
        let vault_signer = account::create_signer_with_capability(&core.vault_signer_cap);
        mark_nullifier_used_with_tables_v4(tables, *&nullifier_hash);
        core.vault_sequence = core.vault_sequence + 1;

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

        // FR-1.1 (Round 4 F): emit V3 — no raw recipient/amount_tag/ca_payload_hash on chain.
        event::emit(WithdrawEventV3 {
            root,
            nullifier_hash,
            recipient_hash,
            request_hash,
            vault_sequence,
        });
    }

    public entry fun withdraw_step2a_eunoma_verify_v3(
        relayer: &signer,
        // V4 (CP2 MB-3): asset_addr +1 routing key; change_commitment public[12] (cache re-assert).
        asset_addr: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        change_commitment: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingWithdrawFinalizationsV3, PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3, PendingWithdrawProofsV3b, PendingWithdrawConservationsV4, PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3, DeoperatorConfigV2, PreparedWithdrawProofVK, CircuitVersionsHashCacheV2, DepositBindingTestOverride {
        assert_initialized_v4();
        assert!(exists<PendingWithdrawFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);
        assert_not_expired(expiry_secs);
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        assert_hash(&change_commitment);

        // V4 MB-2: STATUS GATE at the TOP, before any global table read/write + before the
        // finalization-row write. V4 MA-1: Poseidon-link the attacker-chosen route to the proof.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_id = *&st.asset_id_fr;
        assert!(derive_asset_id(asset_type) == asset_id, E_ASSET_ID_MISMATCH);
        let asset_type_addr = object::object_address(&asset_type);

        let tables = borrow_global<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        assert!(core.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = core.vault_addr;
        let expected_recipient_hash = derive_recipient_hash(recipient);
        assert!(expected_recipient_hash == recipient_hash, E_RECIPIENT_HASH_MISMATCH);

        let amount_p_digest = consume_prepared_withdraw_payload_digest(&request_hash, &ca_payload_hash);
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let circuit_versions_hash = get_or_compute_circuit_versions_hash(cfg);
        let empty_signature: vector<u8> = vector[];
        let empty_fallback_signatures: vector<vector<u8>> = vector[];
        consume_or_verify_withdraw_attestation(
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            empty_signature,
            0,
            empty_fallback_signatures,
            cfg,
            vault_addr,
            asset_type_addr,
            &circuit_versions_hash,
        );

        let empty_proof: vector<u8> = vector[];
        // ASP: step2a is CACHE-ONLY (empty_proof -> cache-path early return in
        // consume_or_verify_withdraw_proof). The asp_root window + the 3 asp publics were already
        // enforced/bound when the proof was first verified at prepare_withdraw_proof_v3, so the
        // asp_root / depths are UNUSED here — pass placeholders. change_commitment IS re-asserted
        // against the V3b cache row on the cache-hit (V4 CP1).
        let empty_asp_root: vector<u8> = vector[];
        consume_or_verify_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            &empty_asp_root,
            0,
            0,
            &change_commitment,
            empty_proof,
        );

        // V4 (CP2 MB-4): a PARTIAL withdraw (has_change) MUST have a cached aggregate-Pedersen
        // conservation proof bound to this spend's amount_p_digest. Consume it here (off the
        // step2b CA-transfer hot path) as a HARD GATE before the finalization row is written, so a
        // bad split (A_old != W + A_rem) can never reach the framework transfer. A FULL withdraw
        // (CHANGE_COMMITMENT_EMPTY) has no remainder and skips this (conservation is trivially
        // A_old = W, already enforced by the withdrawn leg's own CA sigma proof).
        if (has_change_commitment(&change_commitment)) {
            consume_withdraw_conservation_v4(&request_hash, &amount_p_digest);
        };

        let sender_addr = signer::address_of(relayer);
        let key = compose_pending_key(sender_addr, &request_hash);
        let pending = borrow_global_mut<PendingWithdrawFinalizationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&key),
            E_PENDING_WITHDRAW_FINALIZATION,
        );
        table::add(&mut pending.by_request_hash, key, PendingWithdrawFinalizationV3 {
            sender: sender_addr,
            asset_addr,
            asset_id,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
            // V4 (CP2 MB-5): carry the validated change_commitment public[12] to TX4.
            change_commitment,
        });
    }

    public entry fun withdraw_step2b_invoke_framework_v3(
        relayer: &signer,
        request_hash: vector<u8>,
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingWithdrawFinalizationsV3, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_hash(&request_hash);

        let sender_addr = signer::address_of(relayer);
        let key = compose_pending_key(sender_addr, &request_hash);
        let pending = borrow_global_mut<PendingWithdrawFinalizationsV3>(@eunoma);
        assert!(table::contains(&pending.by_request_hash, *&key), E_NO_PENDING_FINALIZATION);
        let entry = table::remove(&mut pending.by_request_hash, key);
        assert!(sender_addr == entry.sender, E_NOT_WITHDRAW_OWNER);
        assert!(&entry.request_hash == &request_hash, E_NO_PENDING_FINALIZATION);
        assert_not_expired(entry.expiry_secs);

        // V4 (CP2 MB-3 / FIX-4): re-resolve the SAME registry entry TX3 validated, from the
        // asset_addr stored on the finalization row. MB-2 STATUS GATE: PAUSED is drain-in-flight,
        // so TX4 settles a post-TX3 row under ACTIVE *or* PAUSED, but a DORMANT asset is never
        // spendable. V4 MA-1: re-assert the Poseidon-link against the row's stored asset_id.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, entry.asset_addr);
        assert!(st.status != ASSET_STATUS_DORMANT, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        assert!(derive_asset_id(asset_type) == entry.asset_id, E_ASSET_ID_MISMATCH);

        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &entry.root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &entry.nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        // PAUSED = drain-in-flight: do NOT block a post-TX3 finalization row on core.paused.
        assert!(core.vault_sequence == entry.vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &entry.recipient,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        ));
        assert!(&computed_hash == &entry.ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);

        let vault_signer = account::create_signer_with_capability(&core.vault_signer_cap);
        mark_nullifier_used_with_tables_v4(tables, *&entry.nullifier_hash);
        core.vault_sequence = core.vault_sequence + 1;

        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            asset_type,
            entry.recipient,
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

        event::emit(WithdrawEventV3 {
            root: entry.root,
            nullifier_hash: entry.nullifier_hash,
            recipient_hash: entry.recipient_hash,
            request_hash: entry.request_hash,
            vault_sequence: entry.vault_sequence,
        });

        // V4 (CP2 MB-5, design §3.3/§4.4/§10.1): a PARTIAL withdraw (has_change) appends the
        // change/remainder note commitment as a first-class leaf to the SINGLE global state
        // LeanIMT, under the GLOBAL next_leaf_index. The remainder is NOT backed by a CA transfer
        // (vault->vault is E_SELF_TRANSFER): the withdrawn leg's own framework sigma proof leaves
        // A_rem in the vault's CA available balance, and the change commitment is the spendable
        // claim on that residual (conservation proven by MB-4 + in-circuit, not a per-note ledger).
        // A FULL withdraw (change_commitment == CHANGE_COMMITMENT_EMPTY) appends NO leaf and bumps
        // NO index. The change leaf's amount_p_digest stays private/in-circuit — NO plaintext
        // amount. The event carries NO parent identifier (avoids on-chain parent->change linkage).
        if (has_change_commitment(&entry.change_commitment)) {
            core.next_leaf_index = core.next_leaf_index + 1;
            let leaf_index = core.next_leaf_index;
            event::emit(ChangeNoteAppendedV4 {
                leaf_index,
                change_commitment: entry.change_commitment,
                asset_type: object::object_address(&asset_type),
            });
        };
    }

    // CP6 ragequit access control (asp-tree-design §8 iron law): resolve the original depositor for
    // `commitment` from DepositSenderMap and assert the caller IS that original depositor. Returns
    // the original deposit address (the forced exit recipient). Aborts E_NOT_ORIGINAL_DEPOSITOR if
    // the map is unseeded, the commitment was never deposited, or the caller is not the original
    // depositor. Extracted so the production `ragequit` entry and the CP6 access-control unit tests
    // exercise the SAME code (not a copy).
    fun resolve_ragequit_original_sender(
        depositor_addr: address,
        commitment: &vector<u8>,
    ): address acquires DepositSenderMap {
        assert!(exists<DepositSenderMap>(@eunoma), E_NOT_ORIGINAL_DEPOSITOR);
        let dsm = borrow_global<DepositSenderMap>(@eunoma);
        assert!(table::contains(&dsm.by_commitment, *commitment), E_NOT_ORIGINAL_DEPOSITOR);
        let original_sender = *table::borrow(&dsm.by_commitment, *commitment);
        assert!(depositor_addr == original_sender, E_NOT_ORIGINAL_DEPOSITOR);
        original_sender
    }

    // CP6 ragequit / transparent original-path exit (asp-tree-design §8).
    //
    // The ORIGINAL depositor reclaims their (unapproved / revoked / not-waiting-for-approval)
    // deposit back to the ORIGINAL deposit address, transparently. Security iron law (§8):
    //   - only the original depositor may initiate (assert signer == deposit_sender[commitment]);
    //   - funds can ONLY exit back to the original deposit address (recipient == original_sender);
    //   - the deposit<->exit link is public (commitment is REVEALED in the proof + event).
    // This closes the "deposit -> ragequit to a clean address" laundering escape. NO ASP inclusion
    // and NO asp_root anywhere in ragequit (that is withdraw's job; ragequit is the transparent
    // escape hatch so funds are never frozen). The amount stays CONFIDENTIAL — it rides the exact
    // same CA confidential_transfer_raw path withdraw uses, which hides the amount; ragequit does
    // NOT bypass the CA framework's own σ-proto / range-proof checks (the 14 CA args still pass
    // through confidential_transfer_raw unchanged).
    //
    // vault_sequence binding (the subtle part): the ragequit circuit has NO vault_sequence public
    // input (its 4 publics are commitment/nullifier_hash/root/state_tree_depth), and
    // confidential_transfer_raw itself never takes vault_sequence — vault_sequence is purely
    // Eunoma's own exit-side monotonic nonce. Ragequit's anti-replay is the NULLIFIER: it is a
    // public input of the ragequit proof and is marked spent ATOMICALLY before the transfer, so a
    // given commitment can ragequit at most once (and can never afterwards withdraw privately —
    // same shared nullifier table). We DO still advance vault.vault_sequence after the CA transfer,
    // exactly like both withdraw paths (withdraw_to_recipient_v2:1649 / step2b:1839), so the vault's
    // exit-side counter stays monotonic across every CA transfer the vault performs. We do NOT
    // accept a caller-supplied vault_sequence and do NOT assert vault.vault_sequence == <param>,
    // because there is no proof binding to such a param (the circuit has no vault_sequence public).
    public entry fun ragequit(
        depositor: &signer,
        // V4 (CP2 MB-3): asset_addr +1 routing key. The ragequit circuit has NO asset_id public,
        // so there is no Poseidon-link to a proof here; the registry row only sources asset_type
        // for the CA exit + the status gate. CA-account isolation (the cUSDC store has no APT to
        // move) + the on-chain-derived asset_id_fr immutability still pin the route.
        asset_addr: address,
        commitment: vector<u8>,
        nullifier_hash: vector<u8>,
        root: vector<u8>,
        state_tree_depth: u64,
        ragequit_proof: vector<u8>,
        // The SAME 14 CA-transfer args as withdraw_step2b_invoke_framework_v3, forwarded verbatim
        // into confidential_transfer_raw (recipient is forced = original_sender, not a caller arg).
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
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, DepositSenderMap, PreparedRagequitProofVK {
        // (a) bridge must be initialized.
        assert_initialized_v4();

        // (b)+(c) resolve the original depositor for this commitment and enforce that the signer IS
        // that original depositor. Returns the original deposit address (the forced exit recipient).
        // Aborts E_NOT_ORIGINAL_DEPOSITOR if the commitment was never deposited (or the map is not
        // seeded) or the signer is not the original depositor. Shared with the CP6 access-control
        // unit tests via test_only_resolve_ragequit_original_sender.
        let original_sender = resolve_ragequit_original_sender(signer::address_of(depositor), &commitment);

        // V4 MB-2: STATUS GATE at the TOP, before any global table write. Resolve the registry row
        // by the attacker-chosen asset_addr and require ACTIVE.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;

        // (d) root must be a known state root + the nullifier must not already be spent. Single
        // mut borrow held across the known-root check + nullifier check + mark (same pattern as
        // withdraw_to_recipient_v2).
        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        // (e) verify the standalone ragequit Groth16 (4 publics, exact order; commitment revealed).
        assert_valid_ragequit_proof(&commitment, &nullifier_hash, &root, state_tree_depth, ragequit_proof);

        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        let vault_signer = account::create_signer_with_capability(&core.vault_signer_cap);

        // (f) mark the nullifier spent BEFORE the transfer (anti-replay), then advance the exit-side
        // vault_sequence counter consistently with both withdraw CA-transfer paths.
        mark_nullifier_used_with_tables_v4(tables, *&nullifier_hash);
        core.vault_sequence = core.vault_sequence + 1;

        // (g) CA transfer the (confidential) amount back to the ORIGINAL depositor. Identical
        // confidential_transfer_raw call as withdraw, recipient forced = original_sender.
        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            asset_type,
            original_sender,
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

        // (h) emit the transparent ragequit event (commitment revealed; amount stays confidential).
        event::emit(RagequitEventV1 {
            commitment,
            original_sender,
            nullifier_hash,
            timestamp: timestamp::now_seconds(),
        });
    }

    // V4 (CP2 MB-6, dormant-lifecycle-VERIFIED §3): de-list EMERGENCY EXIT.
    //
    // THE BROKEN ITEM IT FIXES: normal bridge withdraw (withdraw_step2b -> confidential_transfer_raw)
    // AND ragequit both settle via confidential_transfer, which hard-asserts
    // is_confidentiality_enabled_for_asset_type. If Aptos governance DE-LISTS an active asset for CA,
    // EVERY withdraw and ragequit bricks E_ASSET_TYPE_DISALLOWED — total fund freeze. The design's
    // assumption that ragequit is a universal escape is FALSE under de-list.
    //
    // THE FIX (additive, 5-of-7, no redesign): settle via the framework `withdraw_to_raw` primitive,
    // which checks ONLY is_emergency_paused + is_safe_for_confidentiality (NOT the allow-list), to
    // exit funds to PLAIN FA. Authorized by the SAME 5-of-7 FROST attestation layer (THRESHOLD_V2=5,
    // no override). The recipient is PINNED in the signed message (relayer cannot redirect). The
    // asset_type is READ FROM THE REGISTRY (never a caller-supplied asset_type) and Poseidon-link is
    // unnecessary here (no Groth16 / no asset_id public in this path) — CA-account isolation + the
    // immutable registry asset_type pin the route.
    //
    // GATES: (1) status != DORMANT (a never-CA-registered asset has nothing to drain); PAUSED is
    // allowed (emergency drain is exactly when the bridge is winding an asset down). (2) the asset
    // MUST actually be de-listed (is_confidentiality_enabled == false) else E_NOT_DELISTED — while
    // CA is live, use the normal withdraw / ragequit paths.
    //
    // NOTE: withdraw_to_raw exits to PLAIN FA and takes a PLAINTEXT `amount` — the emergency
    // disclosure is intentional and is bound into the 5-of-7 attestation. No note nullifier is
    // consumed (this is a vault-level emergency drain, not a single-note spend); vault_sequence is
    // still advanced for exit-side monotonicity consistency with all other CA-exit paths.
    //
    // RESIDUAL (disclosure, not fixable on-chain): framework-wide set_emergency_paused is checked by
    // EVERY CA primitive INCLUDING withdraw_to_raw, so a global pause halts even this exit. Surface
    // is_emergency_paused() in the UI; never a silent tx error.
    public entry fun emergency_exit_to_raw_v4(
        // Any relayer may submit — authorization is the 5-of-7 FROST attestation, NOT the submitter
        // (recipient + amount are signed; the relayer is low-privilege and cannot redirect funds).
        _relayer: &signer,
        // asset_addr +1 routing key (the registry-resolved row supplies the immutable asset_type).
        asset_addr: address,
        recipient: address,
        amount: u64,
        expiry_secs: u64,
        // 5-of-7 FROST attestation over the emergency-exit message (group sig OR fallback bitmap).
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        // Framework withdraw_to_raw CA args (new available balance + range/sigma proofs).
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires VaultCoreV4, AssetRegistryV4, DeoperatorConfigV2 {
        assert_initialized_v4();
        assert_not_expired(expiry_secs);

        // Resolve the registry row by the attacker-chosen asset_addr; require it was CA-registered
        // at some point (status != DORMANT). asset_type READ FROM REGISTRY (never caller-supplied).
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status != ASSET_STATUS_DORMANT, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let asset_type_addr = object::object_address(&asset_type);

        // The emergency path is ONLY for a governance-de-listed asset. While CA is still enabled,
        // the normal withdraw / ragequit paths work and MUST be used (this entry reveals the amount).
        assert!(
            !confidential_asset::is_confidentiality_enabled_for_asset_type(asset_type),
            E_NOT_DELISTED,
        );

        // 5-of-7 FROST attestation over (asset_type, recipient, amount, expiry) bound to the config
        // epoch. THRESHOLD_V2 = 5 is enforced inside assert_deop_attestation_v2 -> cfg.threshold; no
        // override path exists. The relayer cannot redirect the recipient or change the amount —
        // both are signed bytes.
        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        let vault_addr = core.vault_addr;
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let msg_bytes = serialize_emergency_exit_attestation_v4_msg(
            &DOMAIN_EMERGENCY_EXIT_V4,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            recipient,
            amount,
            expiry_secs,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );

        // Advance the exit-side monotonic nonce (consistent with every other CA-exit path), then
        // drain to plain FA via the de-list-safe framework primitive.
        let vault_signer = account::create_signer_with_capability(&core.vault_signer_cap);
        core.vault_sequence = core.vault_sequence + 1;
        confidential_asset::withdraw_to_raw(
            &vault_signer,
            asset_type,
            recipient,
            amount,
            new_balance_p,
            new_balance_r,
            new_balance_r_aud,
            zkrp_new_balance,
            sigma_proto_comm,
            sigma_proto_resp,
        );
    }

    public entry fun operator_rollover_vault_pending_v2(
        operator: &signer,
    ) acquires BridgeVault, VaultCoreV4, AssetRegistryV4 {
        assert_admin_legacy_or_v4(operator);
        let (vault_signer, asset_type) = vault_signer_and_active_asset_type_legacy_or_v4();
        confidential_asset::rollover_pending_balance(&vault_signer, asset_type);
    }

    // R7-OPS-2: delegate-signed rollover. Same effect as operator_rollover_vault_pending_v2 but
    // the alpha-box operator (testnet-relayer addr, set as RecorderDelegate in OPS-1) signs
    // instead of admin — so a periodic systemd timer can keep deposits flowing pending→available
    // without admin key on the box. Auth gate is identical to record_known_root_v2_via_delegate
    // (delegate must match RecorderDelegate.addr). Strict scope: only triggers the CA framework's
    // own rollover for the bridge vault — cannot touch any other admin-controlled state.
    public entry fun operator_rollover_vault_pending_via_delegate(
        delegate: &signer,
    ) acquires RecorderDelegate, BridgeVault, VaultCoreV4, AssetRegistryV4 {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        let (vault_signer, asset_type) = vault_signer_and_active_asset_type_legacy_or_v4();
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
    ) acquires BridgeVault, VaultCoreV4, AssetRegistryV4 {
        assert_admin_legacy_or_v4(operator);
        let (vault_signer, asset_type) = vault_signer_and_active_asset_type_legacy_or_v4();
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

    public entry fun operator_normalize_vault_balance_via_delegate(
        delegate: &signer,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires BridgeVault, VaultCoreV4, AssetRegistryV4, RecorderDelegate {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        let (vault_signer, asset_type) = vault_signer_and_active_asset_type_legacy_or_v4();
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
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingDepositBindingsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositBindingsV2 {
            by_commitment: table::new<vector<u8>, PendingDepositBindingV2>(),
        });
    }

    // N1 (gas opt): one-time admin migration after publish, populates V3 cache table.
    // Idempotent via E_ALREADY_INITIALIZED. Must run before first deposit post-upgrade.
    public entry fun init_pending_deposit_bindings_v3(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingDepositBindingsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositBindingsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositBindingV3>(),
        });
    }

    // R6-Plan-B: admin init for split-tx pending finalizations table. One-time,
    // idempotent. Must run before first deposit_step2a_eunoma_verify call.
    public entry fun init_pending_deposit_finalizations_v3(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingDepositFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositFinalizationsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositFinalizationV3>(),
        });
    }

    // R6-Plan-B: DEPRECATED in R7-W1. Original signature kept for Aptos backward-compat;
    // body neutered to no-op since R7-W1 composite (sender, commitment) keys make
    // commitment-only sweep meaningless (lookups always miss). Use
    // admin_evict_stale_pending_deposit_finalizations_v2 instead. Zero external callers
    // existed for this entry (codex round-1 grep confirmed).
    public entry fun admin_evict_stale_pending_deposit_finalizations(
        admin: &signer,
        _commitments: vector<vector<u8>>,
    ) acquires BridgeVault {
        assert_admin(admin);
        // Intentional no-op. Old single-key entries (pre-R7-W1) cannot exist — composite
        // key was the same migration so all PendingDeposit*V3 writes use compose_pending_key.
    }

    // R7-W1: composite-key sweep. Takes parallel `senders` + `commitments` arrays.
    // Both arrays must have equal length; mismatched lengths abort with E_BAD_HASH_LENGTH.
    // Frontend/operator monitors PendingDepositFinalizationsV3 expiries + calls this.
    public entry fun admin_evict_stale_pending_deposit_finalizations_v2(
        admin: &signer,
        senders: vector<address>,
        commitments: vector<vector<u8>>,
    ) acquires PendingDepositFinalizationsV3, BridgeVault {
        assert_admin(admin);
        let n = vector::length(&commitments);
        assert!(vector::length(&senders) == n, E_BAD_HASH_LENGTH);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        let now = timestamp::now_seconds();
        let i = 0u64;
        while (i < n) {
            let s = *vector::borrow(&senders, i);
            let c = vector::borrow(&commitments, i);
            let key = compose_pending_key(s, c);
            if (table::contains(&pending.by_commitment, key)) {
                let entry_expiry = table::borrow(&pending.by_commitment, key).expiry_secs;
                if (entry_expiry < now) {
                    let _ = table::remove(&mut pending.by_commitment, key);
                };
            };
            i = i + 1;
        };
    }

    // C1 (gas opt): one-time admin migration after publish, seeds circuit_versions_hash cache
    // from current DeoperatorConfigV2. Idempotent via E_ALREADY_INITIALIZED.
    public entry fun init_circuit_versions_hash_cache_v2(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4, DeoperatorConfigV2 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<CircuitVersionsHashCacheV2>(@eunoma), E_ALREADY_INITIALIZED);
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let hash = circuit_versions_hash(cfg);
        move_to(admin, CircuitVersionsHashCacheV2 { hash });
    }

    // V4 (CP2 MB-3, 2026-06-01): init_pending_withdraw_proofs_v2 DELETED (cache struct removed).

    public entry fun init_pending_withdraw_attestations_v2(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawAttestationsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV2>(),
        });
    }

    public entry fun init_pending_withdraw_payloads_v2(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawPayloadsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawPayloadsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawPayloadV2>(),
        });
    }

    // V4 (CP2 MB-3, 2026-06-01): init_pending_withdraw_proofs_v3 + ..._v2b DELETED (cache
    // structs removed). The only surviving withdraw-proof cache init is ..._v3b below.

    // Round 5 Wave E.5 (R5-R) — admin init for V3b proof cache (now asset_id + change_commitment).
    public entry fun init_pending_withdraw_proofs_v3b(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawProofsV3b>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV3b {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV3b>(),
        });
    }

    public entry fun init_pending_withdraw_attestations_v3(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawAttestationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV3>(),
        });
    }

    // Round 5 Wave E.1 (R5-D) — admin init for V2b attestation cache.
    public entry fun init_pending_withdraw_attestations_v2b(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawAttestationsV2b>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV2b {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV2b>(),
        });
    }

    public entry fun init_pending_withdraw_payloads_v3(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawPayloadsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawPayloadsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawPayloadV3>(),
        });
    }

    public entry fun init_pending_withdraw_finalizations_v3(
        admin: &signer,
    ) acquires BridgeVault, VaultCoreV4 {
        assert_admin_legacy_or_v4(admin);
        assert!(!exists<PendingWithdrawFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawFinalizationsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawFinalizationV3>(),
        });
    }

    // V4 (CP2 MB-4): create the cache-once aggregate-Pedersen conservation table. Admin-only
    // (anchored to @eunoma so it works under the clean-replace V4 deploy where the legacy
    // BridgeVault singleton may be absent). One-shot. The deploy script calls this alongside the
    // other init_pending_* entries after init_v4.
    public entry fun init_pending_withdraw_conservations_v4(
        admin: &signer,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<PendingWithdrawConservationsV4>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawConservationsV4 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawConservationV4>(),
        });
    }

    // V4 (CP2 MB-2): registry-resolving deposit-binding helper. Resolve the row by asset_addr,
    // require ACTIVE, MA-1 Poseidon-link, and return the per-asset (asset_id_fr, vault_addr_hash_fr)
    // deposit publics for the FROZEN deposit circuit.
    fun resolve_active_asset_deposit_publics_v4(asset_addr: address): (vector<u8>, vector<u8>)
        acquires AssetRegistryV4, DepositBindingTestOverride
    {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_id_fr = *&st.asset_id_fr;
        assert!(derive_asset_id(st.asset_type) == asset_id_fr, E_ASSET_ID_MISMATCH);
        (asset_id_fr, *&st.vault_addr_hash_fr)
    }

    public entry fun prepare_deposit_binding_v2(
        _sender: &signer,
        // V4 (CP2 MB-2): asset_addr +1 routing key.
        asset_addr: address,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires AssetRegistryV4, PendingDepositBindingsV2, PreparedDepositBindingVK, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        assert!(exists<PendingDepositBindingsV2>(@eunoma), E_NOT_INITIALIZED);
        // V4 MB-2: STATUS GATE at the TOP (resolve registry, require ACTIVE, MA-1 Poseidon-link).
        let (asset_id_fr, vault_addr_hash_fr) = resolve_active_asset_deposit_publics_v4(asset_addr);
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_deposit_binding_proof(
            &commitment,
            &amount_tag,
            &asset_id_fr,
            &vault_addr_hash_fr,
            &amount_p_digest,
            deposit_binding_proof,
        );
        let pending = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
        assert!(!table::contains(&pending.by_commitment, *&commitment), E_PENDING_DEPOSIT_BINDING);
        table::add(&mut pending.by_commitment, commitment, PendingDepositBindingV2 {
            amount_tag,
            amount_p_digest,
        });
    }

    public entry fun prepare_deposit_binding_v3(
        sender: &signer,
        asset_addr: address,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires AssetRegistryV4, PendingDepositBindingsV3, PreparedDepositBindingVK, DepositBindingTestOverride {
        prepare_deposit_binding_v3_for_user(
            sender,
            asset_addr,
            signer::address_of(sender),
            commitment,
            amount_tag,
            amount_p,
            deposit_binding_proof,
        );
    }

    // Deposit re-key: additive prepare entry with explicit user_addr. Writes V3 cache table under
    // user_addr so the relayer can pre-run this proof on the depositor's behalf without changing
    // the already-published prepare_deposit_binding_v3 ABI.
    public entry fun prepare_deposit_binding_v3_for_user(
        _relayer: &signer,
        asset_addr: address,
        user_addr: address,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires AssetRegistryV4, PendingDepositBindingsV3, PreparedDepositBindingVK, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        // V4 MB-2: STATUS GATE at the TOP (resolve registry, require ACTIVE, MA-1 Poseidon-link).
        let (asset_id_fr, vault_addr_hash_fr) = resolve_active_asset_deposit_publics_v4(asset_addr);
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_deposit_binding_proof(
            &commitment,
            &amount_tag,
            &asset_id_fr,
            &vault_addr_hash_fr,
            &amount_p_digest,
            deposit_binding_proof,
        );
        // R7-W1: composite (user_addr, commitment) key prevents squat-DoS by adversary
        // pre-occupying victim's commitment slot while still allowing relayer submission.
        let key = compose_pending_key(user_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositBindingsV3>(@eunoma);
        assert!(!table::contains(&pending.by_commitment, *&key), E_PENDING_DEPOSIT_BINDING);
        table::add(&mut pending.by_commitment, key, PendingDepositBindingV3 {
            amount_tag,
            amount_p_digest,
            amount_p,
        });
    }

    // V4 (CP2 MB-3, 2026-06-01): prepare_withdraw_proof_v2 DELETED (wrote the asset_id-blind V2b
    // cache). Only prepare_withdraw_proof_v3 ships, and it now resolves the registry by asset_addr.

    // V4 (CP2 MB-2 + MB-3, 2026-06-01): prepare writes V3b carrying asset_id + change_commitment
    // (re-asserted on cache-hit). asset_addr is threaded as an explicit +1 call-arg (the
    // attacker-chosen routing key); the registry row is resolved, gated status==ACTIVE at the TOP
    // before any global table read/write, and the MA-1 Poseidon-link assert
    // derive_asset_id(st.asset_type) == proven_asset_id (proven_asset_id := st.asset_id_fr fed to
    // publics[2]) fuses the route to the proof. change_commitment is the CP1 public[12]
    // (EMPTY = 32 zero bytes for a full withdraw).
    // ASP (2026-05-30, asp-tree-design §6): the 3 ASP publics (asp_root, state_tree_depth,
    // asp_tree_depth) keep their position AFTER request_hash (before vault_sequence). asp_root is
    // checked against the recent ASP-root window here; the Groth16 verify binds all 13 publics.
    public entry fun prepare_withdraw_proof_v3(
        _sender: &signer,
        asset_addr: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        asp_root: vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        change_commitment: vector<u8>,
        vault_sequence: u64,
        amount_p_old: vector<vector<u8>>,
        withdraw_proof: vector<u8>,
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, KnownASPRoots, PendingWithdrawProofsV3b, PreparedWithdrawProofVK, DepositBindingTestOverride {
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p_old);
        prepare_withdraw_proof_v4(
            _sender,
            asset_addr,
            root,
            nullifier_hash,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            asp_root,
            state_tree_depth,
            asp_tree_depth,
            change_commitment,
            vault_sequence,
            amount_p_digest,
            withdraw_proof,
        );
    }

    // V4 IC7 optimized prepare: amount_p_digest is proof-public, so this hot path avoids the
    // expensive Move-side Poseidon8 over amount_p_old while preserving the old v3 ABI above.
    public entry fun prepare_withdraw_proof_v4(
        _sender: &signer,
        asset_addr: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        asp_root: vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        change_commitment: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        withdraw_proof: vector<u8>,
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, KnownASPRoots, PendingWithdrawProofsV3b, PreparedWithdrawProofVK, DepositBindingTestOverride {
        assert_initialized_v4();
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        // ASP: asp_root is a 32B Fr like root.
        assert_hash(&asp_root);
        // V4 CP1: change_commitment is a 32B Fr (EMPTY = 32 zero bytes).
        assert_hash(&change_commitment);
        assert_hash(&amount_p_digest);
        assert!(exists<PendingWithdrawProofsV3b>(@eunoma), E_NOT_INITIALIZED);
        // V4 MB-2: STATUS GATE at the TOP, before any global table read/write. Resolve the
        // registry row by the attacker-chosen asset_addr and require ACTIVE.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        // V4 MA-1: proven_asset_id = the registry row's immutable asset_id_fr (fed to publics[2]);
        // the Poseidon-link assert fuses the route to the proof.
        let asset_id = *&st.asset_id_fr;
        assert!(derive_asset_id(st.asset_type) == asset_id, E_ASSET_ID_MISMATCH);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE Groth16 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        };
        let tables = borrow_global<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        // ASP (asp-tree-design §6): asp_root must be in the recent ASP-root window.
        assert!(asp_root_in_recent_window(&asp_root), E_INVALID_ASP_ROOT);
        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        assert!(core.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        assert_valid_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            &asp_root,
            state_tree_depth,
            asp_tree_depth,
            &change_commitment,
            withdraw_proof,
        );
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        assert!(!table::contains(&pending.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV3b {
            root,
            nullifier_hash,
            asset_id,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            vault_sequence,
            amount_p_digest,
            change_commitment,
        });
    }

    // V4 (CP2 MB-2, 2026-06-01): prepare_withdraw_attestation_v2 DELETED (read the now-runtime-
    // absent BridgeVault singleton). Only prepare_withdraw_attestation_v3 ships (registry-resolving).

    // Round 4 WB2.E B — V3 prepare entry for withdraw attestation. msg_hash-only cache
    // (32B vs ~600B V2). msg_bytes computed identically to V2 path so the cache-hit reader
    // can recompute byte-identically. Reuses bcs::to_bytes(&WithdrawAttestationV2Message)
    // because the FROST sig is over that exact byte form — DO NOT change struct shape.
    public entry fun prepare_withdraw_attestation_v3(
        _sender: &signer,
        // V4 (CP2 MB-2/MB-3): asset_addr resolves asset_type from the registry to rebuild the FROST
        // attestation message (which already binds asset_type_addr — so a wrong asset_addr fails
        // signature verification). MB-3 only excludes this entry from the proof-publics Poseidon-link
        // (there is no withdraw proof here), NOT from the status gate / registry resolution.
        asset_addr: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
    ) acquires VaultCoreV4, AssetRegistryV4, BridgeTablesV4, PendingWithdrawAttestationsV3, DeoperatorConfigV2, CircuitVersionsHashCacheV2 {
        assert_initialized_v4();
        assert_not_expired(expiry_secs);
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        assert!(exists<PendingWithdrawAttestationsV3>(@eunoma), E_NOT_INITIALIZED);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS + ed25519 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_ATTESTATION);
        };
        // V4 MB-2: STATUS GATE — resolve the registry row by asset_addr and require ACTIVE.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let tables = borrow_global<BridgeTablesV4>(@eunoma);
        assert!(known_root_recorded_with_tables_v4(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables_v4(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        assert!(core.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = core.vault_addr;
        // FR-1.5(a) Round 4 F: entry-level derive_recipient_hash check dropped here —
        // see prepare_withdraw_attestation_v2 sibling comment for the rationale (same
        // V3 cache-hit msg_hash bind at consume_or_verify_withdraw_attestation
        // line ~2579 + top-level withdraw_to_recipient_v2 enforcement at line ~882-883).

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let versions_hash = get_or_compute_circuit_versions_hash(cfg);
        // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
        let msg_bytes = serialize_withdraw_attestation_v2_msg(
            &DOMAIN_WITHDRAW_V2,
            chain_id::get(),
            @eunoma,
            vault_addr,
            object::object_address(&asset_type),
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            &versions_hash,
        );
        // FR-2.5: pass by ref (was `*&msg_bytes` clone before FR-2.5 — saves ~250B clone).
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        let msg_hash = aptos_hash::keccak256(msg_bytes);
        let pending = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV3 {
            msg_hash,
        });
    }

    // V4 (CP2 MB-3, 2026-06-01): prepare_withdraw_payload_v2 DELETED (it read the now-removed
    // PendingWithdrawProofsV2 cache). Only prepare_withdraw_payload_v3 ships (registry-resolving).

    // Round 4 WB2.E B — V3 prepare entry for withdraw payload. msg_hash + amount_p_digest
    // 64B cache (vs ~600B V2 17-field mirror). msg_hash = ca_payload_hash_to_fr_safe(
    // hash_confidential_transfer_payload_v2(...)) — same computation as V2 path so
    // consume V3-branch reader recomputes byte-identically.
    //
    // FR-4.6 SHIPPED HERE: instead of compute_amount_p_digest_v2(&amount_p) (Compose8,
    // ~700-1500 gas), read proof_cached.amount_p_digest directly. Stage 1
    // prepare_withdraw_proof_v3 already Compose8'd this exact amount_p + Groth16-verified
    // it; reading the cached value is sound (cache key = request_hash binds the inputs).
    public entry fun prepare_withdraw_payload_v3(
        _sender: &signer,
        // V4 (CP2 MB-2 + MB-3): asset_addr +1 routing key. Resolve registry, status-gate, source
        // asset_type for the ca_payload_hash recompute, and re-assert the V3b cache asset_id.
        asset_addr: address,
        recipient: address,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
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
    ) acquires VaultCoreV4, AssetRegistryV4, PendingWithdrawProofsV3b, PendingWithdrawPayloadsV3, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_hash(&ca_payload_hash);
        assert_hash(&request_hash);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS+keccak hash.
        {
            let pending_chk = borrow_global<PendingWithdrawPayloadsV3>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PAYLOAD);
        };
        // V4 MB-2: STATUS GATE at the TOP. V4 MA-1: Poseidon-link the route to the proof.
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let asset_type = st.asset_type;
        let proven_asset_id = *&st.asset_id_fr;
        assert!(derive_asset_id(asset_type) == proven_asset_id, E_ASSET_ID_MISMATCH);
        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(!core.paused, E_PAUSED);
        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &recipient,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        ));
        // R5-O.3 (Round 5 A.10.3): ref equality avoids implicit by-value copies of 32B vec.
        assert!(&computed_hash == &ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
        // V4 (CP2 MB-3): cross-stage proof cache read — V3b ONLY (V3 fallback deleted). V3b
        // carries ca_payload_hash + amount_p_digest + asset_id; re-assert the registry-resolved
        // asset_id here so the payload stage is asset-pinned too.
        let (cached_ca_payload_hash, cached_amount_p_digest) = {
            assert!(exists<PendingWithdrawProofsV3b>(@eunoma), E_INVALID_WITHDRAW_PROOF);
            let proofs_v3b = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
            assert!(table::contains(&proofs_v3b.by_request_hash, *&request_hash), E_INVALID_WITHDRAW_PROOF);
            let pc = table::borrow(&proofs_v3b.by_request_hash, *&request_hash);
            assert!(&pc.asset_id == &proven_asset_id, E_INVALID_WITHDRAW_PROOF);
            (*&pc.ca_payload_hash, *&pc.amount_p_digest)
        };
        assert!(&cached_ca_payload_hash == &ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
        // V4 B-prime partial withdraw splits the proof-bound spent-note digest (A_old)
        // from the CA payload's amount_p (W). The recomputed CA payload hash above pins
        // the current `amount_p` to ca_payload_hash; prepare_withdraw_conservation_v4
        // separately proves A_old = W + A_rem before step2a can finalize a partial spend.
        // Keep carrying the proof cache's A_old digest forward for step2a/proof-cache
        // rebind and conservation consumption.
        let amount_p_digest = cached_amount_p_digest;
        let pending = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PAYLOAD,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawPayloadV3 {
            msg_hash: computed_hash,
            amount_p_digest,
        });
    }

    // V4 (CP2 MB-4, design §6 B-prime / §6.4): cache-once aggregate-Pedersen conservation prepare.
    // This runs the HEAVY curve math (3 multi_scalar_mul + 12 VALIDATING decompressions +
    // point_equals) EXACTLY ONCE, in a dedicated prepare tx OFF the already-over-cap settle path
    // (mirrors the amount_p_digest cache pattern: the hot step2b reads only the cached boolean).
    //
    // It does NOT touch any global mutable state and asserts NOTHING about vault_sequence/nullifier
    // (those are the spend path's job) — it ONLY proves A_old = W + A_rem and pins A_old to the
    // Groth16-bound amount_p_digest (public[8]). The status gate + MA-1 Poseidon-link still run
    // (any prepare tx that resolves the registry must gate ACTIVE before touching the cache table).
    //
    // amount_p_old = the spent note's 4 chunks; amount_p_wd = the withdrawn leg (the SAME amount_p
    // fed to the CA transfer); amount_p_rem = the remainder/change chunks. For a FULL withdraw the
    // caller passes amount_p_rem = the 4 encrypted-zero chunks (A_rem = 0) and amount_p_old ==
    // amount_p_wd, so conservation holds trivially.
    public entry fun prepare_withdraw_conservation_v4(
        _sender: &signer,
        asset_addr: address,
        request_hash: vector<u8>,
        amount_p_digest: vector<u8>,
        amount_p_old: vector<vector<u8>>,
        amount_p_wd: vector<vector<u8>>,
        amount_p_rem: vector<vector<u8>>,
    ) acquires AssetRegistryV4, PendingWithdrawConservationsV4, DepositBindingTestOverride {
        assert_initialized_v4();
        assert_hash(&request_hash);
        assert_hash(&amount_p_digest);
        assert!(exists<PendingWithdrawConservationsV4>(@eunoma), E_NOT_INITIALIZED);
        // Hoist duplicate-pending check BEFORE the heavy curve math (cheap fail-fast).
        {
            let pending_chk = borrow_global<PendingWithdrawConservationsV4>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PAYLOAD);
        };
        // V4 MB-2: STATUS GATE at the TOP, before any global table write. V4 MA-1: Poseidon-link
        // the attacker-chosen route to the proof (proven_asset_id := registry row's asset_id_fr).
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        assert!(derive_asset_id(st.asset_type) == st.asset_id_fr, E_ASSET_ID_MISMATCH);
        // The B-prime conservation check (pins P_old to amount_p_digest; aborts on a bad split).
        assert_amount_conservation_v4(&amount_p_old, &amount_p_wd, &amount_p_rem, &amount_p_digest);
        let pending = borrow_global_mut<PendingWithdrawConservationsV4>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PAYLOAD,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawConservationV4 {
            amount_p_digest,
            conserved: true,
        });
    }

    // V4 (CP2 MB-4): consume the cached conservation boolean on the hot path. Aborts if no row was
    // prepared, if the cached amount_p_digest does not match the spend's bound digest (rebind
    // guard), or if conserved is false (defensive — prepare only ever caches true). Removes the row.
    fun consume_withdraw_conservation_v4(
        request_hash: &vector<u8>,
        amount_p_digest: &vector<u8>,
    ) acquires PendingWithdrawConservationsV4 {
        assert!(exists<PendingWithdrawConservationsV4>(@eunoma), E_NOT_INITIALIZED);
        let pending = borrow_global_mut<PendingWithdrawConservationsV4>(@eunoma);
        assert!(table::contains(&pending.by_request_hash, *request_hash), E_AMOUNT_CONSERVATION);
        let cached = table::remove(&mut pending.by_request_hash, *request_hash);
        assert!(&cached.amount_p_digest == amount_p_digest, E_AMOUNT_CONSERVATION);
        assert!(cached.conserved, E_AMOUNT_CONSERVATION);
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

    public fun is_nullifier_used_v2(nullifier_hash: vector<u8>): bool acquires BridgeVaultTablesV2 {
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
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
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
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
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
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5],
        });
    }

    // V4 (CP1, 2026-06-01): publish the withdraw VK with 14 IC elements (was 13). The partial-
    // withdraw circuit added public[12] change_commitment so the VK has IC[0..13]. ic_13 is the
    // new change_commitment IC; the stored ic vector has 14 elements, matching
    // WITHDRAW_VK_IC_LENGTH = 14.
    public entry fun publish_withdraw_proof_vk_v3_asp(
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
        ic_10: vector<u8>,
        ic_11: vector<u8>,
        ic_12: vector<u8>,
        ic_13: vector<u8>,
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
        assert_g1(&ic_10, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_11, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_12, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_13, E_INVALID_WITHDRAW_PROOF);
        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6];
        assert!(vector::length(&ic) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        });
    }

    // V4 pruned-public withdraw VK. The circuit exposes 6 public inputs, so the IC vector has
    // seven elements (const + 6 publics). The trailing IC args are retained only for upgrade
    // compatibility with the old 14-IC publish selector.
    public entry fun publish_withdraw_proof_vk_v4(
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
        ic_10: vector<u8>,
        ic_11: vector<u8>,
        ic_12: vector<u8>,
        ic_13: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        // Backward-compatible public entry signature: the old V4 publish selector accepted
        // ic_0..ic_13. The pruned VK only stores ic_0..ic_6, but keeping and
        // length-checking the trailing args lets the existing package upgrade succeed.
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_9, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_10, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_11, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_12, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_13, E_INVALID_WITHDRAW_PROOF);
        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6];
        assert!(vector::length(&ic) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        });
    }

    public entry fun rotate_withdraw_proof_vk_v4_digest(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
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
        assert!(WITHDRAW_VK_IC_LENGTH == 2, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1],
        });
    }

    // V4 (CP2 MB-5): publish the V4 deposit-binding VK. The deposit circuit is FROZEN under V4 —
    // its 5 publics (commitment, amount_tag, asset_id, vault_addr_hash, amount_p_digest) keep an IC
    // vector of DEPOSIT_VK_IC_LENGTH = 6 (ic_0..ic_5), UNCHANGED. This is the V4-named clone of
    // publish_deposit_binding_vk_v2_a6 — same 6-IC shape — surfaced as a distinct V4 entry so the
    // clean-replace cutover script targets an unambiguous V4 deposit-VK publish selector while the
    // proving key is regenerated for the fresh module address. Admin-only; one-shot.
    public entry fun publish_deposit_binding_vk_v4(
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
        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5];
        assert!(vector::length(&ic) == DEPOSIT_VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        });
    }

    public entry fun publish_prepared_withdraw_proof_vk_v2(
        admin: &signer,
    ) acquires WithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedWithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    // CP6 ragequit (asp-tree-design §8): publish the standalone ragequit-circuit VK with 5 IC
    // elements (ic_0..ic_4). Clone of publish_withdraw_proof_vk_v3_asp but with 5 IC args (the
    // ragequit circuit has 4 publics + const term, so IC length = RAGEQUIT_VK_IC_LENGTH = 5).
    // Admin-only; one-shot (aborts if a RagequitProofVK already exists).
    public entry fun publish_ragequit_proof_vk(
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
        assert!(!exists<RagequitProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4];
        assert!(vector::length(&ic) == RAGEQUIT_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, RagequitProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        });
    }

    // CP6 ragequit: derive the prepared ragequit VK from the published raw VK. Mirrors
    // publish_prepared_withdraw_proof_vk_v2 exactly (admin-only, one-shot).
    public entry fun publish_prepared_ragequit_proof_vk(
        admin: &signer,
    ) acquires RagequitProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<RagequitProofVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedRagequitProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<RagequitProofVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedRagequitProofVK {
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
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6],
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
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
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
        assert!(exists<BridgeVaultTablesV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<CircuitVersionsHashCacheV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<PendingDepositBindingsV3>(@eunoma), E_NOT_INITIALIZED);
    }

    // V4 (CP2, 2026-06-01): the V4 deploy seeds VaultCoreV4 / AssetRegistryV4 / BridgeTablesV4
    // (NOT the legacy BridgeVault singleton). The registry-resolving spend/deposit/withdraw
    // entries use this gate instead of assert_initialized.
    fun assert_initialized_v4() {
        assert!(exists<VaultCoreV4>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<AssetRegistryV4>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<BridgeTablesV4>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<DeoperatorConfigV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<PendingDepositBindingsV3>(@eunoma), E_NOT_INITIALIZED);
    }

    fun assert_admin(admin: &signer) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
    }

    fun assert_admin_legacy_or_v4(admin: &signer) acquires BridgeVault, VaultCoreV4 {
        if (exists<VaultCoreV4>(@eunoma)) {
            assert_admin_v4(admin);
        } else {
            assert_admin(admin);
        }
    }

    // V4 admin gate — authority anchored to VaultCoreV4.admin (the V4 vault core), independent
    // of the legacy BridgeVault singleton.
    fun assert_admin_v4(admin: &signer) acquires VaultCoreV4 {
        let core = borrow_global<VaultCoreV4>(@eunoma);
        assert!(signer::address_of(admin) == core.admin, E_NOT_ADMIN);
    }

    // V4 registry uniqueness helper — true iff `asset_id_fr` is already the derived asset_id of any
    // registered asset. Enumerates asset_list (small: a handful of assets) and byte-compares each
    // row's immutable asset_id_fr. Guarantees no two asset_addrs share an asset_id_fr (which would
    // break the MA-1 Poseidon-link routing).
    fun asset_id_fr_in_use(
        asset_list: &vector<address>,
        by_asset: &Table<address, AssetVaultStateV4>,
        asset_id_fr: &vector<u8>,
    ): bool {
        let n = vector::length(asset_list);
        let i = 0;
        while (i < n) {
            let a = *vector::borrow(asset_list, i);
            if (&table::borrow(by_asset, a).asset_id_fr == asset_id_fr) {
                return true
            };
            i = i + 1;
        };
        false
    }

    fun vault_signer_and_asset_type(): (signer, Object<fungible_asset::Metadata>) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        (
            account::create_signer_with_capability(&vault.vault_signer_cap),
            vault.asset_type,
        )
    }

    fun vault_signer_and_active_asset_type_legacy_or_v4(): (signer, Object<fungible_asset::Metadata>)
    acquires BridgeVault, VaultCoreV4, AssetRegistryV4 {
        if (exists<VaultCoreV4>(@eunoma)) {
            let core = borrow_global<VaultCoreV4>(@eunoma);
            let registry = borrow_global<AssetRegistryV4>(@eunoma);
            let i = 0;
            let n = vector::length(&registry.asset_list);
            while (i < n) {
                let asset_addr = *vector::borrow(&registry.asset_list, i);
                let st = table::borrow(&registry.by_asset, asset_addr);
                if (st.status == ASSET_STATUS_ACTIVE) {
                    return (
                        account::create_signer_with_capability(&core.vault_signer_cap),
                        st.asset_type,
                    )
                };
                i = i + 1;
            };
            abort E_ASSET_NOT_ACTIVE
        } else {
            vault_signer_and_asset_type()
        }
    }

    // Round 4 WB2.E C / FR-2.5: message_bytes by-ref. Body's two consumers already take &:
    // ed25519::signature_verify_strict takes a `message: vector<u8>` by-value but we only need
    // one `*message_bytes` deref there; assert_valid_fallback_attestation already takes &.
    // Net: 1 ~250B msg_bytes clone eliminated at every caller (4 prepare/consume sites).
    fun assert_deop_attestation_v2(
        message_bytes: &vector<u8>,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
    ) {
        if (vector::length(&group_signature) > 0) {
            // R6-C.3: drop explicit ED25519_SIGNATURE_BYTES check — ed25519::new_signature_from_bytes
            // already asserts len == SIGNATURE_NUM_BYTES (stdlib ed25519.move:91). Mirrors R5-N
            // fallback-path pattern. Saves 1 vector::length call on happy path; wrong-length
            // sigs still abort, error code shifts from E_INVALID_DEOP_SIGNATURE → stdlib
            // invalid_argument (acceptable per R5-N precedent).
            let ok = ed25519::signature_verify_strict(
                &ed25519::new_signature_from_bytes(group_signature),
                &ed25519::new_unvalidated_public_key_from_bytes(*&cfg.frost_group_pubkey),
                *message_bytes,
            );
            assert!(ok, E_INVALID_DEOP_SIGNATURE);
        } else {
            assert_valid_fallback_attestation(
                message_bytes,
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
        // Round 5 Wave F.1 (R5-S): popcount(fallback_bitmap) pre-loop guard. Aborts at
        // ~60 gas if fewer than `cfg.threshold` bits are set, skipping ~25-35k gas worth
        // of ed25519 sig verifies on patently insufficient bitmaps. Semantics preserved:
        // the loop below STILL runs all 7 iterations and verifies every non-empty slot,
        // and the final valid_count threshold check at the bottom is unchanged.
        {
            let popcount = 0u64;
            let bi = 0u64;
            while (bi < MAX_DEOPERATORS) {
                if (bit_is_set(fallback_bitmap, bi)) {
                    popcount = popcount + 1;
                };
                bi = bi + 1;
            };
            assert!(popcount >= cfg.threshold, E_TOO_FEW_DEOP_SIGNATURES);
        };
        let valid_count = 0;
        let i = 0;
        while (i < MAX_DEOPERATORS) {
            let sig = vector::borrow(fallback_signatures, i);
            if (vector::length(sig) > 0) {
                assert!(bit_is_set(fallback_bitmap, i), E_INVALID_DEOP_SIGNATURE);
                let pubkey = vector::borrow(&cfg.fallback_pubkeys, i);
                // R5-N (Round 5 A.9): outer `vector::length` guards dropped — stdlib
                // `ed25519::new_signature_from_bytes` and `new_unvalidated_public_key_from_bytes`
                // already assert their respective size constraints internally. pubkey lengths
                // are additionally pre-validated by `assert_valid_fallback_pubkeys` at admin
                // config time. Saves ~150-350 gas per fallback attestation (up to 14 length
                // calls eliminated across 7 slots). Error code on malformed sig/pubkey changes
                // from E_INVALID_DEOP_SIGNATURE to stdlib's invalid-argument abort.
                let ok = ed25519::signature_verify_strict(
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

    fun deposit_nonce_used(nonce: &vector<u8>): bool acquires BridgeVaultTablesV2 {
        table::contains(
            &borrow_global<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
            *nonce,
        )
    }

    fun mark_deposit_nonce_used(nonce: vector<u8>) acquires BridgeVaultTablesV2 {
        table::add(
            &mut borrow_global_mut<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
            nonce,
            true,
        );
    }

    // V1 (gas opt): combined check+mark helper. Single borrow_global_mut, contains+add atomic.
    // R6-A.2: single `let n = *nonce;` reused for contains (copy) + add (move) — saves 1
    // 32B vector<u8> deref-clone vs prior 2× `*nonce`. Abort code preserved (E_DEPOSIT_NONCE_REPLAY).
    fun check_and_mark_deposit_nonce_v2(nonce: &vector<u8>) acquires BridgeVaultTablesV2 {
        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        let n = *nonce;
        assert!(!table::contains(&tables.used_deposit_nonces, n), E_DEPOSIT_NONCE_REPLAY);
        table::add(&mut tables.used_deposit_nonces, n, true);
    }

    // FR-5.4: dropped `known_root_recorded` — 0 callers after FR-4.1 migrated all 4 prepare
    // entries to `known_root_recorded_with_tables`. Withdraw_to_recipient_v2 used the
    // `_with_tables` variant since WB2.D.

    fun record_known_root_internal(root: vector<u8>) acquires BridgeVaultTablesV2 {
        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        if (!table::contains(&tables.known_roots, *&root)) {
            table::add(&mut tables.known_roots, root, true);
        };
    }

    fun record_known_root_internal_v4(root: vector<u8>) acquires BridgeTablesV4 {
        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        if (!table::contains(&tables.known_roots, *&root)) {
            table::add(&mut tables.known_roots, root, true);
        };
    }

    // ASP (2026-05-30, asp-tree-design §6 / D3): returns true iff `asp_root` byte-equals the root
    // of any of the LAST ASP_ROOT_WINDOW_K recorded Association Sets. Iterates from the end of the
    // append-only KnownASPRoots.sets log, scanning at most min(K, len) entries so older roots age
    // out of the window (revocation takes effect once a commitment's root falls past the window).
    // Returns false if KnownASPRoots does not exist or is empty.
    fun asp_root_in_recent_window(asp_root: &vector<u8>): bool acquires KnownASPRoots {
        if (!exists<KnownASPRoots>(@eunoma)) {
            return false
        };
        let sets = &borrow_global<KnownASPRoots>(@eunoma).sets;
        let len = vector::length(sets);
        if (len == 0) {
            return false
        };
        // Walk backwards from the newest entry, up to K entries.
        let scanned = 0;
        let i = len;
        while (i > 0 && scanned < ASP_ROOT_WINDOW_K) {
            i = i - 1;
            let entry = vector::borrow(sets, i);
            if (&entry.root == asp_root) {
                return true
            };
            scanned = scanned + 1;
        };
        false
    }

    fun nullifier_used(nullifier_hash: &vector<u8>): bool acquires BridgeVaultTablesV2 {
        table::contains(
            &borrow_global<BridgeVaultTablesV2>(@eunoma).used_nullifiers,
            *nullifier_hash,
        )
    }

    // WB2.D/FW8.3: `_with_tables` helper variants that take a borrowed/mut-borrowed
    // BridgeVaultTablesV2 instead of borrowing it themselves. Lets withdraw_to_recipient_v2
    // open ONE borrow_global_mut<BridgeVaultTablesV2> across the whole body and reuse it for
    // known_root check + nullifier check + nullifier mark (collapsing 3 borrow_globals → 1).
    fun known_root_recorded_with_tables(tables: &BridgeVaultTablesV2, root: &vector<u8>): bool {
        table::contains(&tables.known_roots, *root)
    }

    fun nullifier_used_with_tables(tables: &BridgeVaultTablesV2, nullifier_hash: &vector<u8>): bool {
        table::contains(&tables.used_nullifiers, *nullifier_hash)
    }

    fun mark_nullifier_used_with_tables(tables: &mut BridgeVaultTablesV2, nullifier_hash: vector<u8>) {
        table::add(&mut tables.used_nullifiers, nullifier_hash, true);
    }

    // FR-5.4: dropped `mark_nullifier_used` — 0 callers after WB2.D migrated
    // withdraw_to_recipient_v2 to `mark_nullifier_used_with_tables`.

    // V4 (CP2 MB-3, 2026-06-01): _with_tables_v4 variants operating on the GLOBAL BridgeTablesV4
    // (one set across all assets — used_nullifiers is global because asset_id lives in the Compose5
    // preimage, so cross-asset nullifier collisions are cryptographically impossible; known_roots
    // is the one unified state tree's root history).
    fun known_root_recorded_with_tables_v4(tables: &BridgeTablesV4, root: &vector<u8>): bool {
        table::contains(&tables.known_roots, *root)
    }

    fun nullifier_used_with_tables_v4(tables: &BridgeTablesV4, nullifier_hash: &vector<u8>): bool {
        table::contains(&tables.used_nullifiers, *nullifier_hash)
    }

    fun mark_nullifier_used_with_tables_v4(tables: &mut BridgeTablesV4, nullifier_hash: vector<u8>) {
        table::add(&mut tables.used_nullifiers, nullifier_hash, true);
    }

    fun check_and_mark_deposit_nonce_v4(tables: &mut BridgeTablesV4, nonce: &vector<u8>) {
        let n = *nonce;
        assert!(!table::contains(&tables.used_deposit_nonces, n), E_DEPOSIT_NONCE_REPLAY);
        table::add(&mut tables.used_deposit_nonces, n, true);
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

    // WB1/FD5.1 gas opt: 16 params by-ref + manual BCS concat encoder.
    // Move struct fields cannot hold refs, so we skip the CAPayloadForHashV2 intermediate
    // entirely. BCS struct serialization is byte-equivalent to field-by-field concat of
    // each field's bcs::to_bytes (no struct framing / no separator), so output is identical
    // to the old `bcs::to_bytes(&CAPayloadForHashV2 { ... })` form. Eliminates 13 deep nested
    // vector clones (some `vector<vector<vector<u8>>>`) at 3 callsites (deposit/prepare_withdraw_payload/consume_or_compute_withdraw_payload).
    fun hash_confidential_transfer_payload_v2(
        asset_type: &Object<fungible_asset::Metadata>,
        to: &address,
        new_balance_p: &vector<vector<u8>>,
        new_balance_r: &vector<vector<u8>>,
        new_balance_r_eff_aud: &vector<vector<u8>>,
        amount_p: &vector<vector<u8>>,
        amount_r_sender: &vector<vector<u8>>,
        amount_r_recip: &vector<vector<u8>>,
        amount_r_eff_aud: &vector<vector<u8>>,
        ek_volun_auds: &vector<vector<u8>>,
        amount_r_volun_auds: &vector<vector<vector<u8>>>,
        zkrp_new_balance: &vector<u8>,
        zkrp_amount: &vector<u8>,
        sigma_proto_comm: &vector<vector<u8>>,
        sigma_proto_resp: &vector<vector<u8>>,
        memo: &vector<u8>,
    ): vector<u8> {
        let buf = bcs::to_bytes(asset_type);
        vector::append(&mut buf, bcs::to_bytes(to));
        vector::append(&mut buf, bcs::to_bytes(new_balance_p));
        vector::append(&mut buf, bcs::to_bytes(new_balance_r));
        vector::append(&mut buf, bcs::to_bytes(new_balance_r_eff_aud));
        vector::append(&mut buf, bcs::to_bytes(amount_p));
        vector::append(&mut buf, bcs::to_bytes(amount_r_sender));
        vector::append(&mut buf, bcs::to_bytes(amount_r_recip));
        vector::append(&mut buf, bcs::to_bytes(amount_r_eff_aud));
        vector::append(&mut buf, bcs::to_bytes(ek_volun_auds));
        vector::append(&mut buf, bcs::to_bytes(amount_r_volun_auds));
        vector::append(&mut buf, bcs::to_bytes(zkrp_new_balance));
        vector::append(&mut buf, bcs::to_bytes(zkrp_amount));
        vector::append(&mut buf, bcs::to_bytes(sigma_proto_comm));
        vector::append(&mut buf, bcs::to_bytes(sigma_proto_resp));
        vector::append(&mut buf, bcs::to_bytes(memo));
        aptos_hash::keccak256(buf)
    }

    fun ca_payload_hash_to_fr_safe(raw: vector<u8>): vector<u8> {
        // H3+R6-B.3 gas opt: single in-place byte write at index 31 instead of pop+push
        // (2 ops, 2 length recomputes, 1 memmove). Output byte-identical: [raw[0..31], 0u8].
        assert!(vector::length(&raw) == FR_BYTES, E_PAYLOAD_HASH_MISMATCH);
        *vector::borrow_mut(&mut raw, 31) = 0u8;
        raw
    }

    // R6-B.4: in-place bool-return sibling of ca_payload_hash_to_fr_safe.
    // Avoids the 32B allocation of the truncated Fr image + the 32-byte `==` loop.
    // Semantics: returns true iff (raw[0..31] || 0u8) equals *expected.
    // Note: `ca_payload_hash_to_fr_safe` still has 4 withdraw-side callers that need
    // the Fr value as a return — kept for those. Deposit hot-path switched to this.
    fun ca_payload_hash_matches_safe(raw: vector<u8>, expected: &vector<u8>): bool {
        assert!(vector::length(&raw) == FR_BYTES, E_PAYLOAD_HASH_MISMATCH);
        if (vector::length(expected) != FR_BYTES) { return false };
        if (*vector::borrow(expected, FR_BYTES - 1) != 0u8) { return false };
        let i = 0u64;
        while (i < FR_BYTES - 1) {
            if (*vector::borrow(&raw, i) != *vector::borrow(expected, i)) {
                return false
            };
            i = i + 1;
        };
        true
    }

    #[test_only]
    public fun test_call_ca_payload_hash_matches_safe(raw: vector<u8>, expected: vector<u8>): bool {
        ca_payload_hash_matches_safe(raw, &expected)
    }

    fun circuit_versions_hash(cfg: &DeoperatorConfigV2): vector<u8> {
        aptos_hash::keccak256(bcs::to_bytes(&CircuitVersionsForHash {
            deposit_circuit_version: *&cfg.deposit_circuit_version,
            withdraw_circuit_version: *&cfg.withdraw_circuit_version,
            ca_payload_circuit_version: *&cfg.ca_payload_circuit_version,
        }))
    }

    // C3 gas opt: defensive cached-lookup helper. Saves ~500-800 gas per deposit and per
    // withdraw attestation by reading a pre-computed 32B field instead of keccak256+bcs.
    // Falls back to recompute when cache resource not yet initialized (pre-migration window).
    fun get_or_compute_circuit_versions_hash(cfg: &DeoperatorConfigV2): vector<u8>
        acquires CircuitVersionsHashCacheV2
    {
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            *&borrow_global<CircuitVersionsHashCacheV2>(@eunoma).hash
        } else {
            circuit_versions_hash(cfg)
        }
    }

    // R5-F (Round 5 A.2): manual BCS prefix helper. All vector<u8> hash inputs are
    // guaranteed 32 bytes (HASH_BYTES) by upstream `assert_hash` gates; BCS length
    // prefix for length=32 is always the single byte 0x20 (=32u8). Avoids the per-field
    // `bcs::to_bytes(&v)` allocation + struct walker overhead. Output is byte-identical
    // to `bcs::to_bytes(&v32: vector<u8>)`.
    fun append_vec32_bcs(buf: &mut vector<u8>, vec: &vector<u8>) {
        vector::push_back(buf, 32u8);
        vector::append(buf, *vec);
    }

    // Round 4 WB2.E B — Shared msg_hash helper for PendingWithdrawProofV3 cache.
    // Single source of truth: BOTH prepare_withdraw_proof_v3 (writer) AND
    // consume_or_verify_withdraw_proof V3-branch (reader) MUST call this — byte-identity
    // is load-bearing for cache-hit detection. Field order MUST match the Groth16 public
    // input order in assert_valid_withdraw_proof (root, nullifier_hash, asset_id,
    // recipient_hash, amount_tag, ca_payload_hash, vault_sequence_le, amount_p_digest)
    // so cache-hit is provably equivalent to Groth16 verify on identical publics.
    // vault_sequence encoded via bcs (LE u64), NOT u64_to_fr_bytes (BE) — cache key is
    // private to this module, not a circuit input (V3W-1.5 gotcha).
    //
    // R5-F (Round 5 A.2): uses append_vec32_bcs to avoid 7 intermediate bcs allocations
    // for the hash inputs. Saves ~350-560 gas per call across two callsites
    // (prepare_withdraw_proof_v3 + consume_or_verify_withdraw_proof V3-branch).
    fun compute_withdraw_proof_msg_hash(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        append_vec32_bcs(&mut buf, root);
        append_vec32_bcs(&mut buf, nullifier_hash);
        append_vec32_bcs(&mut buf, asset_id);
        append_vec32_bcs(&mut buf, recipient_hash);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        vector::append(&mut buf, bcs::to_bytes(&vault_sequence));
        append_vec32_bcs(&mut buf, amount_p_digest);
        aptos_hash::keccak256(buf)
    }

    // R5-C (Round 5 Wave C): struct-free BCS serializer for WithdrawAttestationV2Message.
    // Mirrors WB1's `hash_confidential_transfer_payload_v2` pattern (manual concat in
    // declaration order). Output is byte-identical to `bcs::to_bytes(&WithdrawAttestationV2Message{...})`
    // because BCS struct encoding = field-by-field concat in declaration order (no struct
    // framing prefix). Field order MUST match struct def at line 328 EXACTLY — FROST signs
    // these bytes. Saves ~500-800 gas per callsite × 4 callsites (V2 + V3 prepare + V3
    // cache-hit recompute + cache-miss).
    //
    // Uses `append_vec32_bcs` for the 9 known-32B vector fields (BCS length prefix = 0x20).
    // `domain` is 30 bytes (b"EUNOMA_WITHDRAW_ATTESTATION_V2") so uses bcs::to_bytes directly.
    // Scalars (u8/u64/address) use bcs::to_bytes directly.
    fun serialize_withdraw_attestation_v2_msg(
        domain: &vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: &vector<u8>,
        frost_group_pubkey: &vector<u8>,
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient: address,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: &vector<u8>,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, bcs::to_bytes(domain));
        vector::append(&mut buf, bcs::to_bytes(&chain_id));
        vector::append(&mut buf, bcs::to_bytes(&bridge));
        vector::append(&mut buf, bcs::to_bytes(&vault));
        vector::append(&mut buf, bcs::to_bytes(&asset_type));
        vector::append(&mut buf, bcs::to_bytes(&operator_set_version));
        vector::append(&mut buf, bcs::to_bytes(&dkg_epoch));
        append_vec32_bcs(&mut buf, roster_hash);
        append_vec32_bcs(&mut buf, frost_group_pubkey);
        append_vec32_bcs(&mut buf, root);
        append_vec32_bcs(&mut buf, nullifier_hash);
        vector::append(&mut buf, bcs::to_bytes(&recipient));
        append_vec32_bcs(&mut buf, recipient_hash);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        append_vec32_bcs(&mut buf, request_hash);
        vector::append(&mut buf, bcs::to_bytes(&vault_sequence));
        vector::append(&mut buf, bcs::to_bytes(&expiry_secs));
        append_vec32_bcs(&mut buf, circuit_versions_hash);
        buf
    }

    // R6-C.1 (Round 6 Wave D): struct-free BCS serializer for DepositAttestationV3Message.
    // Mirrors R5-C serialize_withdraw_attestation_v2_msg exactly. Output is byte-identical
    // to bcs::to_bytes(&DepositAttestationV2Message{...}) because BCS struct encoding =
    // field-by-field concat in declaration order (no framing). Field order MUST match struct
    // def at line 361-377 EXACTLY — FROST signs these bytes. Saves ~500-800 gas/deposit.
    //
    // append_vec32_bcs for the 6 known-32B fields (roster_hash, frost_group_pubkey,
    // commitment, amount_tag, ca_payload_hash, circuit_versions_hash) — all upstream-gated
    // to 32B via assert_3_deposit_hashes (R6-A.1) + init-time roster/pubkey + keccak256 cvh.
    // deposit_nonce uses bcs::to_bytes (variable-length, NOT length-gated) so ULEB128 prefix
    // matches BCS struct encoding for any length (test coverage at 16B + 64B variants).
    fun serialize_deposit_attestation_v3_msg(
        domain: &vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: &vector<u8>,
        frost_group_pubkey: &vector<u8>,
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        deposit_nonce: &vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: &vector<u8>,
        user_addr: address,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, bcs::to_bytes(domain));
        vector::append(&mut buf, bcs::to_bytes(&chain_id));
        vector::append(&mut buf, bcs::to_bytes(&bridge));
        vector::append(&mut buf, bcs::to_bytes(&vault));
        vector::append(&mut buf, bcs::to_bytes(&asset_type));
        vector::append(&mut buf, bcs::to_bytes(&operator_set_version));
        vector::append(&mut buf, bcs::to_bytes(&dkg_epoch));
        append_vec32_bcs(&mut buf, roster_hash);
        append_vec32_bcs(&mut buf, frost_group_pubkey);
        append_vec32_bcs(&mut buf, commitment);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        vector::append(&mut buf, bcs::to_bytes(deposit_nonce));
        vector::append(&mut buf, bcs::to_bytes(&expiry_secs));
        append_vec32_bcs(&mut buf, circuit_versions_hash);
        // Append depositing user's address (raw 32B, no length prefix). The off-chain TS serializer
        // MUST writeAddress here too.
        vector::append(&mut buf, bcs::to_bytes(&user_addr));
        buf
    }

    // V4 (CP2 MB-6): struct-free BCS serializer for the de-list emergency-exit attestation. The
    // 5-of-7 deoperators sign these bytes to authorize a withdraw_to_raw to plain FA. Binds the
    // config epoch (operator_set_version/dkg_epoch/roster_hash/frost_group_pubkey) like the other
    // attestations so a rotated roster auto-invalidates a stale emergency signature; binds the
    // recipient + the PLAINTEXT amount (the emergency disclosure) + an expiry. Field order is
    // load-bearing — the off-chain TS signer MUST serialize identically.
    fun serialize_emergency_exit_attestation_v4_msg(
        domain: &vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: &vector<u8>,
        frost_group_pubkey: &vector<u8>,
        recipient: address,
        amount: u64,
        expiry_secs: u64,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, bcs::to_bytes(domain));
        vector::append(&mut buf, bcs::to_bytes(&chain_id));
        vector::append(&mut buf, bcs::to_bytes(&bridge));
        vector::append(&mut buf, bcs::to_bytes(&vault));
        vector::append(&mut buf, bcs::to_bytes(&asset_type));
        vector::append(&mut buf, bcs::to_bytes(&operator_set_version));
        vector::append(&mut buf, bcs::to_bytes(&dkg_epoch));
        append_vec32_bcs(&mut buf, roster_hash);
        append_vec32_bcs(&mut buf, frost_group_pubkey);
        vector::append(&mut buf, bcs::to_bytes(&recipient));
        vector::append(&mut buf, bcs::to_bytes(&amount));
        vector::append(&mut buf, bcs::to_bytes(&expiry_secs));
        buf
    }

    // B1-v2 (codex fix + real Opt #1): take amount_p (not pre-computed digest). V3 cache-hit
    // path byte-compares amount_p directly (128B vs 32B but no Poseidon recompute — ~700 gas
    // saved). V2 cache-hit + Groth16 fallback compute digest internally. Soundness equivalent:
    // V3 cache was populated by prepare_deposit_binding_v3 which Groth16-verified amount_p
    // binds to commitment via compute_amount_p_digest_v2(amount_p). Adversary substituting
    // different amount_p must fail the 128B byte-compare.
    fun consume_or_verify_deposit_binding(
        sender_addr: address,
        // V4 (CP2 MB-2/MB-3): per-asset deposit publics from the registry-resolved row.
        asset_id_fr: &vector<u8>,
        vault_addr_hash_fr: &vector<u8>,
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        amount_p: &vector<vector<u8>>,
        proof: vector<u8>,
    ) acquires PendingDepositBindingsV3, PendingDepositBindingsV2, PreparedDepositBindingVK {
        // R6-D.2: hoist proof-length check (reused by V3 + V2 branches; saves
        // ~10-30 gas on V2-hit + Groth16-fallback paths; 0 on V3-hit).
        let is_cache_path = vector::length(&proof) == 0;
        // V3 fast path: byte-compare amount_p, skip 4-Poseidon compute entirely.
        // R7-W1: V3 cache lookup keyed by composite (sender, commitment) — squat-proof.
        if (is_cache_path && exists<PendingDepositBindingsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingDepositBindingsV3>(@eunoma);
            let key_v3 = compose_pending_key(sender_addr, commitment);
            if (table::contains(&pending_v3.by_commitment, key_v3)) {
                let cached_v3 = table::remove(&mut pending_v3.by_commitment, key_v3);
                // R6-D.1: fail-fast on amount_p (128B, attacker-most-likely tamper)
                // before amount_tag — defense-in-depth, 0 happy-path cost.
                assert!(&cached_v3.amount_p == amount_p, E_INVALID_DEPOSIT_BINDING_PROOF);
                // R6-D.5: ref-compare avoids 32B `*amount_tag` deref-clone.
                assert!(&cached_v3.amount_tag == amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF);
                return
            };
        };
        // V2 legacy cache: must compute digest locally (no amount_p cached). Caller saved
        // having to compute it before this call. Still skips Groth16 verify on cache hit.
        // V2 deliberately NOT reordered (amount_tag check must precede ~700-gas Poseidon).
        if (is_cache_path && exists<PendingDepositBindingsV2>(@eunoma)) {
            let pending_v2 = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
            let key_v2 = *commitment;
            if (table::contains(&pending_v2.by_commitment, key_v2)) {
                let cached_v2 = table::remove(&mut pending_v2.by_commitment, key_v2);
                // R6-D.5: ref-compare avoids 32B `*amount_tag` deref-clone.
                assert!(&cached_v2.amount_tag == amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF);
                let supplied_digest = compute_amount_p_digest_v2(amount_p);
                assert!(cached_v2.amount_p_digest == supplied_digest, E_INVALID_DEPOSIT_BINDING_PROOF);
                return
            };
        };
        // Groth16 fallback path: no cache, full verify with digest as public input.
        let amount_p_digest = compute_amount_p_digest_v2(amount_p);
        assert_valid_deposit_binding_proof(
            commitment,
            amount_tag,
            asset_id_fr,
            vault_addr_hash_fr,
            &amount_p_digest,
            proof,
        );
    }

    // Round 4 WB2.E B / FR-1.3+V3R-1: by-ref hash params (drops 8 `*&` clones at the single
    // withdraw_to_recipient_v2 caller). Three-tier soft lookup: V3 → V2 → Groth16 verify.
    // Both cache branches use soft `if (table::contains)` (not assert!) so a V3-prepared tx
    // doesn't abort when V2 cache is the only one whose `exists` returns true (V3D-1.4).
    // V3 cache-hit: 1 keccak + 32B byte-eq via shared compute_withdraw_proof_msg_hash
    // (writer + reader use SAME helper → byte-identity guaranteed by construction).
    // V2 cache-hit: legacy 8-field eq, kept for in-flight V2-prepared txs.
    fun consume_or_verify_withdraw_proof(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
        // ASP (2026-05-30, asp-tree-design §6): the 3 new withdraw publics. ONLY the VERIFY branch
        // (proof non-empty) uses them; the cache-path (proof empty) byte-equality branches do NOT —
        // the asp_root window check + the asp publics were already enforced when the proof was first
        // verified at prepare time, so the cache-path callers may pass placeholders here.
        asp_root: &vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        // V4 (CP1): change_commitment public[12] (EMPTY = 32 zero bytes). Bound on both the
        // cache-hit re-assert AND the Groth16 verify fallback.
        change_commitment: &vector<u8>,
        proof: vector<u8>,
    ) acquires PendingWithdrawProofsV3b, PreparedWithdrawProofVK {
        let is_cache_path = vector::length(&proof) == 0;
        // V4 (CP2 MB-3, 2026-06-01): V3b is the ONLY surviving withdraw-proof cache. The legacy
        // V3 / V2b / V2 asset_id-blind cache-consume branches are PHYSICALLY DELETED (a surviving
        // asset_id-blind branch is a total cross-asset bypass — MA-1 / FIX-2). V3b now CARRIES
        // asset_id + change_commitment and re-asserts BOTH on cache-hit, so the cache-consume path
        // is asset-pinned and change-pinned exactly like the Groth16 verify.
        if (is_cache_path && exists<PendingWithdrawProofsV3b>(@eunoma)) {
            let pending_v3b = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
            if (table::contains(&pending_v3b.by_request_hash, *request_hash)) {
                let cached_v3b = table::remove(&mut pending_v3b.by_request_hash, *request_hash);
                // R5-M order: cheapest / tamper-likely first.
                assert!(cached_v3b.vault_sequence == vault_sequence, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.nullifier_hash == nullifier_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.recipient_hash == recipient_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.root == root, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.amount_tag == amount_tag, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.ca_payload_hash == ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
                // V4 MB-3: re-assert the registry-resolved asset_id (MA-1 Poseidon-link image).
                assert!(&cached_v3b.asset_id == asset_id, E_INVALID_WITHDRAW_PROOF);
                // V4 CP1: re-assert the change_commitment public.
                assert!(&cached_v3b.change_commitment == change_commitment, E_INVALID_WITHDRAW_PROOF);
                return
            };
        };
        assert_valid_withdraw_proof(
            root, nullifier_hash, asset_id, recipient_hash, amount_tag,
            ca_payload_hash, request_hash, vault_sequence, amount_p_digest,
            asp_root, state_tree_depth, asp_tree_depth, change_commitment, proof,
        );
    }

    fun consume_or_compute_withdraw_payload(
        recipient: address,
        asset_type: Object<fungible_asset::Metadata>,
        request_hash: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        new_balance_p: &vector<vector<u8>>,
        new_balance_r: &vector<vector<u8>>,
        new_balance_r_eff_aud: &vector<vector<u8>>,
        amount_p: &vector<vector<u8>>,
        amount_r_sender: &vector<vector<u8>>,
        amount_r_recip: &vector<vector<u8>>,
        amount_r_eff_aud: &vector<vector<u8>>,
        ek_volun_auds: &vector<vector<u8>>,
        amount_r_volun_auds: &vector<vector<vector<u8>>>,
        zkrp_new_balance: &vector<u8>,
        zkrp_amount: &vector<u8>,
        sigma_proto_comm: &vector<vector<u8>>,
        sigma_proto_resp: &vector<vector<u8>>,
        memo: &vector<u8>,
    ): (vector<u8>, vector<u8>) acquires PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3 {
        // Round 4 WB2.E B / V3R-3: V3-first lookup. msg_hash compute MUST be byte-identical
        // to V3W-3 writer (uses same hash_confidential_transfer_payload_v2 by-ref encoder
        // shipped in WB1 + same ca_payload_hash_to_fr_safe truncation). Cache-hit returns
        // (computed_hash, cached.amount_p_digest) — same shape as V2 path. amount_p_digest
        // preserved in V3 cache so cache-hit doesn't pay Poseidon-4 (FR-4.6-style win).
        if (exists<PendingWithdrawPayloadsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
                    &asset_type, &recipient, new_balance_p, new_balance_r, new_balance_r_eff_aud,
                    amount_p, amount_r_sender, amount_r_recip, amount_r_eff_aud, ek_volun_auds,
                    amount_r_volun_auds, zkrp_new_balance, zkrp_amount, sigma_proto_comm,
                    sigma_proto_resp, memo,
                ));
                // Double bind: cached msg_hash == recomputed (proves prepare-time inputs match
                // current submit inputs) AND recomputed == ca_payload_hash arg (forecloses
                // FW5.1-style binding gap codex flagged).
                assert!(cached_v3.msg_hash == computed_hash, E_PAYLOAD_HASH_MISMATCH);
                assert!(&computed_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                // P0 hotfix (Round 5 Wave A codex audit): defuse any V3 payload cache
                // entries that may have been written by the vulnerable FR-4.6 prepare path
                // before its revert. Recompute amount_p_digest from CURRENT submit-time
                // amount_p and assert equality to the cached digest. If a pre-revert
                // pending entry has digest_A but stage-3 amount_p_C produces digest_C,
                // this aborts before the framework call.
                let digest_now = compute_amount_p_digest_v2(amount_p);
                assert!(cached_v3.amount_p_digest == digest_now, E_INVALID_WITHDRAW_PROOF);
                return (computed_hash, digest_now)
            };
        };
        // R5-K (Round 5 A.6): collapse V2 payload-cache double `borrow_global` (immut for
        // contains + mut for remove) to single `borrow_global_mut + contains + remove`,
        // mirroring the V3 path at 2483-2486 and the V2 proof path at 2413-2415. Saves
        // ~200-500 gas per cache lookup by eliminating one resource-load round-trip.
        if (exists<PendingWithdrawPayloadsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawPayloadsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
            let cached = table::remove(&mut pending.by_request_hash, *request_hash);
            // WB1/FW5.3 gas opt: drop 14 `*X` derefs (each cloned the 32B-to-MB byte vector
            // just to satisfy by-value `==`). Move's `==` accepts `&vector<T>` on both sides
            // and walks element-by-element with no clone. Cache-hit savings ~500-1500 gas.
            assert!(cached.asset_type == object::object_address(&asset_type), E_PAYLOAD_HASH_MISMATCH);
            assert!(cached.recipient == recipient, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.ca_payload_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_p == new_balance_p, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_r == new_balance_r, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_r_eff_aud == new_balance_r_eff_aud, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_p == amount_p, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_sender == amount_r_sender, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_recip == amount_r_recip, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_eff_aud == amount_r_eff_aud, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.ek_volun_auds == ek_volun_auds, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_volun_auds == amount_r_volun_auds, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.zkrp_new_balance == zkrp_new_balance, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.zkrp_amount == zkrp_amount, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.sigma_proto_comm == sigma_proto_comm, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.sigma_proto_resp == sigma_proto_resp, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.memo == memo, E_PAYLOAD_HASH_MISMATCH);
            return (cached.ca_payload_hash, cached.amount_p_digest)
            };
        };

        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &recipient,
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
        ));
        assert!(computed_hash == *ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
        (computed_hash, compute_amount_p_digest_v2(amount_p))
    }

    fun consume_prepared_withdraw_payload_digest(
        request_hash: &vector<u8>,
        ca_payload_hash: &vector<u8>,
    ): vector<u8> acquires PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3 {
        if (exists<PendingWithdrawPayloadsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                assert!(&cached_v3.msg_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                return cached_v3.amount_p_digest
            };
        };
        if (exists<PendingWithdrawPayloadsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawPayloadsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
                let cached = table::remove(&mut pending.by_request_hash, *request_hash);
                assert!(&cached.ca_payload_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                return cached.amount_p_digest
            };
        };
        assert!(false, E_INVALID_WITHDRAW_PROOF);
        vector[]
    }

    // Round 4 WB2.E B / FR-1.3 + V3R-2: 6 hash params by-ref (drops 6 `*&` clones at withdraw
    // caller). 3-tier soft lookup: V3 msg_hash → V2 legacy field-eq → BCS+verify path.
    // V3 cache-hit rebuilds the same WithdrawAttestationV2Message from current inputs + cfg
    // + circuit_versions_hash → keccak → byte-eq cached.msg_hash. Cfg-rotation auto-detected
    // (rotated cfg fields → different msg_hash → abort E_INVALID_DEOP_SIGNATURE). FROST sig
    // re-verify SAFELY skipped on cache-hit: sig was verified at prepare-time + bound to
    // msg_hash; msg_hash byte-equality ⇒ identical signed payload ⇒ original verify transitive.
    // R5-J (Round 5 A.5): `circuit_versions_hash` passed in by-ref from caller. The caller
    // (withdraw_to_recipient_v2) computes once via get_or_compute_circuit_versions_hash(cfg)
    // and passes ref; eliminates inner global borrow + 32B clone at all 3 sub-branches
    // (V3 cache-hit / V2 cache-hit assert / cache-miss msg struct). Saves ~150-300 gas/withdraw.
    // CircuitVersionsHashCacheV2 no longer needs to be acquired here.
    fun consume_or_verify_withdraw_attestation(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient: address,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
        vault_addr: address,
        asset_type_addr: address,
        circuit_versions_hash: &vector<u8>,
    ) acquires PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3 {
        let use_pending = vector::length(&group_signature) == 0
            && fallback_bitmap == 0
            && vector::length(&fallback_signatures) == 0;
        if (use_pending && exists<PendingWithdrawAttestationsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
                let msg_bytes_v3 = serialize_withdraw_attestation_v2_msg(
                    &DOMAIN_WITHDRAW_V2,
                    chain_id::get(),
                    @eunoma,
                    vault_addr,
                    asset_type_addr,
                    cfg.operator_set_version,
                    cfg.dkg_epoch,
                    &cfg.roster_hash,
                    &cfg.frost_group_pubkey,
                    root,
                    nullifier_hash,
                    recipient,
                    recipient_hash,
                    amount_tag,
                    ca_payload_hash,
                    request_hash,
                    vault_sequence,
                    expiry_secs,
                    circuit_versions_hash,
                );
                let computed_msg_hash = aptos_hash::keccak256(msg_bytes_v3);
                assert!(cached_v3.msg_hash == computed_msg_hash, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        // Round 5 Wave E.1 (R5-D): V2b cache-hit (msg_hash-only, same shape as V3).
        // Priority chain: V3 → V2b → V2 → miss. New prepare_withdraw_attestation_v2 writes
        // to V2b; legacy in-flight V2 entries still drain via the V2 branch below.
        if (use_pending && exists<PendingWithdrawAttestationsV2b>(@eunoma)) {
            let pending_v2b = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
            if (table::contains(&pending_v2b.by_request_hash, *request_hash)) {
                let cached_v2b = table::remove(&mut pending_v2b.by_request_hash, *request_hash);
                let msg_bytes_v2b = serialize_withdraw_attestation_v2_msg(
                    &DOMAIN_WITHDRAW_V2,
                    chain_id::get(),
                    @eunoma,
                    vault_addr,
                    asset_type_addr,
                    cfg.operator_set_version,
                    cfg.dkg_epoch,
                    &cfg.roster_hash,
                    &cfg.frost_group_pubkey,
                    root,
                    nullifier_hash,
                    recipient,
                    recipient_hash,
                    amount_tag,
                    ca_payload_hash,
                    request_hash,
                    vault_sequence,
                    expiry_secs,
                    circuit_versions_hash,
                );
                let computed_msg_hash_v2b = aptos_hash::keccak256(msg_bytes_v2b);
                assert!(cached_v2b.msg_hash == computed_msg_hash_v2b, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        if (use_pending && exists<PendingWithdrawAttestationsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawAttestationsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
                let cached = table::remove(&mut pending.by_request_hash, *request_hash);
                assert!(cached.vault == vault_addr, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.asset_type == asset_type_addr, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.operator_set_version == cfg.operator_set_version, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.dkg_epoch == cfg.dkg_epoch, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.roster_hash == cfg.roster_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.frost_group_pubkey == cfg.frost_group_pubkey, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.root == root, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.nullifier_hash == nullifier_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.recipient == recipient, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.recipient_hash == recipient_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.amount_tag == amount_tag, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.ca_payload_hash == ca_payload_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.vault_sequence == vault_sequence, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.expiry_secs == expiry_secs, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.circuit_versions_hash == circuit_versions_hash, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
        let msg_bytes = serialize_withdraw_attestation_v2_msg(
            &DOMAIN_WITHDRAW_V2,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
            circuit_versions_hash,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
    }

    // V4 (CP2 MB-2/MB-3, 2026-06-01): asset_id_fr + vault_addr_hash_fr are now passed in by the
    // caller from the registry-resolved AssetVaultStateV4 row (per-asset deposit publics), NOT read
    // from the dead VaultPublicInputsV2 singleton. The deposit circuit is FROZEN — only the SOURCE
    // of its asset_id/vault_addr_hash publics moves singleton -> registry.
    fun assert_valid_deposit_binding_proof(
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        asset_id_fr: &vector<u8>,
        vault_addr_hash_fr: &vector<u8>,
        amount_p_digest: &vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedDepositBindingVK {
        assert!(exists<PreparedDepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedDepositBindingVK>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == DEPOSIT_VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);
        // WB3/FG2.1: dropped per-verify assert_prepared_vk_shape. The 3 prepared VK byte fields
        // (alpha_g1_beta_g2_fq12, gamma_g2_neg, delta_g2_neg) are produced exclusively by
        // `pairing_fq12_bytes` / `neg_g2_bytes` — both delegate to Aptos `crypto_algebra::
        // serialize` which returns canonical 384B Fq12 / 192B G2. The PreparedDepositBindingVK
        // resource is `move_to`'d once and only replaced via `move_from + move_to` on rotation
        // (no in-place field-mutation path; no `borrow_global_mut<PreparedDepositBindingVK>`
        // exists in the module — verified by codex). INVARIANT: prepared-VK byte fields must
        // only be produced by the canonical `crypto_algebra::serialize` helpers above; any new
        // writer path must preserve this or restore the runtime shape check.
        // Stage 3 A6: amount_p_digest is the 5th public input (after commitment, amount_tag,
        // asset_id, vault_addr_hash). Circuit publics order MUST match this vector exactly.
        let publics = vector[
            de_fr_with_error(commitment, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF),
            // V4: asset_id_fr + vault_addr_hash_fr come from the registry-resolved row (both
            // Poseidon-derived canonical 32B Fr). amount_p_digest = compute_amount_p_digest_v2
            // output. All three are canonical-by-construction → skip the is_some guards.
            de_fr_unchecked(asset_id_fr),
            de_fr_unchecked(vault_addr_hash_fr),
            de_fr_unchecked(amount_p_digest),
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

    // Round 4 WB2.E B / FR-3.3: 7 hash params + amount_p_digest taken by-ref (mirrors
    // assert_valid_deposit_binding_proof's WB3 B3 by-ref refactor). Eliminates the 8
    // *&deref clones at every caller (prepare_withdraw_proof_v2/v3 + consume_or_verify_withdraw_proof
    // cache-miss branch). vault_sequence stays by-value (u64 primitive).
    fun assert_valid_withdraw_proof(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
        // ASP (2026-05-30, asp-tree-design §5.2/§6): 3 new publics appended after amount_p_digest.
        asp_root: &vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        // V4 (CP1, 2026-06-01): partial-withdraw change-note commitment, public[12]. EMPTY
        // (full withdraw) = the field element 0 (CHANGE_COMMITMENT_EMPTY).
        change_commitment: &vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedWithdrawProofVK {
        // Hot-path cost: prepared VK existence/IC length are guaranteed by admin-only
        // publish/rotate entries. `borrow_global` still aborts if provisioning is missing, and
        // the Groth16 helper consumes the canonical prepared vector directly.
        let pvk = borrow_global<PreparedWithdrawProofVK>(@eunoma);
        let _state_tree_depth = state_tree_depth;
        let _asp_tree_depth = asp_tree_depth;
        let expected_request_hash = compute_request_hash_v4(
            amount_tag,
            recipient_hash,
            ca_payload_hash,
            asset_id,
            vault_sequence,
            chain_id::get(),
        );
        assert!(&expected_request_hash == request_hash, E_INVALID_WITHDRAW_PROOF);
        // WB3/FG2.1: dropped per-verify assert_prepared_vk_shape — see deposit-side comment in
        // assert_valid_deposit_binding_proof for the invariant: prepared-VK byte fields are
        // produced exclusively by canonical crypto_algebra::serialize helpers; resource is
        // replaced-not-mutated; no `borrow_global_mut<PreparedWithdrawProofVK>` exists.
        let publics = vector[
            de_fr_with_error(root, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(nullifier_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(request_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(amount_p_digest, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(asp_root, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(change_commitment, E_INVALID_WITHDRAW_PROOF),
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

    // CP6 ragequit (asp-tree-design §8 / §5.4): verify the standalone transparent-exit Groth16.
    // Mirrors assert_valid_withdraw_proof but uses the PreparedRagequitProofVK + the 4-public
    // ragequit circuit. The publics order MUST match the circuit byte-for-byte:
    //   [0]commitment [1]nullifier_hash [2]root [3]state_tree_depth
    // commitment, nullifier_hash and root are 32B Fr supplied by the caller -> de_fr_with_error
    // (validates canonicity); state_tree_depth is a native u64 -> from_u64<Fr> (no temp vector).
    // NO asp_root / no asp_tree_depth — ragequit skips ASP inclusion entirely. NO vault_sequence
    // public input either: the ragequit circuit does not bind vault_sequence (see the ragequit
    // entry for the anti-replay rationale: the nullifier is the anti-replay).
    fun assert_valid_ragequit_proof(
        commitment: &vector<u8>,
        nullifier_hash: &vector<u8>,
        root: &vector<u8>,
        state_tree_depth: u64,
        proof: vector<u8>,
    ) acquires PreparedRagequitProofVK {
        assert!(exists<PreparedRagequitProofVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedRagequitProofVK>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == RAGEQUIT_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        let publics = vector[
            de_fr_with_error(commitment, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(nullifier_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(root, E_INVALID_WITHDRAW_PROOF),
            crypto_algebra::from_u64<Fr>(state_tree_depth),
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
        // WB3/FG4: pass refs to de_*_with_error directly (sig changed to &vector<u8>);
        // eliminates 3 large clones (Fq12=384B + 2×G2=192B = 768B per verify) at this hot path.
        let pvk_alpha_beta = de_fq12_with_error(pvk_alpha_g1_beta_g2_fq12, err);
        let pvk_gamma_neg = de_g2_with_error(pvk_gamma_g2_neg, err);
        let pvk_delta_neg = de_g2_with_error(pvk_delta_g2_neg, err);
        let vk_ic = vector::empty<crypto_algebra::Element<G1>>();
        let i = 0;
        let n = vector::length(pvk_uvw_gamma_g1);
        while (i < n) {
            // WB3/FG4+FG1.5: pass `vector::borrow(...)` ref directly into the deserializer
            // (no more 64B clone per IC element; 6-10 elements per verify).
            vector::push_back(&mut vk_ic, de_g1_with_error(vector::borrow(pvk_uvw_gamma_g1, i), err));
            i = i + 1;
        };
        // R5-G (Round 5 A.3): byte_slice_unchecked safe here — line 2757 already asserts
        // length(&proof) == PROOF_BYTES = G1 + G2 + G1 = 256, so all 3 slice ends are in-bounds.
        let proof_a_bytes = byte_slice_unchecked(&proof, 0, G1_UNCOMPRESSED_BYTES);
        let proof_b_bytes = byte_slice_unchecked(
            &proof,
            G1_UNCOMPRESSED_BYTES,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
        );
        let proof_c_bytes = byte_slice_unchecked(
            &proof,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            PROOF_BYTES,
        );
        let proof_a = de_g1_with_error(&proof_a_bytes, err);
        let proof_b = de_g2_with_error(&proof_b_bytes, err);
        let proof_c = de_g1_with_error(&proof_c_bytes, err);
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

    // WB3/FG4 gas opt: sig 6 deserializers from `vector<u8>` by-value → `&vector<u8>` ref.
    // Internal crypto_algebra::deserialize already takes &bytes, so by-value was pure overhead
    // (forced clone at every callsite). Also: 3 g1/g2/fq12 helpers had `option::extract(&mut opt)`
    // which leaves a None placeholder + drops it — `option::destroy_some(opt)` (already used by
    // de_fr) consumes by-value, cleaner + fewer ops. Codex S4 confirmed multi-call batch
    // pattern allowed (not the rejected single-callsite option::destroy_some variant).
    //
    // de_fr (no-error) + de_fq12 (no-error) DROPPED: zero callers in this file. Sole callers of
    // de_g1/de_g2 no-error are publish_prepared_*_vk entries (4 sites × 4 fields, admin only).
    fun de_fr_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<Fr> {
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    // Round 5 Wave F.2 (R5-T): unchecked Fr deserialize for canonical-by-construction
    // bytes. Callers MUST guarantee `bytes` is a canonical 32B little-endian Fr scalar
    // (Poseidon outputs, derive_asset_id output, compute_amount_p_digest_v2 output).
    // For ANY user-supplied input use `de_fr_with_error` instead. Saves the option::
    // is_some assert + the abort branch (~50-150 gas per Groth16 verify).
    fun de_fr_unchecked(bytes: &vector<u8>): crypto_algebra::Element<Fr> {
        option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes))
    }

    fun de_g1(bytes: &vector<u8>): crypto_algebra::Element<G1> {
        de_g1_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g1_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<G1> {
        let opt = crypto_algebra::deserialize<G1, FormatG1Uncompr>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun de_g2(bytes: &vector<u8>): crypto_algebra::Element<G2> {
        de_g2_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g2_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<G2> {
        let opt = crypto_algebra::deserialize<G2, FormatG2Uncompr>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun de_fq12_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<Fq12> {
        let opt = crypto_algebra::deserialize<Fq12, FormatFq12LscLsb>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun assert_g1(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G1_UNCOMPRESSED_BYTES, err);
    }

    fun assert_g2(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G2_UNCOMPRESSED_BYTES, err);
    }

    // WB3/FH4.1+FH4.2 gas opt: bulk vector::append of 24-zero tail instead of two while-loops.
    // bcs::to_bytes(&u64) deterministically returns 8 LE bytes; just append 24 zeros for the
    // FR_BYTES (32) pad. Output byte-identical (8B LE + 24B zeros). Eliminates 32 push_back
    // iters + the intermediate byte-by-byte copy loop.
    fun u64_to_fr_bytes(n: u64): vector<u8> {
        let out = bcs::to_bytes(&n);
        vector::append(&mut out, vector[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
        out
    }

    fun u8_to_fr_bytes(n: u8): vector<u8> {
        let out = vector[n];
        vector::append(&mut out, vector[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
        out
    }

    fun compute_request_hash_v4(
        amount_tag: &vector<u8>,
        recipient_hash: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        asset_id: &vector<u8>,
        vault_sequence: u64,
        chain_id_value: u8,
    ): vector<u8> {
        let left = poseidon_bn254::hash_3(*amount_tag, *recipient_hash, *ca_payload_hash);
        let right = poseidon_bn254::hash_3(*asset_id, u64_to_fr_bytes(vault_sequence), u8_to_fr_bytes(chain_id_value));
        poseidon_bn254::hash_2(left, right)
    }

    // WB3/FH3.1 REVERTED (codex micro-review): vendored `std::vector::slice` is itself a Move
    // loop (vector.move::732), not a native memcpy. Switching to it added our bounds assert +
    // the stdlib's bounds assert + the same per-byte push_back loop. Net was neutral-to-worse.
    // Restored the original explicit loop — at least we pay only one bounds assert path.
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

    // R5-G (Round 5 A.3): unchecked variant — skips `vector::length(src)` read + bounds
    // assert. Safe ONLY when caller has already validated `end <= length(src)` via an
    // outer gate. Used by assert_groth16_prepared where line 2757 already asserts
    // `length(&proof) == PROOF_BYTES = 256`, guaranteeing the 3 proof-element slices
    // (0..64, 64..192, 192..256) are all in-bounds. Saves ~200-400 gas per Groth16
    // verify (3 redundant vector::length + bounds-assert bundles eliminated).
    //
    // SAFETY: do NOT call this without a prior `assert!(vector::length(src) >= end, ...)`.
    fun byte_slice_unchecked(src: &vector<u8>, start: u64, end: u64): vector<u8> {
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
        // Preserve our error code; vector::slice would abort with the stdlib code otherwise.
        assert!(start <= end && end <= vector::length(src), E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::slice(src, start, end);
        let cur = end - start;
        while (cur < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
            cur = cur + 1;
        };
        out
    }

    fun derive_asset_id(asset_type: Object<fungible_asset::Metadata>): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).asset_id_fr
        };
        derive_address_hash(object::object_address(&asset_type), POSEIDON_DOMAIN_ASSET_ID_FR)
    }

    fun derive_vault_addr_hash(vault_addr: address): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).vault_addr_hash_fr
        };
        derive_address_hash(vault_addr, POSEIDON_DOMAIN_VAULT_ADDR_HASH_FR)
    }

    fun derive_recipient_hash(recipient: address): vector<u8> {
        derive_address_hash(recipient, POSEIDON_DOMAIN_RECIPIENT_HASH_FR)
    }

    // Round 4 WB2.E C / FR-1.5b: takes pre-computed `domain_fr` (32B, already
    // bytes_to_field_le32-equivalent of the original POSEIDON_DOMAIN_* string). Drops the
    // per-call `bytes_to_field_le32` work. Domain consts above are compile-time precomputed
    // and byte-equivalent to the old runtime-derived form.
    fun derive_address_hash(addr: address, domain_fr: vector<u8>): vector<u8> {
        let addr_bytes = bcs::to_bytes(&addr);
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_BAD_HASH_LENGTH);
        let hi = byte_slice_padded(&addr_bytes, 0, 16);
        let lo = byte_slice_padded(&addr_bytes, 16, 32);
        poseidon_bn254::hash_3(domain_fr, hi, lo)
    }

    // V4 (CP2 MB-4, design §6.1 B-prime): collapse a party's 4 × 16-bit-chunk Pedersen commitments
    // into ONE aggregate Pedersen point using the framework's own positional chunk weights
    // [1, 2^16, 2^32, 2^48]. Each amount_p chunk C_i = m_i·G + r_i·H is a 32B COMPRESSED Ristretto
    // point (the CA Twisted-ElGamal amount component). The aggregate
    //   P = Σ 2^{16i}·C_i = (Σ m_i·2^{16i})·G + (Σ r_i·2^{16i})·H = A·G + R·H
    // is a single Pedersen commitment to the FULL integer amount A. Carry-free: subtraction borrows
    // across 16-bit boundaries cancel because aggregation is over the integer, not per-chunk.
    //
    // SOUNDNESS-CRITICAL decompression: use ristretto255::new_point_from_bytes (VALIDATES canonical
    // encoding; returns Option::none on a non-canonical point) NOT point_decompress (which trusts
    // the invariant and would mis-bind malformed bytes). A non-canonical chunk aborts here.
    fun aggregate_pedersen_amount_point(amount_p: &vector<vector<u8>>): ristretto255::RistrettoPoint {
        assert!(vector::length(amount_p) == 4, E_INVALID_AMOUNT_P_SHAPE);
        let c0 = vector::borrow(amount_p, 0);
        let c1 = vector::borrow(amount_p, 1);
        let c2 = vector::borrow(amount_p, 2);
        let c3 = vector::borrow(amount_p, 3);
        assert!(
            vector::length(c0) == 32 && vector::length(c1) == 32
                && vector::length(c2) == 32 && vector::length(c3) == 32,
            E_INVALID_AMOUNT_P_SHAPE
        );
        // VALIDATING decompression — option::extract aborts if new_point_from_bytes returned none
        // (non-canonical encoding), exactly the malformed-bytes mis-bind the spec forbids.
        let p0 = option::extract(&mut ristretto255::new_point_from_bytes(*c0));
        let p1 = option::extract(&mut ristretto255::new_point_from_bytes(*c1));
        let p2 = option::extract(&mut ristretto255::new_point_from_bytes(*c2));
        let p3 = option::extract(&mut ristretto255::new_point_from_bytes(*c3));
        // Positional weights [1, 2^16, 2^32, 2^48] as Ristretto scalars (all < 2^64, fit u128).
        let w0 = ristretto255::new_scalar_from_u128(1u128);
        let w1 = ristretto255::new_scalar_from_u128(1u128 << 16);
        let w2 = ristretto255::new_scalar_from_u128(1u128 << 32);
        let w3 = ristretto255::new_scalar_from_u128(1u128 << 48);
        let points = vector[p0, p1, p2, p3];
        let scalars = vector[w0, w1, w2, w3];
        ristretto255::multi_scalar_mul(&points, &scalars)
    }

    // V4 (CP2 MB-4, design §6 B-prime, HYBRID): on-chain aggregate-Pedersen conservation. Pins the
    // spent note's aggregate P_old to the Groth16-bound amount_p_digest (public[8]) via the existing
    // Compose8 recompute (closes Approach A's "A_old is a free variable" hole), then asserts the
    // carry-free integer-conservation equality on the aggregated points:
    //   point_equals(P_old, P_wd + P_rem)   <=>   A_old·G + R_old·H == (W + A_rem)·G + (R_wd + R_rem)·H
    // The user constructs blinds so R_old = R_wd + R_rem (deterministic HKDF-derived per-chunk
    // scalar_sub); the H terms cancel and Pedersen binding forces A_old = W + A_rem in Z — given all
    // three amounts are in [0, 2^64) << L so there is no mod-L wraparound (the IN-CIRCUIT
    // Num2Bits(16)/LessEqThan(64) remainder range proof is the other half of the hybrid; this Move
    // half binds those integers to the real amount_p commitments). amount_p_old is the spent note's
    // chunks; amount_p_wd is the withdrawn leg (== the CA-transfer amount_p); amount_p_rem is the
    // change/remainder chunks. Returns nothing — aborts E_AMOUNT_CONSERVATION on failure.
    fun assert_amount_conservation_v4(
        amount_p_old: &vector<vector<u8>>,
        amount_p_wd: &vector<vector<u8>>,
        amount_p_rem: &vector<vector<u8>>,
        amount_p_digest: &vector<u8>,
    ) {
        // Pin P_old to the spent note: Compose8(old chunks) MUST equal the Groth16 public[8] digest
        // (which the withdraw circuit binds into the spent Compose5 commitment proven in-tree). So
        // the chunks aggregated below are cryptographically the deposited note's amount, not a
        // prover-invented number.
        let old_digest = compute_amount_p_digest_v2(amount_p_old);
        assert!(&old_digest == amount_p_digest, E_AMOUNT_CONSERVATION);
        let p_old = aggregate_pedersen_amount_point(amount_p_old);
        let p_wd = aggregate_pedersen_amount_point(amount_p_wd);
        let p_rem = aggregate_pedersen_amount_point(amount_p_rem);
        let p_sum = ristretto255::point_add(&p_wd, &p_rem);
        assert!(ristretto255::point_equals(&p_old, &p_sum), E_AMOUNT_CONSERVATION);
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
        // R5-L REVERTED (codex Wave A review RED): exact 32-byte length asserts retained.
        // R6-F.4: collapse 4 inner length asserts into single short-circuit `&&` assert
        // — same error code, same trip behavior, saves 3 assert-frame setups on fallback
        // paths (V3-hit happy path skips this whole function). ~80-160 gas/fallback.
        assert!(
            vector::length(p0) == 32
                && vector::length(p1) == 32
                && vector::length(p2) == 32
                && vector::length(p3) == 32,
            E_INVALID_AMOUNT_P_SHAPE
        );

        // H1 gas opt: inline byte_slice_padded (8 fn-call frames eliminated, ~160 gas).
        // Each slice is 16B from p_i, padded with 16 trailing zeros to 32B (matches FR_BYTES=32).
        let p0_lo = vector::slice(p0, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p0_lo, 0u8); i = i + 1; };
        let p0_hi = vector::slice(p0, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p0_hi, 0u8); i = i + 1; };
        let p1_lo = vector::slice(p1, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p1_lo, 0u8); i = i + 1; };
        let p1_hi = vector::slice(p1, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p1_hi, 0u8); i = i + 1; };
        let p2_lo = vector::slice(p2, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p2_lo, 0u8); i = i + 1; };
        let p2_hi = vector::slice(p2, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p2_hi, 0u8); i = i + 1; };
        let p3_lo = vector::slice(p3, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p3_lo, 0u8); i = i + 1; };
        let p3_hi = vector::slice(p3, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p3_hi, 0u8); i = i + 1; };

        // Compose8 tree (matches circom Compose8 + JS compose8). VK-locked topology.
        let a = poseidon_bn254::hash_3(p0_lo, p0_hi, p1_lo);
        let b = poseidon_bn254::hash_3(p1_hi, p2_lo, p2_hi);
        let c = poseidon_bn254::hash_2(p3_lo, p3_hi);
        poseidon_bn254::hash_3(a, b, c)
    }

    fun assert_hash(bytes: &vector<u8>) {
        assert!(vector::length(bytes) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    // V4 (CP2 MB-5): has_change == change_commitment is NOT the canonical EMPTY sentinel (the field
    // element 0 = 32 LE zero bytes). A partial withdraw produces a non-zero Compose5 change
    // commitment (this is true) and emits ChangeNoteAppendedV4; a full withdraw binds public[12] to
    // CHANGE_COMMITMENT_EMPTY (this is false) and emits no change leaf. Caller has already
    // assert_hash'd the 32B length, so a ref byte-compare to the 32B sentinel is sufficient.
    fun has_change_commitment(change_commitment: &vector<u8>): bool {
        change_commitment != &CHANGE_COMMITMENT_EMPTY
    }

    // Round 5 Wave G.2 (R5-P): inline helper for the 6-hash assertion block shared
    // by 5 withdraw entry points (withdraw_to_recipient_v2 + prepare_withdraw_{proof,
    // attestation}_v{2,3}). `inline fun` inlines at compile time so per-call overhead
    // = 6× direct assert! (no function-call dispatch). Saves ~225 gas total across
    // all 5 entries plus bytecode-size shrinkage. Semantics identical to 6 sequential
    // assert_hash calls.
    inline fun assert_6_withdraw_hashes(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
    ) {
        assert!(vector::length(root) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(nullifier_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(recipient_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(amount_tag) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(ca_payload_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(request_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    // R6-A.1: inline 3-hash helper for deposit_with_commitment_v2 entry assert block.
    inline fun assert_3_deposit_hashes(
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
    ) {
        assert!(vector::length(commitment) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(amount_tag) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(ca_payload_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    #[test_only]
    public fun test_only_assert_3_deposit_hashes(c: vector<u8>, a: vector<u8>, p: vector<u8>) {
        assert_3_deposit_hashes(&c, &a, &p);
    }

    // R7-W1: composite (sender, commitment) key for PendingDeposit*V3 tables. Closes
    // squat-DoS class — attacker can no longer occupy a victim's commitment slot because
    // their own address is part of the key. sender_bytes (32B BCS) || commitment (32B) = 64B key.
    inline fun compose_pending_key(sender: address, commitment: &vector<u8>): vector<u8> {
        let key = bcs::to_bytes(&sender);
        vector::append(&mut key, *commitment);
        key
    }

    #[test_only]
    public fun test_only_compose_pending_key(sender: address, commitment: vector<u8>): vector<u8> {
        compose_pending_key(sender, &commitment)
    }

    fun assert_not_expired(expiry_secs: u64) {
        assert!(timestamp::now_seconds() <= expiry_secs, E_EXPIRED);
    }

    fun bit_is_set(bitmap: u8, index: u64): bool {
        ((bitmap >> (index as u8)) & 1u8) == 1u8
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
            &asset_type,
            &to,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        )
    }

    #[test_only]
    public fun test_call_ca_payload_hash_to_fr_safe_v2(raw: vector<u8>): vector<u8> {
        ca_payload_hash_to_fr_safe(raw)
    }

    // =================================================================================
    // ASP (2026-05-30, asp-tree-design §6) test-only scaffolding. Seeds ASPRecorderDelegate +
    // KnownASPRoots directly at @eunoma (avoids a full vault bootstrap) so tests can exercise the
    // real record_asp_root_via_delegate entry + asp_root_in_recent_window helper. Production paths
    // are unchanged (these are #[test_only], excluded from production bytecode).
    // =================================================================================
    #[test_only]
    public fun test_only_seed_asp_delegate(admin: &signer, delegate_addr: address) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<ASPRecorderDelegate>(@eunoma)) {
            move_to(admin, ASPRecorderDelegate { addr: delegate_addr });
        };
        if (!exists<KnownASPRoots>(@eunoma)) {
            move_to(admin, KnownASPRoots { sets: vector::empty<AssociationSetData>() });
        };
    }

    #[test_only]
    public fun test_only_asp_root_in_recent_window(asp_root: vector<u8>): bool acquires KnownASPRoots {
        asp_root_in_recent_window(&asp_root)
    }

    #[test_only]
    public fun test_only_asp_sets_len(): u64 acquires KnownASPRoots {
        if (!exists<KnownASPRoots>(@eunoma)) {
            return 0
        };
        vector::length(&borrow_global<KnownASPRoots>(@eunoma).sets)
    }

    public fun asp_root_window_k(): u64 { ASP_ROOT_WINDOW_K }
    public fun e_invalid_asp_root(): u64 { E_INVALID_ASP_ROOT }
    public fun e_not_asp_recorder_delegate(): u64 { E_NOT_ASP_RECORDER_DELEGATE }
    public fun e_asp_recorder_delegate_not_initialized(): u64 { E_ASP_RECORDER_DELEGATE_NOT_INITIALIZED }

    // =================================================================================
    // CP6 ragequit (asp-tree-design §8) test-only scaffolding. These shims plant the
    // DepositSenderMap entry + a prepared ragequit VK directly at @eunoma so unit tests can drive
    // the REAL deposit_sender lookup + the REAL E_NOT_ORIGINAL_DEPOSITOR access-control abort
    // inside the production `ragequit` entry, without a full vault/CA bootstrap (the full
    // proof + confidential_transfer_raw flow is E2E, exercised on testnet later). Mirrors the
    // CP2 test_only_seed_asp_delegate shim style. #[test_only] -> excluded from production bytecode.
    // =================================================================================
    #[test_only]
    public fun test_only_seed_deposit_sender(admin: &signer, commitment: vector<u8>, sender: address) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<DepositSenderMap>(@eunoma)) {
            move_to(admin, DepositSenderMap { by_commitment: table::new<vector<u8>, address>() });
        };
        let dsm = borrow_global_mut<DepositSenderMap>(@eunoma);
        if (!table::contains(&dsm.by_commitment, *&commitment)) {
            table::add(&mut dsm.by_commitment, commitment, sender);
        };
    }

    // Read the IC length of the raw RagequitProofVK published by publish_ragequit_proof_vk (proves
    // the stored ic vector has exactly RAGEQUIT_VK_IC_LENGTH = 5 elements).
    #[test_only]
    public fun test_only_ragequit_vk_ic_len(): u64 acquires RagequitProofVK {
        if (!exists<RagequitProofVK>(@eunoma)) { return 0 };
        vector::length(&borrow_global<RagequitProofVK>(@eunoma).ic)
    }

    // Drive the REAL ragequit access-control path (the exact deposit_sender lookup +
    // E_NOT_ORIGINAL_DEPOSITOR assertions the production `ragequit` entry runs at step (b)/(c)),
    // bypassing only the unrelated assert_initialized() / CA-transfer machinery (those are E2E).
    // Returns the resolved original depositor address.
    #[test_only]
    public fun test_only_resolve_ragequit_original_sender(
        depositor_addr: address,
        commitment: vector<u8>,
    ): address acquires DepositSenderMap {
        resolve_ragequit_original_sender(depositor_addr, &commitment)
    }

    public fun e_not_original_depositor(): u64 { E_NOT_ORIGINAL_DEPOSITOR }
    public fun ragequit_vk_ic_length(): u64 { RAGEQUIT_VK_IC_LENGTH }

    public fun e_bad_threshold(): u64 { E_BAD_THRESHOLD }
    public fun e_invalid_deop_signature(): u64 { E_INVALID_DEOP_SIGNATURE }
    public fun e_too_few_deop_signatures(): u64 { E_TOO_FEW_DEOP_SIGNATURES }
    public fun e_payload_hash_mismatch(): u64 { E_PAYLOAD_HASH_MISMATCH }
    public fun e_invalid_deposit_binding_proof(): u64 { E_INVALID_DEPOSIT_BINDING_PROOF }
    public fun e_invalid_withdraw_proof(): u64 { E_INVALID_WITHDRAW_PROOF }
    public fun e_recipient_hash_mismatch(): u64 { E_RECIPIENT_HASH_MISMATCH }
    public fun e_pending_withdraw_attestation(): u64 { E_PENDING_WITHDRAW_ATTESTATION }

    // =================================================================================
    // FR-1.5(a) Round 4 F: codex-required cache-pollution unit-test scaffolding.
    // Shims are #[test_only] (excluded from production bytecode). They expose minimal
    // state injection + cache-comparison hooks so tests verify the downstream cache-
    // mismatch detection (consume_or_verify_withdraw_attestation V2-branch line ~2587-2603
    // and V3-branch line ~2553-2581) still fires after F5 drops the redundant entry-level
    // derive_recipient_hash checks at prepare_withdraw_attestation_v{2,3}. Production
    // code paths are unchanged.
    // =================================================================================

    #[test_only]
    public fun test_only_init_pending_attestations(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<PendingWithdrawAttestationsV2>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV2 { by_request_hash: table::new() });
        };
        if (!exists<PendingWithdrawAttestationsV2b>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV2b { by_request_hash: table::new() });
        };
        if (!exists<PendingWithdrawAttestationsV3>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV3 { by_request_hash: table::new() });
        };
    }

    // Round 5 Wave E.1 (R5-D) test shim: inject a V2b cache entry (msg_hash-only).
    #[test_only]
    public fun test_only_inject_v2b_attestation(
        request_hash: vector<u8>,
        msg_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV2b { msg_hash });
    }

    // Round 5 Wave E.1 (R5-D): V2b cache-hit msg_hash equality check (same shape as V3).
    #[test_only]
    public fun test_only_v2b_cache_msg_hash_matches(
        request_hash: vector<u8>,
        expected_msg_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global<PendingWithdrawAttestationsV2b>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.msg_hash == expected_msg_hash
    }

    #[test_only]
    public fun test_only_v2b_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global<PendingWithdrawAttestationsV2b>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // Round 5 Wave E.1 (R5-D): pop V2b entry (mimics consume_or_verify_withdraw_attestation
    // V2b branch table::remove after msg_hash equality). Returns the cached msg_hash so
    // the round-trip test can verify it matches what prepare wrote.
    #[test_only]
    public fun test_only_v2b_pop(
        request_hash: vector<u8>,
    ): vector<u8> acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
        let cached = table::remove(&mut pending.by_request_hash, request_hash);
        cached.msg_hash
    }

    // V4 (CP2 MB-3, 2026-06-01): the V2b proof-cache test shims are DELETED (struct removed).

    // V4 (CP2 MB-3, 2026-06-01) test shims: V3b proof cache (now 9 fields incl asset_id +
    // change_commitment).
    #[test_only]
    public fun test_only_init_pending_proofs_v3b(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<PendingWithdrawProofsV3b>(@eunoma)) {
            move_to(admin, PendingWithdrawProofsV3b { by_request_hash: table::new() });
        };
    }

    #[test_only]
    public fun test_only_inject_v3b_proof(
        request_hash: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        change_commitment: vector<u8>,
    ) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PROOF,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV3b {
            root, nullifier_hash, asset_id, recipient_hash, amount_tag,
            ca_payload_hash, vault_sequence, amount_p_digest, change_commitment,
        });
    }

    #[test_only]
    public fun test_only_v3b_proof_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawProofsV3b {
        let pending = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // Returns the cross-stage fields used by prepare_withdraw_payload_v3 FR-4.6 hotfix:
    // (ca_payload_hash, amount_p_digest). Same fields V3 partial cache exposes; this test
    // verifies V3b also exposes them so the stage-2 reader can swap V3 → V3b transparently.
    #[test_only]
    public fun test_only_v3b_proof_cross_stage_fields(
        request_hash: vector<u8>,
    ): (vector<u8>, vector<u8>) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
        let c = table::borrow(&pending.by_request_hash, *&request_hash);
        (*&c.ca_payload_hash, *&c.amount_p_digest)
    }

    #[test_only]
    public fun test_only_v3b_proof_pop_triplet(
        request_hash: vector<u8>,
    ): (u64, vector<u8>, vector<u8>) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        let c = table::remove(&mut pending.by_request_hash, request_hash);
        let PendingWithdrawProofV3b {
            root: _, nullifier_hash: _, asset_id: _, recipient_hash, amount_tag: _,
            ca_payload_hash: _, vault_sequence, amount_p_digest, change_commitment: _,
        } = c;
        (vault_sequence, amount_p_digest, recipient_hash)
    }

    // Simulates a maliciously-signed-but-mismatched prepare_v2 (which would require
    // 5-of-7 deoperator threshold compromise to actually craft a valid sig). Asserts
    // the same collision-check production uses (line ~1353-1356): second insert with
    // the same request_hash aborts with E_PENDING_WITHDRAW_ATTESTATION.
    #[test_only]
    public fun test_only_inject_v2_attestation(
        request_hash: vector<u8>,
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
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV2 {
            vault, asset_type, operator_set_version, dkg_epoch, roster_hash,
            frost_group_pubkey, root, nullifier_hash, recipient, recipient_hash,
            amount_tag, ca_payload_hash, vault_sequence, expiry_secs, circuit_versions_hash,
        });
    }

    #[test_only]
    public fun test_only_inject_v3_attestation(
        request_hash: vector<u8>,
        msg_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV3 { msg_hash });
    }

    // Mirrors line ~2595 V2-branch assertion: returns false (would abort
    // E_INVALID_DEOP_SIGNATURE) when cached.recipient != expected_recipient.
    #[test_only]
    public fun test_only_v2_cache_recipient_matches(
        request_hash: vector<u8>,
        expected_recipient: address,
    ): bool acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global<PendingWithdrawAttestationsV2>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.recipient == expected_recipient
    }

    // Mirrors line ~2579 V3-branch assertion: returns false (would abort
    // E_INVALID_DEOP_SIGNATURE) when cached.msg_hash != expected_msg_hash.
    #[test_only]
    public fun test_only_v3_cache_msg_hash_matches(
        request_hash: vector<u8>,
        expected_msg_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.msg_hash == expected_msg_hash
    }

    // Mirrors the `use_pending` gate at consume_or_verify_withdraw_attestation
    // (line ~2550-2552): cache is consulted ONLY when caller passes no signature.
    // Any non-empty group_signature OR non-zero fallback_bitmap OR non-empty
    // fallback_signatures bypasses the cache entirely (no table::remove, no
    // cache-mismatch assertion) and goes straight to FROST/fallback sig verify.
    // Returns true iff the cache path would be taken (= use_pending semantics).
    #[test_only]
    public fun test_only_compute_use_pending(
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
    ): bool {
        vector::length(&group_signature) == 0
            && fallback_bitmap == 0
            && vector::length(&fallback_signatures) == 0
    }

    // Returns true iff a V2 cache entry exists for the given request_hash.
    // Used by bypass tests to assert that non-cache paths do NOT consume the entry.
    #[test_only]
    public fun test_only_v2_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global<PendingWithdrawAttestationsV2>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    #[test_only]
    public fun test_only_v3_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // R5-C (Round 5 Wave C) byte-identity test shims.
    #[test_only]
    public fun test_only_serialize_withdraw_attestation_v2_msg(
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
    ): vector<u8> {
        serialize_withdraw_attestation_v2_msg(
            &domain, chain_id, bridge, vault, asset_type,
            operator_set_version, dkg_epoch,
            &roster_hash, &frost_group_pubkey,
            &root, &nullifier_hash, recipient,
            &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash,
            vault_sequence, expiry_secs, &circuit_versions_hash,
        )
    }

    #[test_only]
    public fun test_only_struct_bcs_withdraw_attestation_v2_msg(
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
    ): vector<u8> {
        let msg = WithdrawAttestationV2Message {
            domain,
            chain_id,
            bridge,
            vault,
            asset_type,
            operator_set_version,
            dkg_epoch,
            roster_hash,
            frost_group_pubkey,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
            circuit_versions_hash,
        };
        bcs::to_bytes(&msg)
    }

    // R6-Plan-B test shims for split-tx deposit (PendingDepositFinalizationV3).
    #[test_only]
    public entry fun test_only_init_pending_deposit_finalizations_v3(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<PendingDepositFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositFinalizationsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositFinalizationV3>(),
        });
    }

    // R7-OPS-1: test shims for RecorderDelegate (bypass assert_admin which requires
    // full BridgeVault init — out of scope for unit tests; integration covered by
    // testnet admin init tx + alpha box deploy).
    #[test_only]
    public entry fun test_only_init_recorder_delegate(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<RecorderDelegate>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, RecorderDelegate { addr: signer::address_of(admin) });
    }

    #[test_only]
    public entry fun test_only_set_recorder_delegate(admin: &signer, delegate_addr: address)
        acquires RecorderDelegate
    {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global_mut<RecorderDelegate>(@eunoma);
        rd.addr = delegate_addr;
    }

    #[test_only]
    public fun test_only_recorder_delegate_addr(): address acquires RecorderDelegate {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        borrow_global<RecorderDelegate>(@eunoma).addr
    }

    #[test_only]
    public fun test_only_assert_delegate_auth(delegate: &signer) acquires RecorderDelegate {
        // Mirrors the auth check inside record_known_root_v2_via_delegate without
        // calling record_known_root_internal (which needs BridgeVaultTablesV2 init).
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
    }

    // R7-W1: composite key (sender, commitment) for test injection / read.
    #[test_only]
    public fun test_only_inject_pending_finalization(
        commitment: vector<u8>,
        sender: address,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    ) acquires PendingDepositFinalizationsV3 {
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        table::add(&mut pending.by_commitment, key, PendingDepositFinalizationV3 {
            sender,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
        });
    }

    #[test_only]
    public fun test_only_pending_finalization_exists(sender: address, commitment: vector<u8>): bool
        acquires PendingDepositFinalizationsV3
    {
        if (!exists<PendingDepositFinalizationsV3>(@eunoma)) { return false };
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global<PendingDepositFinalizationsV3>(@eunoma);
        table::contains(&pending.by_commitment, key)
    }

    #[test_only]
    public fun test_only_pending_finalization_read(sender: address, commitment: vector<u8>): (address, vector<u8>, vector<u8>, vector<u8>, u64)
        acquires PendingDepositFinalizationsV3
    {
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global<PendingDepositFinalizationsV3>(@eunoma);
        let entry = table::borrow(&pending.by_commitment, key);
        (entry.sender, *&entry.amount_tag, *&entry.ca_payload_hash, *&entry.deposit_nonce, entry.expiry_secs)
    }

    // R6-C.1 byte-identity test shims (mirror R5-C pattern above).
    #[test_only]
    public fun test_only_serialize_deposit_attestation_v3_msg(
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
        user_addr: address,
    ): vector<u8> {
        serialize_deposit_attestation_v3_msg(
            &domain, chain_id, bridge, vault, asset_type,
            operator_set_version, dkg_epoch,
            &roster_hash, &frost_group_pubkey,
            &commitment, &amount_tag, &ca_payload_hash, &deposit_nonce,
            expiry_secs, &circuit_versions_hash, user_addr,
        )
    }

    #[test_only]
    public fun test_only_struct_bcs_deposit_attestation_v3_msg(
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
        user_addr: address,
    ): vector<u8> {
        let msg = DepositAttestationV3Message {
            domain,
            chain_id,
            bridge,
            vault,
            asset_type,
            operator_set_version,
            dkg_epoch,
            roster_hash,
            frost_group_pubkey,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
            circuit_versions_hash,
            user_addr,
        };
        bcs::to_bytes(&msg)
    }

    // V4 (CP2 MB-4) test shim: drive the REAL assert_amount_conservation_v4 (aggregate-Pedersen
    // B-prime check). Aborts E_AMOUNT_CONSERVATION on a bad split or a P_old/digest mismatch.
    #[test_only]
    public fun test_only_assert_amount_conservation_v4(
        amount_p_old: vector<vector<u8>>,
        amount_p_wd: vector<vector<u8>>,
        amount_p_rem: vector<vector<u8>>,
        amount_p_digest: vector<u8>,
    ) {
        assert_amount_conservation_v4(&amount_p_old, &amount_p_wd, &amount_p_rem, &amount_p_digest);
    }

    // V4 (CP2 MB-4) test shim: expose compute_amount_p_digest_v2 so a test can pin the spent-note
    // digest (public[8]) for the conservation check input.
    #[test_only]
    public fun test_only_compute_amount_p_digest(amount_p: vector<vector<u8>>): vector<u8> {
        compute_amount_p_digest_v2(&amount_p)
    }

    // V4 (CP2 MB-5) test shim: expose the change-commitment EMPTY sentinel + the has_change helper.
    #[test_only]
    public fun test_only_change_commitment_empty(): vector<u8> { CHANGE_COMMITMENT_EMPTY }

    #[test_only]
    public fun test_only_has_change_commitment(change_commitment: vector<u8>): bool {
        has_change_commitment(&change_commitment)
    }

    // =================================================================================
    // V4 multi-asset (CP2 MB-1..MB-6) test-only scaffolding. Mirrors the ASP/ragequit seeder
    // style: plant the GLOBAL VaultCoreV4 + empty AssetRegistryV4 + BridgeTablesV4 directly at
    // @eunoma (with a real resource-account signer cap so the row shape is identical to init_v4),
    // so unit tests can drive the REAL register_asset_metadata_v4 entry, the REAL status gate, the
    // REAL MA-1 Poseidon-link assert, and the REAL append-only / uniqueness asserts — WITHOUT the
    // confidential_asset::register_raw + 5-of-7 FROST + confidential_transfer_raw machinery (those
    // are E2E, exercised on testnet later). #[test_only] -> excluded from production bytecode; the
    // production lifecycle/gate logic is unchanged.
    //
    // ACTIVE is reached here via test_only_set_asset_status (NOT a standalone production set_status
    // — none exists; production ACTIVE is reachable ONLY through the register_raw-bearing
    // activate_asset_ca_v4). The shim flips the in-registry status byte to let the gate/route tests
    // observe an ACTIVE/PAUSED/DORMANT row; it never touches the immutable asset_type/asset_id_fr.
    // =================================================================================
    #[test_only]
    public fun test_only_seed_v4_core_and_registry(admin: &signer, vault_seed: vector<u8>) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<VaultCoreV4>(@eunoma)) {
            let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
            let vault_addr = signer::address_of(&vault_signer);
            move_to(admin, VaultCoreV4 {
                admin: signer::address_of(admin),
                vault_addr,
                vault_signer_cap,
                paused: false,
                next_leaf_index: 0,
                vault_sequence: 0,
            });
        };
        if (!exists<AssetRegistryV4>(@eunoma)) {
            move_to(admin, AssetRegistryV4 {
                by_asset: table::new<address, AssetVaultStateV4>(),
                asset_list: vector::empty<address>(),
            });
        };
        if (!exists<BridgeTablesV4>(@eunoma)) {
            move_to(admin, BridgeTablesV4 {
                used_deposit_nonces: table::new<vector<u8>, bool>(),
                used_nullifiers: table::new<vector<u8>, bool>(),
                known_roots: table::new<vector<u8>, bool>(),
            });
        };
    }

    // Read the per-asset lifecycle status byte from the REAL registry row (DORMANT/ACTIVE/PAUSED).
    #[test_only]
    public fun test_only_asset_status(asset_addr: address): u8 acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        table::borrow(&registry.by_asset, asset_addr).status
    }

    // Read the on-chain-derived (immutable) asset_id_fr from the REAL registry row. Proves the
    // register entry stored derive_asset_id(asset_type), never a caller-supplied value (FIX-3).
    #[test_only]
    public fun test_only_asset_id_fr(asset_addr: address): vector<u8> acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        *&table::borrow(&registry.by_asset, asset_addr).asset_id_fr
    }

    // Read whether the REAL registry contains a row for asset_addr (append-only membership).
    #[test_only]
    public fun test_only_registry_contains(asset_addr: address): bool acquires AssetRegistryV4 {
        table::contains(&borrow_global<AssetRegistryV4>(@eunoma).by_asset, asset_addr)
    }

    // Flip the in-registry status byte WITHOUT register_raw (test-only; production ACTIVE is
    // reachable ONLY via the register_raw-bearing activate_asset_ca_v4). Touches ONLY the mutable
    // status field — never the immutable asset_type/asset_id_fr/decimals triple.
    #[test_only]
    public fun test_only_set_asset_status(asset_addr: address, status: u8) acquires AssetRegistryV4 {
        let registry = borrow_global_mut<AssetRegistryV4>(@eunoma);
        table::borrow_mut(&mut registry.by_asset, asset_addr).status = status;
    }

    // Drive the REAL DORMANT-idempotency gate inside activate_asset_ca_v4 (the exact
    // `assert(st.status == DORMANT, E_ASSET_ALREADY_ACTIVE)` belt that guards a double-activate),
    // bypassing only the register_raw + EK machinery (E2E). Aborts E_ASSET_ALREADY_ACTIVE (41) if
    // the row is not DORMANT.
    #[test_only]
    public fun test_only_assert_activate_requires_dormant(asset_addr: address) acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        assert!(table::contains(&registry.by_asset, asset_addr), E_ASSET_ID_MISMATCH);
        assert!(
            table::borrow(&registry.by_asset, asset_addr).status == ASSET_STATUS_DORMANT,
            E_ASSET_ALREADY_ACTIVE,
        );
    }

    // Drive the REAL per-asset status gate (`assert(st.status == ACTIVE, E_ASSET_NOT_ACTIVE)`) the
    // production deposit/withdraw/prepare/ragequit entries run at the TOP, before any global write.
    #[test_only]
    public fun test_only_assert_status_active(asset_addr: address) acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        assert!(
            table::borrow(&registry.by_asset, asset_addr).status == ASSET_STATUS_ACTIVE,
            E_ASSET_NOT_ACTIVE,
        );
    }

    // Expose the REAL on-chain derive_asset_id (Poseidon3 over the FA object-address). The MA-1
    // routing premise is that this is one-way + immutable per asset_type.
    #[test_only]
    public fun test_only_derive_asset_id(asset_type: Object<fungible_asset::Metadata>): vector<u8>
        acquires DepositBindingTestOverride
    {
        derive_asset_id(asset_type)
    }

    // Drive the EXACT MA-1 Poseidon-link assert the spend entries run at TX0/TX2/TX3/TX4:
    //   assert!(derive_asset_id(st.asset_type) == proven_asset_id, E_ASSET_ID_MISMATCH)
    // st.asset_type is read from the REAL registry row (attacker-chosen asset_addr is the routing
    // key); proven_asset_id is the value fed to the Groth16 publics. A cUSDC inclusion proof routed
    // through an APT asset_addr => derive_asset_id(APT) != cUSDC proven_asset_id => abort (42).
    #[test_only]
    public fun test_only_assert_ma1_route(asset_addr: address, proven_asset_id: vector<u8>)
        acquires AssetRegistryV4, DepositBindingTestOverride
    {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let asset_type = table::borrow(&registry.by_asset, asset_addr).asset_type;
        assert!(derive_asset_id(asset_type) == proven_asset_id, E_ASSET_ID_MISMATCH);
    }

    // Read whether a deposit nonce is marked in the GLOBAL BridgeTablesV4 (proves the MB-2 ordering
    // invariant: a DORMANT-asset step2a aborts on the status gate BEFORE the nonce is burned).
    #[test_only]
    public fun test_only_deposit_nonce_used(nonce: vector<u8>): bool acquires BridgeTablesV4 {
        if (!exists<BridgeTablesV4>(@eunoma)) { return false };
        table::contains(&borrow_global<BridgeTablesV4>(@eunoma).used_deposit_nonces, nonce)
    }

    // Drive the EXACT deposit_step2a_eunoma_verify_v3 prefix ordering (MB-2, LOAD-BEARING): resolve
    // the registry row, gate `status == ACTIVE` (E_ASSET_NOT_ACTIVE) FIRST, then — and only then —
    // mark the deposit nonce via the REAL check_and_mark_deposit_nonce_v4. If the gate aborts
    // (DORMANT/PAUSED), the abort rolls back the whole tx, so no nonce slot is ever burned. This is
    // the precise prefix of the production entry (lines :1653-1671), with the FROST + Groth16 + CA
    // machinery (E2E) elided AFTER the gate-then-nonce ordering it exists to protect.
    #[test_only]
    public fun test_only_deposit_step2a_gate_then_mark_nonce(asset_addr: address, nonce: vector<u8>)
        acquires AssetRegistryV4, BridgeTablesV4
    {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let st = table::borrow(&registry.by_asset, asset_addr);
        assert!(st.status == ASSET_STATUS_ACTIVE, E_ASSET_NOT_ACTIVE);
        let tables = borrow_global_mut<BridgeTablesV4>(@eunoma);
        check_and_mark_deposit_nonce_v4(tables, &nonce);
    }

    // Read the GLOBAL unified-tree append index (deposits + change leaves). Monotonic.
    #[test_only]
    public fun test_only_next_leaf_index(): u64 acquires VaultCoreV4 {
        borrow_global<VaultCoreV4>(@eunoma).next_leaf_index
    }

    // Bump the GLOBAL next_leaf_index via the SAME production statement shape (post-increment) used
    // by deposit finalization + the partial-withdraw change-leaf emit. Proves the counter is shared
    // + strictly monotonic across asset-agnostic appends.
    #[test_only]
    public fun test_only_bump_next_leaf_index(): u64 acquires VaultCoreV4 {
        let core = borrow_global_mut<VaultCoreV4>(@eunoma);
        core.next_leaf_index = core.next_leaf_index + 1;
        core.next_leaf_index
    }

    // Filter the REAL append-only asset_list to status == ACTIVE — the ops-liveness invariant
    // (dormant-lifecycle-VERIFIED §4.9): the rollover/normalize maintenance loop skips DORMANT (and
    // PAUSED) rows so one not-yet-allow-listed asset can't abort the whole batch.
    #[test_only]
    public fun test_only_active_asset_addrs(): vector<address> acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        let out = vector::empty<address>();
        let n = vector::length(&registry.asset_list);
        let i = 0;
        while (i < n) {
            let a = *vector::borrow(&registry.asset_list, i);
            if (table::borrow(&registry.by_asset, a).status == ASSET_STATUS_ACTIVE) {
                vector::push_back(&mut out, a);
            };
            i = i + 1;
        };
        out
    }

    #[test_only]
    public fun test_only_gas_fee_config_v1(): (u64, address) acquires GasFeeConfigV1 {
        let c = borrow_global<GasFeeConfigV1>(@eunoma);
        (c.flat_fee_octas, c.reserve_addr)
    }

    // Drive the REAL emergency-exit DORMANT gate inside emergency_exit_to_raw_v4 (the
    // `assert(st.status != DORMANT, E_ASSET_NOT_ACTIVE)` belt: a never-CA-registered asset has
    // nothing to drain; PAUSED/ACTIVE are allowed because emergency drain is exactly when winding an
    // asset down). The is_confidentiality_enabled de-list gate + 5-of-7 FROST + withdraw_to_raw are
    // E2E (CA GlobalConfig is public(friend)-init only). Aborts E_ASSET_NOT_ACTIVE (40) on DORMANT.
    #[test_only]
    public fun test_only_assert_emergency_exit_not_dormant(asset_addr: address) acquires AssetRegistryV4 {
        let registry = borrow_global<AssetRegistryV4>(@eunoma);
        assert!(
            table::borrow(&registry.by_asset, asset_addr).status != ASSET_STATUS_DORMANT,
            E_ASSET_NOT_ACTIVE,
        );
    }

    // Expose the REAL emergency-exit attestation serializer (the 5-of-7-signed message). recipient +
    // amount are SIGNED fields, so two different recipients (or amounts) produce different bytes — a
    // low-priv relayer cannot redirect the recipient or change the amount without a fresh 5-of-7 sig.
    #[test_only]
    public fun test_only_serialize_emergency_exit_msg(
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        recipient: address,
        amount: u64,
        expiry_secs: u64,
    ): vector<u8> {
        serialize_emergency_exit_attestation_v4_msg(
            &domain, chain_id, bridge, vault, asset_type,
            operator_set_version, dkg_epoch, &roster_hash, &frost_group_pubkey,
            recipient, amount, expiry_secs,
        )
    }

    public fun domain_emergency_exit_v4(): vector<u8> { DOMAIN_EMERGENCY_EXIT_V4 }
    public fun domain_withdraw_v2(): vector<u8> { DOMAIN_WITHDRAW_V2 }

    // Read the IC length of the raw WithdrawProofVK / DepositBindingVK published by the V4 publish
    // entries (proves the stored ic vectors have WITHDRAW_VK_IC_LENGTH = 7 / DEPOSIT_VK_IC_LENGTH = 6).
    #[test_only]
    public fun test_only_withdraw_vk_ic_len(): u64 acquires WithdrawProofVK {
        if (!exists<WithdrawProofVK>(@eunoma)) { return 0 };
        vector::length(&borrow_global<WithdrawProofVK>(@eunoma).ic)
    }

    #[test_only]
    public fun test_only_deposit_vk_ic_len(): u64 acquires DepositBindingVK {
        if (!exists<DepositBindingVK>(@eunoma)) { return 0 };
        vector::length(&borrow_global<DepositBindingVK>(@eunoma).ic)
    }

    // Build the EXACT 6-public vector that assert_valid_withdraw_proof feeds to Groth16.
    // Returns (length, public[5]) to pin the change_commitment position without running pairing.
    #[test_only]
    public fun test_only_withdraw_publics_index5(
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
        asp_root: vector<u8>,
        state_tree_depth: u64,
        asp_tree_depth: u64,
        change_commitment: vector<u8>,
    ): (u64, vector<u8>) {
        let _asset_id = asset_id;
        let _recipient_hash = recipient_hash;
        let _amount_tag = amount_tag;
        let _ca_payload_hash = ca_payload_hash;
        let _vault_sequence = vault_sequence;
        let _state_tree_depth = state_tree_depth;
        let _asp_tree_depth = asp_tree_depth;
        let publics = vector[
            root,
            nullifier_hash,
            request_hash,
            amount_p_digest,
            asp_root,
            change_commitment,
        ];
        let len = vector::length(&publics);
        let idx5 = *vector::borrow(&publics, 5);
        (len, idx5)
    }

    // V4 const / error-code accessors (sanity-pin the hard invariants in tests).
    public fun withdraw_vk_ic_length(): u64 { WITHDRAW_VK_IC_LENGTH }
    public fun deposit_vk_ic_length(): u64 { DEPOSIT_VK_IC_LENGTH }
    public fun threshold_v2(): u64 { THRESHOLD_V2 }
    public fun asset_status_dormant(): u8 { ASSET_STATUS_DORMANT }
    public fun asset_status_active(): u8 { ASSET_STATUS_ACTIVE }
    public fun asset_status_paused(): u8 { ASSET_STATUS_PAUSED }
    public fun e_asset_not_active(): u64 { E_ASSET_NOT_ACTIVE }
    public fun e_asset_already_active(): u64 { E_ASSET_ALREADY_ACTIVE }
    public fun e_asset_id_mismatch(): u64 { E_ASSET_ID_MISMATCH }
    public fun e_amount_conservation(): u64 { E_AMOUNT_CONSERVATION }
    public fun e_not_delisted(): u64 { E_NOT_DELISTED }
    public fun e_not_admin(): u64 { E_NOT_ADMIN }
    public fun e_already_initialized(): u64 { E_ALREADY_INITIALIZED }
}
