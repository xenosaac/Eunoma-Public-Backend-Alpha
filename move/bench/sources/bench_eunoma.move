// Phase D.0 gas-measurement bench wrappers around eunoma's hot-path functions.
//
// One `entry fun` per measurement target. Each one is called once via
// `aptos move run --session --function-id eunoma_bench::bench_eunoma::<fn>`
// and `gas_used` is parsed from the JSON output. The constant tx-entry overhead
// (auth, sequence bump, etc.) cancels out in candidate-vs-baseline comparisons.
//
// Run via `mvp-backend/move/scripts/measure_gas.sh <fn_name>`.
//
// Bench module is in a separate subpackage (eunoma_bench) so it is *never*
// published to the live testnet — only to ephemeral sim sessions. No attack
// surface on the production deployment.

module eunoma_bench::bench_eunoma {
    use std::bcs;
    use std::hash;
    use std::vector;
    use aptos_framework::event;

    use eunoma::pool_multi_sig_verifier;
    use eunoma::pool_batch_root_update;
    use eunoma_bench::bench_keys;

    // ========================================================================
    // Agent D5 — batched-deposit attestation bench helpers.
    //
    // Why these live in the bench package (not eunoma_bridge):
    //   eunoma_bridge's `deposit_batch_with_commitments` requires VaultConfig +
    //   PreparedDepositBindingVK + VaultConfigCache + chain_id + timestamp +
    //   `confidential_asset::register_raw` state — all infeasible in a sim
    //   session that only publishes the three Move packages. Per
    //   `move/.phase_d_baseline/baseline.json`'s `todo_benches` note:
    //   "bench_deposit_full … need full state setup (VK + vault + CA
    //   registration + Groth16 proof). Likely infeasible in sim without
    //   spoofed VK; defer to testnet measurement."
    //
    //   The benches below isolate the parts of the multi-deposit hot path
    //   that ARE measurable in sim — specifically the multi-sig amortization
    //   over a batched digest message. The per-item Groth16 verify, CA
    //   dispatch, nonce-table write, and pool push are O(N) and unchanged
    //   by the multi-deposit ABI, so they cannot move on the sim signal.
    //   Testnet measurement at Phase E will catch the full picture.
    // ========================================================================

    /// Domain prefix for per-item digest. MUST match
    /// `eunoma::eunoma_bridge::DOMAIN_DEPOSIT_BATCH_ITEM_V1` byte-for-byte
    /// (verified by re-using the same value here so the digest function
    /// produces the same bytes the bridge would compute).
    const DOMAIN_DEPOSIT_BATCH_ITEM_V1: vector<u8> = b"APTOSHIELD_DEPOSIT_BATCH_ITEM_V1";

    /// Local replica of `eunoma_bridge::batch_item_digest`. The bench package
    /// cannot link a `fun` from `eunoma_bridge` (private), but the algorithm
    /// is fixed and one-line — pinning it here gives a stable, attribution-
    /// free bench. If the bridge's digest function ever changes, this
    /// replica must change in lockstep.
    fun bench_batch_item_digest(
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        deposit_nonce: &vector<u8>,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, DOMAIN_DEPOSIT_BATCH_ITEM_V1);
        vector::append(&mut buf, *commitment);
        vector::append(&mut buf, *amount_tag);
        vector::append(&mut buf, *ca_payload_hash);
        vector::append(&mut buf, *deposit_nonce);
        hash::sha3_256(buf)
    }

    /// Hardcoded 32-byte placeholder values used by the batch-attestation
    /// benches. Real on-chain bytes will be Fr scalars from the Gate 4a
    /// fixture, but the sha3 cost is constant w.r.t. content — these are
    /// the cheapest representative bytes that still respect the 32-byte
    /// length invariant the bridge expects.
    fun fixed_32_bytes(): vector<u8> {
        x"942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613"
    }

    /// Build N parallel per-item digests, each over (commitment, amount_tag,
    /// ca_payload_hash, deposit_nonce) tuples that mirror the production
    /// shape. Per-item deposit_nonce differs by index so the resulting
    /// digests are distinct (matching production where the bridge enforces
    /// in-batch nonce uniqueness).
    fun build_n_item_digests(n: u64): vector<vector<u8>> {
        let digests = vector::empty<vector<u8>>();
        let i = 0;
        while (i < n) {
            // Unique nonce: 32 zero bytes with the LSB set to `i`. The
            // bridge accepts arbitrary byte vectors as nonces, so any
            // value with the right uniqueness property works.
            let nonce_i = vector::empty<u8>();
            vector::push_back(&mut nonce_i, (i as u8));
            let j = 1;
            while (j < 32) {
                vector::push_back(&mut nonce_i, 0u8);
                j = j + 1;
            };
            let commitment = fixed_32_bytes();
            let amount_tag = fixed_32_bytes();
            let cph = fixed_32_bytes();
            let dig = bench_batch_item_digest(&commitment, &amount_tag, &cph, &nonce_i);
            vector::push_back(&mut digests, dig);
            i = i + 1;
        };
        digests
    }

    /// Build the canonical batched-attestation message bytes for N items.
    /// Mirrors the BCS shape of `eunoma_bridge::BatchDepositAttestationMessage`
    /// (domain || chain_id || pool_id || op_set_ver || threshold || vault_addr
    /// || asset_type || item_digests || expiry_secs). The exact field types
    /// differ slightly (we use plain bytes / scalars for the bench rather
    /// than full Move framework types like `Object<Metadata>`), so the
    /// resulting bytes won't match a real on-chain attestation — but the
    /// per-byte hash cost over the BCS-encoded blob is representative.
    struct BenchBatchMsg has drop, copy {
        domain: vector<u8>,
        chain_id: u8,
        pool_id: vector<u8>,
        operator_set_version: u64,
        threshold: u64,
        vault_addr: address,
        asset_type: address, // placeholder for Object<Metadata>
        item_digests: vector<vector<u8>>,
        expiry_secs: u64,
    }

    fun build_batch_msg_bytes(n: u64): vector<u8> {
        let m = BenchBatchMsg {
            domain: b"APTOSHIELD_DEPOSIT_BATCH_OK_V1",
            chain_id: 2u8,
            pool_id: fixed_32_bytes(),
            operator_set_version: 1,
            threshold: 4,
            vault_addr: @eunoma_bench,
            asset_type: @eunoma_bench,
            item_digests: build_n_item_digests(n),
            expiry_secs: 1_900_000_000,
        };
        bcs::to_bytes(&m)
    }

    // Bare-minimum entry. Measures the tx envelope cost (~29 gas). Useful as a
    // floor — subtract this from other bench numbers to get the "pure function
    // cost". Phase D.0 smoke test target.
    public entry fun bench_noop() {
        // Intentionally empty.
    }

    /// Phase D.0 — measure `pool_multi_sig_verifier::assert_valid_attestation`
    /// with a valid 4-of-7 attestation (slot 0 = main + slots 1,2,3, slots 4-6
    /// empty). Pubkeys + sigs + message are hardcoded from bench_keys.move
    /// (auto-generated via scripts/gen_bench_keys.ts).
    ///
    /// Expected gas: ~1500-2000 (4× ed25519::signature_verify_strict +
    /// 7-slot loop overhead + length asserts). Used to bound the impact of
    /// changes Agent D5 (multi-deposit), D7 (fail-fast), and any other agent
    /// that touches assert_valid_attestation.
    public entry fun bench_multi_sig_4of7() {
        let msg = bench_keys::message_bytes();
        let sigs = bench_keys::signatures_4of7();
        let pks = bench_keys::pubkeys();
        pool_multi_sig_verifier::assert_valid_attestation(
            msg, sigs, &pks, 4, 0,
        );
    }

    // ========================================================================
    // Phase D / Agent D6 — Event payload trim micro-benches.
    //
    // PURPOSE
    //   Quantify per-byte storage gas for emitting Eunoma's four hot-path
    //   events. The bench cannot call the real `event::emit(DepositEvent {...})`
    //   sites because (a) those events are defined `has store` in modules
    //   that own them and the structs are not public, (b) the real emit sites
    //   require fully initialized VaultConfig / PendingQueue resources which
    //   are expensive sim-session setup.
    //
    // BYTE-LAYOUT EQUIVALENCE
    //   Aptos charges per-byte storage-fee gas on event payload BCS bytes.
    //   `Object<T>` is defined in aptos_framework::object as
    //       struct Object<phantom T> has copy, drop, store { inner: address }
    //   so its BCS encoding is identical to a bare `address` (32 bytes). We
    //   therefore mirror DepositEvent / WithdrawEvent here with the
    //   `Object<Metadata>` field replaced by `address`. The fixed-size fields
    //   (`u64`) and variable-size fields (`vector<u8>`) have identical BCS
    //   layout. Net effect: the per-emit BCS byte count is byte-exact, and
    //   the storage-fee gas charged is the same as the production emit.
    //
    // BASELINE vs CANDIDATE
    //   For each event we provide two structs + two entry funs:
    //     bench_emit_<event>_baseline()  — all fields present (current ABI)
    //     bench_emit_<event>_candidate() — proposed trimmed fields removed
    //   Delta = baseline - candidate is the per-emit storage-gas saved by
    //   dropping the field.
    // ========================================================================

    // ---- Helpers ----

    // Build a 32-byte vector with deterministic content (i = i-th byte).
    fun bytes32(): vector<u8> {
        let v = vector::empty<u8>();
        let i: u64 = 0;
        while (i < 32) {
            vector::push_back(&mut v, (i as u8));
            i = i + 1;
        };
        v
    }

    // ----- Phase D-Agent-D1 BCS-shrink slope probes -----
    //
    // These probes measure the gas cost of BCS-encoding a struct whose total
    // serialized size approximates the realistic DepositAttestationMessage
    // (~200 bytes BCS). The goal is to bound the gas/byte slope of
    // `bcs::to_bytes` on the attestation hot path so we can decide whether
    // shrinking the on-wire payload (pool_id u64 instead of vector<u8>, etc.)
    // gives any measurable saving.
    //
    // We can't use the production DepositAttestationMessage struct directly
    // (it's module-private). Mirror its field layout & sizes here so BCS cost
    // matches the production hot path to within a few bytes.

    struct AttnMsgLike has drop {
        domain: vector<u8>,        // ~24 bytes
        chain_id: u8,
        pool_id: vector<u8>,       // current: 32 bytes (Move pool_id_to_fr_bytes)
        operator_set_version: u64,
        threshold: u64,
        vault_addr: address,       // 32 bytes
        asset_type: address,       // 32 bytes
        commitment: vector<u8>,    // 32 bytes
        amount_tag: vector<u8>,    // 32 bytes
        ca_payload_hash: vector<u8>, // 32 bytes
        deposit_nonce: vector<u8>, // ~16 bytes
        expiry_secs: u64,
    }

    // Build a realistic-shape AttnMsgLike using a fill byte. Total BCS size:
    //   uleb(domain_len)+domain_len + 1 + uleb(pool_id_len)+pool_id_len
    //   + 8 + 8 + 32 + 32 + uleb(32)+32 + uleb(32)+32
    //   + uleb(32)+32 + uleb(16)+16 + 8
    //   With domain_len=24, pool_id_len=32: 25 + 1 + 33 + 8 + 8 + 32 + 32 + 33 + 33 + 33 + 17 + 8 = 263 bytes
    //   With domain_len=8,  pool_id_len=8:  9  + 1 + 9  + 8 + 8 + 32 + 32 + 33 + 33 + 33 + 17 + 8 = 223 bytes
    fun mk_msg_realistic(domain_len: u64, pool_id_len: u64): AttnMsgLike {
        let domain = repeat_byte(0xAB, domain_len);
        let pool_id = repeat_byte(0x01, pool_id_len);
        let commitment = repeat_byte(0x11, 32);
        let amount_tag = repeat_byte(0x22, 32);
        let ca_payload_hash = repeat_byte(0x33, 32);
        let deposit_nonce = repeat_byte(0x44, 16);
        AttnMsgLike {
            domain,
            chain_id: 2,
            pool_id,
            operator_set_version: 1,
            threshold: 4,
            vault_addr: @0x1,
            asset_type: @0x2,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs: 1735689600,
        }
    }

    fun repeat_byte(b: u8, n: u64): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut v, b);
            i = i + 1;
        };
        v
    }

    // Fixed placeholder asset address — byte-cost-equivalent to a real
    // `Object<Metadata>.inner`. Chosen to mirror the inner address that a
    // real APT-metadata Object would carry.
    const BENCH_ASSET_ADDR: address =
        @0x000000000000000000000000000000000000000000000000000000000000000a;

    // ---- DepositEvent (eunoma_bridge.move:405) ----
    //
    // Real layout:
    //   commitment: vector<u8>,    leaf_index: u64,
    //   asset_type: Object<Metadata>, amount_tag: vector<u8>,
    //   ca_payload_hash: vector<u8>, deposit_nonce: vector<u8>,
    //
    // Candidate drops asset_type (32 bytes, fixed per deployment — readable
    // from VaultConfig view).

    #[event]
    struct BenchDepositEventBaseline has drop, store {
        commitment: vector<u8>,
        leaf_index: u64,
        asset_type: address,        // mirror of Object<Metadata> (32 bytes)
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    #[event]
    struct BenchDepositEventCandidate has drop, store {
        commitment: vector<u8>,
        leaf_index: u64,
        // asset_type DROPPED — readable from VaultConfig
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    public entry fun bench_emit_deposit_event_baseline() {
        event::emit(BenchDepositEventBaseline {
            commitment: bytes32(),
            leaf_index: 42,
            asset_type: BENCH_ASSET_ADDR,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            deposit_nonce: bytes32(),
        });
    }

    public entry fun bench_emit_deposit_event_candidate() {
        event::emit(BenchDepositEventCandidate {
            commitment: bytes32(),
            leaf_index: 42,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            deposit_nonce: bytes32(),
        });
    }

    // ---- WithdrawEvent (eunoma_bridge.move:376) ----
    //
    // Real layout:
    //   nullifier_hash: vector<u8>, recipient: address,
    //   asset_type: Object<Metadata>, amount_tag: vector<u8>,
    //   ca_payload_hash: vector<u8>, vault_sequence: u64,
    //
    // Candidate drops asset_type (32 bytes).

    #[event]
    struct BenchWithdrawEventBaseline has drop, store {
        nullifier_hash: vector<u8>,
        recipient: address,
        asset_type: address,        // mirror of Object<Metadata> (32 bytes)
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
    }

    #[event]
    struct BenchWithdrawEventCandidate has drop, store {
        nullifier_hash: vector<u8>,
        recipient: address,
        // asset_type DROPPED
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
    }

    public entry fun bench_emit_withdraw_event_baseline() {
        event::emit(BenchWithdrawEventBaseline {
            nullifier_hash: bytes32(),
            recipient: @0xbeef,
            asset_type: BENCH_ASSET_ADDR,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            vault_sequence: 123,
        });
    }

    public entry fun bench_emit_withdraw_event_candidate() {
        event::emit(BenchWithdrawEventCandidate {
            nullifier_hash: bytes32(),
            recipient: @0xbeef,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            vault_sequence: 123,
        });
    }

    // ---- BatchRootUpdated (pool/batch_root_update.move:196) ----
    //
    // Real layout:
    //   batch_id: u64, old_root: vector<u8>, new_root: vector<u8>,
    //   start_index: u64, end_index: u64, batch_size: u64,
    //   queue_range_hash: vector<u8>, frontier_or_meta_hash: vector<u8>,
    //
    // Candidate drops queue_range_hash + frontier_or_meta_hash (64 bytes).
    // Both are inputs to the on-chain invariant verification (E_INV5) — once
    // verified, they're observability-only. No operator-services consumer
    // reads them back from the emitted event (verified via grep).

    #[event]
    struct BenchBatchRootUpdatedBaseline has drop, store {
        batch_id: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
    }

    #[event]
    struct BenchBatchRootUpdatedCandidate has drop, store {
        batch_id: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        // queue_range_hash + frontier_or_meta_hash DROPPED (observability only)
    }

    public entry fun bench_emit_batch_root_updated_baseline() {
        event::emit(BenchBatchRootUpdatedBaseline {
            batch_id: 7,
            old_root: bytes32(),
            new_root: bytes32(),
            start_index: 0,
            end_index: 4,
            batch_size: 4,
            queue_range_hash: bytes32(),
            frontier_or_meta_hash: bytes32(),
        });
    }

    public entry fun bench_emit_batch_root_updated_candidate() {
        event::emit(BenchBatchRootUpdatedCandidate {
            batch_id: 7,
            old_root: bytes32(),
            new_root: bytes32(),
            start_index: 0,
            end_index: 4,
            batch_size: 4,
        });
    }

    // ---- DepositQueued (pool/pending_queue.move:151) ----
    //
    // Real layout:
    //   deposit_index: u64, leaf_commitment: vector<u8>,
    //   deposit_batch_id: u64, queue_position: u64,
    //   compliance_attestation_id: u64,
    //
    // Candidate drops queue_position (8 bytes). Comment in source says
    // "equal to deposit_index for MVP (1:1)" — operator-services script
    // (testnet_batch_root_update.ts) reads deposit_index, not queue_position.

    #[event]
    struct BenchDepositQueuedBaseline has drop, store {
        deposit_index: u64,
        leaf_commitment: vector<u8>,
        deposit_batch_id: u64,
        queue_position: u64,
        compliance_attestation_id: u64,
    }

    #[event]
    struct BenchDepositQueuedCandidate has drop, store {
        deposit_index: u64,
        leaf_commitment: vector<u8>,
        deposit_batch_id: u64,
        // queue_position DROPPED (= deposit_index in MVP 1:1)
        compliance_attestation_id: u64,
    }

    public entry fun bench_emit_deposit_queued_baseline() {
        event::emit(BenchDepositQueuedBaseline {
            deposit_index: 0,
            leaf_commitment: bytes32(),
            deposit_batch_id: 0,
            queue_position: 0,
            compliance_attestation_id: 0,
        });
    }

    public entry fun bench_emit_deposit_queued_candidate() {
        event::emit(BenchDepositQueuedCandidate {
            deposit_index: 0,
            leaf_commitment: bytes32(),
            deposit_batch_id: 0,
            compliance_attestation_id: 0,
        });
    }
    /// Phase D / Agent D7 — measure the cost of `is_root_in_history(<unknown>)`
    /// in isolation. The Phase D7 fail-fast hoist relocates this call from
    /// "after borrow_global_mut<VaultConfig>" to "before borrow_global_mut",
    /// so an invalid-root abort no longer pays the VaultConfig write-set
    /// entry (Aptos charges write-set storage gas even on aborted tx).
    ///
    /// This bench measures `is_root_in_history` ALONE — answers the question:
    /// "what does it cost to call this read-only check?" Useful because the
    /// hoist moves it earlier in the call graph; if its cost ever spikes
    /// (e.g. someone makes V2 lookup O(N) by accident), the hoist would
    /// regress every withdraw success path, not just abort paths.
    ///
    /// On the eunoma_bench session (RootHistoryV2 not initialized), this
    /// hits the V1 fallback path (linear scan over h.root_history), which
    /// in a fresh session has zero entries -> returns false immediately.
    /// Expected gas: tx-envelope (~29) + 1 exists<...> check + 1 borrow_global
    /// + length(0) early-exit ≈ 35-50 gas. Subtract bench_noop (29) for the
    /// pure function cost (~10-25 gas).
    ///
    /// NOTE: requires RootHistory to exist at the session-derived address.
    /// In a fresh session it does NOT exist, so the entry just calls
    /// is_root_in_history and the bench is "what does V2-absent + V1-absent
    /// cost". Bench is informational only — primary value of the Phase D7
    /// hoist is on the ABORT path, where a real withdraw_to_recipient call
    /// with an invalid root saves one VaultConfig write-set entry. That
    /// saving only materializes on testnet (or a fully-bootstrapped sim
    /// session, which the bench infra does not currently set up).
    public entry fun bench_is_root_in_history_unknown() {
        // Read-only no-op when RootHistory doesn't exist (early return false).
        // When RootHistory exists with N entries, costs O(N) for the linear
        // scan in the V1 fallback (or O(1) lookup in V2 post-migration).
        let bogus_root = vector[
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let _ = pool_batch_root_update::is_root_in_history(bogus_root);
    }

    /// Probe A: BCS encode a realistic-sized attestation-shape message with
    /// the PRE-c1/c3 encoding: 24-byte domain + 32-byte pool_id. Matches
    /// production Move side BEFORE Phase D Agent D1's changes.
    /// Total BCS size: ~263 bytes.
    public entry fun bench_bcs_encode_attn_pool32() {
        let msg = mk_msg_realistic(24, 32);
        let _bytes = bcs::to_bytes(&msg);
    }

    /// Probe B: pool_id shrunk to 8 bytes (Phase D c1 + c2). Matches
    /// production AFTER c1/c2 (24-byte domain still). The 8-byte LE u64
    /// pool_id form mirrors the TS deposit encoder
    /// (operator-services/shared/src/attestation.ts:60-89).
    /// Total BCS size: ~239 bytes.
    public entry fun bench_bcs_encode_attn_pool8() {
        let msg = mk_msg_realistic(24, 8);
        let _bytes = bcs::to_bytes(&msg);
    }

    /// Probe C: both domain (24 → 8) AND pool_id (32 → 8) shrunk. Matches
    /// production AFTER c1 + c2 + c3. Domain separator is now "DEP_OK_1" /
    /// "WDR_OK_1" (8 bytes each) so the BCS-encoded domain shrinks from 25B
    /// (uleb(24)=1 + 24) to 9B (uleb(8)=1 + 8) = 16 bytes saved on top of c1/c2.
    /// Total BCS size: ~223 bytes.
    public entry fun bench_bcs_encode_attn_dom8_pool8() {
        let msg = mk_msg_realistic(8, 8);
        let _bytes = bcs::to_bytes(&msg);
    }

    // ====================================================================
    // Agent D5 — multi-deposit attestation benches.
    //
    // What these isolate: the bridge-side cost of (build N per-item digests
    // + BCS-encode the batched attestation message). NOT the multi-sig
    // verify itself — `bench_multi_sig_4of7` already measures that. The
    // coordinator can compute the multi-sig amortization SIM signal as:
    //
    //   per_tx_sim_savings_for_n =
    //       (n − 1) × (bench_multi_sig_4of7 − bench_noop)
    //     − (bench_deposit_batch_digest_build_nN − bench_noop)
    //     − (bench_deposit_batch_msg_build_nN − bench_deposit_batch_digest_build_nN)
    //
    // For n=4 sim, ~3 × (84−29) = 165 gas saved from amortizing 3 multi-sig
    // verifies, MINUS the cost of building the batched digest vector and
    // BCS-encoding the larger attestation message. Net sim signal will be
    // a single-digit-to-low-hundreds gas saving per batch. Whether that
    // scales to testnet is open — see `baseline.sim_vs_testnet_caveat`.
    //
    // We deliberately do NOT call `pool_multi_sig_verifier::assert_valid_attestation`
    // inside these benches: bench_keys's hardcoded signatures sign a
    // DIFFERENT message, so calling the verifier would abort and gas would
    // not be reported. Splitting the bench cleanly into "build" + "verify"
    // matches how the coordinator decomposes the savings model anyway.
    //
    // Per-item Groth16 verify, CA dispatch, nonce-table write, and pool push
    // are O(N) and ABI-unchanged by multi-deposit — they cannot move on the
    // sim signal. Testnet measurement at Phase E will catch the full picture.
    // ====================================================================

    /// Cost of building N=1 per-item digest + BCS-encoding the batch
    /// attestation message for a 1-item batch.
    public entry fun bench_deposit_batch_msg_build_n1() {
        let _msg = build_batch_msg_bytes(1);
    }

    /// Cost of building N=2 per-item digests + BCS-encoding the batch
    /// attestation message for a 2-item batch. Pair with
    /// `bench_multi_sig_4of7` (=baseline single-deposit attestation cost):
    /// expected to amortize ~55 sim gas (= bench_multi_sig_4of7 − bench_noop)
    /// across the 1 extra item, minus the digest/BCS overhead measured here.
    public entry fun bench_deposit_batch_msg_build_n2() {
        let _msg = build_batch_msg_bytes(2);
    }

    /// Cost of building N=4 per-item digests + BCS-encoding the batch
    /// attestation message for a 4-item batch. The brief's main target —
    /// projected sim savings of ~165 gas (= 3 × 55 amortized multi-sig)
    /// minus the digest+BCS overhead measured here.
    public entry fun bench_deposit_batch_msg_build_n4() {
        let _msg = build_batch_msg_bytes(4);
    }

    /// Cost of building N=8 per-item digests + BCS-encoding (max allowed
    /// batch size). Sanity check the digest+BCS overhead doesn't dominate
    /// at the upper bound; coordinator uses this to decide whether to ship
    /// `MAX_BATCH_DEPOSITS = 8` or trim it back.
    public entry fun bench_deposit_batch_msg_build_n8() {
        let _msg = build_batch_msg_bytes(8);
    }
}
