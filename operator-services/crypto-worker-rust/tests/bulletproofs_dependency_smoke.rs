//! Milestone 4a commit 1: confirm bulletproofs + merlin crates resolve cleanly and
//! basic constructors work. The actual transfer/range-proof parity tests land in
//! commits 3-5 (transfer_sigma_reference, bulletproof_reference modules).

use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

#[test]
fn bulletproofs_generators_construct() {
    // Aptos uses n=16 bits, capacity matching transfer chunks (4) or balance chunks (8).
    let bp_gens_balance = BulletproofGens::new(16, 8);
    assert_eq!(bp_gens_balance.gens_capacity, 16);
    let bp_gens_amount = BulletproofGens::new(16, 4);
    assert_eq!(bp_gens_amount.gens_capacity, 16);
    let _ped_gens = PedersenGens::default();
}

#[test]
fn merlin_transcript_with_aptos_label() {
    // Aptos uses outer transcript label "AptosConfidentialAsset/BulletproofRangeProof"
    // per the WASM string table. Confirm merlin accepts it.
    let mut t = Transcript::new(b"AptosConfidentialAsset/BulletproofRangeProof");
    let mut challenge = [0u8; 32];
    t.challenge_bytes(b"test", &mut challenge);
    // Just verify the call works; the actual byte values are checked in commit 4.
    assert!(challenge.iter().any(|&b| b != 0));
}
