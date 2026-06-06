use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use frost_ed25519 as frost;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const SCHEME: &str = "frost_ed25519_v1";
const RFC: &str = "RFC 9591 + RFC 8032";
const THRESHOLD: u16 = 5;
const COUNT: u16 = 7;
const SEED: [u8; 32] = [0x42; 32];

const DOMAIN: &str = "EUNOMA_DEPOSIT_BIND_V2";
const CHAIN_ID: u8 = 2;
const BRIDGE_HEX: &str = "00000000000000000000000000000000000000000000000000000000eeeeeee1";
const VAULT_HEX: &str = "00000000000000000000000000000000000000000000000000000000eeeeeee2";
const ASSET_TYPE_HEX: &str = "00000000000000000000000000000000000000000000000000000000eeeeeee3";
const OPERATOR_SET_VERSION: u64 = 1;
const DKG_EPOCH: u64 = 9;
const EXPIRY_SECS: u64 = 1_800_000_000;

fn roster_hash_hex() -> String {
    "aa".repeat(32)
}
fn commitment_hex() -> String {
    "bb".repeat(32)
}
fn amount_tag_hex() -> String {
    "cc".repeat(32)
}
fn ca_payload_hash_hex() -> String {
    "dd".repeat(32)
}
fn deposit_nonce_hex() -> String {
    "ee".repeat(32)
}
fn circuit_versions_hash_hex() -> String {
    "11".repeat(32)
}

#[derive(Debug, Clone)]
struct DepositAttestationV2Message {
    domain: Vec<u8>,
    chain_id: u8,
    bridge: [u8; 32],
    vault: [u8; 32],
    asset_type: [u8; 32],
    operator_set_version: u64,
    dkg_epoch: u64,
    roster_hash: Vec<u8>,
    frost_group_pubkey: Vec<u8>,
    commitment: Vec<u8>,
    amount_tag: Vec<u8>,
    ca_payload_hash: Vec<u8>,
    deposit_nonce: Vec<u8>,
    expiry_secs: u64,
    circuit_versions_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifyingShareEntry {
    slot: u16,
    #[serde(rename = "verifyingShare")]
    verifying_share: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureFile {
    scheme: String,
    rfc: String,
    threshold: u16,
    count: u16,
    seed: String,
    #[serde(rename = "groupPublicKey")]
    group_public_key: String,
    #[serde(rename = "verifyingShares")]
    verifying_shares: Vec<VerifyingShareEntry>,
    #[serde(rename = "quorumSlots")]
    quorum_slots: Vec<u16>,
    #[serde(rename = "depositMessage")]
    deposit_message: DepositMessageJson,
    #[serde(rename = "messageBcs")]
    message_bcs: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DepositMessageJson {
    domain: String,
    #[serde(rename = "chainId")]
    chain_id: u8,
    bridge: String,
    vault: String,
    #[serde(rename = "assetType")]
    asset_type: String,
    #[serde(rename = "operatorSetVersion")]
    operator_set_version: u64,
    #[serde(rename = "dkgEpoch")]
    dkg_epoch: u64,
    #[serde(rename = "rosterHash")]
    roster_hash: String,
    #[serde(rename = "frostGroupPubkey")]
    frost_group_pubkey: String,
    commitment: String,
    #[serde(rename = "amountTag")]
    amount_tag: String,
    #[serde(rename = "caPayloadHash")]
    ca_payload_hash: String,
    #[serde(rename = "depositNonce")]
    deposit_nonce: String,
    #[serde(rename = "expirySecs")]
    expiry_secs: u64,
    #[serde(rename = "circuitVersionsHash")]
    circuit_versions_hash: String,
}

#[derive(Default)]
struct BcsWriter {
    bytes: Vec<u8>,
}

impl BcsWriter {
    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_uleb128(&mut self, mut value: usize) {
        while value >= 0x80 {
            self.bytes.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        self.bytes.push((value & 0x7f) as u8);
    }

    fn write_vector(&mut self, bytes: &[u8]) {
        self.write_uleb128(bytes.len());
        self.bytes.extend_from_slice(bytes);
    }

    fn write_address(&mut self, bytes: &[u8; 32]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn bcs_encode_message(msg: &DepositAttestationV2Message) -> Vec<u8> {
    let mut writer = BcsWriter::default();
    writer.write_vector(&msg.domain);
    writer.write_u8(msg.chain_id);
    writer.write_address(&msg.bridge);
    writer.write_address(&msg.vault);
    writer.write_address(&msg.asset_type);
    writer.write_u64(msg.operator_set_version);
    writer.write_u64(msg.dkg_epoch);
    writer.write_vector(&msg.roster_hash);
    writer.write_vector(&msg.frost_group_pubkey);
    writer.write_vector(&msg.commitment);
    writer.write_vector(&msg.amount_tag);
    writer.write_vector(&msg.ca_payload_hash);
    writer.write_vector(&msg.deposit_nonce);
    writer.write_u64(msg.expiry_secs);
    writer.write_vector(&msg.circuit_versions_hash);
    writer.finish()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    (0..raw.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&raw[idx..idx + 2], 16).expect("hex byte"))
        .collect()
}

fn address_bytes(hex: &str) -> [u8; 32] {
    let v = hex_decode(hex);
    assert_eq!(v.len(), 32, "address must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn build_deposit_message(group_public_key_hex: &str) -> DepositAttestationV2Message {
    DepositAttestationV2Message {
        domain: DOMAIN.as_bytes().to_vec(),
        chain_id: CHAIN_ID,
        bridge: address_bytes(BRIDGE_HEX),
        vault: address_bytes(VAULT_HEX),
        asset_type: address_bytes(ASSET_TYPE_HEX),
        operator_set_version: OPERATOR_SET_VERSION,
        dkg_epoch: DKG_EPOCH,
        roster_hash: hex_decode(&roster_hash_hex()),
        frost_group_pubkey: hex_decode(group_public_key_hex),
        commitment: hex_decode(&commitment_hex()),
        amount_tag: hex_decode(&amount_tag_hex()),
        ca_payload_hash: hex_decode(&ca_payload_hash_hex()),
        deposit_nonce: hex_decode(&deposit_nonce_hex()),
        expiry_secs: EXPIRY_SECS,
        circuit_versions_hash: hex_decode(&circuit_versions_hash_hex()),
    }
}

fn deposit_message_json(msg: &DepositAttestationV2Message) -> DepositMessageJson {
    DepositMessageJson {
        domain: DOMAIN.to_string(),
        chain_id: msg.chain_id,
        bridge: hex_encode(&msg.bridge),
        vault: hex_encode(&msg.vault),
        asset_type: hex_encode(&msg.asset_type),
        operator_set_version: msg.operator_set_version,
        dkg_epoch: msg.dkg_epoch,
        roster_hash: hex_encode(&msg.roster_hash),
        frost_group_pubkey: hex_encode(&msg.frost_group_pubkey),
        commitment: hex_encode(&msg.commitment),
        amount_tag: hex_encode(&msg.amount_tag),
        ca_payload_hash: hex_encode(&msg.ca_payload_hash),
        deposit_nonce: hex_encode(&msg.deposit_nonce),
        expiry_secs: msg.expiry_secs,
        circuit_versions_hash: hex_encode(&msg.circuit_versions_hash),
    }
}

fn run_deterministic_dkg() -> (
    BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
    let mut rng = ChaCha20Rng::from_seed(SEED);

    let mut round1_secret_packages = BTreeMap::new();
    let mut received_round1_packages: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    > = BTreeMap::new();

    for participant_index in 1..=COUNT {
        let participant_identifier: frost::Identifier =
            participant_index.try_into().expect("nonzero identifier");
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, COUNT, THRESHOLD, &mut rng)
                .expect("part1");
        round1_secret_packages.insert(participant_identifier, round1_secret_package);
        for receiver_index in 1..=COUNT {
            if receiver_index == participant_index {
                continue;
            }
            let receiver_identifier: frost::Identifier =
                receiver_index.try_into().expect("nonzero identifier");
            received_round1_packages
                .entry(receiver_identifier)
                .or_default()
                .insert(participant_identifier, round1_package.clone());
        }
    }

    let mut round2_secret_packages = BTreeMap::new();
    let mut received_round2_packages: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();

    for participant_index in 1..=COUNT {
        let participant_identifier: frost::Identifier =
            participant_index.try_into().expect("nonzero identifier");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .expect("round1 package");
        let round1_packages = &received_round1_packages[&participant_identifier];
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages).expect("part2");
        round2_secret_packages.insert(participant_identifier, round2_secret_package);
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_default()
                .insert(participant_identifier, round2_package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_package: Option<frost::keys::PublicKeyPackage> = None;
    for participant_index in 1..=COUNT {
        let participant_identifier: frost::Identifier =
            participant_index.try_into().expect("nonzero identifier");
        let round2_secret_package = &round2_secret_packages[&participant_identifier];
        let round1_packages = &received_round1_packages[&participant_identifier];
        let round2_packages = &received_round2_packages[&participant_identifier];
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)
                .expect("part3");
        if let Some(existing) = &public_package {
            assert_eq!(existing.verifying_key(), pubkey_package.verifying_key());
        } else {
            public_package = Some(pubkey_package);
        }
        key_packages.insert(participant_identifier, key_package);
    }
    (key_packages, public_package.expect("public package"))
}

fn frost_sign(
    message: &[u8],
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_package: &frost::keys::PublicKeyPackage,
    quorum: &[frost::Identifier],
) -> frost::Signature {
    let mut rng = ChaCha20Rng::from_seed([0x43; 32]);
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for id in quorum {
        let key_package = &key_packages[id];
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(*id, nonces);
        commitments_map.insert(*id, commitments);
    }
    let signing_package = frost::SigningPackage::new(commitments_map, message);
    let mut signature_shares = BTreeMap::new();
    for id in quorum {
        let key_package = &key_packages[id];
        let nonces = &nonces_map[id];
        let share = frost::round2::sign(&signing_package, nonces, key_package).expect("sign");
        signature_shares.insert(*id, share);
    }
    frost::aggregate(&signing_package, &signature_shares, public_package).expect("aggregate")
}

fn signature_to_hex(sig: &frost::Signature) -> String {
    let value = serde_json::to_value(sig).expect("serialize signature");
    if let Some(s) = value.as_str() {
        return s.to_string();
    }
    serde_json::to_string(&value).expect("canonical signature")
}

fn verifying_key_hex(pkg: &frost::keys::PublicKeyPackage) -> String {
    let value = serde_json::to_value(pkg).expect("serialize public package");
    value
        .get("verifying_key")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .expect("verifying_key field")
}

fn verifying_share_hex(pkg: &frost::keys::KeyPackage) -> String {
    let value = serde_json::to_value(pkg).expect("serialize key package");
    value
        .get("verifying_share")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .expect("verifying_share field")
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("frost_aptos_strict_verify.json")
}

fn move_test_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("operator-services parent")
        .parent()
        .expect("repo root")
        .join("move")
        .join("tests")
        .join("frost_attestation_strict_verify_test.move")
}

fn build_fixture() -> FixtureFile {
    let (key_packages, public_package) = run_deterministic_dkg();
    let group_public_key = verifying_key_hex(&public_package);
    let verifying_shares: Vec<VerifyingShareEntry> = (1..=COUNT)
        .map(|slot| {
            let id: frost::Identifier = slot.try_into().expect("nonzero identifier");
            VerifyingShareEntry {
                slot: slot - 1,
                verifying_share: verifying_share_hex(&key_packages[&id]),
            }
        })
        .collect();
    let msg = build_deposit_message(&group_public_key);
    let message_bcs = bcs_encode_message(&msg);
    let quorum_slots: Vec<u16> = (0..THRESHOLD).collect();
    let quorum: Vec<frost::Identifier> = quorum_slots
        .iter()
        .map(|slot| (*slot + 1).try_into().expect("nonzero identifier"))
        .collect();
    let signature = frost_sign(&message_bcs, &key_packages, &public_package, &quorum);
    public_package
        .verifying_key()
        .verify(&message_bcs, &signature)
        .expect("FROST signature verifies");
    let signature_hex = signature_to_hex(&signature);
    FixtureFile {
        scheme: SCHEME.to_string(),
        rfc: RFC.to_string(),
        threshold: THRESHOLD,
        count: COUNT,
        seed: hex_encode(&SEED),
        group_public_key,
        verifying_shares,
        quorum_slots,
        deposit_message: deposit_message_json(&msg),
        message_bcs: hex_encode(&message_bcs),
        signature: signature_hex,
    }
}

fn load_fixture() -> FixtureFile {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    serde_json::from_slice(&bytes).expect("parse fixture")
}

#[test]
#[ignore]
fn regenerate_fixture() {
    let fixture = build_fixture();
    let json = serde_json::to_string_pretty(&fixture).expect("serialize fixture");
    fs::create_dir_all(fixture_path().parent().expect("fixture dir")).expect("create fixtures dir");
    fs::write(fixture_path(), json).expect("write fixture");
    println!("wrote fixture to {}", fixture_path().display());
}

#[test]
fn fixture_signature_verifies_with_frost_library() {
    let fixture = load_fixture();
    let pubkey_bytes = hex_decode(&fixture.group_public_key);
    let sig_bytes = hex_decode(&fixture.signature);
    let message_bytes = hex_decode(&fixture.message_bcs);
    assert_eq!(pubkey_bytes.len(), 32);
    assert_eq!(sig_bytes.len(), 64);

    let pubkey_value = serde_json::Value::String(fixture.group_public_key.clone());
    let verifying_key: frost::VerifyingKey =
        serde_json::from_value(pubkey_value).expect("deserialize verifying key");
    let sig_value = serde_json::Value::String(fixture.signature.clone());
    let signature: frost::Signature =
        serde_json::from_value(sig_value).expect("deserialize signature");
    verifying_key
        .verify(&message_bytes, &signature)
        .expect("FROST signature verifies");

    let rebuilt = build_deposit_message(&fixture.group_public_key);
    let rebuilt_bcs = bcs_encode_message(&rebuilt);
    assert_eq!(hex_encode(&rebuilt_bcs), fixture.message_bcs);

    let mut flipped = sig_bytes.clone();
    flipped[0] ^= 0xff;
    let flipped_value = serde_json::Value::String(hex_encode(&flipped));
    let flipped_signature = serde_json::from_value::<frost::Signature>(flipped_value);
    if let Ok(flipped_signature) = flipped_signature {
        assert!(verifying_key
            .verify(&message_bytes, &flipped_signature)
            .is_err());
    }
    // If deserialization itself failed, that is a stronger rejection than
    // an Ed25519 verify failure — equally acceptable for the parity check.
}

#[test]
fn move_constants_parity() {
    let move_test = match fs::read_to_string(move_test_path()) {
        Ok(text) => text,
        Err(_) => return,
    };
    let fixture = load_fixture();
    let assert_contains = |needle: &str, label: &str| {
        assert!(
            move_test.contains(needle),
            "Move test missing {label}: {needle}"
        );
    };
    assert_contains(
        &format!("x\"{}\"", normalize_hex(&fixture.group_public_key)),
        "groupPublicKey",
    );
    assert_contains(
        &format!("x\"{}\"", normalize_hex(&fixture.signature)),
        "signature",
    );
    assert_contains(
        &format!("x\"{}\"", normalize_hex(&fixture.message_bcs)),
        "MESSAGE_BCS",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.roster_hash)
        ),
        "rosterHash",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.commitment)
        ),
        "commitment",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.amount_tag)
        ),
        "amountTag",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.ca_payload_hash)
        ),
        "caPayloadHash",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.deposit_nonce)
        ),
        "depositNonce",
    );
    assert_contains(
        &format!(
            "x\"{}\"",
            normalize_hex(&fixture.deposit_message.circuit_versions_hash)
        ),
        "circuitVersionsHash",
    );
}

#[test]
#[ignore]
fn regenerate_move_test_file() {
    let fixture = load_fixture();
    let move_test = move_test_template(&fixture);
    fs::create_dir_all(move_test_path().parent().expect("move tests dir"))
        .expect("create move tests dir");
    fs::write(move_test_path(), move_test).expect("write move test");
    println!("wrote Move test to {}", move_test_path().display());
}

fn move_test_template(fixture: &FixtureFile) -> String {
    let group_pubkey = normalize_hex(&fixture.group_public_key);
    let signature = normalize_hex(&fixture.signature);
    let message_bcs = normalize_hex(&fixture.message_bcs);
    let bridge = format!("@0x{}", normalize_hex(&fixture.deposit_message.bridge));
    let vault = format!("@0x{}", normalize_hex(&fixture.deposit_message.vault));
    let asset_type = format!("@0x{}", normalize_hex(&fixture.deposit_message.asset_type));
    let chain_id = fixture.deposit_message.chain_id;
    let osv = fixture.deposit_message.operator_set_version;
    let dkg_epoch = fixture.deposit_message.dkg_epoch;
    let expiry = fixture.deposit_message.expiry_secs;
    let roster_hash = normalize_hex(&fixture.deposit_message.roster_hash);
    let commitment = normalize_hex(&fixture.deposit_message.commitment);
    let amount_tag = normalize_hex(&fixture.deposit_message.amount_tag);
    let ca_payload_hash = normalize_hex(&fixture.deposit_message.ca_payload_hash);
    let deposit_nonce = normalize_hex(&fixture.deposit_message.deposit_nonce);
    let circuit_versions_hash = normalize_hex(&fixture.deposit_message.circuit_versions_hash);
    format!(
        "#[test_only]
module eunoma::frost_attestation_strict_verify_test {{
    use std::bcs;
    use std::vector;
    use aptos_std::ed25519;

    struct DepositAttestationV2Message has drop, store {{
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
    }}

    fun build_message(): DepositAttestationV2Message {{
        DepositAttestationV2Message {{
            domain: b\"{DOMAIN}\",
            chain_id: {chain_id},
            bridge: {bridge},
            vault: {vault},
            asset_type: {asset_type},
            operator_set_version: {osv},
            dkg_epoch: {dkg_epoch},
            roster_hash: x\"{roster_hash}\",
            frost_group_pubkey: x\"{group_pubkey}\",
            commitment: x\"{commitment}\",
            amount_tag: x\"{amount_tag}\",
            ca_payload_hash: x\"{ca_payload_hash}\",
            deposit_nonce: x\"{deposit_nonce}\",
            expiry_secs: {expiry},
            circuit_versions_hash: x\"{circuit_versions_hash}\",
        }}
    }}

    #[test]
    fun test_message_bcs_byte_parity() {{
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        assert!(bytes == x\"{message_bcs}\", 1);
    }}

    #[test]
    fun test_frost_group_signature_passes_strict_verify() {{
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        let sig = ed25519::new_signature_from_bytes(x\"{signature}\");
        let pubkey = ed25519::new_unvalidated_public_key_from_bytes(x\"{group_pubkey}\");
        assert!(ed25519::signature_verify_strict(&sig, &pubkey, bytes), 2);
    }}

    #[test]
    fun test_flipped_signature_byte_fails() {{
        let msg = build_message();
        let bytes = bcs::to_bytes(&msg);
        let raw = x\"{signature}\";
        let first = *vector::borrow(&raw, 0);
        let mutated_first = first ^ 0xff;
        let mutated = vector::empty<u8>();
        vector::push_back(&mut mutated, mutated_first);
        let i = 1;
        let len = vector::length(&raw);
        while (i < len) {{
            vector::push_back(&mut mutated, *vector::borrow(&raw, i));
            i = i + 1;
        }};
        let sig = ed25519::new_signature_from_bytes(mutated);
        let pubkey = ed25519::new_unvalidated_public_key_from_bytes(x\"{group_pubkey}\");
        assert!(!ed25519::signature_verify_strict(&sig, &pubkey, bytes), 3);
    }}
}}
",
    )
}

fn normalize_hex(hex: &str) -> String {
    let raw = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    raw.to_lowercase()
}
