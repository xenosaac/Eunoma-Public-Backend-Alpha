pub const DEOPERATOR_COUNT: usize = 7;
pub const DEOPERATOR_THRESHOLD: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    NotImplemented(&'static str),
    BadThreshold { threshold: usize, count: usize },
    UnderQuorum { threshold: usize, count: usize },
    ForbiddenPlaintextField(&'static str),
    MissingLocalState(String),
    InvalidRequest(String),
    Io(String),
    Serde(String),
    Crypto(String),
    InvalidDkgState(String),
    Complaint(String),
    InvalidPathSegment(&'static str),
}

pub fn validate_decimal_segment(value: &str) -> WorkerResult<()> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WorkerError::InvalidPathSegment("decimal segment"));
    }
    Ok(())
}

pub type WorkerResult<T> = Result<T, WorkerError>;

pub fn assert_v2_threshold(threshold: usize, count: usize) -> WorkerResult<()> {
    if threshold == DEOPERATOR_THRESHOLD && count == DEOPERATOR_COUNT {
        Ok(())
    } else {
        Err(WorkerError::BadThreshold { threshold, count })
    }
}

pub fn assert_slot(slot: usize) -> WorkerResult<()> {
    if slot < DEOPERATOR_COUNT {
        Ok(())
    } else {
        Err(WorkerError::BadThreshold {
            threshold: DEOPERATOR_THRESHOLD,
            count: slot + 1,
        })
    }
}

pub fn assert_quorum_slots5(slots: &[usize]) -> WorkerResult<[usize; DEOPERATOR_THRESHOLD]> {
    if slots.len() < DEOPERATOR_THRESHOLD {
        return Err(WorkerError::UnderQuorum {
            threshold: DEOPERATOR_THRESHOLD,
            count: slots.len(),
        });
    }
    if slots.len() != DEOPERATOR_THRESHOLD {
        return Err(WorkerError::BadThreshold {
            threshold: DEOPERATOR_THRESHOLD,
            count: slots.len(),
        });
    }
    let mut seen = [false; DEOPERATOR_COUNT];
    for slot in slots {
        assert_slot(*slot)?;
        if seen[*slot] {
            return Err(WorkerError::InvalidRequest(format!(
                "duplicate quorum slot {slot}"
            )));
        }
        seen[*slot] = true;
    }
    Ok(slots.try_into().expect("exactly five quorum slots"))
}

pub(crate) mod hpke_aead {
    use crate::{WorkerError, WorkerResult};
    use hpke::{
        aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
        OpModeR, OpModeS, Serializable,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    pub(crate) type HpkeKem = X25519HkdfSha256;
    pub(crate) type HpkeKdf = HkdfSha256;
    pub(crate) type HpkeAead = AesGcm256;

    pub(crate) const KEM_LABEL: &str = "DHKEM_X25519_HKDF_SHA256";
    pub(crate) const KDF_LABEL: &str = "HKDF_SHA256";
    pub(crate) const AEAD_LABEL: &str = "AES_256_GCM";

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct HpkeEnvelope {
        pub kem: String,
        pub kdf: String,
        pub aead: String,
        pub enc: String,
        pub ciphertext: String,
        pub aad_hash: String,
    }

    pub(crate) fn seal(
        public_key_hex: &str,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> WorkerResult<HpkeEnvelope> {
        let public_key_bytes = hex_decode(public_key_hex)?;
        let pk = <HpkeKem as KemTrait>::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| WorkerError::Crypto("invalid HPKE public key".to_string()))?;
        let mut rng = rand_core_09::UnwrapErr(rand_core_09::OsRng);
        let (enc, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &pk,
            info,
            plaintext,
            aad,
            &mut rng,
        )
        .map_err(|_| WorkerError::Crypto("HPKE seal failed".to_string()))?;
        Ok(HpkeEnvelope {
            kem: KEM_LABEL.to_string(),
            kdf: KDF_LABEL.to_string(),
            aead: AEAD_LABEL.to_string(),
            enc: hex_encode(enc.to_bytes().as_slice()),
            ciphertext: hex_encode(&ciphertext),
            aad_hash: sha256_hex(aad),
        })
    }

    pub(crate) fn open(
        private_key_hex: &str,
        info: &[u8],
        aad: &[u8],
        envelope: &HpkeEnvelope,
    ) -> WorkerResult<Vec<u8>> {
        validate(envelope)?;
        let private_key_bytes = hex_decode(private_key_hex)?;
        let sk = <HpkeKem as KemTrait>::PrivateKey::from_bytes(&private_key_bytes)
            .map_err(|_| WorkerError::Crypto("invalid HPKE private key".to_string()))?;
        let enc_bytes = hex_decode(&envelope.enc)?;
        let enc = <HpkeKem as KemTrait>::EncappedKey::from_bytes(&enc_bytes)
            .map_err(|_| WorkerError::Crypto("invalid HPKE encapsulated key".to_string()))?;
        let ciphertext = hex_decode(&envelope.ciphertext)?;
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
            &ciphertext,
            aad,
        )
        .map_err(|_| WorkerError::Crypto("HPKE open failed".to_string()))
    }

    pub(crate) fn validate(envelope: &HpkeEnvelope) -> WorkerResult<()> {
        if envelope.kem != KEM_LABEL || envelope.kdf != KDF_LABEL || envelope.aead != AEAD_LABEL {
            return Err(WorkerError::InvalidRequest(
                "unsupported HPKE ciphersuite".to_string(),
            ));
        }
        let enc = hex_decode(&envelope.enc)?;
        if enc.len() != 32 {
            return Err(WorkerError::InvalidRequest(
                "HPKE encapsulated key must be 32 bytes".to_string(),
            ));
        }
        let aad = hex_decode(&envelope.aad_hash)?;
        if aad.len() != 32 {
            return Err(WorkerError::InvalidRequest(
                "HPKE aadHash must be 32 bytes".to_string(),
            ));
        }
        let _ = hex_decode(&envelope.ciphertext)?;
        Ok(())
    }

    pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        hex_encode(digest.as_slice())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(hex: &str) -> WorkerResult<Vec<u8>> {
        let raw = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        if raw.len() % 2 != 0 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WorkerError::InvalidRequest(
                "expected even-length hex".to_string(),
            ));
        }
        (0..raw.len())
            .step_by(2)
            .map(|idx| {
                u8::from_str_radix(&raw[idx..idx + 2], 16)
                    .map_err(|err| WorkerError::InvalidRequest(err.to_string()))
            })
            .collect()
    }
}

pub mod local_state {
    use crate::{
        assert_quorum_slots5, assert_slot, assert_v2_threshold, WorkerError, WorkerResult,
        DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD,
    };
    use frost_ed25519 as frost;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    const FROST_KEY_PACKAGE_FILE: &str = "frost_key_package.json";
    const FROST_PUBLIC_PACKAGE_FILE: &str = "frost_public_package.json";
    const FROST_MANIFEST_FILE: &str = "frost_state_manifest.json";
    const FROST_NONCES_DIR: &str = "frost_nonces";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalFrostInitSummary {
        pub state_root: String,
        pub threshold: usize,
        pub count: usize,
        pub group_public_key: String,
        pub verifying_shares: Vec<LocalFrostVerifyingShare>,
        pub slots: Vec<LocalSlotStateSummary>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalFrostVerifyingShare {
        pub slot: usize,
        pub frost_verifying_share: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalSlotStateSummary {
        pub slot: usize,
        pub state_dir: String,
        pub has_frost_key_package: bool,
        pub has_frost_public_package: bool,
        pub frost_key_package_hash: Option<String>,
        pub frost_public_package_hash: Option<String>,
        pub pending_frost_nonces: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FrostNonceCommitmentResult {
        pub nonce_id: String,
        pub commitment_hash: String,
        pub commitments: Value,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FrostPartialSignatureResult {
        pub nonce_id: String,
        pub signature_share_hash: String,
        pub signature_share: Value,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FrostAggregateSignatureResult {
        pub signature: String,
        pub signature_hash: String,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct FrostCommitmentInput {
        pub slot: usize,
        pub commitments: Value,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct FrostSignatureShareInput {
        pub slot: usize,
        #[serde(rename = "signatureShare")]
        pub signature_share: Value,
    }

    pub fn default_state_dir(slot: usize) -> WorkerResult<PathBuf> {
        assert_slot(slot)?;
        let root = std::env::var("CRYPTO_WORKER_STATE_ROOT")
            .or_else(|_| std::env::var("EUNOMA_LOCAL_STATE_ROOT"))
            .unwrap_or_else(|_| ".agent-local/eunoma-v2".to_string());
        Ok(PathBuf::from(root).join(format!("slot-{slot}")))
    }

    pub fn state_summary(slot: usize, state_dir: &Path) -> WorkerResult<LocalSlotStateSummary> {
        assert_slot(slot)?;
        let key_path = state_dir.join(FROST_KEY_PACKAGE_FILE);
        let public_path = state_dir.join(FROST_PUBLIC_PACKAGE_FILE);
        let nonces_path = state_dir.join(FROST_NONCES_DIR);
        Ok(LocalSlotStateSummary {
            slot,
            state_dir: state_dir.display().to_string(),
            has_frost_key_package: key_path.exists(),
            has_frost_public_package: public_path.exists(),
            frost_key_package_hash: optional_file_hash(&key_path)?,
            frost_public_package_hash: optional_file_hash(&public_path)?,
            pending_frost_nonces: count_json_files(&nonces_path)?,
        })
    }

    pub fn init_frost_local(
        state_root: &Path,
        force: bool,
    ) -> WorkerResult<LocalFrostInitSummary> {
        assert_v2_threshold(DEOPERATOR_THRESHOLD, DEOPERATOR_COUNT)?;
        for slot in 0..DEOPERATOR_COUNT {
            let key_path = slot_dir(state_root, slot).join(FROST_KEY_PACKAGE_FILE);
            if key_path.exists() && !force {
                return Err(WorkerError::InvalidRequest(format!(
                    "{} already exists; pass --force to replace local FROST state",
                    key_path.display()
                )));
            }
        }

        let (key_packages, pubkey_package) = run_frost_dkg_fixture()?;
        let public_package_json = to_json_value(&pubkey_package)?;
        let group_public_key = json_string_field(&public_package_json, "verifying_key")?;
        let mut verifying_shares = Vec::with_capacity(DEOPERATOR_COUNT);
        let mut slot_summaries = Vec::with_capacity(DEOPERATOR_COUNT);

        for slot in 0..DEOPERATOR_COUNT {
            let identifier = slot_to_identifier(slot)?;
            let key_package = key_packages
                .get(&identifier)
                .ok_or_else(|| WorkerError::Crypto(format!("missing FROST key package for slot {slot}")))?;
            let key_package_json = to_json_value(key_package)?;
            let frost_verifying_share = json_string_field(&key_package_json, "verifying_share")?;
            verifying_shares.push(LocalFrostVerifyingShare {
                slot,
                frost_verifying_share,
            });

            let dir = slot_dir(state_root, slot);
            create_private_dir(&dir)?;
            create_private_dir(&dir.join(FROST_NONCES_DIR))?;
            write_private_json(&dir.join(FROST_KEY_PACKAGE_FILE), &key_package_json)?;
            write_private_json(&dir.join(FROST_PUBLIC_PACKAGE_FILE), &public_package_json)?;
            let key_hash = optional_file_hash(&dir.join(FROST_KEY_PACKAGE_FILE))?;
            let public_hash = optional_file_hash(&dir.join(FROST_PUBLIC_PACKAGE_FILE))?;
            write_private_json(
                &dir.join(FROST_MANIFEST_FILE),
                &json!({
                    "slot": slot,
                    "threshold": DEOPERATOR_THRESHOLD,
                    "count": DEOPERATOR_COUNT,
                    "groupPublicKey": group_public_key,
                    "frostVerifyingShare": verifying_shares.last().expect("share").frost_verifying_share,
                    "frostKeyPackageHash": key_hash,
                    "frostPublicPackageHash": public_hash,
                    "createdAtUnixMs": now_millis()
                }),
            )?;
            slot_summaries.push(state_summary(slot, &dir)?);
        }

        Ok(LocalFrostInitSummary {
            state_root: state_root.display().to_string(),
            threshold: DEOPERATOR_THRESHOLD,
            count: DEOPERATOR_COUNT,
            group_public_key,
            verifying_shares,
            slots: slot_summaries,
        })
    }

    pub fn create_frost_nonce_commitment(
        state_dir: &Path,
        request_id: &str,
    ) -> WorkerResult<FrostNonceCommitmentResult> {
        let key_package = load_key_package(state_dir)?;
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        let commitments_json = to_json_value(&commitments)?;
        let nonces_json = to_json_value(&nonces)?;
        let commitment_bytes = canonical_json_bytes(&commitments_json)?;
        let commitment_hash = sha256_hex(&commitment_bytes);
        let nonce_id = sha256_hex(
            [
                b"EUNOMA_FROST_NONCE_V2".as_slice(),
                request_id.as_bytes(),
                commitment_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_FROST_NONCE_TRANSCRIPT_V2".as_slice(),
                request_id.as_bytes(),
                nonce_id.as_bytes(),
                commitment_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        let nonce_path = nonces_path(state_dir, &nonce_id)?;
        write_private_json(
            &nonce_path,
            &json!({
                "nonceId": nonce_id,
                "requestId": request_id,
                "commitmentHash": commitment_hash,
                "signingNonces": nonces_json,
                "createdAtUnixMs": now_millis()
            }),
        )?;
        Ok(FrostNonceCommitmentResult {
            nonce_id,
            commitment_hash,
            commitments: commitments_json,
            transcript_hash,
        })
    }

    pub fn create_frost_partial_signature(
        state_dir: &Path,
        nonce_id: &str,
        message_hex: &str,
        commitments: Vec<FrostCommitmentInput>,
    ) -> WorkerResult<FrostPartialSignatureResult> {
        let commitment_slots = frost_commitment_slots(&commitments)?;
        assert_quorum_slots5(&commitment_slots)?;
        let key_package = load_key_package(state_dir)?;
        let nonce_path = nonces_path(state_dir, nonce_id)?;
        let stored = read_json(&nonce_path)?;
        let nonces_value = stored
            .get("signingNonces")
            .cloned()
            .ok_or_else(|| WorkerError::InvalidRequest("stored nonce file is missing signingNonces".to_string()))?;
        let nonces: frost::round1::SigningNonces = from_json_value(nonces_value)?;
        let message = hex_decode(message_hex)?;
        let commitments_map = commitments_to_map(commitments)?;
        let signing_package = frost::SigningPackage::new(commitments_map, &message);
        let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|err| WorkerError::Crypto(err.to_string()))?;
        let signature_share_json = to_json_value(&signature_share)?;
        let signature_share_hash = sha256_hex(canonical_json_bytes(&signature_share_json)?.as_slice());
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_FROST_PARTIAL_TRANSCRIPT_V2".as_slice(),
                nonce_id.as_bytes(),
                message_hex.as_bytes(),
                signature_share_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        fs::remove_file(&nonce_path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(FrostPartialSignatureResult {
            nonce_id: nonce_id.to_string(),
            signature_share_hash,
            signature_share: signature_share_json,
            transcript_hash,
        })
    }

    pub fn aggregate_frost_signature(
        state_dir: &Path,
        message_hex: &str,
        commitments: Vec<FrostCommitmentInput>,
        signature_shares: Vec<FrostSignatureShareInput>,
    ) -> WorkerResult<FrostAggregateSignatureResult> {
        let commitment_slots = frost_commitment_slots(&commitments)?;
        let signature_slots = frost_signature_share_slots(&signature_shares)?;
        assert_quorum_slots5(&commitment_slots)?;
        assert_quorum_slots5(&signature_slots)?;
        if commitment_slots != signature_slots {
            return Err(WorkerError::InvalidRequest(
                "FROST commitments and signature shares must use the same quorum slots in the same order"
                    .to_string(),
            ));
        }
        let public_package = load_public_package(state_dir)?;
        let message = hex_decode(message_hex)?;
        let signing_package = frost::SigningPackage::new(commitments_to_map(commitments)?, &message);
        let signature_share_map = signature_shares_to_map(signature_shares)?;
        let signature = frost::aggregate(&signing_package, &signature_share_map, &public_package)
            .map_err(|err| WorkerError::Crypto(err.to_string()))?;
        public_package
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|err| WorkerError::Crypto(err.to_string()))?;
        let signature_json = to_json_value(&signature)?;
        let signature = signature_json
            .as_str()
            .ok_or_else(|| WorkerError::Serde("FROST signature did not serialize as hex".to_string()))?
            .to_string();
        let signature_hash = sha256_hex(hex_decode(&signature)?.as_slice());
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_FROST_AGGREGATE_TRANSCRIPT_V2".as_slice(),
                message_hex.as_bytes(),
                signature_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        Ok(FrostAggregateSignatureResult {
            signature,
            signature_hash,
            transcript_hash,
        })
    }

    fn run_frost_dkg_fixture(
    ) -> WorkerResult<(
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    )> {
        let mut rng = rand::rngs::OsRng;
        let max_signers = DEOPERATOR_COUNT as u16;
        let min_signers = DEOPERATOR_THRESHOLD as u16;

        let mut round1_secret_packages = BTreeMap::new();
        let mut received_round1_packages = BTreeMap::new();

        for participant_index in 1..=max_signers {
            let participant_identifier = identifier_from_u16(participant_index)?;
            let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
                participant_identifier,
                max_signers,
                min_signers,
                &mut rng,
            )
            .map_err(|err| WorkerError::Crypto(err.to_string()))?;
            round1_secret_packages.insert(participant_identifier, round1_secret_package);

            for receiver_index in 1..=max_signers {
                if receiver_index == participant_index {
                    continue;
                }
                let receiver_identifier = identifier_from_u16(receiver_index)?;
                received_round1_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round1_package.clone());
            }
        }

        let mut round2_secret_packages = BTreeMap::new();
        let mut received_round2_packages = BTreeMap::new();

        for participant_index in 1..=max_signers {
            let participant_identifier = identifier_from_u16(participant_index)?;
            let round1_secret_package = round1_secret_packages
                .remove(&participant_identifier)
                .ok_or_else(|| WorkerError::Crypto("missing round1 secret package".to_string()))?;
            let round1_packages = &received_round1_packages[&participant_identifier];
            let (round2_secret_package, round2_packages) =
                frost::keys::dkg::part2(round1_secret_package, round1_packages)
                    .map_err(|err| WorkerError::Crypto(err.to_string()))?;
            round2_secret_packages.insert(participant_identifier, round2_secret_package);

            for (receiver_identifier, round2_package) in round2_packages {
                received_round2_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round2_package);
            }
        }

        let mut key_packages = BTreeMap::new();
        let mut public_package: Option<frost::keys::PublicKeyPackage> = None;

        for participant_index in 1..=max_signers {
            let participant_identifier = identifier_from_u16(participant_index)?;
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            let (key_package, pubkey_package) =
                frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)
                    .map_err(|err| WorkerError::Crypto(err.to_string()))?;
            if let Some(existing) = &public_package {
                if existing.verifying_key() != pubkey_package.verifying_key() {
                    return Err(WorkerError::Crypto(
                        "FROST DKG produced inconsistent group public keys".to_string(),
                    ));
                }
            } else {
                public_package = Some(pubkey_package);
            }
            key_packages.insert(participant_identifier, key_package);
        }

        Ok((
            key_packages,
            public_package.ok_or_else(|| WorkerError::Crypto("missing public key package".to_string()))?,
        ))
    }

    fn load_key_package(state_dir: &Path) -> WorkerResult<frost::keys::KeyPackage> {
        from_json_value(read_json(&state_dir.join(FROST_KEY_PACKAGE_FILE))?)
    }

    fn load_public_package(state_dir: &Path) -> WorkerResult<frost::keys::PublicKeyPackage> {
        from_json_value(read_json(&state_dir.join(FROST_PUBLIC_PACKAGE_FILE))?)
    }

    fn commitments_to_map(
        commitments: Vec<FrostCommitmentInput>,
    ) -> WorkerResult<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
        let mut out = BTreeMap::new();
        for item in commitments {
            assert_slot(item.slot)?;
            let previous = out.insert(
                slot_to_identifier(item.slot)?,
                from_json_value(item.commitments)?,
            );
            if previous.is_some() {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate FROST commitment slot {}",
                    item.slot
                )));
            }
        }
        Ok(out)
    }

    fn frost_commitment_slots(commitments: &[FrostCommitmentInput]) -> WorkerResult<Vec<usize>> {
        commitments
            .iter()
            .map(|item| {
                assert_slot(item.slot)?;
                Ok(item.slot)
            })
            .collect()
    }

    fn signature_shares_to_map(
        signature_shares: Vec<FrostSignatureShareInput>,
    ) -> WorkerResult<BTreeMap<frost::Identifier, frost::round2::SignatureShare>> {
        let mut out = BTreeMap::new();
        for item in signature_shares {
            assert_slot(item.slot)?;
            let previous = out.insert(
                slot_to_identifier(item.slot)?,
                from_json_value(item.signature_share)?,
            );
            if previous.is_some() {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate FROST signature share slot {}",
                    item.slot
                )));
            }
        }
        Ok(out)
    }

    fn frost_signature_share_slots(signature_shares: &[FrostSignatureShareInput]) -> WorkerResult<Vec<usize>> {
        signature_shares
            .iter()
            .map(|item| {
                assert_slot(item.slot)?;
                Ok(item.slot)
            })
            .collect()
    }

    pub(crate) fn slot_to_identifier(slot: usize) -> WorkerResult<frost::Identifier> {
        assert_slot(slot)?;
        identifier_from_u16((slot + 1) as u16)
    }

    fn identifier_from_u16(value: u16) -> WorkerResult<frost::Identifier> {
        value
            .try_into()
            .map_err(|_| WorkerError::InvalidRequest(format!("invalid FROST identifier {value}")))
    }

    fn slot_dir(state_root: &Path, slot: usize) -> PathBuf {
        state_root.join(format!("slot-{slot}"))
    }

    fn nonces_path(state_dir: &Path, nonce_id: &str) -> WorkerResult<PathBuf> {
        if !nonce_id.chars().all(|c| c.is_ascii_hexdigit()) || nonce_id.len() != 64 {
            return Err(WorkerError::InvalidRequest(
                "nonceId must be a 32-byte hex string".to_string(),
            ));
        }
        Ok(state_dir.join(FROST_NONCES_DIR).join(format!("{nonce_id}.json")))
    }

    fn read_json(path: &Path) -> WorkerResult<Value> {
        let bytes = fs::read(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WorkerError::MissingLocalState(path.display().to_string())
            } else {
                WorkerError::Io(err.to_string())
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn write_private_json(path: &Path, value: &Value) -> WorkerResult<()> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        write_private_file(path, &bytes)
    }

    fn write_private_file(path: &Path, bytes: &[u8]) -> WorkerResult<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        fs::write(path, bytes).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    fn create_private_dir(path: &Path) -> WorkerResult<()> {
        fs::create_dir_all(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_dir_permissions(path)?;
        Ok(())
    }

    fn optional_file_hash(path: &Path) -> WorkerResult<Option<String>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(Some(sha256_hex(&bytes)))
    }

    fn count_json_files(path: &Path) -> WorkerResult<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in fs::read_dir(path).map_err(|err| WorkerError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| WorkerError::Io(err.to_string()))?;
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                count += 1;
            }
        }
        Ok(count)
    }

    fn canonical_json_bytes(value: &Value) -> WorkerResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn to_json_value<T: Serialize>(value: &T) -> WorkerResult<Value> {
        serde_json::to_value(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn from_json_value<T>(value: Value) -> WorkerResult<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn json_string_field(value: &Value, key: &str) -> WorkerResult<String> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| WorkerError::Serde(format!("FROST JSON missing string field {key}")))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(hex: &str) -> WorkerResult<Vec<u8>> {
        let raw = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
        if raw.len() % 2 != 0 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WorkerError::InvalidRequest("expected even-length hex".to_string()));
        }
        (0..raw.len())
            .step_by(2)
            .map(|idx| {
                u8::from_str_radix(&raw[idx..idx + 2], 16)
                    .map_err(|err| WorkerError::InvalidRequest(err.to_string()))
            })
            .collect()
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_millis()
    }

    #[cfg(unix)]
    fn set_private_file_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_file_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn set_private_dir_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_dir_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }
}

pub mod ca_local {
    use crate::{
        assert_quorum_slots5, assert_slot, assert_v2_threshold, WorkerError, WorkerResult,
        DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD,
    };
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256, Sha512};
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    const CA_DKG_SHARE_FILE: &str = "ca_dkg_share.json";
    const CA_REGISTRATION_NONCES_DIR: &str = "ca_registration_nonces";
    const H_RISTRETTO_HEX: &str =
        "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";
    const REGISTRATION_PROTOCOL_ID: &str = "AptosConfidentialAsset/RegistrationV1";
    const REGISTRATION_TYPE_NAME: &str = "0x1::sigma_protocol_registration::Registration";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalCaDkgInitSummary {
        pub state_root: String,
        pub scheme: String,
        pub threshold: usize,
        pub count: usize,
        pub dkg_epoch: String,
        pub vault_ek: String,
        pub transcript_hash: String,
        pub commitments: Vec<String>,
        pub slots: Vec<LocalCaSlotSummary>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalCaSlotSummary {
        pub slot: usize,
        pub state_dir: String,
        pub ca_dkg_share_hash: String,
        pub public_share: String,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalCaShareFile {
        pub scheme: String,
        pub slot: usize,
        pub threshold: usize,
        pub count: usize,
        pub dkg_epoch: String,
        pub share: String,
        pub blind_share: String,
        pub public_share: String,
        pub vault_ek: String,
        pub commitments: Vec<String>,
        pub transcript_hash: String,
        pub created_at_unix_ms: u128,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LocalCaStateSummary {
        pub slot: usize,
        pub state_dir: String,
        pub has_ca_dkg_share: bool,
        pub ca_dkg_share_hash: Option<String>,
        pub vault_ek: Option<String>,
        pub ca_dkg_transcript_hash: Option<String>,
        pub pending_registration_nonces: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationNonceCommitmentResult {
        pub nonce_id: String,
        pub commitment: String,
        pub commitment_hash: String,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationPartialResponseResult {
        pub nonce_id: String,
        pub response: String,
        pub response_hash: String,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RegistrationCommitmentInput {
        pub slot: usize,
        pub commitment: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RegistrationResponseInput {
        pub slot: usize,
        pub response: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationProofResult {
        pub sigma_proto_comm: Vec<String>,
        pub sigma_proto_resp: Vec<String>,
        pub challenge: String,
        pub proof_hash: String,
        pub transcript_hash: String,
    }

    pub fn init_ca_dkg_local(
        state_root: &Path,
        dkg_epoch: &str,
        force: bool,
    ) -> WorkerResult<LocalCaDkgInitSummary> {
        assert_v2_threshold(DEOPERATOR_THRESHOLD, DEOPERATOR_COUNT)?;
        if dkg_epoch.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "dkg_epoch must be non-empty".to_string(),
            ));
        }
        for slot in 0..DEOPERATOR_COUNT {
            let share_path = slot_dir(state_root, slot).join(CA_DKG_SHARE_FILE);
            if share_path.exists() && !force {
                return Err(WorkerError::InvalidRequest(format!(
                    "{} already exists; pass --force to replace local CA DKG state",
                    share_path.display()
                )));
            }
        }

        let mut rng = OsRng;
        let dk = random_nonzero_scalar(&mut rng);
        let mut coeffs = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        coeffs.push(dk);
        for _ in 1..DEOPERATOR_THRESHOLD {
            coeffs.push(Scalar::random(&mut rng));
        }
        let mut blind_coeffs = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for _ in 0..DEOPERATOR_THRESHOLD {
            blind_coeffs.push(Scalar::random(&mut rng));
        }
        let h = h_ristretto()?;
        let commitments: Vec<RistrettoPoint> = coeffs
            .iter()
            .zip(blind_coeffs.iter())
            .map(|(coeff, blind)| RISTRETTO_BASEPOINT_POINT * coeff + h * blind)
            .collect();
        let commitment_hexes = commitments
            .iter()
            .map(|point| hex_encode(point.compress().as_bytes()))
            .collect::<Vec<_>>();
        let vault_ek = (h * dk.invert()).compress();
        let vault_ek_hex = hex_encode(vault_ek.as_bytes());
        let transcript_hash = ca_dkg_transcript_hash(dkg_epoch, &vault_ek_hex, &commitment_hexes);
        let mut slot_summaries = Vec::with_capacity(DEOPERATOR_COUNT);

        for slot in 0..DEOPERATOR_COUNT {
            let x = slot_scalar(slot)?;
            let share = eval_polynomial(&coeffs, x);
            let blind_share = eval_polynomial(&blind_coeffs, x);
            verify_pedersen_share(slot, share, blind_share, &commitments, h)?;
            let public_share = RISTRETTO_BASEPOINT_POINT * share;
            let dir = slot_dir(state_root, slot);
            create_private_dir(&dir)?;
            create_private_dir(&dir.join(CA_REGISTRATION_NONCES_DIR))?;
            let share_file = LocalCaShareFile {
                scheme: "pedersen-vss-ristretto255-local-ca-dkg-v1".to_string(),
                slot,
                threshold: DEOPERATOR_THRESHOLD,
                count: DEOPERATOR_COUNT,
                dkg_epoch: dkg_epoch.to_string(),
                share: scalar_hex(share),
                blind_share: scalar_hex(blind_share),
                public_share: hex_encode(public_share.compress().as_bytes()),
                vault_ek: vault_ek_hex.clone(),
                commitments: commitment_hexes.clone(),
                transcript_hash: transcript_hash.clone(),
                created_at_unix_ms: now_millis(),
            };
            let share_value = serde_json::to_value(&share_file)
                .map_err(|err| WorkerError::Serde(err.to_string()))?;
            let share_path = dir.join(CA_DKG_SHARE_FILE);
            write_private_json(&share_path, &share_value)?;
            let share_hash = file_hash(&share_path)?;
            slot_summaries.push(LocalCaSlotSummary {
                slot,
                state_dir: dir.display().to_string(),
                ca_dkg_share_hash: share_hash,
                public_share: share_file.public_share,
                transcript_hash: transcript_hash.clone(),
            });
        }

        Ok(LocalCaDkgInitSummary {
            state_root: state_root.display().to_string(),
            scheme: "pedersen-vss-ristretto255-local-ca-dkg-v1".to_string(),
            threshold: DEOPERATOR_THRESHOLD,
            count: DEOPERATOR_COUNT,
            dkg_epoch: dkg_epoch.to_string(),
            vault_ek: vault_ek_hex,
            transcript_hash,
            commitments: commitment_hexes,
            slots: slot_summaries,
        })
    }

    pub fn ca_state_summary(slot: usize, state_dir: &Path) -> WorkerResult<LocalCaStateSummary> {
        assert_slot(slot)?;
        let share_path = state_dir.join(CA_DKG_SHARE_FILE);
        let share = if share_path.exists() {
            Some(load_ca_share(state_dir)?)
        } else {
            None
        };
        Ok(LocalCaStateSummary {
            slot,
            state_dir: state_dir.display().to_string(),
            has_ca_dkg_share: share_path.exists(),
            ca_dkg_share_hash: optional_file_hash(&share_path)?,
            vault_ek: share.as_ref().map(|item| item.vault_ek.clone()),
            ca_dkg_transcript_hash: share.as_ref().map(|item| item.transcript_hash.clone()),
            pending_registration_nonces: count_json_files(&state_dir.join(CA_REGISTRATION_NONCES_DIR))?,
        })
    }

    pub fn load_ca_share(state_dir: &Path) -> WorkerResult<LocalCaShareFile> {
        let value = read_json(&state_dir.join(CA_DKG_SHARE_FILE))?;
        let share: LocalCaShareFile =
            serde_json::from_value(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        assert_slot(share.slot)?;
        assert_v2_threshold(share.threshold, share.count)?;
        verify_ca_share_file(&share)?;
        Ok(share)
    }

    pub fn create_registration_nonce_commitment(
        state_dir: &Path,
        request_id: &str,
    ) -> WorkerResult<RegistrationNonceCommitmentResult> {
        let share = load_ca_share(state_dir)?;
        let vault_ek = ristretto_from_hex(&share.vault_ek)?;
        let mut rng = OsRng;
        let nonce = Scalar::random(&mut rng);
        let commitment = vault_ek * nonce;
        let commitment_hex = hex_encode(commitment.compress().as_bytes());
        let commitment_hash = sha256_hex(hex_decode(&commitment_hex)?.as_slice());
        let nonce_id = sha256_hex(
            [
                b"EUNOMA_CA_REGISTRATION_NONCE_V1".as_slice(),
                request_id.as_bytes(),
                commitment_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_CA_REGISTRATION_NONCE_TRANSCRIPT_V1".as_slice(),
                request_id.as_bytes(),
                nonce_id.as_bytes(),
                share.transcript_hash.as_bytes(),
                commitment_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        write_private_json(
            &registration_nonce_path(state_dir, &nonce_id)?,
            &json!({
                "nonceId": nonce_id,
                "requestId": request_id,
                "nonce": scalar_hex(nonce),
                "commitment": commitment_hex,
                "commitmentHash": commitment_hash,
                "caDkgTranscriptHash": share.transcript_hash,
                "createdAtUnixMs": now_millis()
            }),
        )?;
        Ok(RegistrationNonceCommitmentResult {
            nonce_id,
            commitment: commitment_hex,
            commitment_hash,
            transcript_hash,
        })
    }

    pub fn create_registration_partial_response(
        state_dir: &Path,
        nonce_id: &str,
        challenge_hex: &str,
    ) -> WorkerResult<RegistrationPartialResponseResult> {
        let share = load_ca_share(state_dir)?;
        let nonce_path = registration_nonce_path(state_dir, nonce_id)?;
        let stored = read_json(&nonce_path)?;
        let nonce = scalar_from_hex(json_string_field(&stored, "nonce")?)?;
        let challenge = scalar_from_hex(challenge_hex)?;
        let share_scalar = scalar_from_hex(&share.share)?;
        let response = nonce + challenge * share_scalar;
        let response_hex = scalar_hex(response);
        let response_hash = sha256_hex(hex_decode(&response_hex)?.as_slice());
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_CA_REGISTRATION_RESPONSE_TRANSCRIPT_V1".as_slice(),
                nonce_id.as_bytes(),
                challenge_hex.as_bytes(),
                response_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        fs::remove_file(&nonce_path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(RegistrationPartialResponseResult {
            nonce_id: nonce_id.to_string(),
            response: response_hex,
            response_hash,
            transcript_hash,
        })
    }

    pub fn aggregate_registration_commitment(
        commitments: &[RegistrationCommitmentInput],
    ) -> WorkerResult<String> {
        let slots = slots_from_commitments(commitments)?;
        assert_quorum_slots5(&slots)?;
        let coeffs = lagrange_coefficients_at_zero(&slots)?;
        let mut aggregate = RistrettoPoint::default();
        for (item, coeff) in commitments.iter().zip(coeffs.iter()) {
            aggregate += ristretto_from_hex(&item.commitment)? * coeff;
        }
        Ok(hex_encode(aggregate.compress().as_bytes()))
    }

    pub fn registration_challenge(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        aggregate_commitment_hex: &str,
    ) -> WorkerResult<String> {
        Ok(scalar_hex(registration_challenge_scalar(
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            aggregate_commitment_hex,
        )?))
    }

    pub fn aggregate_registration_proof(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        commitments: Vec<RegistrationCommitmentInput>,
        responses: Vec<RegistrationResponseInput>,
    ) -> WorkerResult<RegistrationProofResult> {
        let commitment_slots = slots_from_commitments(&commitments)?;
        let response_slots = slots_from_responses(&responses)?;
        assert_quorum_slots5(&commitment_slots)?;
        assert_quorum_slots5(&response_slots)?;
        if commitment_slots != response_slots {
            return Err(WorkerError::InvalidRequest(
                "registration commitments and responses must use the same slots in the same order"
                    .to_string(),
            ));
        }
        let aggregate_commitment = aggregate_registration_commitment(&commitments)?;
        let challenge = registration_challenge(
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            &aggregate_commitment,
        )?;
        let coeffs = lagrange_coefficients_at_zero(&response_slots)?;
        let mut aggregate_response = Scalar::ZERO;
        for (item, coeff) in responses.iter().zip(coeffs.iter()) {
            aggregate_response += scalar_from_hex(&item.response)? * coeff;
        }
        verify_registration_proof(
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            &aggregate_commitment,
            &scalar_hex(aggregate_response),
        )?;
        let response_hex = scalar_hex(aggregate_response);
        let proof_hash = sha256_hex(
            [
                hex_decode(&aggregate_commitment)?.as_slice(),
                hex_decode(&response_hex)?.as_slice(),
            ]
            .concat()
            .as_slice(),
        );
        let transcript_hash = sha256_hex(
            [
                b"EUNOMA_CA_REGISTRATION_AGGREGATE_TRANSCRIPT_V1".as_slice(),
                vault_ek_hex.as_bytes(),
                sender_address_hex.as_bytes(),
                asset_type_hex.as_bytes(),
                &[chain_id],
                challenge.as_bytes(),
                proof_hash.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        Ok(RegistrationProofResult {
            sigma_proto_comm: vec![aggregate_commitment],
            sigma_proto_resp: vec![response_hex],
            challenge,
            proof_hash,
            transcript_hash,
        })
    }

    pub fn verify_registration_proof(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        commitment_hex: &str,
        response_hex: &str,
    ) -> WorkerResult<()> {
        let vault_ek = ristretto_from_hex(vault_ek_hex)?;
        let h = h_ristretto()?;
        let commitment = ristretto_from_hex(commitment_hex)?;
        let response = scalar_from_hex(response_hex)?;
        let challenge = registration_challenge_scalar(
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            commitment_hex,
        )?;
        let lhs = vault_ek * response;
        let rhs = commitment + h * challenge;
        if lhs == rhs {
            Ok(())
        } else {
            Err(WorkerError::Crypto(
                "registration sigma proof verification failed".to_string(),
            ))
        }
    }

    fn verify_ca_share_file(share: &LocalCaShareFile) -> WorkerResult<()> {
        if share.commitments.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "CA DKG share must contain {} commitments",
                DEOPERATOR_THRESHOLD
            )));
        }
        let commitments = share
            .commitments
            .iter()
            .map(|item| ristretto_from_hex(item))
            .collect::<WorkerResult<Vec<_>>>()?;
        verify_pedersen_share(
            share.slot,
            scalar_from_hex(&share.share)?,
            scalar_from_hex(&share.blind_share)?,
            &commitments,
            h_ristretto()?,
        )
    }

    fn verify_pedersen_share(
        slot: usize,
        share: Scalar,
        blind_share: Scalar,
        commitments: &[RistrettoPoint],
        h: RistrettoPoint,
    ) -> WorkerResult<()> {
        let x = slot_scalar(slot)?;
        let lhs = RISTRETTO_BASEPOINT_POINT * share + h * blind_share;
        let mut rhs = RistrettoPoint::default();
        let mut power = Scalar::ONE;
        for commitment in commitments {
            rhs += commitment * power;
            power *= x;
        }
        if lhs == rhs {
            Ok(())
        } else {
            Err(WorkerError::Crypto(format!(
                "CA DKG share verification failed for slot {slot}"
            )))
        }
    }

    fn ca_dkg_transcript_hash(
        dkg_epoch: &str,
        vault_ek: &str,
        commitments: &[String],
    ) -> String {
        sha256_hex(
            [
                b"EUNOMA_CA_DKG_TRANSCRIPT_V1".as_slice(),
                dkg_epoch.as_bytes(),
                vault_ek.as_bytes(),
                commitments.join("").as_bytes(),
            ]
            .concat()
            .as_slice(),
        )
    }

    fn registration_challenge_scalar(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        aggregate_commitment_hex: &str,
    ) -> WorkerResult<Scalar> {
        let h = h_ristretto()?;
        let vault_ek = compressed_ristretto_from_hex(vault_ek_hex)?;
        let aggregate_commitment = compressed_ristretto_from_hex(aggregate_commitment_hex)?;
        let sender = address_bytes(sender_address_hex)?;
        let asset = address_bytes(asset_type_hex)?;
        let mut dst = Writer::new();
        dst.write_uleb128(0);
        let mut framework = [0u8; 32];
        framework[31] = 1;
        dst.write_raw(&framework);
        dst.write_u8(chain_id);
        dst.write_vector(REGISTRATION_PROTOCOL_ID.as_bytes());
        let session = registration_session_bytes(&sender, &asset);
        dst.write_vector(&session);

        let mut challenge = Writer::new();
        challenge.write_raw(&dst.finish());
        challenge.write_vector(REGISTRATION_TYPE_NAME.as_bytes());
        challenge.write_u64(1);
        challenge.write_uleb128(2);
        challenge.write_vector(h.compress().as_bytes());
        challenge.write_vector(vault_ek.as_bytes());
        challenge.write_uleb128(0);
        challenge.write_uleb128(1);
        challenge.write_vector(aggregate_commitment.as_bytes());
        let first = Sha512::digest(challenge.finish());
        let mut expanded = [0u8; 65];
        expanded[..64].copy_from_slice(&first);
        expanded[64] = 0;
        let wide = Sha512::digest(expanded);
        let mut wide_array = [0u8; 64];
        wide_array.copy_from_slice(&wide);
        Ok(Scalar::from_bytes_mod_order_wide(&wide_array))
    }

    fn registration_session_bytes(sender: &[u8; 32], asset: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(sender);
        out.extend_from_slice(asset);
        out
    }

    fn slots_from_commitments(items: &[RegistrationCommitmentInput]) -> WorkerResult<Vec<usize>> {
        let mut slots = Vec::with_capacity(items.len());
        for item in items {
            assert_slot(item.slot)?;
            if slots.contains(&item.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate registration commitment slot {}",
                    item.slot
                )));
            }
            ristretto_from_hex(&item.commitment)?;
            slots.push(item.slot);
        }
        Ok(slots)
    }

    fn slots_from_responses(items: &[RegistrationResponseInput]) -> WorkerResult<Vec<usize>> {
        let mut slots = Vec::with_capacity(items.len());
        for item in items {
            assert_slot(item.slot)?;
            if slots.contains(&item.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate registration response slot {}",
                    item.slot
                )));
            }
            scalar_from_hex(&item.response)?;
            slots.push(item.slot);
        }
        Ok(slots)
    }

    fn lagrange_coefficients_at_zero(slots: &[usize]) -> WorkerResult<Vec<Scalar>> {
        assert_quorum_slots5(slots)?;
        let xs = slots
            .iter()
            .map(|slot| slot_scalar(*slot))
            .collect::<WorkerResult<Vec<_>>>()?;
        let mut out = Vec::with_capacity(xs.len());
        for (i, x_i) in xs.iter().enumerate() {
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;
            for (j, x_j) in xs.iter().enumerate() {
                if i == j {
                    continue;
                }
                numerator *= -*x_j;
                denominator *= *x_i - *x_j;
            }
            out.push(numerator * denominator.invert());
        }
        Ok(out)
    }

    fn eval_polynomial(coeffs: &[Scalar], x: Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for coeff in coeffs.iter().rev() {
            acc = acc * x + coeff;
        }
        acc
    }

    fn random_nonzero_scalar(rng: &mut OsRng) -> Scalar {
        loop {
            let scalar = Scalar::random(rng);
            if scalar != Scalar::ZERO {
                return scalar;
            }
        }
    }

    fn slot_scalar(slot: usize) -> WorkerResult<Scalar> {
        assert_slot(slot)?;
        Ok(Scalar::from((slot as u64) + 1))
    }

    fn h_ristretto() -> WorkerResult<RistrettoPoint> {
        ristretto_from_hex(H_RISTRETTO_HEX)
    }

    fn ristretto_from_hex(hex: &str) -> WorkerResult<RistrettoPoint> {
        compressed_ristretto_from_hex(hex)?
            .decompress()
            .ok_or_else(|| WorkerError::InvalidRequest("invalid compressed Ristretto point".to_string()))
    }

    fn compressed_ristretto_from_hex(hex: &str) -> WorkerResult<CompressedRistretto> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "compressed Ristretto point must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(CompressedRistretto(array))
    }

    fn scalar_from_hex(hex: &str) -> WorkerResult<Scalar> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "scalar must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(array))
    }

    fn scalar_hex(scalar: Scalar) -> String {
        hex_encode(&scalar.to_bytes())
    }

    fn address_bytes(hex: &str) -> WorkerResult<[u8; 32]> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "address must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn slot_dir(state_root: &Path, slot: usize) -> PathBuf {
        state_root.join(format!("slot-{slot}"))
    }

    fn registration_nonce_path(state_dir: &Path, nonce_id: &str) -> WorkerResult<PathBuf> {
        if !nonce_id.chars().all(|c| c.is_ascii_hexdigit()) || nonce_id.len() != 64 {
            return Err(WorkerError::InvalidRequest(
                "nonceId must be a 32-byte hex string".to_string(),
            ));
        }
        Ok(state_dir
            .join(CA_REGISTRATION_NONCES_DIR)
            .join(format!("{nonce_id}.json")))
    }

    fn read_json(path: &Path) -> WorkerResult<Value> {
        let bytes = fs::read(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WorkerError::MissingLocalState(path.display().to_string())
            } else {
                WorkerError::Io(err.to_string())
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn write_private_json(path: &Path, value: &Value) -> WorkerResult<()> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        write_private_file(path, &bytes)
    }

    fn write_private_file(path: &Path, bytes: &[u8]) -> WorkerResult<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        fs::write(path, bytes).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    fn create_private_dir(path: &Path) -> WorkerResult<()> {
        fs::create_dir_all(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_dir_permissions(path)?;
        Ok(())
    }

    fn file_hash(path: &Path) -> WorkerResult<String> {
        let bytes = fs::read(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    fn optional_file_hash(path: &Path) -> WorkerResult<Option<String>> {
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(file_hash(path)?))
    }

    fn count_json_files(path: &Path) -> WorkerResult<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in fs::read_dir(path).map_err(|err| WorkerError::Io(err.to_string()))? {
            let entry = entry.map_err(|err| WorkerError::Io(err.to_string()))?;
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                count += 1;
            }
        }
        Ok(count)
    }

    fn json_string_field<'a>(value: &'a Value, key: &str) -> WorkerResult<&'a str> {
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| WorkerError::Serde(format!("CA JSON missing string field {key}")))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(hex: &str) -> WorkerResult<Vec<u8>> {
        let raw = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
        if raw.len() % 2 != 0 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WorkerError::InvalidRequest("expected even-length hex".to_string()));
        }
        (0..raw.len())
            .step_by(2)
            .map(|idx| {
                u8::from_str_radix(&raw[idx..idx + 2], 16)
                    .map_err(|err| WorkerError::InvalidRequest(err.to_string()))
            })
            .collect()
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_millis()
    }

    #[derive(Default)]
    struct Writer {
        parts: Vec<u8>,
    }

    impl Writer {
        fn new() -> Self {
            Self { parts: Vec::new() }
        }

        fn write_raw(&mut self, bytes: &[u8]) {
            self.parts.extend_from_slice(bytes);
        }

        fn write_u8(&mut self, value: u8) {
            self.parts.push(value);
        }

        fn write_u64(&mut self, value: u64) {
            self.parts.extend_from_slice(&value.to_le_bytes());
        }

        fn write_uleb128(&mut self, mut value: usize) {
            while value >= 0x80 {
                self.parts.push(((value & 0x7f) as u8) | 0x80);
                value >>= 7;
            }
            self.parts.push((value & 0x7f) as u8);
        }

        fn write_vector(&mut self, bytes: &[u8]) {
            self.write_uleb128(bytes.len());
            self.write_raw(bytes);
        }

        fn finish(self) -> Vec<u8> {
            self.parts
        }
    }

    #[cfg(unix)]
    fn set_private_file_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_file_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn set_private_dir_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_dir_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }
}

pub mod ca_dkg_v2 {
    use crate::hpke_aead;
    pub use crate::hpke_aead::HpkeEnvelope;
    use crate::{
        assert_slot, assert_v2_threshold, WorkerError, WorkerResult, DEOPERATOR_COUNT,
        DEOPERATOR_THRESHOLD,
    };
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use hpke::{Deserializable, Kem as KemTrait, Serializable};
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    type HpkeKem = hpke_aead::HpkeKem;

    pub(crate) const CA_DKG_V2_SHARE_FILE: &str = "ca_dkg_share_v2.json";
    pub(crate) const HPKE_KEYPAIR_FILE: &str = "hpke_x25519_keypair_v2.json";
    const HPKE_INFO: &[u8] = b"EUNOMA_CA_DKG_V2_HPKE_INFO";
    const H_RISTRETTO_HEX: &str =
        "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2Roster {
        pub operator_set_version: String,
        pub dkg_epoch: String,
        pub ca_dkg_scheme: String,
        pub threshold: usize,
        pub nodes: Vec<CaDkgV2RosterNode>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2RosterNode {
        pub slot: usize,
        pub node_id: String,
        pub endpoint: String,
        pub hpke_public_key: String,
        pub transcript_public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct EncryptedDkgShare {
        pub dealer_slot: usize,
        pub to_slot: usize,
        pub share_commitment: String,
        pub hpke: HpkeEnvelope,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DealerBroadcast {
        pub slot: usize,
        pub commitments: Vec<String>,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2Complaint {
        pub accused_slot: usize,
        pub evidence_hash: String,
        pub reason: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2RoundRequest {
        pub request_id: String,
        pub session_id: String,
        pub round: String,
        pub operator_set_version: String,
        pub dkg_epoch: String,
        pub roster_hash: String,
        pub threshold: usize,
        pub participant_slots: Vec<usize>,
        pub slot: usize,
        pub ca_dkg_v2_roster: Option<CaDkgV2Roster>,
        #[serde(default)]
        pub dealer_broadcasts: Vec<DealerBroadcast>,
        #[serde(default)]
        pub encrypted_shares: Vec<EncryptedDkgShare>,
        pub transcript_hash: Option<String>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2RoundResult {
        pub request_id: String,
        pub session_id: String,
        pub protocol: String,
        pub round: String,
        pub operator_set_version: String,
        pub dkg_epoch: String,
        pub slot: usize,
        pub accepted: bool,
        pub transcript_hash: String,
        pub artifact_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub dealer_broadcast: Option<DealerBroadcast>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub encrypted_shares: Vec<EncryptedDkgShare>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub accepted_dealers: Vec<usize>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub aggregate_commitments: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ca_dkg_share_hash: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub complaints: Vec<CaDkgV2Complaint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub abort_evidence_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub finalized: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ca_dkg_transcript_hash: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HpkeKeypairFile {
        pub scheme: String,
        pub slot: usize,
        pub public_key: String,
        pub private_key: String,
        pub created_at_unix_ms: u128,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HpkeInitSummary {
        pub state_root: String,
        pub scheme: String,
        pub slots: Vec<HpkeSlotSummary>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HpkeSlotSummary {
        pub slot: usize,
        pub state_dir: String,
        pub hpke_public_key: String,
        pub keypair_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2ShareFile {
        pub scheme: String,
        pub slot: usize,
        pub threshold: usize,
        pub count: usize,
        pub dkg_epoch: String,
        pub dk_share: String,
        pub blind_share: String,
        pub valid_dealers: Vec<usize>,
        pub aggregate_commitments: Vec<String>,
        pub transcript_hash: String,
        pub created_at_unix_ms: u128,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DkgSharePlaintext {
        dealer_slot: usize,
        receiver_slot: usize,
        dkg_epoch: String,
        roster_hash: String,
        commitments_hash: String,
        share: String,
        blind_share: String,
    }

    pub fn init_hpke_local(state_root: &Path, force: bool) -> WorkerResult<HpkeInitSummary> {
        let mut slots = Vec::with_capacity(DEOPERATOR_COUNT);
        for slot in 0..DEOPERATOR_COUNT {
            let dir = slot_dir(state_root, slot);
            create_private_dir(&dir)?;
            let path = dir.join(HPKE_KEYPAIR_FILE);
            if path.exists() && !force {
                let keypair = load_hpke_keypair_for_slot(&dir, slot)?;
                slots.push(HpkeSlotSummary {
                    slot,
                    state_dir: dir.display().to_string(),
                    hpke_public_key: keypair.public_key,
                    keypair_hash: file_hash(&path)?,
                });
                continue;
            }
            let mut rng = rand_core_09::UnwrapErr(rand_core_09::OsRng);
            let (sk, pk) = HpkeKem::gen_keypair(&mut rng);
            let keypair = HpkeKeypairFile {
                scheme: "hpke-x25519-hkdf-sha256-aes256gcm-v2".to_string(),
                slot,
                public_key: hex_encode(pk.to_bytes().as_slice()),
                private_key: hex_encode(sk.to_bytes().as_slice()),
                created_at_unix_ms: now_millis(),
            };
            write_private_json(
                &path,
                &serde_json::to_value(&keypair).map_err(|err| WorkerError::Serde(err.to_string()))?,
            )?;
            slots.push(HpkeSlotSummary {
                slot,
                state_dir: dir.display().to_string(),
                hpke_public_key: keypair.public_key,
                keypair_hash: file_hash(&path)?,
            });
        }
        Ok(HpkeInitSummary {
            state_root: state_root.display().to_string(),
            scheme: "ca_dkg_v2_hpke_x25519".to_string(),
            slots,
        })
    }

    pub fn load_ca_dkg_v2_share(state_dir: &Path) -> WorkerResult<CaDkgV2ShareFile> {
        let value = read_json(&state_dir.join(CA_DKG_V2_SHARE_FILE))?;
        let share: CaDkgV2ShareFile =
            serde_json::from_value(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        assert_slot(share.slot)?;
        assert_v2_threshold(share.threshold, share.count)?;
        if share.valid_dealers.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 share must contain all 7 valid dealers".to_string(),
            ));
        }
        if share.aggregate_commitments.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 share must contain 5 aggregate commitments".to_string(),
            ));
        }
        verify_pedersen_share(
            share.slot,
            scalar_from_hex(&share.dk_share)?,
            scalar_from_hex(&share.blind_share)?,
            &share
                .aggregate_commitments
                .iter()
                .map(|item| ristretto_from_hex(item))
                .collect::<WorkerResult<Vec<_>>>()?,
            h_ristretto()?,
        )?;
        Ok(share)
    }

    pub fn run_round(state_dir: &Path, req: CaDkgV2RoundRequest) -> WorkerResult<CaDkgV2RoundResult> {
        validate_round_request(&req)?;
        match req.round.as_str() {
            "round1" => run_round1(&req),
            "round2" => run_round2(state_dir, &req),
            "finalize" => run_finalize(state_dir, &req),
            "complaint" => Err(WorkerError::InvalidRequest(
                "CA DKG V2 complaints are emitted by round2 and abort the session".to_string(),
            )),
            _ => Err(WorkerError::InvalidRequest("invalid DKG round".to_string())),
        }
    }

    fn run_round1(req: &CaDkgV2RoundRequest) -> WorkerResult<CaDkgV2RoundResult> {
        let roster = req.ca_dkg_v2_roster.as_ref().ok_or_else(|| {
            WorkerError::InvalidRequest("caDkgV2Roster is required for CA DKG V2 round1".to_string())
        })?;
        validate_roster(roster)?;
        let mut rng = OsRng;
        let mut coeffs = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        coeffs.push(random_nonzero_scalar(&mut rng));
        for _ in 1..DEOPERATOR_THRESHOLD {
            coeffs.push(Scalar::random(&mut rng));
        }
        let mut blind_coeffs = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for _ in 0..DEOPERATOR_THRESHOLD {
            blind_coeffs.push(Scalar::random(&mut rng));
        }
        let h = h_ristretto()?;
        let commitments = coeffs
            .iter()
            .zip(blind_coeffs.iter())
            .map(|(coeff, blind)| RISTRETTO_BASEPOINT_POINT * coeff + h * blind)
            .map(|point| hex_encode(point.compress().as_bytes()))
            .collect::<Vec<_>>();
        let commitments_hash = commitments_hash(&commitments)?;
        let dealer_broadcast = DealerBroadcast {
            slot: req.slot,
            commitments: commitments.clone(),
            transcript_hash: dealer_transcript_hash(req, &commitments)?,
        };
        let mut encrypted_shares = Vec::with_capacity(DEOPERATOR_COUNT);
        for node in &roster.nodes {
            let receiver_slot = node.slot;
            let plaintext = DkgSharePlaintext {
                dealer_slot: req.slot,
                receiver_slot,
                dkg_epoch: req.dkg_epoch.clone(),
                roster_hash: normalize_hex(&req.roster_hash)?,
                commitments_hash: commitments_hash.clone(),
                share: scalar_hex(eval_polynomial(&coeffs, slot_scalar(receiver_slot)?)),
                blind_share: scalar_hex(eval_polynomial(&blind_coeffs, slot_scalar(receiver_slot)?)),
            };
            let plaintext_bytes =
                serde_json::to_vec(&plaintext).map_err(|err| WorkerError::Serde(err.to_string()))?;
            let share_commitment = sha256_hex(&plaintext_bytes);
            let aad = hpke_aad(req, req.slot, receiver_slot, &commitments_hash)?;
            let hpke = hpke_seal(&node.hpke_public_key, &plaintext_bytes, &aad)?;
            encrypted_shares.push(EncryptedDkgShare {
                dealer_slot: req.slot,
                to_slot: receiver_slot,
                share_commitment,
                hpke,
            });
        }
        let transcript_hash = dealer_broadcast.transcript_hash.clone();
        let artifact_hash = artifact_hash(req, &transcript_hash, &[b"round1".as_slice(), commitments_hash.as_bytes()]);
        Ok(CaDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "ca".to_string(),
            round: "round1".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash,
            artifact_hash,
            dealer_broadcast: Some(dealer_broadcast),
            encrypted_shares,
            accepted_dealers: Vec::new(),
            aggregate_commitments: Vec::new(),
            ca_dkg_share_hash: None,
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: None,
            ca_dkg_transcript_hash: None,
        })
    }

    fn run_round2(state_dir: &Path, req: &CaDkgV2RoundRequest) -> WorkerResult<CaDkgV2RoundResult> {
        let broadcasts = broadcasts_by_slot(req, &req.dealer_broadcasts)?;
        let envelopes = envelopes_by_dealer_for_receiver(&req.encrypted_shares, req.slot)?;
        let keypair = load_hpke_keypair_for_slot(state_dir, req.slot)?;
        let h = h_ristretto()?;
        let mut accepted = Vec::with_capacity(DEOPERATOR_COUNT);
        let mut shares = Vec::with_capacity(DEOPERATOR_COUNT);
        let mut blind_shares = Vec::with_capacity(DEOPERATOR_COUNT);
        let mut complaints = Vec::new();

        for dealer_slot in 0..DEOPERATOR_COUNT {
            let Some(broadcast) = broadcasts.get(&dealer_slot) else {
                complaints.push(complaint(dealer_slot, "missing-dealer-broadcast"));
                continue;
            };
            let Some(envelope) = envelopes.get(&dealer_slot) else {
                complaints.push(complaint(dealer_slot, "missing-encrypted-share"));
                continue;
            };
            let commitments_hash = commitments_hash(&broadcast.commitments)?;
            let aad = hpke_aad(req, dealer_slot, req.slot, &commitments_hash)?;
            if envelope.hpke.aad_hash != sha256_hex(&aad) {
                complaints.push(complaint(dealer_slot, "bad-aad-hash"));
                continue;
            }
            let plaintext_bytes = match hpke_open(&keypair.private_key, &envelope.hpke, &aad) {
                Ok(bytes) => bytes,
                Err(_) => {
                    complaints.push(complaint(dealer_slot, "hpke-open-failed"));
                    continue;
                }
            };
            if sha256_hex(&plaintext_bytes) != envelope.share_commitment {
                complaints.push(complaint(dealer_slot, "share-commitment-mismatch"));
                continue;
            }
            let plaintext: DkgSharePlaintext = match serde_json::from_slice(&plaintext_bytes) {
                Ok(value) => value,
                Err(_) => {
                    complaints.push(complaint(dealer_slot, "bad-share-plaintext"));
                    continue;
                }
            };
            if plaintext.dealer_slot != dealer_slot
                || plaintext.receiver_slot != req.slot
                || plaintext.dkg_epoch != req.dkg_epoch
                || normalize_hex(&plaintext.roster_hash)? != normalize_hex(&req.roster_hash)?
                || plaintext.commitments_hash != commitments_hash
            {
                complaints.push(complaint(dealer_slot, "share-context-mismatch"));
                continue;
            }
            let commitment_points = match broadcast
                .commitments
                .iter()
                .map(|item| ristretto_from_hex(item))
                .collect::<WorkerResult<Vec<_>>>()
            {
                Ok(points) => points,
                Err(_) => {
                    complaints.push(complaint(dealer_slot, "bad-commitment-point"));
                    continue;
                }
            };
            let share = scalar_from_hex(&plaintext.share)?;
            let blind_share = scalar_from_hex(&plaintext.blind_share)?;
            if verify_pedersen_share(req.slot, share, blind_share, &commitment_points, h).is_err() {
                complaints.push(complaint(dealer_slot, "bad-share"));
                continue;
            }
            accepted.push(dealer_slot);
            shares.push(share);
            blind_shares.push(blind_share);
        }

        let abort_evidence_hash = if complaints.is_empty() {
            None
        } else {
            Some(sha256_hex(
                serde_json::to_vec(&complaints)
                    .map_err(|err| WorkerError::Serde(err.to_string()))?
                    .as_slice(),
            ))
        };
        if !complaints.is_empty() {
            let transcript_hash = sha256_hex(abort_evidence_hash.as_ref().expect("complaints").as_bytes());
            return Ok(CaDkgV2RoundResult {
                request_id: req.request_id.clone(),
                session_id: req.session_id.clone(),
                protocol: "ca".to_string(),
                round: "round2".to_string(),
                operator_set_version: req.operator_set_version.clone(),
                dkg_epoch: req.dkg_epoch.clone(),
                slot: req.slot,
                accepted: true,
                artifact_hash: artifact_hash(req, &transcript_hash, &[b"round2-abort".as_slice()]),
                transcript_hash,
                dealer_broadcast: None,
                encrypted_shares: Vec::new(),
                accepted_dealers: accepted,
                aggregate_commitments: Vec::new(),
                ca_dkg_share_hash: None,
                complaints,
                abort_evidence_hash,
                finalized: None,
                ca_dkg_transcript_hash: None,
            });
        }

        let mut dk_share = Scalar::ZERO;
        let mut blind_share = Scalar::ZERO;
        for share in shares {
            dk_share += share;
        }
        for share in blind_shares {
            blind_share += share;
        }
        let aggregate_commitments = aggregate_commitments(&req.dealer_broadcasts)?;
        verify_pedersen_share(
            req.slot,
            dk_share,
            blind_share,
            &aggregate_commitments
                .iter()
                .map(|item| ristretto_from_hex(item))
                .collect::<WorkerResult<Vec<_>>>()?,
            h,
        )?;
        let transcript_hash = aggregate_transcript_hash(req, &req.dealer_broadcasts, &aggregate_commitments)?;
        let share_file = CaDkgV2ShareFile {
            scheme: "ca_dkg_v2_pedersen_vss_ristretto255_hpke".to_string(),
            slot: req.slot,
            threshold: DEOPERATOR_THRESHOLD,
            count: DEOPERATOR_COUNT,
            dkg_epoch: req.dkg_epoch.clone(),
            dk_share: scalar_hex(dk_share),
            blind_share: scalar_hex(blind_share),
            valid_dealers: accepted.clone(),
            aggregate_commitments: aggregate_commitments.clone(),
            transcript_hash: transcript_hash.clone(),
            created_at_unix_ms: now_millis(),
        };
        let path = state_dir.join(CA_DKG_V2_SHARE_FILE);
        write_private_json(
            &path,
            &serde_json::to_value(&share_file).map_err(|err| WorkerError::Serde(err.to_string()))?,
        )?;
        let ca_dkg_share_hash = file_hash(&path)?;
        Ok(CaDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "ca".to_string(),
            round: "round2".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            artifact_hash: artifact_hash(req, &transcript_hash, &[b"round2".as_slice(), ca_dkg_share_hash.as_bytes()]),
            transcript_hash,
            dealer_broadcast: None,
            encrypted_shares: Vec::new(),
            accepted_dealers: accepted,
            aggregate_commitments,
            ca_dkg_share_hash: Some(ca_dkg_share_hash),
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: None,
            ca_dkg_transcript_hash: None,
        })
    }

    fn run_finalize(state_dir: &Path, req: &CaDkgV2RoundRequest) -> WorkerResult<CaDkgV2RoundResult> {
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(
                "dkgEpoch does not match local CA DKG V2 share".to_string(),
            ));
        }
        if let Some(transcript_hash) = req.transcript_hash.as_ref() {
            if normalize_hex(transcript_hash)? != share.transcript_hash {
                return Err(WorkerError::InvalidRequest(
                    "transcriptHash does not match local CA DKG V2 share".to_string(),
                ));
            }
        }
        let share_hash = file_hash(&state_dir.join(CA_DKG_V2_SHARE_FILE))?;
        Ok(CaDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "ca".to_string(),
            round: "finalize".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash: share.transcript_hash.clone(),
            artifact_hash: artifact_hash(req, &share.transcript_hash, &[b"finalize".as_slice(), share_hash.as_bytes()]),
            dealer_broadcast: None,
            encrypted_shares: Vec::new(),
            accepted_dealers: share.valid_dealers,
            aggregate_commitments: share.aggregate_commitments,
            ca_dkg_share_hash: Some(share_hash),
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: Some(true),
            ca_dkg_transcript_hash: Some(share.transcript_hash),
        })
    }

    fn validate_round_request(req: &CaDkgV2RoundRequest) -> WorkerResult<()> {
        assert_v2_threshold(req.threshold, req.participant_slots.len())?;
        assert_slot(req.slot)?;
        let expected = (0..DEOPERATOR_COUNT).collect::<Vec<_>>();
        if req.participant_slots != expected {
            return Err(WorkerError::InvalidRequest(
                "participantSlots must be [0,1,2,3,4,5,6]".to_string(),
            ));
        }
        if req.operator_set_version.is_empty() || req.dkg_epoch.is_empty() {
            return Err(WorkerError::InvalidRequest(
                "operatorSetVersion and dkgEpoch must be non-empty".to_string(),
            ));
        }
        normalize_hex(&req.roster_hash)?;
        Ok(())
    }

    fn validate_roster(roster: &CaDkgV2Roster) -> WorkerResult<()> {
        if roster.ca_dkg_scheme != "ca_dkg_v2" {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 roster scheme must be ca_dkg_v2".to_string(),
            ));
        }
        assert_v2_threshold(roster.threshold, roster.nodes.len())?;
        let mut seen = BTreeSet::new();
        for node in &roster.nodes {
            assert_slot(node.slot)?;
            if !seen.insert(node.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate CA DKG V2 roster slot {}",
                    node.slot
                )));
            }
            expect_hex_len(&node.hpke_public_key, 32)?;
            expect_hex_len(&node.transcript_public_key, 32)?;
        }
        Ok(())
    }

    fn broadcasts_by_slot(
        req: &CaDkgV2RoundRequest,
        broadcasts: &[DealerBroadcast],
    ) -> WorkerResult<BTreeMap<usize, DealerBroadcast>> {
        if broadcasts.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 round2 requires 7 dealer broadcasts".to_string(),
            ));
        }
        let mut out = BTreeMap::new();
        for broadcast in broadcasts {
            assert_slot(broadcast.slot)?;
            if broadcast.commitments.len() != DEOPERATOR_THRESHOLD {
                return Err(WorkerError::InvalidRequest(
                    "dealer broadcast must contain 5 commitments".to_string(),
                ));
            }
            for commitment in &broadcast.commitments {
                ristretto_from_hex(commitment)?;
            }
            let expected = dealer_transcript_hash_with_context(
                &req.request_id,
                &req.session_id,
                &req.operator_set_version,
                &req.dkg_epoch,
                &normalize_hex(&req.roster_hash)?,
                broadcast.slot,
                &broadcast.commitments,
            )?;
            if broadcast.transcript_hash != expected {
                return Err(WorkerError::InvalidRequest(format!(
                    "dealer broadcast transcript hash mismatch for slot {}",
                    broadcast.slot
                )));
            }
            if out.insert(broadcast.slot, broadcast.clone()).is_some() {
                return Err(WorkerError::InvalidRequest(
                    "duplicate dealer broadcast".to_string(),
                ));
            }
        }
        Ok(out)
    }

    fn envelopes_by_dealer_for_receiver(
        envelopes: &[EncryptedDkgShare],
        receiver_slot: usize,
    ) -> WorkerResult<BTreeMap<usize, EncryptedDkgShare>> {
        if envelopes.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 round2 requires 7 encrypted shares for the receiver".to_string(),
            ));
        }
        let mut out = BTreeMap::new();
        for envelope in envelopes {
            assert_slot(envelope.dealer_slot)?;
            assert_slot(envelope.to_slot)?;
            if envelope.to_slot != receiver_slot {
                return Err(WorkerError::InvalidRequest(
                    "encrypted share receiver slot mismatch".to_string(),
                ));
            }
            expect_hex_len(&envelope.share_commitment, 32)?;
            validate_hpke_envelope(&envelope.hpke)?;
            if out.insert(envelope.dealer_slot, envelope.clone()).is_some() {
                return Err(WorkerError::InvalidRequest(
                    "duplicate encrypted share dealer".to_string(),
                ));
            }
        }
        Ok(out)
    }

    fn validate_hpke_envelope(envelope: &HpkeEnvelope) -> WorkerResult<()> {
        hpke_aead::validate(envelope)
    }

    fn hpke_seal(public_key_hex: &str, plaintext: &[u8], aad: &[u8]) -> WorkerResult<HpkeEnvelope> {
        hpke_aead::seal(public_key_hex, HPKE_INFO, aad, plaintext)
    }

    fn hpke_open(private_key_hex: &str, envelope: &HpkeEnvelope, aad: &[u8]) -> WorkerResult<Vec<u8>> {
        hpke_aead::open(private_key_hex, HPKE_INFO, aad, envelope)
    }

    fn aggregate_commitments(broadcasts: &[DealerBroadcast]) -> WorkerResult<Vec<String>> {
        let mut sums = vec![RistrettoPoint::default(); DEOPERATOR_THRESHOLD];
        for broadcast in broadcasts {
            if broadcast.commitments.len() != DEOPERATOR_THRESHOLD {
                return Err(WorkerError::InvalidRequest(
                    "dealer broadcast must contain 5 commitments".to_string(),
                ));
            }
            for (idx, commitment) in broadcast.commitments.iter().enumerate() {
                sums[idx] += ristretto_from_hex(commitment)?;
            }
        }
        Ok(sums
            .into_iter()
            .map(|point| hex_encode(point.compress().as_bytes()))
            .collect())
    }

    fn verify_pedersen_share(
        slot: usize,
        share: Scalar,
        blind_share: Scalar,
        commitments: &[RistrettoPoint],
        h: RistrettoPoint,
    ) -> WorkerResult<()> {
        let x = slot_scalar(slot)?;
        let lhs = RISTRETTO_BASEPOINT_POINT * share + h * blind_share;
        let mut rhs = RistrettoPoint::default();
        let mut power = Scalar::ONE;
        for commitment in commitments {
            rhs += commitment * power;
            power *= x;
        }
        if lhs == rhs {
            Ok(())
        } else {
            Err(WorkerError::Crypto(format!(
                "CA DKG V2 share verification failed for slot {slot}"
            )))
        }
    }

    fn hpke_aad(
        req: &CaDkgV2RoundRequest,
        dealer_slot: usize,
        receiver_slot: usize,
        commitments_hash: &str,
    ) -> WorkerResult<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({
            "domain": "EUNOMA_CA_DKG_V2_HPKE_AAD",
            "requestId": req.request_id,
            "sessionId": req.session_id,
            "operatorSetVersion": req.operator_set_version,
            "dkgEpoch": req.dkg_epoch,
            "rosterHash": normalize_hex(&req.roster_hash)?,
            "dealerSlot": dealer_slot,
            "receiverSlot": receiver_slot,
            "commitmentsHash": commitments_hash,
        }))
        .map_err(|err| WorkerError::Serde(err.to_string()))?)
    }

    fn commitments_hash(commitments: &[String]) -> WorkerResult<String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_CA_DKG_V2_COMMITMENTS");
        for commitment in commitments {
            bytes.extend_from_slice(&hex_decode(commitment)?);
        }
        Ok(sha256_hex(&bytes))
    }

    fn dealer_transcript_hash(req: &CaDkgV2RoundRequest, commitments: &[String]) -> WorkerResult<String> {
        dealer_transcript_hash_with_context(
            &req.request_id,
            &req.session_id,
            &req.operator_set_version,
            &req.dkg_epoch,
            &normalize_hex(&req.roster_hash)?,
            req.slot,
            commitments,
        )
    }

    fn dealer_transcript_hash_with_context(
        request_id: &str,
        session_id: &str,
        operator_set_version: &str,
        dkg_epoch: &str,
        roster_hash: &str,
        slot: usize,
        commitments: &[String],
    ) -> WorkerResult<String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_CA_DKG_V2_DEALER_BROADCAST_CTX");
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.extend_from_slice(operator_set_version.as_bytes());
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.extend_from_slice(&(slot as u64).to_le_bytes());
        bytes.extend_from_slice(commitments_hash(commitments)?.as_bytes());
        Ok(sha256_hex(&bytes))
    }

    fn aggregate_transcript_hash(
        req: &CaDkgV2RoundRequest,
        broadcasts: &[DealerBroadcast],
        aggregate_commitments: &[String],
    ) -> WorkerResult<String> {
        let mut sorted = broadcasts.to_vec();
        sorted.sort_by_key(|item| item.slot);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_CA_DKG_V2_AGGREGATE_TRANSCRIPT");
        bytes.extend_from_slice(req.request_id.as_bytes());
        bytes.extend_from_slice(req.session_id.as_bytes());
        bytes.extend_from_slice(req.operator_set_version.as_bytes());
        bytes.extend_from_slice(req.dkg_epoch.as_bytes());
        bytes.extend_from_slice(normalize_hex(&req.roster_hash)?.as_bytes());
        for broadcast in sorted {
            bytes.extend_from_slice(broadcast.transcript_hash.as_bytes());
        }
        for commitment in aggregate_commitments {
            bytes.extend_from_slice(&hex_decode(commitment)?);
        }
        Ok(sha256_hex(&bytes))
    }

    fn artifact_hash(req: &CaDkgV2RoundRequest, transcript_hash: &str, parts: &[&[u8]]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_CA_DKG_V2_ROUND_ARTIFACT");
        bytes.extend_from_slice(req.request_id.as_bytes());
        bytes.extend_from_slice(req.session_id.as_bytes());
        bytes.extend_from_slice(req.operator_set_version.as_bytes());
        bytes.extend_from_slice(req.dkg_epoch.as_bytes());
        bytes.extend_from_slice(&(req.slot as u64).to_le_bytes());
        bytes.extend_from_slice(req.round.as_bytes());
        bytes.extend_from_slice(transcript_hash.as_bytes());
        for part in parts {
            bytes.extend_from_slice(part);
        }
        sha256_hex(&bytes)
    }

    fn complaint(accused_slot: usize, reason: &str) -> CaDkgV2Complaint {
        let evidence_hash = sha256_hex(
            [
                b"EUNOMA_CA_DKG_V2_COMPLAINT".as_slice(),
                &(accused_slot as u64).to_le_bytes(),
                reason.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        CaDkgV2Complaint {
            accused_slot,
            evidence_hash,
            reason: reason.to_string(),
        }
    }

    fn load_hpke_keypair_for_slot(state_dir: &Path, slot: usize) -> WorkerResult<HpkeKeypairFile> {
        let value = read_json(&state_dir.join(HPKE_KEYPAIR_FILE))?;
        let keypair: HpkeKeypairFile =
            serde_json::from_value(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        if keypair.slot != slot {
            return Err(WorkerError::InvalidRequest(
                "HPKE keypair slot mismatch".to_string(),
            ));
        }
        expect_hex_len(&keypair.public_key, 32)?;
        expect_hex_len(&keypair.private_key, 32)?;
        let sk = <HpkeKem as KemTrait>::PrivateKey::from_bytes(&hex_decode(&keypair.private_key)?)
            .map_err(|_| WorkerError::Crypto("invalid HPKE private key".to_string()))?;
        let expected_pk = HpkeKem::sk_to_pk(&sk);
        if hex_encode(expected_pk.to_bytes().as_slice()) != normalize_hex(&keypair.public_key)? {
            return Err(WorkerError::Crypto(
                "HPKE public key does not match private key".to_string(),
            ));
        }
        Ok(keypair)
    }

    fn eval_polynomial(coeffs: &[Scalar], x: Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for coeff in coeffs.iter().rev() {
            acc = acc * x + coeff;
        }
        acc
    }

    fn random_nonzero_scalar(rng: &mut OsRng) -> Scalar {
        loop {
            let scalar = Scalar::random(rng);
            if scalar != Scalar::ZERO {
                return scalar;
            }
        }
    }

    fn slot_scalar(slot: usize) -> WorkerResult<Scalar> {
        assert_slot(slot)?;
        Ok(Scalar::from((slot as u64) + 1))
    }

    fn h_ristretto() -> WorkerResult<RistrettoPoint> {
        ristretto_from_hex(H_RISTRETTO_HEX)
    }

    fn ristretto_from_hex(hex: &str) -> WorkerResult<RistrettoPoint> {
        compressed_ristretto_from_hex(hex)?
            .decompress()
            .ok_or_else(|| WorkerError::InvalidRequest("invalid compressed Ristretto point".to_string()))
    }

    fn compressed_ristretto_from_hex(hex: &str) -> WorkerResult<CompressedRistretto> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "compressed Ristretto point must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(CompressedRistretto(array))
    }

    fn scalar_from_hex(hex: &str) -> WorkerResult<Scalar> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "scalar must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(array))
    }

    fn scalar_hex(scalar: Scalar) -> String {
        hex_encode(&scalar.to_bytes())
    }

    fn slot_dir(state_root: &Path, slot: usize) -> PathBuf {
        state_root.join(format!("slot-{slot}"))
    }

    fn read_json(path: &Path) -> WorkerResult<Value> {
        let bytes = fs::read(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WorkerError::MissingLocalState(path.display().to_string())
            } else {
                WorkerError::Io(err.to_string())
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn write_private_json(path: &Path, value: &Value) -> WorkerResult<()> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        write_private_file(path, &bytes)
    }

    fn write_private_file(path: &Path, bytes: &[u8]) -> WorkerResult<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        fs::write(path, bytes).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    fn create_private_dir(path: &Path) -> WorkerResult<()> {
        fs::create_dir_all(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_dir_permissions(path)?;
        Ok(())
    }

    fn file_hash(path: &Path) -> WorkerResult<String> {
        let bytes = fs::read(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    fn expect_hex_len(hex: &str, bytes: usize) -> WorkerResult<()> {
        let parsed = hex_decode(hex)?;
        if parsed.len() != bytes {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {bytes}-byte hex, got {}",
                parsed.len()
            )));
        }
        Ok(())
    }

    fn normalize_hex(hex: &str) -> WorkerResult<String> {
        Ok(hex_encode(&hex_decode(hex)?))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(hex: &str) -> WorkerResult<Vec<u8>> {
        let raw = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
        if raw.len() % 2 != 0 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WorkerError::InvalidRequest("expected even-length hex".to_string()));
        }
        (0..raw.len())
            .step_by(2)
            .map(|idx| {
                u8::from_str_radix(&raw[idx..idx + 2], 16)
                    .map_err(|err| WorkerError::InvalidRequest(err.to_string()))
            })
            .collect()
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_millis()
    }

    #[cfg(unix)]
    fn set_private_file_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_file_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn set_private_dir_permissions(path: &Path) -> WorkerResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|err| WorkerError::Io(err.to_string()))
    }

    #[cfg(not(unix))]
    fn set_private_dir_permissions(_path: &Path) -> WorkerResult<()> {
        Ok(())
    }
}

pub mod dkg_ca {
    use crate::{
        assert_v2_threshold, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DkgCaTranscript {
        pub dkg_epoch: u64,
        pub transcript_hash: [u8; 32],
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DkgRound {
        Round1,
        Round2,
        Complaint,
        Finalize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DkgRoundContext {
        pub dkg_epoch: u64,
        pub round: DkgRound,
        pub slot: usize,
        pub threshold: usize,
        pub participant_count: usize,
    }

    pub fn validate_round_context(ctx: &DkgRoundContext) -> WorkerResult<()> {
        assert_v2_threshold(ctx.threshold, ctx.participant_count)?;
        if ctx.slot >= DEOPERATOR_COUNT {
            return Err(WorkerError::BadThreshold {
                threshold: DEOPERATOR_THRESHOLD,
                count: ctx.slot + 1,
            });
        }
        Ok(())
    }

    pub fn run_pedersen_gjkr_round() -> WorkerResult<DkgCaTranscript> {
        Err(WorkerError::NotImplemented(
            "DKG A vault CA key generation must be implemented with audited VSS/DKG",
        ))
    }

    pub fn run_round(ctx: DkgRoundContext) -> WorkerResult<DkgCaTranscript> {
        validate_round_context(&ctx)?;
        Err(WorkerError::NotImplemented(
            "malicious-secure CA DKG round execution is not enabled",
        ))
    }
}

pub mod frost_attestation {
    use crate::{dkg_ca::DkgRoundContext, WorkerError, WorkerResult};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FrostShare {
        pub slot: u8,
        pub signature_share: [u8; 32],
    }

    pub fn sign_partial(_message: &[u8]) -> WorkerResult<FrostShare> {
        Err(WorkerError::NotImplemented(
            "FROST Ed25519 RFC 9591 signing is not implemented in this skeleton",
        ))
    }

    pub fn run_dkg_round(ctx: DkgRoundContext) -> WorkerResult<[u8; 32]> {
        crate::dkg_ca::validate_round_context(&ctx)?;
        Err(WorkerError::NotImplemented(
            "FROST Ed25519 DKG round execution is not enabled",
        ))
    }
}

pub mod threshold_sigma {
    use crate::{WorkerError, WorkerResult};

    pub fn aggregate_sigma_response() -> WorkerResult<[u8; 32]> {
        Err(WorkerError::NotImplemented(
            "threshold Aptos CA sigma aggregation is not implemented in this skeleton",
        ))
    }
}

pub mod bulletproof_mpc {
    use crate::{WorkerError, WorkerResult};

    pub fn prove_range_collaboratively() -> WorkerResult<Vec<u8>> {
        Err(WorkerError::NotImplemented(
            "collaborative Bulletproof adapter is not implemented in this skeleton",
        ))
    }
}

pub mod mpcca {
    use crate::{
        assert_v2_threshold, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MpccaRound {
        Round1,
        Round2,
        Prove,
        Finalize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MpccaRoundContext {
        pub vault_sequence: u64,
        pub round: MpccaRound,
        pub slot: usize,
        pub threshold: usize,
        pub participant_count: usize,
    }

    pub fn run_withdraw_round(ctx: MpccaRoundContext) -> WorkerResult<[u8; 32]> {
        assert_v2_threshold(ctx.threshold, ctx.participant_count)?;
        if ctx.slot >= DEOPERATOR_COUNT {
            return Err(WorkerError::BadThreshold {
                threshold: DEOPERATOR_THRESHOLD,
                count: ctx.slot + 1,
            });
        }
        Err(WorkerError::NotImplemented(
            "collaborative Aptos CA withdraw payload generation is not enabled",
        ))
    }
}

pub mod mpc_spdz {
    use crate::{assert_quorum_slots5, assert_slot, WorkerError, WorkerResult};
    use serde_json::json;
    use std::{
        path::{Path, PathBuf},
        process::Command,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MpcSpdzRunOutput {
        pub status_code: i32,
        pub stdout: String,
        pub stderr: String,
    }

    pub fn run_program(
        program: &str,
        party_id: usize,
        quorum: &[usize],
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> WorkerResult<MpcSpdzRunOutput> {
        let runner = std::env::var("EUNOMA_MPC_SPDZ_RUNNER")
            .map(PathBuf::from)
            .map_err(|_| WorkerError::MissingLocalState("EUNOMA_MPC_SPDZ_RUNNER".to_string()))?;
        run_program_with_runner(
            &runner,
            program,
            party_id,
            quorum,
            private_inputs,
            public_inputs,
        )
    }

    pub fn run_program_with_runner(
        runner: &Path,
        program: &str,
        party_id: usize,
        quorum: &[usize],
        private_inputs: &[String],
        public_inputs: &[String],
    ) -> WorkerResult<MpcSpdzRunOutput> {
        validate_program_name(program)?;
        assert_slot(party_id)?;
        let quorum = assert_quorum_slots5(quorum)?;
        if !quorum.contains(&party_id) {
            return Err(WorkerError::InvalidRequest(
                "party_id must be included in quorum".to_string(),
            ));
        }
        if !runner.exists() {
            return Err(WorkerError::MissingLocalState(runner.display().to_string()));
        }

        let quorum_csv = quorum
            .iter()
            .map(|slot| slot.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let private_json = serde_json::to_string(private_inputs)
            .map_err(|err| WorkerError::Serde(err.to_string()))?;
        let public_json = serde_json::to_string(public_inputs)
            .map_err(|err| WorkerError::Serde(err.to_string()))?;

        let output = Command::new(runner)
            .arg("--program")
            .arg(program)
            .arg("--party-id")
            .arg(party_id.to_string())
            .arg("--quorum")
            .arg(quorum_csv)
            .arg("--private-input-json")
            .arg(private_json)
            .arg("--public-input-json")
            .arg(public_json)
            .output()
            .map_err(|err| WorkerError::Io(err.to_string()))?;

        let status_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() {
            return Err(WorkerError::Crypto(
                json!({
                    "runner": runner.display().to_string(),
                    "program": program,
                    "statusCode": status_code,
                    "stderr": stderr,
                })
                .to_string(),
            ));
        }
        Ok(MpcSpdzRunOutput {
            status_code,
            stdout,
            stderr,
        })
    }

    fn validate_program_name(program: &str) -> WorkerResult<()> {
        if program.is_empty()
            || !program
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(WorkerError::InvalidRequest(
                "MP-SPDZ program names must use ASCII alphanumeric, underscore, or hyphen"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

pub mod twisted_elgamal {
    use crate::{WorkerError, WorkerResult};

    pub fn bind_ciphertext_to_shared_chunks() -> WorkerResult<[u8; 32]> {
        Err(WorkerError::NotImplemented(
            "Twisted ElGamal CA ciphertext binding is not implemented in this skeleton",
        ))
    }
}

pub mod poseidon_bn254_mpc {
    use crate::{WorkerError, WorkerResult};

    pub fn compute_shared_amount_tag() -> WorkerResult<[u8; 32]> {
        Err(WorkerError::NotImplemented(
            "BN254 Poseidon MPC amount tag is not implemented in this skeleton",
        ))
    }
}

pub mod field_conversion {
    use crate::{WorkerError, WorkerResult};

    pub fn aptos_u64_to_bn254_chunks(_bytes: &[u8]) -> WorkerResult<[u16; 4]> {
        Err(WorkerError::NotImplemented(
            "Aptos CA/Bn254 field conversion harness is not implemented in this skeleton",
        ))
    }
}

pub mod vault_state {
    use crate::{WorkerError, WorkerResult};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VaultStateCommitment {
        pub vault_sequence: u64,
        pub commitment: [u8; 32],
    }

    pub fn load_shared_state(_vault_sequence: u64) -> WorkerResult<VaultStateCommitment> {
        Err(WorkerError::NotImplemented(
            "secret-shared vault state storage is not implemented in this skeleton",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_fixed_to_five_of_seven() {
        assert!(assert_v2_threshold(5, 7).is_ok());
        assert_eq!(
            assert_v2_threshold(4, 7),
            Err(WorkerError::BadThreshold {
                threshold: 4,
                count: 7
            })
        );
        assert!(assert_quorum_slots5(&[0, 1, 2, 3, 4]).is_ok());
        assert_eq!(
            assert_quorum_slots5(&[0, 1, 2, 3]),
            Err(WorkerError::UnderQuorum {
                threshold: 5,
                count: 4,
            })
        );
        assert_eq!(
            assert_quorum_slots5(&[0, 1, 2, 3, 4, 5]),
            Err(WorkerError::BadThreshold {
                threshold: 5,
                count: 6,
            })
        );
        assert!(matches!(
            assert_quorum_slots5(&[0, 1, 2, 3, 3]),
            Err(WorkerError::InvalidRequest(_))
        ));
    }

    #[test]
    fn crypto_modules_fail_closed_until_real_implementations_land() {
        assert!(matches!(
            dkg_ca::run_pedersen_gjkr_round(),
            Err(WorkerError::NotImplemented(_))
        ));
        assert!(matches!(
            frost_attestation::sign_partial(b"msg"),
            Err(WorkerError::NotImplemented(_))
        ));
        assert!(matches!(
            threshold_sigma::aggregate_sigma_response(),
            Err(WorkerError::NotImplemented(_))
        ));
        assert!(matches!(
            dkg_ca::run_round(dkg_ca::DkgRoundContext {
                dkg_epoch: 1,
                round: dkg_ca::DkgRound::Round1,
                slot: 0,
                threshold: 5,
                participant_count: 7,
            }),
            Err(WorkerError::NotImplemented(_))
        ));
        assert!(matches!(
            mpcca::run_withdraw_round(mpcca::MpccaRoundContext {
                vault_sequence: 1,
                round: mpcca::MpccaRound::Round1,
                slot: 0,
                threshold: 5,
                participant_count: 7,
            }),
            Err(WorkerError::NotImplemented(_))
        ));
    }

    #[test]
    fn mpc_spdz_adapter_validates_runner_and_quorum() {
        use crate::mpc_spdz::run_program_with_runner;
        use std::path::PathBuf;

        let runner = PathBuf::from("/tmp/eunoma-missing-mpc-spdz-runner");
        assert_eq!(
            run_program_with_runner(
                &runner,
                "invert_and_additive_share",
                0,
                &[0, 1, 2, 3],
                &[],
                &[],
            ),
            Err(WorkerError::UnderQuorum {
                threshold: 5,
                count: 4,
            })
        );
        assert!(matches!(
            run_program_with_runner(
                &runner,
                "../bad",
                0,
                &[0, 1, 2, 3, 4],
                &[],
                &[],
            ),
            Err(WorkerError::InvalidRequest(_))
        ));
        assert!(matches!(
            run_program_with_runner(
                &runner,
                "invert_and_additive_share",
                6,
                &[0, 1, 2, 3, 4],
                &[],
                &[],
            ),
            Err(WorkerError::InvalidRequest(_))
        ));
        assert!(matches!(
            run_program_with_runner(
                &runner,
                "invert_and_additive_share",
                0,
                &[0, 1, 2, 3, 4],
                &[],
                &[],
            ),
            Err(WorkerError::MissingLocalState(_))
        ));
    }

    #[test]
    fn ca_dkg_v2_roundtrip_persists_only_worker_shares() {
        use crate::ca_dkg_v2::{
            init_hpke_local, load_ca_dkg_v2_share, run_round, CaDkgV2Roster, CaDkgV2RosterNode,
            CaDkgV2RoundRequest,
        };

        let root = std::env::temp_dir().join(format!(
            "eunoma-ca-dkg-v2-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let hpke = init_hpke_local(&root, false).expect("init HPKE keys");
        let roster = CaDkgV2Roster {
            operator_set_version: "1".to_string(),
            dkg_epoch: "9".to_string(),
            ca_dkg_scheme: "ca_dkg_v2".to_string(),
            threshold: DEOPERATOR_THRESHOLD,
            nodes: hpke
                .slots
                .iter()
                .map(|slot| CaDkgV2RosterNode {
                    slot: slot.slot,
                    node_id: format!("node-{}", slot.slot),
                    endpoint: format!("http://127.0.0.1:{}", 4100 + slot.slot),
                    hpke_public_key: slot.hpke_public_key.clone(),
                    transcript_public_key: "77".repeat(32),
                })
                .collect(),
        };
        let request_id = "ca-dkg-v2-test".to_string();
        let session_id = "ca-dkg-v2-session".to_string();
        let roster_hash = "33".repeat(32);
        let participant_slots = (0..DEOPERATOR_COUNT).collect::<Vec<_>>();

        let mut round1 = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                CaDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "round1".to_string(),
                    operator_set_version: "1".to_string(),
                    dkg_epoch: "9".to_string(),
                    roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    ca_dkg_v2_roster: Some(roster.clone()),
                    dealer_broadcasts: Vec::new(),
                    encrypted_shares: Vec::new(),
                    transcript_hash: None,
                },
            )
            .expect("round1");
            assert_eq!(result.encrypted_shares.len(), DEOPERATOR_COUNT);
            round1.push(result);
        }

        let broadcasts = round1
            .iter()
            .map(|result| result.dealer_broadcast.clone().expect("broadcast"))
            .collect::<Vec<_>>();
        let all_envelopes = round1
            .iter()
            .flat_map(|result| result.encrypted_shares.clone())
            .collect::<Vec<_>>();

        let mut transcript_hash = None;
        for slot in 0..DEOPERATOR_COUNT {
            let encrypted_shares = all_envelopes
                .iter()
                .filter(|share| share.to_slot == slot)
                .cloned()
                .collect::<Vec<_>>();
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                CaDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "round2".to_string(),
                    operator_set_version: "1".to_string(),
                    dkg_epoch: "9".to_string(),
                    roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    ca_dkg_v2_roster: None,
                    dealer_broadcasts: broadcasts.clone(),
                    encrypted_shares,
                    transcript_hash: None,
                },
            )
            .expect("round2");
            assert!(result.complaints.is_empty());
            assert_eq!(result.accepted_dealers.len(), DEOPERATOR_COUNT);
            assert_eq!(result.aggregate_commitments.len(), DEOPERATOR_THRESHOLD);
            if let Some(existing) = transcript_hash.as_ref() {
                assert_eq!(existing, &result.transcript_hash);
            } else {
                transcript_hash = Some(result.transcript_hash.clone());
            }
            let share = load_ca_dkg_v2_share(&root.join(format!("slot-{slot}"))).expect("share");
            assert_eq!(share.valid_dealers.len(), DEOPERATOR_COUNT);
        }

        let transcript_hash = transcript_hash.expect("transcript");
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                CaDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "finalize".to_string(),
                    operator_set_version: "1".to_string(),
                    dkg_epoch: "9".to_string(),
                    roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    ca_dkg_v2_roster: None,
                    dealer_broadcasts: Vec::new(),
                    encrypted_shares: Vec::new(),
                    transcript_hash: Some(transcript_hash.clone()),
                },
            )
            .expect("finalize");
            assert_eq!(result.finalized, Some(true));
            assert_eq!(result.ca_dkg_transcript_hash, Some(transcript_hash.clone()));
        }

        let persisted = std::fs::read_to_string(root.join("slot-0").join("ca_dkg_share_v2.json"))
            .expect("read persisted share");
        assert!(!persisted.contains("vaultEk"));
        assert!(!persisted.contains("dkInv"));
        assert!(!persisted.contains("dealerPoly"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("slot-0").join("ca_dkg_share_v2.json"))
                .expect("CA DKG V2 share metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let mut corrupted = all_envelopes
            .iter()
            .filter(|share| share.to_slot == 0)
            .cloned()
            .collect::<Vec<_>>();
        corrupted[0].hpke.ciphertext = "00".repeat(16);
        let result = run_round(
            &root.join("slot-0"),
            CaDkgV2RoundRequest {
                request_id,
                session_id,
                round: "round2".to_string(),
                operator_set_version: "1".to_string(),
                dkg_epoch: "9".to_string(),
                roster_hash,
                threshold: DEOPERATOR_THRESHOLD,
                participant_slots,
                slot: 0,
                ca_dkg_v2_roster: None,
                dealer_broadcasts: broadcasts,
                encrypted_shares: corrupted,
                transcript_hash: None,
            },
        )
        .expect("corrupt round2 emits complaint");
        assert!(!result.complaints.is_empty());
        assert!(result.abort_evidence_hash.is_some());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn frost_ed25519_dkg_and_threshold_signature_fixture() -> Result<(), frost_ed25519::Error> {
        use frost_ed25519 as frost;
        use std::collections::BTreeMap;

        let mut rng = rand::rngs::OsRng;
        let max_signers = DEOPERATOR_COUNT as u16;
        let min_signers = DEOPERATOR_THRESHOLD as u16;

        let mut round1_secret_packages = BTreeMap::new();
        let mut received_round1_packages = BTreeMap::new();

        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("nonzero identifier");
            let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
                participant_identifier,
                max_signers,
                min_signers,
                &mut rng,
            )?;
            round1_secret_packages.insert(participant_identifier, round1_secret_package);

            for receiver_index in 1..=max_signers {
                if receiver_index == participant_index {
                    continue;
                }
                let receiver_identifier: frost::Identifier =
                    receiver_index.try_into().expect("nonzero identifier");
                received_round1_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round1_package.clone());
            }
        }

        let mut round2_secret_packages = BTreeMap::new();
        let mut received_round2_packages = BTreeMap::new();

        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("nonzero identifier");
            let round1_secret_package = round1_secret_packages
                .remove(&participant_identifier)
                .expect("round1 package");
            let round1_packages = &received_round1_packages[&participant_identifier];
            let (round2_secret_package, round2_packages) =
                frost::keys::dkg::part2(round1_secret_package, round1_packages)?;
            round2_secret_packages.insert(participant_identifier, round2_secret_package);

            for (receiver_identifier, round2_package) in round2_packages {
                received_round2_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round2_package);
            }
        }

        let mut key_packages = BTreeMap::new();
        let mut pubkey_packages = BTreeMap::new();

        for participant_index in 1..=max_signers {
            let participant_identifier = participant_index.try_into().expect("nonzero identifier");
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            let (key_package, pubkey_package) =
                frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;
            key_packages.insert(participant_identifier, key_package);
            pubkey_packages.insert(participant_identifier, pubkey_package);
        }

        let pubkey_package = pubkey_packages
            .values()
            .next()
            .expect("public key package")
            .clone();
        for candidate in pubkey_packages.values() {
            assert_eq!(candidate.verifying_key(), pubkey_package.verifying_key());
        }

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for participant_index in 1..=min_signers {
            let participant_identifier = participant_index.try_into().expect("nonzero identifier");
            let key_package = &key_packages[&participant_identifier];
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(participant_identifier, nonces);
            commitments_map.insert(participant_identifier, commitments);
        }

        let message = b"EUNOMA_V2_FROST_ATTESTATION_FIXTURE";
        let signing_package = frost::SigningPackage::new(commitments_map, message);
        let mut signature_shares = BTreeMap::new();
        for participant_identifier in nonces_map.keys() {
            let key_package = &key_packages[participant_identifier];
            let nonces = &nonces_map[participant_identifier];
            let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;
            signature_shares.insert(*participant_identifier, signature_share);
        }

        let group_signature =
            frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
        pubkey_package
            .verifying_key()
            .verify(message, &group_signature)?;

        Ok(())
    }

    #[test]
    fn local_frost_state_init_and_signing_roundtrip() {
        use crate::local_state::{
            aggregate_frost_signature, create_frost_nonce_commitment,
            create_frost_partial_signature, init_frost_local, FrostCommitmentInput,
            FrostSignatureShareInput,
        };
        use std::path::PathBuf;

        let root = std::env::temp_dir().join(format!(
            "eunoma-frost-local-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let summary = init_frost_local(&root, false).expect("init local FROST state");
        assert_eq!(summary.threshold, DEOPERATOR_THRESHOLD);
        assert_eq!(summary.verifying_shares.len(), DEOPERATOR_COUNT);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("slot-0").join("frost_key_package.json"))
                .expect("key package metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let mut nonce_results = Vec::new();
        for slot in 0..DEOPERATOR_THRESHOLD {
            let state_dir = root.join(format!("slot-{slot}"));
            nonce_results.push((
                slot,
                create_frost_nonce_commitment(&state_dir, "sign-r").expect("nonce commit"),
            ));
        }
        let commitments: Vec<FrostCommitmentInput> = nonce_results
            .iter()
            .map(|(slot, result)| FrostCommitmentInput {
                slot: *slot,
                commitments: result.commitments.clone(),
            })
            .collect();

        let mut signature_shares = Vec::new();
        for (slot, nonce_result) in &nonce_results {
            let state_dir = root.join(format!("slot-{slot}"));
            let partial = create_frost_partial_signature(
                &state_dir,
                &nonce_result.nonce_id,
                "45554e4f4d415f46524f53545f54455354",
                commitments.clone(),
            )
            .expect("partial signature");
            signature_shares.push(FrostSignatureShareInput {
                slot: *slot,
                signature_share: partial.signature_share,
            });
        }

        let aggregate = aggregate_frost_signature(
            &PathBuf::from(root.join("slot-0")),
            "45554e4f4d415f46524f53545f54455354",
            commitments.clone(),
            signature_shares.clone(),
        )
        .expect("aggregate signature");
        assert_eq!(aggregate.signature.len(), 128);

        assert!(matches!(
            aggregate_frost_signature(
                &PathBuf::from(root.join("slot-0")),
                "45554e4f4d415f46524f53545f54455354",
                commitments[..4].to_vec(),
                signature_shares[..4].to_vec(),
            ),
            Err(WorkerError::UnderQuorum {
                threshold: 5,
                count: 4
            })
        ));

        let mut duplicate_commitments = commitments.clone();
        duplicate_commitments[4].slot = duplicate_commitments[3].slot;
        assert!(matches!(
            aggregate_frost_signature(
                &PathBuf::from(root.join("slot-0")),
                "45554e4f4d415f46524f53545f54455354",
                duplicate_commitments,
                signature_shares.clone(),
            ),
            Err(WorkerError::InvalidRequest(_))
        ));

        let mut over_commitments = commitments.clone();
        over_commitments.push(commitments[0].clone());
        let mut over_signature_shares = signature_shares.clone();
        over_signature_shares.push(signature_shares[0].clone());
        assert!(matches!(
            aggregate_frost_signature(
                &PathBuf::from(root.join("slot-0")),
                "45554e4f4d415f46524f53545f54455354",
                over_commitments,
                over_signature_shares,
            ),
            Err(WorkerError::BadThreshold {
                threshold: 5,
                count: 6
            })
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn local_ca_dkg_registration_sigma_roundtrip() {
        use crate::ca_local::{
            aggregate_registration_commitment, aggregate_registration_proof,
            create_registration_nonce_commitment, create_registration_partial_response,
            init_ca_dkg_local, load_ca_share, registration_challenge,
            verify_registration_proof, RegistrationCommitmentInput, RegistrationResponseInput,
        };

        let root = std::env::temp_dir().join(format!(
            "eunoma-ca-local-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let summary = init_ca_dkg_local(&root, "7", false).expect("init local CA DKG state");
        assert_eq!(summary.threshold, DEOPERATOR_THRESHOLD);
        assert_eq!(summary.slots.len(), DEOPERATOR_COUNT);
        assert_eq!(summary.vault_ek.len(), 64);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("slot-0").join("ca_dkg_share.json"))
                .expect("CA DKG share metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        for slot in 0..DEOPERATOR_COUNT {
            let share = load_ca_share(&root.join(format!("slot-{slot}"))).expect("load CA share");
            assert_eq!(share.vault_ek, summary.vault_ek);
            assert_eq!(share.transcript_hash, summary.transcript_hash);
        }

        let sender = "11".repeat(32);
        let asset = "22".repeat(32);
        let mut nonce_results = Vec::new();
        for slot in 0..DEOPERATOR_THRESHOLD {
            let state_dir = root.join(format!("slot-{slot}"));
            let nonce =
                create_registration_nonce_commitment(&state_dir, "register-r").expect("nonce");
            nonce_results.push((slot, nonce));
        }
        let commitments: Vec<RegistrationCommitmentInput> = nonce_results
            .iter()
            .map(|(slot, result)| RegistrationCommitmentInput {
                slot: *slot,
                commitment: result.commitment.clone(),
            })
            .collect();
        let aggregate_commitment =
            aggregate_registration_commitment(&commitments).expect("aggregate commitment");
        let challenge = registration_challenge(&summary.vault_ek, &sender, &asset, 2, &aggregate_commitment)
            .expect("challenge");

        let mut responses = Vec::new();
        for (slot, nonce_result) in &nonce_results {
            let state_dir = root.join(format!("slot-{slot}"));
            let partial = create_registration_partial_response(
                &state_dir,
                &nonce_result.nonce_id,
                &challenge,
            )
            .expect("partial response");
            responses.push(RegistrationResponseInput {
                slot: *slot,
                response: partial.response,
            });
        }

        let proof = aggregate_registration_proof(
            &summary.vault_ek,
            &sender,
            &asset,
            2,
            commitments,
            responses,
        )
        .expect("aggregate registration sigma proof");
        assert_eq!(proof.sigma_proto_comm.len(), 1);
        assert_eq!(proof.sigma_proto_resp.len(), 1);
        verify_registration_proof(
            &summary.vault_ek,
            &sender,
            &asset,
            2,
            &proof.sigma_proto_comm[0],
            &proof.sigma_proto_resp[0],
        )
        .expect("verify registration proof");

        assert!(matches!(
            aggregate_registration_proof(&summary.vault_ek, &sender, &asset, 2, Vec::new(), Vec::new()),
            Err(WorkerError::UnderQuorum { threshold: 5, count: 0 })
        ));

        let valid_commitment = summary.commitments[0].clone();
        let five_commitments: Vec<RegistrationCommitmentInput> = [0, 1, 2, 3, 4]
            .into_iter()
            .map(|slot| RegistrationCommitmentInput {
                slot,
                commitment: valid_commitment.clone(),
            })
            .collect();
        let five_responses: Vec<RegistrationResponseInput> = [0, 1, 2, 3, 4]
            .into_iter()
            .map(|slot| RegistrationResponseInput {
                slot,
                response: "00".repeat(32),
            })
            .collect();
        let mut duplicate_commitments = five_commitments.clone();
        duplicate_commitments[4].slot = duplicate_commitments[3].slot;
        assert!(matches!(
            aggregate_registration_commitment(&duplicate_commitments),
            Err(WorkerError::InvalidRequest(_))
        ));
        let mut over_commitments = five_commitments.clone();
        over_commitments.push(RegistrationCommitmentInput {
            slot: 5,
            commitment: valid_commitment,
        });
        assert!(matches!(
            aggregate_registration_commitment(&over_commitments),
            Err(WorkerError::BadThreshold {
                threshold: 5,
                count: 6
            })
        ));
        assert!(matches!(
            aggregate_registration_proof(
                &summary.vault_ek,
                &sender,
                &asset,
                2,
                five_commitments,
                five_responses[..4].to_vec(),
            ),
            Err(WorkerError::UnderQuorum {
                threshold: 5,
                count: 4
            })
        ));

        let _ = std::fs::remove_dir_all(root);
    }
}
