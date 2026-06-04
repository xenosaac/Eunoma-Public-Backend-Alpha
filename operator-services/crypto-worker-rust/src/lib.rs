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

pub(crate) const H_RISTRETTO_HEX: &str =
    "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";

pub(crate) fn h_ristretto() -> WorkerResult<curve25519_dalek::ristretto::RistrettoPoint> {
    let raw = H_RISTRETTO_HEX
        .strip_prefix("0x")
        .or_else(|| H_RISTRETTO_HEX.strip_prefix("0X"))
        .unwrap_or(H_RISTRETTO_HEX);
    if raw.len() != 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WorkerError::InvalidRequest(
            "H_RISTRETTO_HEX must be 32-byte hex".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    for idx in 0..32 {
        bytes[idx] = u8::from_str_radix(&raw[idx * 2..idx * 2 + 2], 16)
            .map_err(|err| WorkerError::InvalidRequest(err.to_string()))?;
    }
    curve25519_dalek::ristretto::CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| {
            WorkerError::Crypto("H_RISTRETTO_HEX is not a valid Ristretto point".to_string())
        })
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
    #[serde(rename_all = "camelCase")]
    pub struct FrostNonceCommitmentResult {
        pub nonce_id: String,
        pub commitment_hash: String,
        pub commitments: Value,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostPartialSignatureResult {
        pub nonce_id: String,
        pub signature_share_hash: String,
        pub signature_share: Value,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
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

/// Public CA-registration sigma-protocol verifier + helpers.
///
/// Codex M2a P1: V2 production code paths previously imported the public verifier
/// (`verify_registration_proof`) and the Fiat-Shamir challenge derivation
/// (`registration_challenge_scalar`) from `crate::ca_local`. The architectural invariant
/// states that `ca_local` is unit/local-smoke fixture ONLY and V2 production code must
/// not import from it. This module hosts the pure-math, share-independent verifier
/// surface so V2 callers can depend on it without crossing the trusted-party namespace
/// boundary.
///
/// Contents:
/// - `verify_registration_proof(...)` — the equation `vault_ek * response == commitment
///   + h * challenge`. Fail-closed on mismatch.
/// - `registration_challenge_scalar(...)` / `registration_challenge(...)` — Fiat-Shamir
///   over `(vault_ek, sender, asset, chain_id, aggregate_commitment)`. Mirrors the
///   Aptos Confidential-Asset registration domain separator byte-for-byte.
/// - `aggregate_registration_commitment(...)` — Lagrange-aggregate a 5-of-7
///   `(slot, commitment)` set at x = 0. Pure public algebra.
/// - `RegistrationCommitmentInput` / `RegistrationResponseInput` — public DTOs.
///
/// What this module deliberately does NOT contain:
/// - Anything that touches secret share material (dk, blind, nonce).
/// - Anything that reads/writes disk state.
/// - Anything from `crate::ca_local::{init_ca_dkg_local, registration_proof,
///   load_ca_share, ...}` — those are the trusted-party fixture code and stay in
///   `ca_local`.
///
/// `ca_local` re-exports each item from this module to keep V1 local-smoke tests and
/// the legacy `local_ca_dkg_registration_sigma_roundtrip` test compiling. Production
/// V2 code paths (`ca_registration_v2`, `vault_state_v2`, future MPCCA rounds) MUST
/// import directly from `crate::registration_verifier` to honor the invariant.
pub mod registration_verifier {
    use crate::{
        assert_quorum_slots5, assert_slot, h_ristretto, WorkerError, WorkerResult,
        DEOPERATOR_THRESHOLD,
    };
    use curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha512};

    const REGISTRATION_PROTOCOL_ID: &str = "AptosConfidentialAsset/RegistrationV1";
    const REGISTRATION_TYPE_NAME: &str = "0x1::sigma_protocol_registration::Registration";

    /// Input DTO: a per-slot Round-1 commitment `T_i = vault_ek * r_i`. Public.
    #[derive(Debug, Clone, Deserialize)]
    pub struct RegistrationCommitmentInput {
        pub slot: usize,
        pub commitment: String,
    }

    /// Input DTO: a per-slot Round-2 response `s_i = r_i + challenge * dk_share_i`. Public.
    #[derive(Debug, Clone, Deserialize)]
    pub struct RegistrationResponseInput {
        pub slot: usize,
        pub response: String,
    }

    /// Verify the aggregate registration sigma proof: `vault_ek * response ==
    /// aggregate_commitment + H * challenge` where `challenge` is derived via
    /// `registration_challenge_scalar`. Pure public algebra — caller passes only
    /// public material.
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

    /// Fiat-Shamir challenge as a `Scalar`. Domain-separates over the Aptos Confidential
    /// Asset registration prefix + protocol id + chain id + asset session bytes + `(H,
    /// vault_ek, aggregate_commitment)`. Byte-identical with the TS reconstructor.
    pub fn registration_challenge_scalar(
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

    /// Fiat-Shamir challenge as 32-byte hex. Thin wrapper over `registration_challenge_scalar`.
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

    /// Lagrange-aggregate a 5-of-7 `(slot, commitment)` set at x = 0. Public algebra.
    /// Returns the aggregate commitment hex.
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

    /// Public helper: extract + validate the slot vector from a commitment list.
    pub fn slots_from_commitments(
        items: &[RegistrationCommitmentInput],
    ) -> WorkerResult<Vec<usize>> {
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

    /// Public helper: extract + validate the slot vector from a response list.
    pub fn slots_from_responses(
        items: &[RegistrationResponseInput],
    ) -> WorkerResult<Vec<usize>> {
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

    /// Public helper: Lagrange coefficients at x = 0 for the given 5-slot subset. Pure
    /// public algebra (Shamir recombination).
    pub fn lagrange_coefficients_at_zero(slots: &[usize]) -> WorkerResult<Vec<Scalar>> {
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

    fn slot_scalar(slot: usize) -> WorkerResult<Scalar> {
        assert_slot(slot)?;
        Ok(Scalar::from((slot as u64) + 1))
    }

    fn registration_session_bytes(sender: &[u8; 32], asset: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(sender);
        out.extend_from_slice(asset);
        out
    }

    fn ristretto_from_hex(hex: &str) -> WorkerResult<RistrettoPoint> {
        compressed_ristretto_from_hex(hex)?
            .decompress()
            .ok_or_else(|| {
                WorkerError::InvalidRequest("invalid compressed Ristretto point".to_string())
            })
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

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(hex: &str) -> WorkerResult<Vec<u8>> {
        let raw = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
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

    // Silence dead-code: DEOPERATOR_THRESHOLD is brought into scope above via the `use`
    // line for completeness with the rest of the crate; it's referenced through
    // assert_quorum_slots5 only.
    const _: usize = DEOPERATOR_THRESHOLD;

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
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    const CA_DKG_SHARE_FILE: &str = "ca_dkg_share.json";
    const CA_REGISTRATION_NONCES_DIR: &str = "ca_registration_nonces";
    use crate::h_ristretto;

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

    // Codex M2a P1: the public verifier surface (DTOs + verifier + Fiat-Shamir + Lagrange)
    // lives in `crate::registration_verifier`. We re-export here so V1 local-smoke tests
    // and the legacy `local_ca_dkg_registration_sigma_roundtrip` test that still imports
    // from `eunoma_crypto_worker::ca_local::{...}` continue to compile unchanged. V2
    // production code paths import from `crate::registration_verifier` directly.
    pub use crate::registration_verifier::{
        aggregate_registration_commitment, registration_challenge, registration_challenge_scalar,
        verify_registration_proof, RegistrationCommitmentInput, RegistrationResponseInput,
    };
    use crate::registration_verifier::{lagrange_coefficients_at_zero, slots_from_responses};

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

    pub fn aggregate_registration_proof(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        commitments: Vec<RegistrationCommitmentInput>,
        responses: Vec<RegistrationResponseInput>,
    ) -> WorkerResult<RegistrationProofResult> {
        let commitment_slots = crate::registration_verifier::slots_from_commitments(&commitments)?;
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
    use crate::h_ristretto;

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

    /// Codex M2a P2 #1: belt-and-suspenders zeroize for the secret-bearing share struct.
    ///
    /// `load_ca_dkg_v2_share` returns a `CaDkgV2ShareFile` whose `dk_share` and
    /// `blind_share` fields hold the secret share material in hex. The metadata-only
    /// loader (`load_ca_dkg_v2_share_metadata`) is preferred for init paths that don't
    /// need the secret — but `load_ca_dkg_v2_share` is still used by paths that DO need
    /// it (ca_registration_v2 round2, vault_ek_derivation_v2 round1). This Drop impl
    /// wipes the underlying bytes of those two fields when the struct goes out of scope.
    ///
    /// We use `zeroize::Zeroize::zeroize` on each `String`, which clears the heap-owned
    /// bytes in place. The struct is not `ZeroizeOnDrop` derive-able because of the
    /// non-`Zeroize` `Vec<usize>` / `u128` fields, so we hand-write Drop for clarity
    /// over what's wiped (the two secret fields) and what's intentionally left alone
    /// (the public metadata).
    impl Drop for CaDkgV2ShareFile {
        fn drop(&mut self) {
            use zeroize::Zeroize as _;
            self.dk_share.zeroize();
            self.blind_share.zeroize();
        }
    }

    /// Codex M2a P2 #1: metadata-only view of `ca_dkg_share_v2.json`. Contains every
    /// public binding init paths need to validate (slot/dkg_epoch/transcript_hash/
    /// threshold/count/valid_dealers/aggregate_commitments) but EXCLUDES the secret
    /// `dk_share` and `blind_share` fields by serde construction. Returned by
    /// `load_ca_dkg_v2_share_metadata`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CaDkgV2ShareMetadata {
        pub scheme: String,
        pub slot: usize,
        pub threshold: usize,
        pub count: usize,
        pub dkg_epoch: String,
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

    /// Codex M2a v2 P2 #1 + M3a tightening: metadata-only share loader.
    ///
    /// `init_vault_state_v2` needs only `(slot, dkg_epoch, transcript_hash, threshold,
    /// count)` to validate the (Phase 2 + Milestone 1 + CA DKG V2) bindings. It does NOT
    /// need the secret `dk_share` / `blind_share` material. The shared
    /// `load_ca_dkg_v2_share` loader deserializes BOTH and runs a Pedersen-share verify
    /// over them — that's correct for paths that actually use the share (e.g.
    /// ca_registration_v2 round2), but for init-style paths it pulls secret bytes into
    /// memory unnecessarily.
    ///
    /// Codex M2a v2 P2 #1 residual fix: the previous implementation routed through
    /// `read_json` → `serde_json::Value` → `from_value(value)`. The intermediate `Value`
    /// owned ALL the file's fields including `dk_share` / `blind_share` as `String`s
    /// (allocated on the heap, with no zeroize semantics). The metadata struct then
    /// extracted only the public fields, but the secret strings lingered in the `Value`
    /// for the lifetime of the parse.
    ///
    /// New flow:
    ///   1. Read raw bytes into a `Vec<u8>` (carried in a `Zeroizing` wrapper so the
    ///      buffer is wiped before drop).
    ///   2. Deserialize via `serde_json::from_slice::<CaDkgV2ShareMetadata>` — serde walks
    ///      the JSON tokens in place, allocating String storage only for fields the target
    ///      struct claims. The struct excludes `dk_share` / `blind_share`, so those tokens
    ///      are decoded-then-discarded without persistent heap allocation.
    ///   3. The raw byte buffer is zeroized on Drop (Zeroizing).
    ///
    /// Init paths use this loader; ca_registration_v2 round2 still uses
    /// `load_ca_dkg_v2_share` because it genuinely needs the secret share.
    pub fn load_ca_dkg_v2_share_metadata(
        state_dir: &Path,
    ) -> WorkerResult<CaDkgV2ShareMetadata> {
        use zeroize::Zeroizing;
        let path = state_dir.join(CA_DKG_V2_SHARE_FILE);
        let raw_bytes = fs::read(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WorkerError::MissingLocalState(path.display().to_string())
            } else {
                WorkerError::Io(err.to_string())
            }
        })?;
        let raw_bytes = Zeroizing::new(raw_bytes);
        let meta: CaDkgV2ShareMetadata = serde_json::from_slice(&raw_bytes)
            .map_err(|err| WorkerError::Serde(err.to_string()))?;
        assert_slot(meta.slot)?;
        assert_v2_threshold(meta.threshold, meta.count)?;
        if meta.valid_dealers.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 share must contain all 7 valid dealers".to_string(),
            ));
        }
        if meta.aggregate_commitments.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(
                "CA DKG V2 share must contain 5 aggregate commitments".to_string(),
            ));
        }
        // Sanity-check the aggregate commitments parse as Ristretto points so we still
        // fail closed on a corrupted file, but DO NOT decompress + verify_pedersen_share
        // (which would require dk_share/blind_share — exactly what we are avoiding).
        for commitment in &meta.aggregate_commitments {
            ristretto_from_hex(commitment)?;
        }
        // `raw_bytes` is zeroized on drop here.
        Ok(meta)
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
            accepted_dealers: share.valid_dealers.clone(),
            aggregate_commitments: share.aggregate_commitments.clone(),
            ca_dkg_share_hash: Some(share_hash),
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: Some(true),
            ca_dkg_transcript_hash: Some(share.transcript_hash.clone()),
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

    pub(crate) fn load_hpke_keypair_for_slot(
        state_dir: &Path,
        slot: usize,
    ) -> WorkerResult<HpkeKeypairFile> {
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

pub mod mpc_inverse_adapter {
    use crate::h_ristretto;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use std::path::PathBuf;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AdapterError {
        McpSpdzNotAvailable,
        InvalidInput(String),
        Internal(String),
    }

    impl std::fmt::Display for AdapterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AdapterError::McpSpdzNotAvailable => write!(f, "mp-spdz runtime not available"),
                AdapterError::InvalidInput(msg) => write!(f, "adapter input invalid: {msg}"),
                AdapterError::Internal(msg) => write!(f, "adapter internal: {msg}"),
            }
        }
    }

    impl std::error::Error for AdapterError {}

    #[derive(Debug, Clone)]
    pub struct InversionContext {
        pub dkg_epoch: String,
        pub ca_dkg_transcript_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub roster_hash: String,
        /// Phase 2: round1 request identifier. Combined with `session_id` to namespace the
        /// per-call MP-SPDZ work directory.
        pub request_id: String,
        /// Phase 2: outer coordination session identifier. Equal to `request_id` while only
        /// one vault_ek derivation runs at a time (see plan §"Concurrent vault_ek derivations").
        pub session_id: String,
        /// Phase 2: root under which the adapter creates `mpc-sessions/<request_id>__<session_id>/`.
        /// Worker's state_dir is the natural choice.
        pub work_dir: PathBuf,
        /// Phase 2: ordered `host:port` for the 5 MASCOT parties — index = player ordinal
        /// among selected_slots (sorted). Same content on every party for a given derivation.
        pub peer_addresses: Vec<String>,
        /// Phase 2: this party's ordinal among `selected_slots` (sorted ascending). 0..N-1.
        /// Distinct from `self_slot`, which is the deoperator slot identity in 0..DEOPERATOR_COUNT-1.
        pub player_id: usize,
        /// Phase 2: hex-encoded public Lagrange coefficients at x=0 for `sorted(selected_slots)`,
        /// in player-ordinal order. The adapter recomputes locally and rejects on mismatch.
        pub lagrange_coefficients_hex: Vec<String>,
    }

    /// Per-party output of one MPC inversion call. The worker publishes h_r_i + mpc_open_m
    /// alongside h_q_i so the verifier can publicly check `h_q_i * m == h_r_i`. Cross-party
    /// MAC-check (in MASCOT) guarantees all 5 parties see the SAME `mpc_open_m`; coordinator
    /// cross-checks at verify time. See codex P1 #4 fix.
    #[derive(Debug, Clone)]
    pub struct InversionShare {
        /// q_i = r_i * m^{-1}. Sum over the 5 selected parties = 1/dk.
        pub q_i: Scalar,
        /// h * r_i. Each party publishes this so the verifier can check that q_i is the
        /// MPC-derived value (no malicious worker can substitute an arbitrary scalar).
        pub h_r_i: RistrettoPoint,
        /// MPC-opened m. All 5 parties report the same value (MASCOT MAC-check).
        pub mpc_open_m: Scalar,
    }

    pub trait MpcInverseAdapter: Send + Sync {
        /// Run the MASCOT inversion subprocess (or its mock) using `r_i` as this party's
        /// fresh random scalar. The adapter does NOT generate r_i — that responsibility now
        /// lives in `run_round0`, which commits `h_r_i = H * r_i` to disk BEFORE the MPC
        /// runs and BEFORE any party sees `m`. This is the codex P1 #4 round0 fix.
        ///
        /// Returns the MPC-opened m, q_i = r_i * m^-1, and the committed h_r_i (which the
        /// adapter recomputes from the supplied r_i so the caller can compare against the
        /// round0 commitment).
        fn compute_inverse_share(
            &self,
            dk_share: &Scalar,
            r_i: &Scalar,
            ctx: &InversionContext,
        ) -> Result<InversionShare, AdapterError>;
    }

    pub struct UnavailableMpcInverseAdapter;

    impl MpcInverseAdapter for UnavailableMpcInverseAdapter {
        fn compute_inverse_share(
            &self,
            _dk_share: &Scalar,
            _r_i: &Scalar,
            _ctx: &InversionContext,
        ) -> Result<InversionShare, AdapterError> {
            Err(AdapterError::McpSpdzNotAvailable)
        }
    }

    /// Helper to build an `InversionShare` from a pre-computed q_i for tests/mocks that don't
    /// actually run MPC. Picks mpc_open_m = 1 so h_r_i = h * q_i trivially satisfies the
    /// `h_q_i * m == h_r_i` per-party check. All mocks must use the SAME m (=1) so the
    /// coordinator's cross-party consistency check also passes.
    pub fn mock_inversion_share_from_q(q_i: Scalar) -> Result<InversionShare, AdapterError> {
        let h = h_ristretto().map_err(|e| AdapterError::Internal(format!("h_ristretto: {e:?}")))?;
        let h_q_i = h * q_i;
        // With m = 1: h_r_i = h_q_i, and h_q_i * 1 == h_r_i.
        Ok(InversionShare {
            q_i,
            h_r_i: h_q_i,
            mpc_open_m: Scalar::ONE,
        })
    }
}

pub mod mpc_spdz_adapter;

pub mod transfer_sigma_reference;

pub mod bulletproof_reference;

pub mod twisted_elgamal_reference;

// M10-b: chain re-fetch helper + partial-decrypt handler. Worker-side of the
// threshold balance-decrypt protocol that backs the orchestrator's truthful
// `newBalanceChunks = oldBalanceChunks − transferAmountChunks` witness.
pub mod chain_fetch;

pub mod balance_decrypt;

// Normalize ceremony — worker-side partial computation for the σ-position-0
// threshold response `s[0]_threshold = α[0] + e · dk_REAL`. Mirrors the
// balance_decrypt pattern (load dk_share, compute, zeroize) without chain
// re-fetch.
pub mod normalize_sigma_partial;

// =================================================================================================
// Codex M3a P2 #2: atomic write helper applied uniformly across V2 production sites.
//
// Pre-fix posture (M2a P2 #2): each V2 module had its own `write_secret_file` that did
// tmp + create_new + rename. The atomic rename guarantees a partial file is never observed,
// but `rename(2)` REPLACES the destination unconditionally — two concurrent writers to the
// same canonical path can both win the tmp create and the later one clobbers the earlier
// one's content.
//
// Codex M3a P2 #2 closes this by adding a pre-rename idempotency gate:
//   1. If the destination does NOT exist → tmp write + rename, same as before. Atomic.
//   2. If the destination exists AND is byte-identical to the new content → return OK.
//      Idempotent replay.
//   3. If the destination exists AND differs → fail closed with
//      InvalidDkgState("<context>_already_exists_with_different_content"). The caller is
//      responsible for having done an upstream content equality check if the new write is
//      intentionally replacing the file.
//
// The race window is non-zero (a concurrent writer can land between our existence check and
// our rename), but it's bounded: the post-rename file is the LATER of the two writes by
// definition of rename(2), and BOTH writers are writing the same content shape (callers
// passing different content would have failed the upstream equality check). The persisted
// file is therefore always SOMEONE's intended content; we don't need cross-writer ordering.
//
// Applied to: vault_state_v2.json, ca_registration_v2 nonce file, mpcca_withdraw_v2 session
// state file, vault_ek_derivation_v2 round0.json. Each call site documents its idempotency
// contract.
// =================================================================================================
pub mod atomic_io {
    use crate::{WorkerError, WorkerResult};
    use std::fs;
    use std::path::Path;

    /// Codex M3a P2 #2 v2 (TOCTOU close-out): truly-atomic no-clobber write.
    ///
    /// Pre-fix shape (M3a P2 #2 v1) was `path.exists()` check → tmp write → plain
    /// `fs::rename(tmp, target)`. That left a window where two writers both observed
    /// `path.exists() == false`, both wrote tmp files, and the later `rename` clobbered
    /// the earlier one. The race window is microseconds in practice but the contract
    /// said "fail closed for the loser" — `rename(2)` never fails closed, so the loser
    /// silently overwrote the winner.
    ///
    /// Fix: use POSIX `link(2)` via `std::fs::hard_link(tmp, target)`. `link(2)` is the
    /// canonical atomic create-only primitive: it succeeds iff the target did not exist
    /// at the moment the kernel processed the syscall, otherwise it returns `EEXIST`
    /// (Rust `io::ErrorKind::AlreadyExists`). There is NO race window — the kernel
    /// performs the existence check + creation in a single critical section.
    ///
    /// On `link` success: target is now a hard link to the same inode as tmp; we
    /// unlink tmp and the file persists at `target`.
    /// On `link` AlreadyExists: another writer beat us. Read the existing target and
    /// compare for byte-equal idempotency. Match → return Ok (race winner won fairly).
    /// Mismatch → return InvalidDkgState(<context>_already_exists_with_different_content),
    /// which is the fail-closed contract the original docstring promised.
    ///
    /// `context` is a snake_case tag bound into the error code so callers can
    /// distinguish a vault_state_v2 collision from a mpcca_withdraw_v2 session-state
    /// collision in logs.
    pub fn write_atomic_no_clobber(
        path: &Path,
        contents: &[u8],
        context: &str,
    ) -> WorkerResult<()> {
        write_atomic_link_no_clobber(path, contents, context)
    }

    /// Tmp + rename, no existence check — used by callers that WANT to overwrite an
    /// existing file (observe_deposit cursor bump, finalize hash pin). The upstream
    /// caller is responsible for any content-equality / provenance assertion before
    /// invoking this.
    pub fn write_atomic_replace(path: &Path, contents: &[u8], context: &str) -> WorkerResult<()> {
        write_atomic_tmp_then_rename(path, contents, context)
    }

    /// Truly-atomic no-clobber write via `link(2)`. See `write_atomic_no_clobber` above
    /// for the contract; this is the implementation.
    fn write_atomic_link_no_clobber(
        path: &Path,
        contents: &[u8],
        context: &str,
    ) -> WorkerResult<()> {
        let (tmp_path, _file_name) = write_tmp_file(path, contents, context)?;
        // KILLER: `hard_link(2)` atomic create-only. Failure with AlreadyExists is the
        // signal that another writer beat us; ANY other error is propagated.
        match fs::hard_link(&tmp_path, path) {
            Ok(()) => {
                // Success: target is now a hard link to tmp's inode. Unlink tmp so the
                // file ends up at `path` only.
                let _ = fs::remove_file(&tmp_path);
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // Race lost (or idempotent replay). Read the existing target and compare.
                // The tmp file is no longer needed regardless of the comparison outcome.
                let read_result = fs::read(path);
                let _ = fs::remove_file(&tmp_path);
                let existing = read_result.map_err(|read_err| {
                    WorkerError::Crypto(format!(
                        "{context}: read existing {} for idempotency check: {read_err}",
                        path.display()
                    ))
                })?;
                if existing == contents {
                    // Byte-identical: race winner wrote the SAME content as us; this is
                    // an idempotent replay. The persisted file matches what we wanted.
                    Ok(())
                } else {
                    Err(WorkerError::InvalidDkgState(format!(
                        "{context}_already_exists_with_different_content"
                    )))
                }
            }
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                Err(WorkerError::Crypto(format!(
                    "{context}: hard_link {} -> {}: {err}",
                    tmp_path.display(),
                    path.display()
                )))
            }
        }
    }

    /// Write `contents` to a unique tmp file in `path`'s parent dir, mode 0o600,
    /// fsynced. Returns `(tmp_path, file_name)` so the caller can decide whether to
    /// link-atomic into place or rename-replace.
    fn write_tmp_file(
        path: &Path,
        contents: &[u8],
        context: &str,
    ) -> WorkerResult<(std::path::PathBuf, String)> {
        use rand::RngCore as _;
        use std::io::Write as _;
        let parent = path.parent().ok_or_else(|| {
            WorkerError::Crypto(format!(
                "{context}: path {} has no parent dir",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            WorkerError::Crypto(format!(
                "{context}: create parent dir {}: {err}",
                parent.display()
            ))
        })?;
        let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
            WorkerError::Crypto(format!("{context}: path {} has no file name", path.display()))
        })?;
        let pid = std::process::id();
        let mut rng = rand::rngs::OsRng;
        const MAX_ATTEMPTS: usize = 16;
        for _ in 0..MAX_ATTEMPTS {
            let suffix: u64 = rng.next_u64();
            let tmp_path = parent.join(format!("{file_name}.tmp.{pid}.{suffix:016x}"));
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = match opts.open(&tmp_path) {
                Ok(f) => f,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(WorkerError::Crypto(format!(
                        "{context}: open tmp {}: {err}",
                        tmp_path.display()
                    )));
                }
            };
            if let Err(err) = file.write_all(contents) {
                let _ = fs::remove_file(&tmp_path);
                return Err(WorkerError::Crypto(format!(
                    "{context}: write tmp {}: {err}",
                    tmp_path.display()
                )));
            }
            if let Err(err) = file.sync_all() {
                let _ = fs::remove_file(&tmp_path);
                return Err(WorkerError::Crypto(format!(
                    "{context}: fsync tmp {}: {err}",
                    tmp_path.display()
                )));
            }
            drop(file);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(err) =
                    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
                {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(WorkerError::Crypto(format!(
                        "{context}: chmod 0o600 tmp {}: {err}",
                        tmp_path.display()
                    )));
                }
            }
            return Ok((tmp_path, file_name.to_string()));
        }
        Err(WorkerError::Crypto(format!(
            "{context}: exhausted {MAX_ATTEMPTS} tmp-suffix retries writing {}",
            path.display()
        )))
    }

    fn write_atomic_tmp_then_rename(
        path: &Path,
        contents: &[u8],
        context: &str,
    ) -> WorkerResult<()> {
        let (tmp_path, _file_name) = write_tmp_file(path, contents, context)?;
        if let Err(err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(WorkerError::Crypto(format!(
                "{context}: rename {} -> {}: {err}",
                tmp_path.display(),
                path.display()
            )));
        }
        Ok(())
    }
}

pub mod vault_ek_derivation_v2 {
    use crate::ca_dkg_v2::load_ca_dkg_v2_share;
    use crate::h_ristretto;
    use crate::mpc_inverse_adapter::{AdapterError, InversionContext, MpcInverseAdapter};
    use crate::mpc_spdz_adapter::{is_safe_id, random_scalar};
    use crate::{assert_slot, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD};
    use curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256, Sha512};
    use std::fs;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroize;

    pub(crate) const WORKER_TRANSCRIPT_DOMAIN: &str = "EUNOMA_VAULT_EK_DERIVATION_V1";
    pub(crate) const FINAL_TRANSCRIPT_DOMAIN: &str = "EUNOMA_VAULT_EK_DERIVATION_FINAL_V1";
    pub(crate) const SCHNORR_CHALLENGE_DOMAIN: &str = "EUNOMA_VAULT_EK_DERIVATION_SCHNORR_V1";
    pub(crate) const ROUND0_HASH_DOMAIN: &str = "EUNOMA_VAULT_EK_DERIVATION_ROUND0_V1";

    // Codex P1 #4 round0: file basenames + on-disk shape for the per-session r_i + h_r_i
    // commitment. The file lives under `state_dir/mpc-sessions/<request_id>__<session_id>/round0.json`
    // with mode 0o600. The session-namespaced path prevents two parallel derivations from
    // clobbering each other (Phase 2 only runs one at a time via the coordinator lock, but
    // defense in depth: a bug there shouldn't let workers cross-pollinate state).
    pub(crate) const ROUND0_FILE_NAME: &str = "round0.json";

    /// Codex P1 #4 round0: pre-MPC h_r_i commitment endpoint.
    ///
    /// Workers must publish a commitment to `h_r_i = H * r_i` BEFORE the MPC opens `m`.
    /// Otherwise a malicious party can wait for `m`, pick any scalar `y`, publish
    /// `h_r' = H*y` and `h_q' = H*(y*m_inv)` and produce a Schnorr POK on `y*m_inv` — the
    /// per-party `h_q * m == h_r` and aggregate `vault_ek * m == sum(h_r)` checks both
    /// pass trivially, and the registration sigma is fooled into accepting a malicious
    /// `vault_ek`. Committing h_r_i pre-MPC forces every party to fix r_i before seeing
    /// m, breaking the adaptive choice.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round0Request {
        pub dkg_epoch: String,
        pub ca_dkg_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub request_id: String,
        pub session_id: String,
        /// Round0 still receives `peerAddresses` and `lagrangeCoefficients` so the
        /// adapter's validation pipeline (slot-binding + lambda recompute) can fire
        /// before any r_i is persisted. Mirrors round1's request shape for symmetry.
        pub peer_addresses: Vec<String>,
        pub player_id: usize,
        pub lagrange_coefficients: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round0Result {
        pub slot: usize,
        /// `h_r_i = H * r_i` in compressed Ristretto (lowercase hex). The coordinator
        /// collects all 5 and broadcasts them as `allHRoundZero` in round1.
        pub h_r: String,
        /// `sha256(canonical(sessionId, rosterHash, selectedSlots, selfSlot, h_r_hex))`.
        /// Coordinator can cross-check this (defense in depth) against locally-recomputed
        /// hash from the body.
        pub worker_round0_hash: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1Request {
        pub dkg_epoch: String,
        pub ca_dkg_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        /// Phase 2: see plan §"Coordinator delta"; identifies this derivation request.
        #[serde(default)]
        pub request_id: String,
        /// Phase 2: outer coordination session identifier. Coordinator sets `sessionId = requestId`.
        #[serde(default)]
        pub session_id: String,
        /// Phase 2: `host:port` for each MASCOT peer (player-ordinal order).
        #[serde(default)]
        pub peer_addresses: Vec<String>,
        /// Phase 2: this party's ordinal among `sorted(selected_slots)`.
        #[serde(default)]
        pub player_id: usize,
        /// Phase 2: hex-encoded public Lagrange coefficients at x=0 for sorted(selected_slots).
        #[serde(default)]
        pub lagrange_coefficients: Vec<String>,
        /// Codex P1 #4 round0: the coordinator-broadcast vector of all 5 parties'
        /// `h_r_i` commitments published in round0. Length 5, ordered by player ordinal.
        /// This party asserts `allHRoundZero[playerId]` byte-matches its own persisted
        /// `h_r_i` before running MPC.
        #[serde(default)]
        pub all_h_round_zero: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SchnorrProof {
        /// JSON-serialized as `R` to match the TS `VaultEkContribution.schnorrProof` shape
        /// (which the coordinator validates via `assembleVaultEkTranscript`).
        #[serde(rename = "R")]
        pub r: String,
        pub s: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1Result {
        pub slot: usize,
        pub h_contribution: String,
        pub schnorr_proof: SchnorrProof,
        pub worker_transcript_hash: String,
        /// Codex P1 #4: MPC-opened m (Scalar, lowercase little-endian hex). All 5 parties
        /// in a session MUST report the same value.
        pub mpc_open_m: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ContributionInput {
        pub slot: usize,
        pub h_contribution: String,
        pub schnorr_proof: SchnorrProof,
        pub worker_transcript_hash: String,
        /// Codex P1 #4: see Round1Result::mpc_open_m.
        pub mpc_open_m: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VerifyRequest {
        pub dkg_epoch: String,
        pub ca_dkg_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub contributions: Vec<ContributionInput>,
        /// Codex P1 #4 round0: the coordinator-broadcast vector of all 5 parties'
        /// h_r_i commitments published in round0, in player-ordinal (sorted slot) order.
        /// Verify uses these instead of a per-contribution `hR` field — that field is gone.
        pub all_h_round_zero: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VerifyResult {
        pub vault_ek: String,
        pub final_transcript_hash: String,
    }

    /// On-disk shape for the round0 commitment file. Mode 0o600. Lives at
    /// `state_dir/mpc-sessions/<request_id>__<session_id>/round0.json`.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct Round0FileLayout {
        pub session_id: String,
        pub request_id: String,
        pub self_slot: usize,
        pub player_id: usize,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        /// Canonical 32-byte little-endian Scalar, hex. Sensitive.
        pub r_i_hex: String,
        /// 32-byte compressed Ristretto point, hex. Public commitment.
        pub h_r_i_hex: String,
        pub created_at_unix_ms: u128,
    }

    fn round0_session_dir(state_dir: &Path, request_id: &str, session_id: &str) -> PathBuf {
        state_dir
            .join("mpc-sessions")
            .join(format!("{}__{}", request_id, session_id))
    }

    fn round0_file_path(state_dir: &Path, request_id: &str, session_id: &str) -> PathBuf {
        round0_session_dir(state_dir, request_id, session_id).join(ROUND0_FILE_NAME)
    }

    /// Codex P1 #4 round0: hash the locally-committed `h_r_i` together with the binding
    /// fields. Returned to the coordinator as `workerRound0Hash` for defense-in-depth
    /// cross-check; not security-critical (the file persists the canonical r_i + h_r_i),
    /// but a useful sanity hook for the orchestrator.
    pub fn worker_round0_hash(
        session_id: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        h_r_hex: &str,
    ) -> String {
        let joined_slots = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROUND0_HASH_DOMAIN.as_bytes());
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined_slots.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(h_r_hex.as_bytes());
        sha256_hex(&bytes)
    }

    /// Codex P1 #4 round0: hash the full ordered round0 commitment vector. Binds this
    /// party's view of WHAT all 5 parties' h_r_i values are into its Schnorr proof's
    /// transcript hash. A malicious worker can't alter its view of allHRoundZero between
    /// rounds without invalidating the transcript signature.
    pub fn round0_commit_hash(all_h_round_zero: &[String]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROUND0_HASH_DOMAIN.as_bytes());
        bytes.extend_from_slice(b"AGG:");
        for (idx, h_r) in all_h_round_zero.iter().enumerate() {
            if idx > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(h_r.to_lowercase().as_bytes());
        }
        sha256_hex(&bytes)
    }

    /// Round0 endpoint handler. Validates request shape (mirrors run_round1 validation),
    /// generates a fresh random `r_i`, computes `h_r_i = H * r_i`, persists the
    /// commitment file under `state_dir/mpc-sessions/<request_id>__<session_id>/round0.json`
    /// with mode 0o600. Idempotency: if the file already exists with the same sessionId
    /// (same selected_slots, same self_slot), return the persisted h_r_i — never
    /// regenerate r_i (that would break the commit-reveal). If sessionId clashes with a
    /// DIFFERENT request_id-session_id pair the path differs by construction, so this
    /// only matters for true replays.
    pub fn run_round0(state_dir: &Path, req: &Round0Request) -> WorkerResult<Round0Result> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.peer_addresses.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "peer_addresses must have {DEOPERATOR_THRESHOLD} entries"
            )));
        }
        if req.lagrange_coefficients.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "lagrange_coefficients must have {DEOPERATOR_THRESHOLD} entries"
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted_slots = sorted_unique_slots(&req.selected_slots)?;
        if sorted_slots[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted_slots[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        let ca_dkg_transcript_hash = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        // Cross-check: this party MUST already have a matching share file on disk so we
        // don't write a round0 commitment for a session we can't actually complete in
        // round1. Failing here surfaces missing-share early.
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.self_slot
            )));
        }
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.dkg_epoch
            )));
        }
        if share.transcript_hash.to_lowercase() != ca_dkg_transcript_hash {
            return Err(WorkerError::InvalidRequest(
                "ca_dkg_transcript_hash does not match local share".to_string(),
            ));
        }
        // Idempotency / replay handling. If a round0 file already exists for this
        // request_id+session_id, return the persisted h_r_i instead of re-generating
        // r_i. Regenerating would break the commit (the originally-committed h_r_i is
        // still in the broadcast vector). If the persisted file's sessionId disagrees
        // with the request, treat as a collision and refuse.
        let file_path = round0_file_path(state_dir, &req.request_id, &req.session_id);
        if file_path.exists() {
            let raw = fs::read(&file_path).map_err(|err| {
                WorkerError::Crypto(format!("read existing round0 file: {err}"))
            })?;
            let layout: Round0FileLayout = serde_json::from_slice(&raw)
                .map_err(|err| WorkerError::Crypto(format!("parse round0 file: {err}")))?;
            if layout.session_id != req.session_id || layout.request_id != req.request_id {
                return Err(WorkerError::InvalidDkgState(
                    "round0_session_collision".to_string(),
                ));
            }
            if layout.self_slot != req.self_slot || layout.player_id != req.player_id {
                return Err(WorkerError::InvalidDkgState(
                    "round0_self_slot_mismatch".to_string(),
                ));
            }
            // Return the previously-committed h_r_i. r_i is NOT touched.
            let h_r_hex = normalize_hex(&layout.h_r_i_hex, 32)?;
            let worker_round0_hash = worker_round0_hash(
                &req.session_id,
                &roster_hash,
                &sorted_slots,
                req.self_slot,
                &h_r_hex,
            );
            return Ok(Round0Result {
                slot: req.self_slot,
                h_r: h_r_hex,
                worker_round0_hash,
            });
        }

        // Fresh round0. Generate r_i, compute h_r_i, persist with 0o600 mode.
        let mut r_i = random_scalar();
        let h = h_ristretto()?;
        let h_r_point = h * r_i;
        let h_r_hex = compressed_hex(&h_r_point);
        let r_i_hex = hex_encode(r_i.to_bytes().as_slice());
        let layout = Round0FileLayout {
            session_id: req.session_id.clone(),
            request_id: req.request_id.clone(),
            self_slot: req.self_slot,
            player_id: req.player_id,
            roster_hash: roster_hash.clone(),
            selected_slots: sorted_slots.clone(),
            r_i_hex,
            h_r_i_hex: h_r_hex.clone(),
            created_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        };
        let session_dir = round0_session_dir(state_dir, &req.request_id, &req.session_id);
        fs::create_dir_all(&session_dir)
            .map_err(|err| WorkerError::Crypto(format!("create session_dir: {err}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o700);
            if let Err(err) = fs::set_permissions(&session_dir, perm) {
                // Not fatal; surface a clear error if we couldn't lock down the dir.
                return Err(WorkerError::Crypto(format!(
                    "chmod 700 {}: {err}",
                    session_dir.display()
                )));
            }
        }
        let bytes = serde_json::to_vec(&layout)
            .map_err(|err| WorkerError::Crypto(format!("encode round0 file: {err}")))?;
        write_secret_file(&file_path, &bytes)?;
        // After persisting, scrub r_i from this stack frame — the next read happens via
        // load_round0_file.
        r_i.zeroize();
        let worker_round0_hash = worker_round0_hash(
            &req.session_id,
            &roster_hash,
            &sorted_slots,
            req.self_slot,
            &h_r_hex,
        );
        Ok(Round0Result {
            slot: req.self_slot,
            h_r: h_r_hex,
            worker_round0_hash,
        })
    }

    /// Codex P1 #4 round0 + M3a P2 #2: atomic write with no-clobber + byte-equality
    /// idempotency gate. The caller (run_round0) ALREADY does an idempotency check above
    /// (`file_path.exists() → return persisted h_r_i`), so by the time this function is
    /// reached the destination file should not exist. The no-clobber guard catches a race
    /// where two concurrent round0 callers both passed the upstream existence check.
    ///
    /// Both writers will be writing different content (each call draws a fresh `r_i`), so
    /// the loser sees `InvalidDkgState("vault_ek_round0_file_already_exists_with_different_content")`
    /// and fails closed. The winner's content is persisted. Defense in depth — the upstream
    /// idempotency check makes this race nearly impossible to hit, but the guard ensures
    /// fail-closed semantics if it ever does.
    fn write_secret_file(path: &Path, contents: &[u8]) -> WorkerResult<()> {
        crate::atomic_io::write_atomic_no_clobber(path, contents, "vault_ek_round0_file")
    }

    /// Codex P1 #4 round0: read + parse + validate the round0 commitment file. Loaded by
    /// `run_round1` to fetch the persisted `r_i` and to assert that
    /// `allHRoundZero[playerId]` matches the locally-committed `h_r_i` byte-for-byte.
    fn load_round0_file(
        state_dir: &Path,
        request_id: &str,
        session_id: &str,
    ) -> WorkerResult<Round0FileLayout> {
        let path = round0_file_path(state_dir, request_id, session_id);
        if !path.exists() {
            return Err(WorkerError::InvalidDkgState(
                "round0_file_missing".to_string(),
            ));
        }
        let raw = fs::read(&path)
            .map_err(|err| WorkerError::Crypto(format!("read round0 file: {err}")))?;
        let layout: Round0FileLayout = serde_json::from_slice(&raw)
            .map_err(|err| WorkerError::Crypto(format!("parse round0 file: {err}")))?;
        if layout.session_id != session_id || layout.request_id != request_id {
            return Err(WorkerError::InvalidDkgState(
                "round0_session_mismatch".to_string(),
            ));
        }
        Ok(layout)
    }

    /// Codex P1 #4 round0: scrub + delete the round0 commitment file. Called from
    /// `run_round1` after a successful (or failed) round1 so `r_i` doesn't linger.
    fn drop_round0_file(state_dir: &Path, request_id: &str, session_id: &str) {
        let path = round0_file_path(state_dir, request_id, session_id);
        if !path.exists() {
            return;
        }
        // Best-effort scrub.
        if let Ok(metadata) = fs::metadata(&path) {
            let len = metadata.len() as usize;
            let zeros = vec![0u8; len];
            if let Ok(mut file) = fs::OpenOptions::new().write(true).truncate(false).open(&path) {
                use std::io::Write as _;
                let _ = file.write_all(&zeros);
                let _ = file.sync_all();
            }
        }
        let _ = fs::remove_file(&path);
        let parent = round0_session_dir(state_dir, request_id, session_id);
        // Don't fail on cleanup; if the dir is empty after the file is gone, remove it.
        let _ = fs::remove_dir(parent);
    }

    pub fn run_round1(
        state_dir: &Path,
        req: &Round1Request,
        adapter: &dyn MpcInverseAdapter,
    ) -> WorkerResult<Round1Result> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        // Codex P1 #4 round0: round1 MUST receive the coordinator-broadcast
        // `allHRoundZero` vector and assert that the entry at this party's ordinal
        // byte-matches the locally-persisted commitment. Without this binding the
        // post-m bias attack is open.
        if req.all_h_round_zero.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "all_h_round_zero must have {DEOPERATOR_THRESHOLD} entries, got {}",
                req.all_h_round_zero.len()
            )));
        }
        let ca_dkg_transcript_hash = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let sorted_slots = sorted_unique_slots(&req.selected_slots)?;
        if sorted_slots[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted_slots[req.player_id], req.self_slot
            )));
        }

        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.self_slot
            )));
        }
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.dkg_epoch
            )));
        }
        if share.transcript_hash.to_lowercase() != ca_dkg_transcript_hash {
            return Err(WorkerError::InvalidRequest(
                "ca_dkg_transcript_hash does not match local share".to_string(),
            ));
        }

        let dk_share = scalar_from_hex(&share.dk_share)?;

        // Codex P1 #4 round0: load persisted (r_i, h_r_i). Reject if missing or if the
        // sessionId doesn't match. Then assert this party's h_r_i matches the
        // coordinator's `all_h_round_zero[player_id]` byte-for-byte. If they disagree,
        // the coordinator forwarded a tampered vector — fail closed.
        let round0 = load_round0_file(state_dir, &req.request_id, &req.session_id)?;
        let persisted_h_r = normalize_hex(&round0.h_r_i_hex, 32)?;
        let claimed_h_r = normalize_hex(&req.all_h_round_zero[req.player_id], 32)?;
        if persisted_h_r != claimed_h_r {
            // Defense in depth — clean up the round0 file so a stale commit doesn't
            // hang around.
            drop_round0_file(state_dir, &req.request_id, &req.session_id);
            return Err(WorkerError::Crypto(format!(
                "round0_commitment_mismatch: persisted h_r_i differs from allHRoundZero[{}]",
                req.player_id
            )));
        }
        // Normalize the entire all_h_round_zero vector so the hash binding is byte-stable.
        let mut all_h_normalized: Vec<String> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for entry in &req.all_h_round_zero {
            all_h_normalized.push(normalize_hex(entry, 32)?);
        }
        let round0_commit_hash_hex = round0_commit_hash(&all_h_normalized);

        let mut r_i = scalar_from_hex(&round0.r_i_hex).map_err(|_| {
            WorkerError::Crypto("round0_file_r_i_not_canonical".to_string())
        })?;

        // Phase 2: derive the per-session work directory from request_id + session_id.
        // Coordinator chooses these (both non-empty in production).
        let work_dir = state_dir.to_path_buf();
        let ctx = InversionContext {
            dkg_epoch: req.dkg_epoch.clone(),
            ca_dkg_transcript_hash: ca_dkg_transcript_hash.clone(),
            selected_slots: req.selected_slots.clone(),
            self_slot: req.self_slot,
            roster_hash: roster_hash.clone(),
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            work_dir,
            peer_addresses: req.peer_addresses.clone(),
            player_id: req.player_id,
            lagrange_coefficients_hex: req.lagrange_coefficients.clone(),
        };
        let inversion_result = adapter.compute_inverse_share(&dk_share, &r_i, &ctx);
        // Whether MPC succeeded or failed, scrub the round0 file and our local r_i copy.
        // The persisted r_i is now redundant (MPC consumed it) and must not leak.
        drop_round0_file(state_dir, &req.request_id, &req.session_id);
        let inversion = match inversion_result {
            Ok(share) => share,
            Err(err) => {
                r_i.zeroize();
                return Err(adapter_error_to_worker(err));
            }
        };
        // Defense in depth: the adapter recomputes h_r_i = h * r_i internally and
        // returns it. Assert it matches what we just persisted in round0 — otherwise
        // either the adapter is buggy or r_i changed mid-flight.
        let h = h_ristretto()?;
        let expected_h_r_point = h * r_i;
        r_i.zeroize();
        if expected_h_r_point != inversion.h_r_i {
            return Err(WorkerError::Crypto(
                "adapter_h_r_disagrees_with_round0".to_string(),
            ));
        }
        let h_r_hex_from_adapter = compressed_hex(&inversion.h_r_i);
        if normalize_hex(&h_r_hex_from_adapter, 32)? != persisted_h_r {
            return Err(WorkerError::Crypto(
                "adapter_h_r_hex_disagrees_with_round0".to_string(),
            ));
        }
        let mut inv_share = inversion.q_i;
        let mpc_open_m = inversion.mpc_open_m;

        let h_contribution = h * inv_share;
        let h_contribution_hex = compressed_hex(&h_contribution);
        let mpc_open_m_hex = hex_encode(mpc_open_m.to_bytes().as_slice());
        let worker_transcript_hash = worker_transcript_hash(
            &req.dkg_epoch,
            &ca_dkg_transcript_hash,
            &roster_hash,
            &sorted_slots,
            req.self_slot,
            &h_contribution_hex,
            &persisted_h_r,
            &mpc_open_m_hex,
            &round0_commit_hash_hex,
        );
        let proof = schnorr_pok(&inv_share, &h_contribution, &worker_transcript_hash)?;
        // Codex P2 #7: zeroize q_i after producing the public artifacts.
        inv_share.zeroize();

        Ok(Round1Result {
            slot: req.self_slot,
            h_contribution: h_contribution_hex,
            schnorr_proof: proof,
            worker_transcript_hash,
            mpc_open_m: mpc_open_m_hex,
        })
    }

    pub fn run_verify(req: &VerifyRequest) -> WorkerResult<VerifyResult> {
        validate_selected_slots(&req.selected_slots)?;
        if req.contributions.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {DEOPERATOR_THRESHOLD} contributions, got {}",
                req.contributions.len()
            )));
        }
        // Codex P1 #4 round0: verify takes the full allHRoundZero vector. Per-party
        // check `h_q_i * m == h_r_i` now uses the round0-committed h_r_i (NOT a
        // round1-supplied value, which would let a malicious worker post-hoc-pick).
        if req.all_h_round_zero.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "all_h_round_zero must have {DEOPERATOR_THRESHOLD} entries, got {}",
                req.all_h_round_zero.len()
            )));
        }
        let ca_dkg_transcript_hash = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let sorted_slots = sorted_unique_slots(&req.selected_slots)?;
        let selected_set: std::collections::BTreeSet<usize> = sorted_slots.iter().copied().collect();

        // Normalize the allHRoundZero vector and decompress for the aggregate check.
        let mut all_h_normalized: Vec<String> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        let mut all_h_points: Vec<RistrettoPoint> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for entry in &req.all_h_round_zero {
            let norm = normalize_hex(entry, 32)?;
            all_h_points.push(decompress_hex(&norm)?);
            all_h_normalized.push(norm);
        }
        let round0_commit_hash_hex = round0_commit_hash(&all_h_normalized);

        let mut seen = [false; DEOPERATOR_COUNT];
        let mut points: Vec<RistrettoPoint> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        // ordered (slot, h_contribution_hex, proof, mpc_open_m_hex); h_r dropped — it's
        // bound by allHRoundZero now.
        let mut ordered: Vec<(usize, String, SchnorrProof, String)> =
            Vec::with_capacity(DEOPERATOR_THRESHOLD);
        // Codex P1 #4: cross-party consistency. All 5 workers must report the same MPC-
        // opened m (MAC-checked by MASCOT). Reject if any disagrees.
        let mut shared_m: Option<Scalar> = None;
        for contribution in &req.contributions {
            assert_slot(contribution.slot)?;
            if !selected_set.contains(&contribution.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "contribution slot {} not in selected_slots",
                    contribution.slot
                )));
            }
            if seen[contribution.slot] {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate contribution slot {}",
                    contribution.slot
                )));
            }
            seen[contribution.slot] = true;

            let h_contribution_norm = normalize_hex(&contribution.h_contribution, 32)?;
            let mpc_open_m_norm = normalize_hex(&contribution.mpc_open_m, 32)?;
            // Codex P1 #4 round0: locate this party's ordinal within sorted_slots so we
            // can fetch the round0-committed h_r_i for this contribution.
            let player_ordinal = sorted_slots
                .iter()
                .position(|s| *s == contribution.slot)
                .ok_or_else(|| {
                    WorkerError::InvalidRequest(format!(
                        "contribution slot {} not in sorted selected_slots",
                        contribution.slot
                    ))
                })?;
            let h_r_norm = all_h_normalized[player_ordinal].clone();
            let expected_worker_hash = worker_transcript_hash(
                &req.dkg_epoch,
                &ca_dkg_transcript_hash,
                &roster_hash,
                &sorted_slots,
                contribution.slot,
                &h_contribution_norm,
                &h_r_norm,
                &mpc_open_m_norm,
                &round0_commit_hash_hex,
            );
            let supplied = normalize_hex(&contribution.worker_transcript_hash, 32)?;
            if supplied != expected_worker_hash {
                return Err(WorkerError::InvalidRequest(format!(
                    "worker_transcript_hash mismatch for slot {}",
                    contribution.slot
                )));
            }

            let point = decompress_hex(&h_contribution_norm)?;
            let h_r_point = all_h_points[player_ordinal];
            let m_scalar = scalar_from_hex(&mpc_open_m_norm)?;
            if m_scalar == Scalar::ZERO {
                return Err(WorkerError::InvalidRequest(format!(
                    "mpc_open_m is zero for slot {}",
                    contribution.slot
                )));
            }
            // Codex P1 #4 round0: per-party check `h_q_i * m == allHRoundZero[i]`. The
            // h_r_i value comes from the round0 commitment vector, NOT from a
            // round1-supplied field — so a malicious worker can't pick (h_q', h_r') as a
            // matched pair after seeing m.
            if point * m_scalar != h_r_point {
                return Err(WorkerError::Crypto(format!(
                    "h_q_i * m != allHRoundZero[{}] for slot {}",
                    player_ordinal, contribution.slot
                )));
            }
            // All 5 parties must report the same m.
            match &shared_m {
                None => shared_m = Some(m_scalar),
                Some(prev) => {
                    if *prev != m_scalar {
                        return Err(WorkerError::InvalidRequest(format!(
                            "mpc_open_m disagreement across parties at slot {}",
                            contribution.slot
                        )));
                    }
                }
            }
            if !verify_schnorr_pok(&point, &contribution.schnorr_proof, &expected_worker_hash)? {
                return Err(WorkerError::Crypto(format!(
                    "schnorr verification failed for slot {}",
                    contribution.slot
                )));
            }
            points.push(point);
            ordered.push((
                contribution.slot,
                h_contribution_norm,
                contribution.schnorr_proof.clone(),
                mpc_open_m_norm,
            ));
        }

        let mut vault_ek = RistrettoPoint::default();
        for point in &points {
            vault_ek += point;
        }
        let mut h_r_sum = RistrettoPoint::default();
        for point in &all_h_points {
            h_r_sum += point;
        }
        // Cross-aggregate sanity check: vault_ek * m == sum(allHRoundZero). Implied by
        // the per-party check but cheap to verify (codex P1 #4 round0).
        let m_final = shared_m.expect("at least one contribution sets shared_m");
        if vault_ek * m_final != h_r_sum {
            return Err(WorkerError::Crypto(
                "vault_ek * m != sum(allHRoundZero) — aggregate consistency check failed"
                    .to_string(),
            ));
        }
        let vault_ek_hex = compressed_hex(&vault_ek);
        ordered.sort_by_key(|item| item.0);
        let final_transcript_hash = final_transcript_hash(
            &req.dkg_epoch,
            &ca_dkg_transcript_hash,
            &roster_hash,
            &sorted_slots,
            &vault_ek_hex,
            &ordered,
            &all_h_normalized,
        );

        Ok(VerifyResult {
            vault_ek: vault_ek_hex,
            final_transcript_hash,
        })
    }

    pub fn schnorr_pok(
        secret: &Scalar,
        h_contribution: &RistrettoPoint,
        worker_transcript_hash: &str,
    ) -> WorkerResult<SchnorrProof> {
        let h = h_ristretto()?;
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let r_point = h * r;
        let challenge = schnorr_challenge(worker_transcript_hash, &r_point, h_contribution);
        let s = r + challenge * secret;
        Ok(SchnorrProof {
            r: compressed_hex(&r_point),
            s: hex_encode(s.to_bytes().as_slice()),
        })
    }

    pub fn verify_schnorr_pok(
        h_contribution: &RistrettoPoint,
        proof: &SchnorrProof,
        worker_transcript_hash: &str,
    ) -> WorkerResult<bool> {
        let h = h_ristretto()?;
        let r_point = decompress_hex(&normalize_hex(&proof.r, 32)?)?;
        let s = scalar_from_hex(&proof.s)?;
        let challenge = schnorr_challenge(worker_transcript_hash, &r_point, h_contribution);
        let lhs = h * s;
        let rhs = r_point + h_contribution * challenge;
        Ok(lhs == rhs)
    }

    pub fn worker_transcript_hash(
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        slot: usize,
        h_contribution_hex: &str,
        h_r_hex: &str,
        mpc_open_m_hex: &str,
        round0_commit_hash: &str,
    ) -> String {
        let joined_slots = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(WORKER_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined_slots.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(h_contribution_hex.as_bytes());
        // Codex P1 #4: bind h_r_i and mpc_open_m into the transcript hash so the Schnorr POK
        // challenge covers them too; otherwise a malicious worker could swap (h_r, m) post-
        // signing without invalidating the proof.
        bytes.push(b':');
        bytes.extend_from_slice(h_r_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(mpc_open_m_hex.as_bytes());
        // Codex P1 #4 round0: also bind this party's view of ALL 5 parties'
        // round0-committed h_r_i values via `round0_commit_hash`. Without this binding a
        // malicious party could see m, derive an adversarial (h_q, h_r) pair locally, and
        // produce a Schnorr POK that satisfies the per-party and aggregate checks. With
        // it, the Schnorr challenge depends on the agreed-upon vector of pre-MPC h_r_i
        // commitments — the party cannot retroactively choose a different r_i.
        bytes.push(b':');
        bytes.extend_from_slice(round0_commit_hash.as_bytes());
        sha256_hex(&bytes)
    }

    pub fn final_transcript_hash(
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        vault_ek_hex: &str,
        ordered_contributions: &[(usize, String, SchnorrProof, String)],
        all_h_round_zero: &[String],
    ) -> String {
        let joined_slots = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FINAL_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined_slots.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        // Codex P1 #4 round0: bind the round0 commitment vector into the final transcript
        // so audit trails record the pre-MPC commitment values (the per-contribution h_r
        // field is gone — the canonical h_r_i lives in allHRoundZero).
        bytes.push(b':');
        bytes.extend_from_slice(b"R0:");
        bytes.extend_from_slice(round0_commit_hash(all_h_round_zero).as_bytes());
        for (slot, h_contribution_hex, proof, mpc_open_m_hex) in ordered_contributions {
            bytes.push(b':');
            bytes.extend_from_slice(slot.to_string().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(h_contribution_hex.as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(proof.r.to_lowercase().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(proof.s.to_lowercase().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(mpc_open_m_hex.to_lowercase().as_bytes());
        }
        sha256_hex(&bytes)
    }

    fn schnorr_challenge(
        worker_transcript_hash: &str,
        r_point: &RistrettoPoint,
        h_contribution: &RistrettoPoint,
    ) -> Scalar {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SCHNORR_CHALLENGE_DOMAIN.as_bytes());
        bytes.extend_from_slice(worker_transcript_hash.to_lowercase().as_bytes());
        bytes.extend_from_slice(r_point.compress().as_bytes());
        bytes.extend_from_slice(h_contribution.compress().as_bytes());
        let digest = Sha512::digest(&bytes);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(digest.as_slice());
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn validate_selected_slots(slots: &[usize]) -> WorkerResult<()> {
        if slots.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "selected_slots must have {DEOPERATOR_THRESHOLD} entries, got {}",
                slots.len()
            )));
        }
        let mut seen = [false; DEOPERATOR_COUNT];
        for slot in slots {
            assert_slot(*slot)?;
            if seen[*slot] {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate selected_slots entry {slot}"
                )));
            }
            seen[*slot] = true;
        }
        Ok(())
    }

    fn sorted_unique_slots(slots: &[usize]) -> WorkerResult<Vec<usize>> {
        validate_selected_slots(slots)?;
        let mut copy = slots.to_vec();
        copy.sort_unstable();
        Ok(copy)
    }

    fn adapter_error_to_worker(err: AdapterError) -> WorkerError {
        match err {
            AdapterError::McpSpdzNotAvailable => {
                WorkerError::NotImplemented("mpc_inverse_unavailable")
            }
            AdapterError::InvalidInput(msg) => WorkerError::InvalidRequest(msg),
            AdapterError::Internal(msg) => WorkerError::Crypto(msg),
        }
    }

    fn compressed_hex(point: &RistrettoPoint) -> String {
        hex_encode(point.compress().as_bytes())
    }

    fn decompress_hex(hex: &str) -> WorkerResult<RistrettoPoint> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(
                "Ristretto point must be 32 bytes".to_string(),
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        CompressedRistretto(buf)
            .decompress()
            .ok_or_else(|| WorkerError::InvalidRequest("invalid Ristretto point".to_string()))
    }

    /// Codex P2 #9: parse a 32-byte hex scalar and REJECT non-canonical encodings
    /// (bytes >= q). Schnorr `s`, mpc_open_m, and on-disk dk_share values are all serialized
    /// via `Scalar::to_bytes()` which is always canonical; any input that fails the canonical
    /// check is malformed or tampered. Use `Scalar::from_canonical_bytes(...).into_option()`
    /// rather than the silently-reducing `from_bytes_mod_order`.
    fn scalar_from_hex(hex: &str) -> WorkerResult<Scalar> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "scalar must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Scalar::from_canonical_bytes(buf)
            .into_option()
            .ok_or_else(|| {
                WorkerError::InvalidRequest("scalar bytes are not canonical (>= Q)".to_string())
            })
    }

    fn normalize_hex(hex: &str, expected_bytes: usize) -> WorkerResult<String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != expected_bytes {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {expected_bytes}-byte hex, got {}",
                bytes.len()
            )));
        }
        Ok(hex_encode(&bytes))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
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

}

/// Milestone 1: V2 threshold CA registration sigma.
///
/// V1 (`ca_local::create_registration_nonce_commitment` / `create_registration_partial_response`)
/// loads a centralized share file (`ca_dkg_share.json`) that carries both the Shamir share
/// AND a hard-coded `vault_ek`. V2 has neither:
///
/// - The dk Shamir share lives in `ca_dkg_share_v2.json` (real Pedersen VSS, threshold 5-of-7).
/// - `vault_ek` is dynamically derived per session via Phase 2 (`vault_ek_derivation_v2`) and
///   passed into this module as a request parameter, not loaded from disk.
///
/// The wire-level sigma protocol is identical to V1 (Schnorr-style proof of knowledge of `dk`
/// with `vault_ek` as the generator). What changes is the SOURCE of inputs. The aggregator
/// path re-uses the public verifier in `crate::registration_verifier`
/// (`aggregate_registration_commitment`, `registration_challenge_scalar`,
/// `verify_registration_proof`) because those operate on inputs (commitments / responses /
/// vault_ek_hex), not on the share file. Codex M2a P1: this module MUST NOT import from
/// `crate::ca_local` — that namespace is reserved for unit/local-smoke fixtures only.
pub mod ca_registration_v2 {
    use crate::ca_dkg_v2::load_ca_dkg_v2_share;
    use crate::registration_verifier::{
        aggregate_registration_commitment, registration_challenge_scalar, verify_registration_proof,
        RegistrationCommitmentInput, RegistrationResponseInput,
    };
    use crate::mpc_spdz_adapter::{is_safe_id, random_scalar};
    use crate::{assert_slot, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD};
    use curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroize;

    pub(crate) const ROUND1_TRANSCRIPT_DOMAIN: &str = "EUNOMA_CA_REGISTRATION_V2_NONCE_V1";
    pub(crate) const ROUND2_TRANSCRIPT_DOMAIN: &str = "EUNOMA_CA_REGISTRATION_V2_RESPONSE_V1";
    pub(crate) const NONCE_FILE_NAME: &str = "ca_registration_v2_nonce.json";

    /// Round 1 request: each selected worker generates a fresh per-session nonce `r_i`, commits
    /// `T_i = vault_ek * r_i`, persists `r_i` to a per-session file (0o600), and returns
    /// `(commitment_hex, commitment_hash, nonce_id, worker_transcript_hash)`. The dk Shamir
    /// share is loaded from `ca_dkg_share_v2.json`; the public `vault_ek` MUST be supplied
    /// by the coordinator (it is the Phase 2-derived value).
    ///
    /// Binding: this function asserts `share.transcript_hash == ca_dkg_transcript_hash`,
    /// `share.dkg_epoch == dkg_epoch`, `share.slot == self_slot`. A mismatch on any → 400.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1Request {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub ca_dkg_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        /// Phase 2-derived `vault_ek = H * dk^-1` in compressed Ristretto hex. Used as the
        /// generator of the sigma protocol — `commitment = vault_ek * r_i`.
        pub vault_ek: String,
        /// Asset metadata bound into the sigma proof. Mirror V1's `aggregate_registration_proof`
        /// shape so the same Aptos CA payload can carry the V2-derived (commitment, response).
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1Result {
        pub slot: usize,
        pub commitment_hex: String,
        pub commitment_hash: String,
        pub nonce_id: String,
        pub worker_transcript_hash: String,
    }

    /// Round 2 request: coordinator delivers the aggregate-challenge scalar back to each worker;
    /// worker reloads its `r_i` from the persisted nonce file, computes
    /// `response_i = r_i + challenge * dk_share_i (mod q)`, returns `response_hex +
    /// response_hash + worker_transcript_hash`. The nonce file is scrubbed + removed via
    /// RAII regardless of success or failure. dk_share_i and r_i are zeroized after use.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2Request {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub ca_dkg_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        pub nonce_id: String,
        /// Coordinator-computed aggregate challenge scalar (Fiat-Shamir over vault_ek,
        /// sender_address, asset_type, chain_id, aggregate_commitment). Hex, 32 bytes.
        pub challenge: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2Result {
        pub slot: usize,
        pub response_hex: String,
        pub response_hash: String,
        pub worker_transcript_hash: String,
    }

    /// Local verifier endpoint: same equation as `ca_local::verify_registration_proof` —
    /// `vault_ek * response == aggregate_commitment + h * challenge`. Coordinator runs this
    /// against the verifier-slot worker before returning success.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VerifyRequest {
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub aggregate_commitment: String,
        pub aggregate_response: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VerifyResult {
        pub ok: bool,
    }

    /// Aggregation request — share-independent public compute over already-published
    /// commitments + responses. The verifier worker runs this so the coordinator gets back
    /// a fully-verified `(aggregateCommitment, challenge, aggregateResponse)` tuple in one
    /// round-trip after collecting per-slot round1+round2 results.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AggregateRequest {
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub commitments: Vec<RegistrationCommitmentInput>,
        pub responses: Vec<RegistrationResponseInput>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AggregateResult {
        pub aggregate_commitment: String,
        pub challenge: String,
        pub aggregate_response: String,
        pub proof_hash: String,
    }

    /// On-disk shape for the per-session nonce file. Mode 0o600. Lives at
    /// `state_dir/mpc-sessions/<request_id>__<session_id>/ca_registration_v2_nonce.json`.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct NonceFileLayout {
        pub session_id: String,
        pub request_id: String,
        pub self_slot: usize,
        pub player_id: usize,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub vault_ek_hex: String,
        pub ca_dkg_transcript_hash: String,
        pub dkg_epoch: String,
        /// Canonical 32-byte little-endian Scalar, hex. Sensitive.
        pub nonce_hex: String,
        /// 32-byte compressed Ristretto point, hex. Public.
        pub commitment_hex: String,
        pub nonce_id: String,
        pub created_at_unix_ms: u128,
    }

    fn session_dir(state_dir: &Path, request_id: &str, session_id: &str) -> PathBuf {
        state_dir
            .join("mpc-sessions")
            .join(format!("{}__{}", request_id, session_id))
    }

    fn nonce_file_path(state_dir: &Path, request_id: &str, session_id: &str) -> PathBuf {
        session_dir(state_dir, request_id, session_id).join(NONCE_FILE_NAME)
    }

    /// RAII guard: on drop, scrub + unlink the nonce file. Used by `run_round2` so even on
    /// panic the plaintext `r_i` never lingers.
    struct NonceFileGuard {
        path: PathBuf,
        active: bool,
    }

    impl NonceFileGuard {
        fn new(path: PathBuf) -> Self {
            Self { path, active: true }
        }
    }

    impl Drop for NonceFileGuard {
        fn drop(&mut self) {
            if !self.active || !self.path.exists() {
                return;
            }
            // Best-effort scrub before unlink. Same pattern as
            // `vault_ek_derivation_v2::drop_round0_file`.
            if let Ok(metadata) = fs::metadata(&self.path) {
                let len = metadata.len() as usize;
                let zeros = vec![0u8; len];
                if let Ok(mut file) = fs::OpenOptions::new()
                    .write(true)
                    .truncate(false)
                    .open(&self.path)
                {
                    use std::io::Write as _;
                    let _ = file.write_all(&zeros);
                    let _ = file.sync_all();
                }
            }
            let _ = fs::remove_file(&self.path);
            let parent = self.path.parent().map(Path::to_path_buf);
            if let Some(parent) = parent {
                // Best-effort directory cleanup (only succeeds if empty).
                let _ = fs::remove_dir(parent);
            }
        }
    }

    /// Round 1 — generate nonce, commit, persist. Idempotency: if a nonce file already exists
    /// for this (request_id, session_id) AND the persisted (vault_ek, dkg_epoch, slot,
    /// player_id) match the request, return the same nonce + commitment instead of generating
    /// a new one. This protects against commit-reveal violations under coordinator retries
    /// (the broadcast set of T_i values must be fixed before challenge generation).
    pub fn create_registration_nonce_commitment_v2(
        state_dir: &Path,
        req: &Round1Request,
    ) -> WorkerResult<Round1Result> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        let ca_transcript = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let vault_ek_hex = normalize_hex(&req.vault_ek, 32)?;
        let sender = normalize_hex(&req.sender_address, 32)?;
        let asset = normalize_hex(&req.asset_type, 32)?;

        let vault_ek_point = decompress_hex(&vault_ek_hex)?;

        // Cross-check: V2 share file must exist and bind to this request.
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.self_slot
            )));
        }
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.dkg_epoch
            )));
        }
        if share.transcript_hash.to_lowercase() != ca_transcript {
            return Err(WorkerError::InvalidRequest(
                "ca_dkg_transcript_hash does not match local share".to_string(),
            ));
        }

        let file_path = nonce_file_path(state_dir, &req.request_id, &req.session_id);
        if file_path.exists() {
            // Idempotency replay.
            let raw = fs::read(&file_path).map_err(|err| {
                WorkerError::Crypto(format!("read existing nonce file: {err}"))
            })?;
            let layout: NonceFileLayout = serde_json::from_slice(&raw)
                .map_err(|err| WorkerError::Crypto(format!("parse nonce file: {err}")))?;
            if layout.session_id != req.session_id || layout.request_id != req.request_id {
                return Err(WorkerError::InvalidDkgState(
                    "ca_registration_v2_session_collision".to_string(),
                ));
            }
            if layout.self_slot != req.self_slot || layout.player_id != req.player_id {
                return Err(WorkerError::InvalidDkgState(
                    "ca_registration_v2_self_slot_mismatch".to_string(),
                ));
            }
            if normalize_hex(&layout.vault_ek_hex, 32)? != vault_ek_hex {
                // Forbid commit-reveal under a different vault_ek — that's a different sigma
                // statement and we MUST NOT silently reuse the persisted nonce.
                return Err(WorkerError::InvalidDkgState(
                    "ca_registration_v2_vault_ek_mismatch".to_string(),
                ));
            }
            let commitment_hex = normalize_hex(&layout.commitment_hex, 32)?;
            let commitment_hash =
                sha256_hex(hex_decode(&commitment_hex)?.as_slice());
            let worker_transcript_hash = round1_worker_transcript_hash(
                &req.session_id,
                &req.request_id,
                &req.dkg_epoch,
                &ca_transcript,
                &roster_hash,
                &sorted,
                req.self_slot,
                req.player_id,
                &vault_ek_hex,
                &sender,
                &asset,
                req.chain_id,
                &commitment_hex,
                &layout.nonce_id,
            );
            return Ok(Round1Result {
                slot: req.self_slot,
                commitment_hex,
                commitment_hash,
                nonce_id: layout.nonce_id,
                worker_transcript_hash,
            });
        }

        // Fresh round1. Draw r_i, compute T_i = vault_ek * r_i, persist with 0o600.
        let mut r_i = random_scalar();
        let commitment_point = vault_ek_point * r_i;
        let commitment_hex = compressed_hex(&commitment_point);
        let commitment_hash = sha256_hex(hex_decode(&commitment_hex)?.as_slice());
        let nonce_id = nonce_id_hash(
            &req.request_id,
            &req.session_id,
            req.self_slot,
            &commitment_hash,
        );
        let r_i_hex = scalar_hex(&r_i);
        let layout = NonceFileLayout {
            session_id: req.session_id.clone(),
            request_id: req.request_id.clone(),
            self_slot: req.self_slot,
            player_id: req.player_id,
            roster_hash: roster_hash.clone(),
            selected_slots: sorted.clone(),
            vault_ek_hex: vault_ek_hex.clone(),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            nonce_hex: r_i_hex,
            commitment_hex: commitment_hex.clone(),
            nonce_id: nonce_id.clone(),
            created_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        };
        let sdir = session_dir(state_dir, &req.request_id, &req.session_id);
        fs::create_dir_all(&sdir)
            .map_err(|err| WorkerError::Crypto(format!("create session_dir: {err}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o700);
            if let Err(err) = fs::set_permissions(&sdir, perm) {
                return Err(WorkerError::Crypto(format!(
                    "chmod 700 {}: {err}",
                    sdir.display()
                )));
            }
        }
        let bytes = serde_json::to_vec(&layout)
            .map_err(|err| WorkerError::Crypto(format!("encode nonce file: {err}")))?;
        write_secret_file(&file_path, &bytes)?;
        r_i.zeroize();

        let worker_transcript_hash = round1_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &ca_transcript,
            &roster_hash,
            &sorted,
            req.self_slot,
            req.player_id,
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            &commitment_hex,
            &nonce_id,
        );

        Ok(Round1Result {
            slot: req.self_slot,
            commitment_hex,
            commitment_hash,
            nonce_id,
            worker_transcript_hash,
        })
    }

    /// Round 2 — compute partial response. Loads the persisted nonce file (which carries
    /// `r_i` + the round1 bindings); reloads the V2 share to fetch `dk_share_i`; computes
    /// `response_i = r_i + challenge * dk_share_i`. RAII removes the nonce file on every
    /// return path. dk_share_i and r_i are zeroized after use.
    pub fn create_registration_partial_response_v2(
        state_dir: &Path,
        req: &Round2Request,
    ) -> WorkerResult<Round2Result> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.nonce_id.is_empty() || req.nonce_id.len() != 64
            || !req.nonce_id.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(WorkerError::InvalidRequest(
                "nonce_id must be 64 hex chars (sha256)".to_string(),
            ));
        }
        let ca_transcript = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let _roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let challenge = scalar_from_hex(&req.challenge)?;

        // Load and validate the V2 share before touching the nonce file. If the share is
        // wrong/missing we return without disturbing the persisted nonce.
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.self_slot
            )));
        }
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.dkg_epoch
            )));
        }
        if share.transcript_hash.to_lowercase() != ca_transcript {
            return Err(WorkerError::InvalidRequest(
                "ca_dkg_transcript_hash does not match local share".to_string(),
            ));
        }

        let path = nonce_file_path(state_dir, &req.request_id, &req.session_id);
        if !path.exists() {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_nonce_file_missing".to_string(),
            ));
        }
        // Codex P1 #1 (nonce-reuse → dk_share recovery attack): atomic single-use of the
        // nonce file. Two concurrent /round2 requests with the same nonceId but DIFFERENT
        // challenges could both read r_i before either deleted the file. Computing
        //   s1 = r_i + c1*dk_share
        //   s2 = r_i + c2*dk_share
        // lets the attacker recover dk_share = (s1 - s2)*(c1 - c2)^-1. Five such races on
        // five slots reconstruct dk and break the vault.
        //
        // Fix: `std::fs::rename` is atomic on POSIX within the same filesystem. We rename
        // the nonce file to a unique `*.consuming-<random>` path BEFORE reading it; only
        // ONE concurrent caller can win the rename. The loser sees ENOENT and is rejected
        // with `ca_registration_v2_nonce_already_consumed`. The random suffix guarantees
        // that even if two callers race the rename itself, they land on distinct paths and
        // neither clobbers the other.
        let consuming_suffix: [u8; 16] = {
            let mut buf = [0u8; 16];
            use rand::rngs::OsRng;
            use rand::RngCore as _;
            OsRng.fill_bytes(&mut buf);
            buf
        };
        let consuming_name = {
            let base = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(NONCE_FILE_NAME);
            let mut hex = String::with_capacity(base.len() + ".consuming-".len() + 32);
            hex.push_str(base);
            hex.push_str(".consuming-");
            for byte in consuming_suffix {
                hex.push_str(&format!("{byte:02x}"));
            }
            hex
        };
        let consuming_path = path
            .parent()
            .map(|parent| parent.join(&consuming_name))
            .unwrap_or_else(|| PathBuf::from(&consuming_name));
        match fs::rename(&path, &consuming_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Race-loser branch: another concurrent caller already renamed (and is
                // consuming) this file. Distinct error code so callers can distinguish
                // "no round1 ever ran" (file_missing above) from "lost a concurrent race"
                // (already_consumed). Both fail closed; neither reveals r_i.
                return Err(WorkerError::InvalidDkgState(
                    "ca_registration_v2_nonce_already_consumed".to_string(),
                ));
            }
            Err(err) => {
                return Err(WorkerError::InvalidDkgState(format!(
                    "ca_registration_v2_nonce_consume_failed: {err}"
                )));
            }
        }
        // Atomic single-use is now guaranteed: only this caller holds the path. Arm the
        // guard so any subsequent failure (parse error, share mismatch, etc.) still scrubs
        // and unlinks the consumed file.
        let guard = NonceFileGuard::new(consuming_path.clone());

        let raw = fs::read(&consuming_path)
            .map_err(|err| WorkerError::Crypto(format!("read nonce file: {err}")))?;
        let layout: NonceFileLayout = serde_json::from_slice(&raw)
            .map_err(|err| WorkerError::Crypto(format!("parse nonce file: {err}")))?;
        if layout.session_id != req.session_id || layout.request_id != req.request_id {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_session_mismatch".to_string(),
            ));
        }
        if layout.self_slot != req.self_slot || layout.player_id != req.player_id {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_slot_mismatch".to_string(),
            ));
        }
        if layout.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_dkg_epoch_mismatch".to_string(),
            ));
        }
        if normalize_hex(&layout.ca_dkg_transcript_hash, 32)? != ca_transcript {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_ca_dkg_transcript_mismatch".to_string(),
            ));
        }
        if layout.nonce_id != req.nonce_id {
            return Err(WorkerError::InvalidDkgState(
                "ca_registration_v2_nonce_id_mismatch".to_string(),
            ));
        }

        let mut r_i = scalar_from_hex(&layout.nonce_hex).map_err(|_| {
            WorkerError::Crypto("ca_registration_v2_nonce_file_r_i_not_canonical".to_string())
        })?;
        let mut dk_share = scalar_from_hex(&share.dk_share)?;
        let response = r_i + challenge * dk_share;
        let response_hex = scalar_hex(&response);
        // Scrub immediately after computing the public response.
        r_i.zeroize();
        dk_share.zeroize();

        let response_hash = sha256_hex(hex_decode(&response_hex)?.as_slice());
        let worker_transcript_hash = round2_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &ca_transcript,
            &sorted,
            req.self_slot,
            req.player_id,
            &req.nonce_id,
            &req.challenge,
            &response_hash,
        );

        // Successful response: the guard's Drop unlinks (scrub + remove) the nonce file. We
        // WANT this on every return path because the nonce must not survive — replay would
        // compromise dk. The guard stays armed; explicit drop here triggers cleanup before
        // returning.
        drop(guard);

        Ok(Round2Result {
            slot: req.self_slot,
            response_hex,
            response_hash,
            worker_transcript_hash,
        })
    }

    /// Local verifier — recompute the registration challenge from `(vault_ek, sender, asset,
    /// chain_id, aggregate_commitment)`, then check `vault_ek * aggregate_response ==
    /// aggregate_commitment + h * challenge`. Same equation as
    /// `ca_local::verify_registration_proof`; this is just an HTTP-exposed wrapper.
    pub fn run_verify_v2(req: &VerifyRequest) -> WorkerResult<VerifyResult> {
        verify_registration_proof(
            &req.vault_ek,
            &req.sender_address,
            &req.asset_type,
            req.chain_id,
            &req.aggregate_commitment,
            &req.aggregate_response,
        )?;
        Ok(VerifyResult { ok: true })
    }

    /// One-shot aggregator: Lagrange-aggregate commitments, derive Fiat-Shamir challenge,
    /// Lagrange-aggregate responses, then locally verify. The coordinator hits this on the
    /// verifier-slot worker AFTER collecting all 5 round1+round2 results. Pure public
    /// compute — no share file access.
    ///
    /// Fail-closed: if `verify_registration_proof(...)` fails (the public equation `vault_ek
    /// * agg_response == agg_commitment + h * challenge` doesn't hold), returns an error.
    /// The coordinator translates that into a 502 `aggregate_proof_invalid` response.
    pub fn run_aggregate_v2(req: &AggregateRequest) -> WorkerResult<AggregateResult> {
        let aggregate_commitment = aggregate_registration_commitment(&req.commitments)?;
        let challenge_scalar = registration_challenge_scalar(
            &req.vault_ek,
            &req.sender_address,
            &req.asset_type,
            req.chain_id,
            &aggregate_commitment,
        )?;
        let challenge_hex = scalar_hex(&challenge_scalar);
        let aggregate_response = aggregate_responses_v2(&req.responses)?;
        verify_registration_proof(
            &req.vault_ek,
            &req.sender_address,
            &req.asset_type,
            req.chain_id,
            &aggregate_commitment,
            &aggregate_response,
        )?;
        let proof_hash = sha256_hex(
            [
                hex_decode(&aggregate_commitment)?.as_slice(),
                hex_decode(&aggregate_response)?.as_slice(),
            ]
            .concat()
            .as_slice(),
        );
        Ok(AggregateResult {
            aggregate_commitment,
            challenge: challenge_hex,
            aggregate_response,
            proof_hash,
        })
    }

    /// Coordinator-side helpers exposed for the orchestrator: aggregate commitments via
    /// Lagrange (re-uses `ca_local::aggregate_registration_commitment`), aggregate responses
    /// via Lagrange, compute challenge. The worker NEVER calls these — only the coordinator.
    pub fn aggregate_commitments_v2(
        commitments: &[RegistrationCommitmentInput],
    ) -> WorkerResult<String> {
        aggregate_registration_commitment(commitments)
    }

    pub fn challenge_v2(
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        aggregate_commitment_hex: &str,
    ) -> WorkerResult<String> {
        Ok(scalar_hex(&registration_challenge_scalar(
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            aggregate_commitment_hex,
        )?))
    }

    /// Lagrange-aggregate responses: `sum_i λ_i(0) * response_i (mod q)` where the λ_i are the
    /// public Lagrange coefficients for the selected slot set evaluated at x=0. Same Shamir
    /// recombination as V1 `aggregate_registration_proof`.
    pub fn aggregate_responses_v2(
        responses: &[RegistrationResponseInput],
    ) -> WorkerResult<String> {
        let slots = response_slots(responses)?;
        let coeffs = lagrange_coefficients_at_zero(&slots)?;
        let mut aggregate = Scalar::ZERO;
        for (item, coeff) in responses.iter().zip(coeffs.iter()) {
            aggregate += scalar_from_hex(&item.response)? * coeff;
        }
        Ok(scalar_hex(&aggregate))
    }

    fn response_slots(items: &[RegistrationResponseInput]) -> WorkerResult<Vec<usize>> {
        if items.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {DEOPERATOR_THRESHOLD} responses, got {}",
                items.len()
            )));
        }
        let mut slots = Vec::with_capacity(items.len());
        for item in items {
            assert_slot(item.slot)?;
            if slots.contains(&item.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate response slot {}",
                    item.slot
                )));
            }
            slots.push(item.slot);
        }
        Ok(slots)
    }

    fn lagrange_coefficients_at_zero(slots: &[usize]) -> WorkerResult<Vec<Scalar>> {
        if slots.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "lagrange: expected {DEOPERATOR_THRESHOLD} slots, got {}",
                slots.len()
            )));
        }
        let xs = slots
            .iter()
            .map(|slot| {
                assert_slot(*slot)?;
                Ok::<Scalar, WorkerError>(Scalar::from((*slot as u64) + 1))
            })
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

    pub fn round1_worker_transcript_hash(
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        commitment_hex: &str,
        nonce_id: &str,
    ) -> String {
        let joined = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROUND1_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sender_address_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(asset_type_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(commitment_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(nonce_id.as_bytes());
        sha256_hex(&bytes)
    }

    pub fn round2_worker_transcript_hash(
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        nonce_id: &str,
        challenge_hex: &str,
        response_hash: &str,
    ) -> String {
        let joined = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ROUND2_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(nonce_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(challenge_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(response_hash.as_bytes());
        sha256_hex(&bytes)
    }

    /// nonce_id = sha256("EUNOMA_CA_REGISTRATION_V2_NONCE_ID" || request_id || session_id ||
    /// self_slot || commitment_hash). 64 lowercase hex chars.
    fn nonce_id_hash(
        request_id: &str,
        session_id: &str,
        self_slot: usize,
        commitment_hash: &str,
    ) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EUNOMA_CA_REGISTRATION_V2_NONCE_ID");
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(commitment_hash.as_bytes());
        sha256_hex(&bytes)
    }

    fn validate_selected_slots(slots: &[usize]) -> WorkerResult<()> {
        if slots.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "selected_slots must have {DEOPERATOR_THRESHOLD} entries, got {}",
                slots.len()
            )));
        }
        let mut seen = [false; DEOPERATOR_COUNT];
        for slot in slots {
            assert_slot(*slot)?;
            if seen[*slot] {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate selected_slots entry {slot}"
                )));
            }
            seen[*slot] = true;
        }
        Ok(())
    }

    fn sorted_unique_slots(slots: &[usize]) -> WorkerResult<Vec<usize>> {
        validate_selected_slots(slots)?;
        let mut copy = slots.to_vec();
        copy.sort_unstable();
        Ok(copy)
    }

    /// Codex M3a P2 #2: atomic write with no-clobber + byte-equality idempotency gate for
    /// the ca_registration_v2 round1 nonce file. The caller (round1) already gates this
    /// function on `path.exists() && layout matches` upstream — the no-clobber guard catches
    /// a race where two concurrent fresh round1 callers both pass the upstream existence
    /// check. Differing content (e.g. two callers each drawing a fresh r_i) fails closed
    /// with `InvalidDkgState("ca_registration_v2_nonce_file_already_exists_with_different_content")`.
    fn write_secret_file(path: &Path, contents: &[u8]) -> WorkerResult<()> {
        crate::atomic_io::write_atomic_no_clobber(path, contents, "ca_registration_v2_nonce_file")
    }

    fn compressed_hex(point: &RistrettoPoint) -> String {
        hex_encode(point.compress().as_bytes())
    }

    fn decompress_hex(hex: &str) -> WorkerResult<RistrettoPoint> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(
                "Ristretto point must be 32 bytes".to_string(),
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        CompressedRistretto(buf)
            .decompress()
            .ok_or_else(|| WorkerError::InvalidRequest("invalid Ristretto point".to_string()))
    }

    /// Same canonical-scalar gate as `vault_ek_derivation_v2::scalar_from_hex`. Reject
    /// non-canonical encodings (bytes >= q).
    fn scalar_from_hex(hex: &str) -> WorkerResult<Scalar> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "scalar must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Scalar::from_canonical_bytes(buf)
            .into_option()
            .ok_or_else(|| {
                WorkerError::InvalidRequest("scalar bytes are not canonical (>= Q)".to_string())
            })
    }

    fn scalar_hex(scalar: &Scalar) -> String {
        hex_encode(&scalar.to_bytes())
    }

    fn normalize_hex(hex: &str, expected_bytes: usize) -> WorkerResult<String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != expected_bytes {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {expected_bytes}-byte hex, got {}",
                bytes.len()
            )));
        }
        Ok(hex_encode(&bytes))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
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

// =================================================================================================
// Milestone 2 sub-milestone 2a — per-deoperator vault state share initialization.
//
// After Phase 2 (vault_ek derivation) and Milestone 1 (V2 threshold registration sigma), each of
// the 5 selected deoperators must provision a per-vault state file that pins:
//   - the Phase 2-derived `vault_ek` public point
//   - the Milestone 1 (aggregateCommitment, aggregateResponse, challenge, registrationTranscriptHash) tuple
//   - the chain-side `vault_sequence` cursor (starts at 0; bumps on each accepted deposit/withdraw)
//   - the per-worker `deposit_count_observed` cursor (starts at 0; sub-milestone 2b will bump it)
//
// No secret material — this file is mode 0o600 anyway because it sits next to the worker's CA DKG
// V2 share, but its CONTENTS contain only public points, hashes, and decimal counters. Mirrors the
// Phase 2 round0 pattern: idempotent re-call returns the same `vault_state_v2.json` bytes, fresh
// re-init under a different `(dkg_epoch, vault_ek, registration_transcript_hash)` is REJECTED
// (returns `vault_state_v2_already_initialized_with_different_inputs`) — the operator must rotate
// the DKG epoch + re-derive vault_ek + re-run Milestone 1 before re-initialising.
//
// Transcript shape — byte-identical with `deop-protocol::vault_state_v2`:
//   "EUNOMA_VAULT_STATE_V2_INIT_V1"
//   || ":" || session_id || ":" || request_id
//   || ":" || dkg_epoch
//   || ":" || ca_dkg_transcript_hash (norm lower hex)
//   || ":" || vault_ek_transcript_hash (Phase 2)
//   || ":" || registration_transcript_hash (Milestone 1)
//   || ":" || roster_hash (norm lower hex)
//   || ":" || joined(sorted_selected_slots, ",")
//   || ":" || self_slot || ":" || player_id
//   || ":" || vault_ek (norm lower hex)
//   || ":" || sender_address (norm lower hex)
//   || ":" || asset_type (norm lower hex)
//   || ":" || chain_id (decimal)
//   || ":" || aggregate_commitment (norm lower hex)
//   || ":" || aggregate_response (norm lower hex)
//   || ":" || challenge (norm lower hex)
//   || ":" || vault_sequence (decimal)
//   || ":" || deposit_count_observed (decimal)
//   → sha256 → lowercase hex.
// =================================================================================================
pub mod vault_state_v2 {
    // Codex M2a P2 #1: init reads only the share's PUBLIC metadata
    // (slot/dkg_epoch/transcript_hash/...), so we use the metadata-only loader rather
    // than `load_ca_dkg_v2_share` (which deserializes + verifies dk_share/blind_share).
    // The dedicated struct excludes secret fields by serde construction — they never
    // enter this code path's memory.
    use crate::ca_dkg_v2::load_ca_dkg_v2_share_metadata;
    // Codex M2a P1: V2 production code MUST NOT import from `crate::ca_local`. The public
    // sigma verifier + Fiat-Shamir challenge live in `crate::registration_verifier`.
    //
    // Codex M2a P2 #4: import `registration_challenge` to recompute the Fiat-Shamir
    // challenge locally instead of trusting the caller-supplied value.
    use crate::registration_verifier::{registration_challenge, verify_registration_proof};
    use crate::mpc_spdz_adapter::is_safe_id;
    use crate::{assert_slot, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};

    pub(crate) const INIT_TRANSCRIPT_DOMAIN: &str = "EUNOMA_VAULT_STATE_V2_INIT_V1";
    /// Codex M3a P1 (regression fix): the coordinator's FINAL init transcript hash binds the
    /// (public inputs) + (sorted per-slot contributions) tuple. This is the byte-identical
    /// TS-side `assembleVaultStateV2InitTranscript` / `vaultStateV2InitFinalTranscriptHash`
    /// digest. ALL 5 workers + the coordinator MUST agree on this single value — it's what
    /// downstream MPCCA withdraw rounds gate on.
    pub(crate) const FINAL_TRANSCRIPT_DOMAIN: &str = "EUNOMA_VAULT_STATE_V2_FINAL_V1";
    /// Codex M3a P1 v4 (canonical vault_state_hash): replaces the pre-v4 definition of
    /// `vault_state_hash = sha256(on-disk file bytes)`. The pre-v4 value MUTATED on finalize
    /// (which sets `init_transcript_hash`) and on observe-deposit (which bumps
    /// `deposit_count_observed`). A coordinator re-running init across a partial-finalize
    /// boundary would receive DIFFERENT `vault_state_hash` values from finalized vs not-yet-
    /// finalized slots; the recomputed FINAL_V1 transcript hash would diverge from the
    /// original; already-finalized workers would then reject the new final hash via
    /// `vault_state_v2_finalize_already_pinned_with_different_value`. Recovery from a
    /// partial finalize was IMPOSSIBLE.
    ///
    /// v4 fix: define `vault_state_hash` as a hash over a CANONICAL SUBSET of immutable
    /// fields — everything that's frozen at init time + `worker_transcript_hash` (which is
    /// itself frozen at init). EXCLUDED fields: `init_transcript_hash`, `deposit_count_observed`,
    /// `vault_sequence`, `created_at_unix_ms` (immutable but not part of the binding —
    /// timing skew across worker boots shouldn't perturb the hash).
    ///
    /// The on-disk file STILL contains every field for state-machine + audit, but the HASH
    /// returned to the coordinator is now byte-stable across init → finalize → observe-deposit
    /// → withdraw lifecycles. This is the load-bearing fix for partial-finalize recovery.
    pub(crate) const VAULT_STATE_HASH_DOMAIN: &str = "EUNOMA_VAULT_STATE_V2_STATE_HASH_V1";
    pub(crate) const VAULT_STATE_FILE_NAME: &str = "vault_state_v2.json";

    /// Request shape for `/worker/v2/vault_state/init`. Each of the 5 selected workers receives
    /// the same payload (modulo `self_slot` / `player_id`). The coordinator has already
    /// (a) verified Phase 2 + Milestone 1 provenance against persisted transcripts, and
    /// (b) recomputed `vaultEkTranscriptHash` and `registrationTranscriptHash` from those
    /// artifacts. The worker re-binds them into its on-disk vault-state file so any future
    /// MPCCA round can cross-check.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InitRequest {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub ca_dkg_transcript_hash: String,
        /// Phase 2 vault_ek derivation transcript hash. Bound into the worker transcript so any
        /// MPCCA derivation that consumes this state can verify it descends from a real Phase 2
        /// run by the coordinator.
        pub vault_ek_transcript_hash: String,
        /// Milestone 1 CA registration transcript hash. Likewise bound.
        pub registration_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        /// Phase 2-derived public point H * dk^-1. 32-byte hex.
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        /// Milestone 1 aggregate sigma commitment (32-byte hex).
        pub aggregate_commitment: String,
        /// Milestone 1 aggregate sigma response (32-byte hex scalar).
        pub aggregate_response: String,
        /// Milestone 1 Fiat-Shamir challenge (32-byte hex scalar).
        pub challenge: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InitResult {
        pub slot: usize,
        pub player_id: usize,
        pub vault_state_path: String,
        pub vault_state_hash: String,
        pub worker_transcript_hash: String,
        pub vault_sequence: u64,
        pub deposit_count_observed: u64,
        pub created_at_unix_ms: u128,
        /// Codex M3a P1 v5 (partial-finalize recovery — `initialized` mutability removal):
        /// monotonic "the vault state file has been written" flag. ALWAYS `true` on every
        /// successful response — both on a fresh init (file just materialised) AND on an
        /// idempotent replay (file already exists). Once a vault is initialized, it stays
        /// initialized; this flag never flips back to `false`.
        ///
        /// Pre-v5 semantic was "did THIS call write a new file" (true on fresh init, false
        /// on replay). That made the coordinator's per-slot contribution non-stable across
        /// retries: a partial-finalize recovery would re-init all 5 workers (file exists for
        /// every worker → all 5 return initialized=false) and recompute a final_transcript_hash
        /// that differed from the original (every worker had returned initialized=true on
        /// the first round). Already-finalized workers then rejected the new final hash as
        /// `vault_state_v2_finalize_already_pinned_with_different_value`, leaving the cluster
        /// permanently wedged.
        ///
        /// v5 makes `initialized` a property of the VAULT (has the file been written?) rather
        /// than the CALL (did this invocation do the writing?). Init replays therefore return
        /// byte-identical responses to the first init for the same vault, the
        /// final_transcript_hash is stable across retries, and partial-finalize recovery
        /// genuinely works without any coordinator-side normalisation.
        pub initialized: bool,
    }

    /// On-disk shape for the per-worker vault-state file. Mode 0o600 (no secret material, but
    /// the directory layout mirrors `ca_dkg_share_v2.json` so we keep the same posture).
    /// Persisted at `state_dir/vault_state_v2.json`.
    ///
    /// Codex M3a P1 v3 (partial-finalize recovery): two distinct hash fields encode the
    /// two-phase init/finalize lifecycle:
    ///   - `worker_transcript_hash` — FROZEN at init time, NEVER overwritten. The per-slot
    ///     `EUNOMA_VAULT_STATE_V2_INIT_V1` digest the worker returns from `/v2/vault_state/init`.
    ///     Idempotent replays of init return this exact value byte-for-byte regardless of how
    ///     many finalize / observe-deposit calls landed in between. This is what the coordinator
    ///     uses to build the FINAL_V1 transcript; it's also what `finalize_vault_state_v2`
    ///     cross-checks the supplied `per_slot_contributions[self_slot]` against.
    ///   - `init_transcript_hash: Option<String>` — set ONLY by `finalize_vault_state_v2` once
    ///     the FINAL_V1 transcript is canonical. `None` means "init ran but finalize hasn't
    ///     landed yet" — the legitimate partial-finalize recovery state. MPCCA withdraw rounds
    ///     read this field; `None` surfaces `InvalidDkgState("vault_state_v2_not_finalized")`
    ///     distinct from a mismatch.
    ///
    /// Pre-v3 layout (single `init_transcript_hash` field doing double duty as per-slot init
    /// hash + finalized canonical hash) is rejected on load with
    /// `vault_state_v2_legacy_layout_requires_reinit`. Operators upgrading must wipe + re-init.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub struct VaultStateFile {
        pub scheme: String,
        pub slot: usize,
        pub player_id: usize,
        pub dkg_epoch: String,
        pub ca_dkg_transcript_hash: String,
        pub vault_ek_transcript_hash: String,
        pub registration_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub vault_ek_hex: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub aggregate_commitment: String,
        pub aggregate_response: String,
        pub challenge: String,
        /// Mirrors the on-chain `BridgeVault.vault_sequence`. Starts at 0; bumps on each accepted
        /// withdraw.
        pub vault_sequence: u64,
        /// Per-worker cursor — number of confirmed deposit events this worker has observed for
        /// this vault. Starts at 0; sub-milestone 2b will increment.
        pub deposit_count_observed: u64,
        pub created_at_unix_ms: u128,
        /// Codex M3a P1 v3: FROZEN per-slot init transcript hash. Computed and persisted by
        /// `init_vault_state_v2`; NEVER overwritten by finalize or observe_deposit. Idempotent
        /// init replays return this exact value, which is critical for partial-finalize
        /// recovery: a coordinator re-running init after a partial finalize MUST receive the
        /// SAME per-slot hash on every retry so it can rebuild the canonical FINAL_V1
        /// transcript byte-for-byte.
        pub worker_transcript_hash: String,
        /// Codex M3a P1 v3: canonical FINAL_V1 transcript hash, set ONLY by
        /// `finalize_vault_state_v2`. `None` between init and finalize. The MPCCA withdraw
        /// rounds read this; `None` surfaces a distinct error code so a coordinator can
        /// re-finalize the slots that didn't acknowledge a previous finalize round.
        ///
        /// Idempotent finalize replay: persisted value equals the request's claim → return OK
        /// with `finalized=false`. Persisted value differs from the claim → fail closed with
        /// `vault_state_v2_finalize_already_pinned_with_different_value`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub init_transcript_hash: Option<String>,
        /// M11: the chain tx hash that the `/v2/vault/resync` handler last verified +
        /// bound when advancing `vault_sequence`. `None` until the first resync (or for
        /// legacy/pre-M11 files). Used for idempotent-replay detection (`existing ==
        /// expected_next AND last_bound_tx_hash == req.tx_hash`) and the legacy-state
        /// guard. Excluded from `compute_vault_state_hash_canonical` (mutable metadata).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_bound_tx_hash: Option<String>,
        /// M11: unix-ms timestamp of the last resync write. Observability only;
        /// excluded from the canonical hash.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_resync_at: Option<u64>,
    }

    fn vault_state_file_path(state_dir: &Path) -> PathBuf {
        state_dir.join(VAULT_STATE_FILE_NAME)
    }

    /// Compute the per-worker init transcript hash. Byte-identical with the TS reconstructor in
    /// `deop-protocol::vault_state_v2::vaultStateV2InitWorkerTranscriptHash`.
    pub fn init_worker_transcript_hash(
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        aggregate_commitment_hex: &str,
        aggregate_response_hex: &str,
        challenge_hex: &str,
        vault_sequence: u64,
        deposit_count_observed: u64,
    ) -> String {
        let joined = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INIT_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(registration_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sender_address_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(asset_type_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(aggregate_commitment_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(aggregate_response_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(challenge_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_sequence.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(deposit_count_observed.to_string().as_bytes());
        sha256_hex(&bytes)
    }

    /// Codex M3a P1 (regression fix): per-slot init contribution that participates in the
    /// coordinator's FINAL transcript hash. Byte-identical with the TS
    /// `VaultStateV2InitContribution` shape in deop-protocol.
    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizeContribution {
        pub slot: usize,
        pub vault_state_hash: String,
        pub worker_transcript_hash: String,
        pub vault_sequence: u64,
        pub deposit_count_observed: u64,
        pub initialized: bool,
    }

    /// Codex M3a P1 (regression fix): compute the coordinator's FINAL init transcript hash.
    /// Byte-identical with the TS `vaultStateV2InitFinalTranscriptHash` helper in
    /// `deop-protocol::vault_state_v2`. The single canonical value every worker MUST persist
    /// as `init_transcript_hash` so the downstream MPCCA withdraw cross-check matches the
    /// coordinator's request body.
    ///
    /// `sorted_contributions` MUST already be sorted by `slot` ascending — the caller
    /// (finalize_vault_state_v2) sorts before invoking this helper.
    pub fn final_transcript_hash(
        dkg_epoch: &str,
        ca_dkg_transcript_hash: &str,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        aggregate_commitment_hex: &str,
        aggregate_response_hex: &str,
        challenge_hex: &str,
        sorted_contributions: &[FinalizeContribution],
    ) -> String {
        let joined = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FINAL_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_dkg_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(registration_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sender_address_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(asset_type_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(aggregate_commitment_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(aggregate_response_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(challenge_hex.as_bytes());
        for c in sorted_contributions {
            bytes.push(b':');
            bytes.extend_from_slice(c.slot.to_string().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(c.vault_state_hash.as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(c.worker_transcript_hash.as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(c.vault_sequence.to_string().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(c.deposit_count_observed.to_string().as_bytes());
            bytes.push(b'|');
            bytes.extend_from_slice(if c.initialized { b"1" } else { b"0" });
        }
        sha256_hex(&bytes)
    }

    /// Codex M3a P1 v4 (canonical vault_state_hash): hash a CANONICAL SUBSET of the on-disk
    /// `VaultStateFile` consisting ONLY of fields that are immutable across the init/finalize/
    /// observe-deposit lifecycle. The output is what `init_vault_state_v2`,
    /// `finalize_vault_state_v2`, and `observe_deposit_v2` return as `vault_state_hash` — and
    /// what the coordinator pins into per-slot finalize contributions when rebuilding the
    /// FINAL_V1 transcript.
    ///
    /// EXCLUDED fields (mutate across lifecycle):
    ///   - `init_transcript_hash` (mutated by finalize)
    ///   - `deposit_count_observed` (mutated by observe-deposit)
    ///   - `vault_sequence` (mutated by withdraw, future M3b/M4)
    ///   - `created_at_unix_ms` (immutable, but a per-boot timestamp shouldn't bind into a
    ///     hash that must be reproducible from public state)
    ///
    /// INCLUDED fields (all frozen at init time):
    ///   - scheme, slot, player_id
    ///   - dkg_epoch
    ///   - ca_dkg_transcript_hash, vault_ek_transcript_hash, registration_transcript_hash,
    ///     roster_hash
    ///   - selected_slots (sorted at write time)
    ///   - vault_ek_hex, sender_address, asset_type, chain_id
    ///   - aggregate_commitment, aggregate_response, challenge
    ///   - worker_transcript_hash (frozen at init by `init_worker_transcript_hash` — same
    ///     value across init replays regardless of finalize state)
    ///
    /// Domain-separated by `VAULT_STATE_HASH_DOMAIN` so the output cannot be confused with
    /// `worker_transcript_hash` (`INIT_TRANSCRIPT_DOMAIN`) or the final aggregated transcript
    /// (`FINAL_TRANSCRIPT_DOMAIN`).
    ///
    /// Pre-v4 behaviour: `sha256_hex(&serde_json::to_vec_pretty(&layout))` — i.e. the SHA-256
    /// of the on-disk JSON byte buffer. That value mutated on every finalize / observe-deposit,
    /// making partial-finalize recovery impossible (codex M3a P1 v4 finding).
    pub fn compute_vault_state_hash_canonical(file: &VaultStateFile) -> String {
        let joined = file
            .selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VAULT_STATE_HASH_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.scheme.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.ca_dkg_transcript_hash.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.vault_ek_transcript_hash.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.registration_transcript_hash.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.roster_hash.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.vault_ek_hex.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.sender_address.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.asset_type.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.aggregate_commitment.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.aggregate_response.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.challenge.to_lowercase().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(file.worker_transcript_hash.to_lowercase().as_bytes());
        sha256_hex(&bytes)
    }

    /// Codex M3a P1 (regression fix): request for `/worker/v2/vault_state/init/finalize`. The
    /// coordinator computes the FINAL transcript hash by aggregating the 5 per-slot init
    /// contributions, then fans this body out to all 5 selected workers so each worker can
    /// (a) re-derive the same final hash locally and assert byte-equality with the supplied
    /// value, (b) UPDATE its persisted `vault_state_v2.json` to pin `init_transcript_hash =
    /// finalTranscriptHash`. After finalize, the worker rejects any MPCCA withdraw round body
    /// whose `vault_state_init_transcript_hash` differs from this canonical value.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizeRequest {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub ca_dkg_transcript_hash: String,
        pub vault_ek_transcript_hash: String,
        pub registration_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub aggregate_commitment: String,
        pub aggregate_response: String,
        pub challenge: String,
        /// Sorted by `slot` ascending — the worker re-sorts defensively before hashing so the
        /// order of incoming contributions doesn't affect the digest.
        pub per_slot_contributions: Vec<FinalizeContribution>,
        /// The coordinator's claimed final transcript hash. Worker re-derives the same digest
        /// from public inputs + sorted contributions and asserts byte-equality BEFORE
        /// persisting. A mismatch fails closed with
        /// `InvalidDkgState("vault_state_v2_finalize_hash_mismatch")`.
        pub final_transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizeResult {
        pub slot: usize,
        pub player_id: usize,
        pub vault_state_path: String,
        /// Sha256 of the post-finalize `vault_state_v2.json` byte buffer. Coordinator can pin
        /// this in its persisted artifact so an auditor can verify the post-finalize file
        /// matches.
        pub vault_state_hash: String,
        /// The pinned `init_transcript_hash` value — byte-equal to the request's
        /// `final_transcript_hash`. Coordinator asserts byte-equality with its own computed
        /// final hash as defense in depth (catches a worker that returns a tampered value).
        pub init_transcript_hash: String,
        /// `true` when this call materialised a change; `false` on idempotent replay (the
        /// persisted `init_transcript_hash` already equalled the request's value).
        pub finalized: bool,
    }

    /// Worker entrypoint for `/worker/v2/vault_state/init`. Validates the (Phase 2, Milestone 1,
    /// CA DKG V2 share) bindings, then writes `vault_state_v2.json` atomically with mode 0o600.
    /// Idempotent: a subsequent call with the SAME `(dkg_epoch, vault_ek, vault_ek_transcript_hash,
    /// registration_transcript_hash, sender_address, asset_type, chain_id, aggregate_commitment,
    /// aggregate_response, challenge)` returns the same response (Codex M3a P1 v5: byte-identical
    /// to the first call, including `initialized: true` — the file IS initialized); a
    /// call with ANY of these changed is rejected `vault_state_v2_already_initialized_with_different_inputs`
    /// — operator must rotate epoch + re-derive.
    ///
    /// Codex M3a P1 v5 (partial-finalize recovery — `initialized` mutability removal):
    /// the response is now byte-stable across init replays for the same vault, regardless of
    /// finalize state. `initialized` is monotonic ("the vault state file has been written");
    /// `vault_state_hash` is computed via `compute_vault_state_hash_canonical` over the
    /// immutable field subset; `worker_transcript_hash` is frozen at init time and read back
    /// from disk on replay; `vault_sequence` and `deposit_count_observed` are read back from
    /// disk and only mutate through their own dedicated endpoints (withdraw / observe-deposit).
    /// The ONLY field that drifts on replay is `created_at_unix_ms` — which is NOT part of
    /// `perSlotContributions` and therefore not bound into the coordinator's
    /// `final_transcript_hash`. See server.ts:2041 for the contribution mapping.
    pub fn init_vault_state_v2(state_dir: &Path, req: &InitRequest) -> WorkerResult<InitResult> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.dkg_epoch.is_empty() || !req.dkg_epoch.chars().all(|c| c.is_ascii_digit()) {
            return Err(WorkerError::InvalidRequest(
                "dkg_epoch must be a non-empty decimal string".to_string(),
            ));
        }

        let ca_transcript = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let vault_ek_transcript = normalize_hex(&req.vault_ek_transcript_hash, 32)?;
        let registration_transcript = normalize_hex(&req.registration_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let vault_ek_hex = normalize_hex(&req.vault_ek, 32)?;
        let sender = normalize_hex(&req.sender_address, 32)?;
        let asset = normalize_hex(&req.asset_type, 32)?;
        let aggregate_commitment = normalize_hex(&req.aggregate_commitment, 32)?;
        let aggregate_response = normalize_hex(&req.aggregate_response, 32)?;
        let challenge = normalize_hex(&req.challenge, 32)?;

        // Cross-check: the supplied Milestone 1 sigma tuple MUST satisfy the public verify
        // equation against this vault_ek. We refuse to persist a forged tuple. This is the
        // same equation the coordinator+verifier worker already enforces, but doing it again
        // here means a node that booted from a corrupted state-dir can still detect that the
        // tuple it was handed is bogus before it commits to disk.
        verify_registration_proof(
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            &aggregate_commitment,
            &aggregate_response,
        )?;

        // Codex M2a P2 #4: recompute the Fiat-Shamir challenge LOCALLY and assert it
        // matches the supplied `req.challenge`. The supplied challenge was previously
        // persisted into vault_state_v2.json verbatim — but `verify_registration_proof`
        // recomputes the challenge INTERNALLY and takes no supplied challenge parameter,
        // so a caller could persist an arbitrary `challenge` alongside a valid
        // `(commitment, response)` tuple without anyone here noticing the mismatch. The
        // coordinator's provenance-resolved transcript guarantees this in stateRoot mode,
        // but inline mode (no stateRoot) accepts the challenge from the request body
        // directly. A future replay/2b path that reads vault_state_v2.json and relies on
        // the persisted `challenge` field could be misled.
        //
        // This makes the worker an independent Fiat-Shamir verifier rather than a
        // trusting persister.
        let expected_challenge = registration_challenge(
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            &aggregate_commitment,
        )?;
        if expected_challenge.to_lowercase() != challenge.to_lowercase() {
            return Err(WorkerError::InvalidRequest(
                "challenge_mismatch".to_string(),
            ));
        }

        // Cross-check: V2 share must exist and bind to (dkg_epoch, slot, ca_dkg_transcript_hash).
        // Codex M2a P2 #1: We use `load_ca_dkg_v2_share_metadata`, which deserializes into a
        // struct that does NOT include `dk_share` / `blind_share`, so no secret material is
        // pulled into this code path's memory.
        let share = load_ca_dkg_v2_share_metadata(state_dir)?;
        if share.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.self_slot
            )));
        }
        if share.dkg_epoch != req.dkg_epoch {
            return Err(WorkerError::InvalidRequest(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.dkg_epoch
            )));
        }
        if share.transcript_hash.to_lowercase() != ca_transcript {
            return Err(WorkerError::InvalidRequest(
                "ca_dkg_transcript_hash does not match local share".to_string(),
            ));
        }

        let file_path = vault_state_file_path(state_dir);
        if file_path.exists() {
            // Idempotency replay: every field bound into the transcript must match. Any
            // mismatch → `vault_state_v2_already_initialized_with_different_inputs`. We reject
            // even cursor-bump attempts via this endpoint: 2b will have its own dedicated
            // endpoint with its own cursor-monotonicity check.
            //
            // Codex M3a P1: `load_vault_state_v2` auto-migrates a missing `init_transcript_hash`
            // here so old files written before this field landed get the value backfilled. The
            // re-init path runs through this branch so the migrated `Some(_)` is available
            // when we return.
            let existing = load_vault_state_v2(state_dir)?.ok_or_else(|| {
                WorkerError::Crypto(
                    "vault_state_v2 file present but load returned None".to_string(),
                )
            })?;
            if existing.scheme != "vault_state_v2" {
                return Err(WorkerError::InvalidDkgState(
                    "vault_state_v2_unexpected_scheme_on_disk".to_string(),
                ));
            }
            if existing.dkg_epoch != req.dkg_epoch
                || existing.slot != req.self_slot
                || existing.player_id != req.player_id
                || normalize_hex(&existing.ca_dkg_transcript_hash, 32)? != ca_transcript
                || normalize_hex(&existing.vault_ek_transcript_hash, 32)? != vault_ek_transcript
                || normalize_hex(&existing.registration_transcript_hash, 32)? != registration_transcript
                || normalize_hex(&existing.roster_hash, 32)? != roster_hash
                || existing.selected_slots != sorted
                || normalize_hex(&existing.vault_ek_hex, 32)? != vault_ek_hex
                || normalize_hex(&existing.sender_address, 32)? != sender
                || normalize_hex(&existing.asset_type, 32)? != asset
                || existing.chain_id != req.chain_id
                || normalize_hex(&existing.aggregate_commitment, 32)? != aggregate_commitment
                || normalize_hex(&existing.aggregate_response, 32)? != aggregate_response
                || normalize_hex(&existing.challenge, 32)? != challenge
            {
                return Err(WorkerError::InvalidDkgState(
                    "vault_state_v2_already_initialized_with_different_inputs".to_string(),
                ));
            }
            // Codex M3a P1 v4 (canonical vault_state_hash): hash the immutable subset of
            // `existing`, NOT the raw file bytes. Pre-v4, this hashed the on-disk JSON buffer
            // — which mutated whenever `finalize_vault_state_v2` set `init_transcript_hash`
            // or `observe_deposit_v2` bumped `deposit_count_observed`. A coordinator re-running
            // init after a partial finalize would receive DIFFERENT vault_state_hash values
            // from finalized vs not-yet-finalized slots, so the recomputed FINAL_V1 transcript
            // would diverge from the original and already-finalized workers would reject the
            // retry. With v4 the value is byte-stable across the full init/finalize/observe
            // lifecycle, so partial-finalize recovery is now genuinely retryable.
            let vault_state_hash = compute_vault_state_hash_canonical(&existing);
            // Codex M3a P1 v3 (partial-finalize recovery): return the FROZEN per-slot
            // `worker_transcript_hash` from disk. This value is set at init time and NEVER
            // overwritten — not by finalize, not by observe_deposit. A coordinator re-running
            // init after a partial finalize MUST receive the same per-slot hash on every retry,
            // so it can rebuild the canonical FINAL_V1 transcript byte-for-byte and resume
            // finalize on the slots that didn't acknowledge a previous round.
            //
            // Legacy v2 files (pre-v3 layout — `worker_transcript_hash` field absent on disk)
            // are rejected by `load_vault_state_v2` with `vault_state_v2_legacy_layout_requires_reinit`.
            // Codex M3a P1 v5: `initialized` is a monotonic VAULT-level property — "the
            // vault state file has been written". Once true, stays true. An idempotent replay
            // returns `true` here (the file IS initialized) so the coordinator's per-slot
            // contribution is byte-stable across init replays, enabling partial-finalize
            // recovery without any test-side or coordinator-side normalisation.
            return Ok(InitResult {
                slot: req.self_slot,
                player_id: req.player_id,
                vault_state_path: file_path.display().to_string(),
                vault_state_hash,
                worker_transcript_hash: existing.worker_transcript_hash.clone(),
                vault_sequence: existing.vault_sequence,
                deposit_count_observed: existing.deposit_count_observed,
                created_at_unix_ms: existing.created_at_unix_ms,
                initialized: true,
            });
        }

        // Fresh init.
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // Codex M3a P1 v3 (partial-finalize recovery): compute and FREEZE the per-slot init
        // transcript hash. This goes into `worker_transcript_hash` — a separate field from
        // `init_transcript_hash`. The `init_transcript_hash` (canonical FINAL_V1) is set later
        // by `finalize_vault_state_v2`; until then it stays `None`. This separation is the
        // load-bearing fix for the partial-finalize recovery story: a coordinator re-running
        // init after a partial finalize must receive the SAME per-slot hash on every retry,
        // regardless of whether some slots already finalized.
        let worker_transcript_hash = init_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &ca_transcript,
            &vault_ek_transcript,
            &registration_transcript,
            &roster_hash,
            &sorted,
            req.self_slot,
            req.player_id,
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            &aggregate_commitment,
            &aggregate_response,
            &challenge,
            0,
            0,
        );
        let layout = VaultStateFile {
            scheme: "vault_state_v2".to_string(),
            slot: req.self_slot,
            player_id: req.player_id,
            dkg_epoch: req.dkg_epoch.clone(),
            ca_dkg_transcript_hash: ca_transcript.clone(),
            vault_ek_transcript_hash: vault_ek_transcript.clone(),
            registration_transcript_hash: registration_transcript.clone(),
            roster_hash: roster_hash.clone(),
            selected_slots: sorted.clone(),
            vault_ek_hex: vault_ek_hex.clone(),
            sender_address: sender.clone(),
            asset_type: asset.clone(),
            chain_id: req.chain_id,
            aggregate_commitment: aggregate_commitment.clone(),
            aggregate_response: aggregate_response.clone(),
            challenge: challenge.clone(),
            vault_sequence: 0,
            deposit_count_observed: 0,
            created_at_unix_ms: created_at,
            // Frozen at init time; never overwritten downstream.
            worker_transcript_hash: worker_transcript_hash.clone(),
            // Set by finalize_vault_state_v2; None until then. The MPCCA withdraw rounds
            // reject `None` with InvalidDkgState("vault_state_v2_not_finalized") — distinct
            // from a hash mismatch — so coordinators can distinguish "needs finalize" from
            // "tampered request".
            init_transcript_hash: None,
            // M11: never resynced at init time.
            last_bound_tx_hash: None,
            last_resync_at: None,
        };
        // pretty-print so the file is human-auditable. Codex M3a P1 v4: the `vault_state_hash`
        // returned to the caller is NO LONGER the SHA-256 of the on-disk byte buffer (that
        // mutated on finalize / observe-deposit and made partial-finalize recovery impossible).
        // It's now computed via `compute_vault_state_hash_canonical` over the IMMUTABLE field
        // subset — byte-stable across the full init/finalize/observe lifecycle.
        let bytes = serde_json::to_vec_pretty(&layout)
            .map_err(|err| WorkerError::Crypto(format!("encode vault_state_v2 file: {err}")))?;
        write_secret_file(&file_path, &bytes)?;

        // Codex M3a P1 v4 (canonical vault_state_hash): compute over the IMMUTABLE field
        // subset of `layout` so init replays after finalize/observe-deposit return the same
        // value. See `compute_vault_state_hash_canonical` for the field list.
        let vault_state_hash = compute_vault_state_hash_canonical(&layout);
        Ok(InitResult {
            slot: req.self_slot,
            player_id: req.player_id,
            vault_state_path: file_path.display().to_string(),
            vault_state_hash,
            worker_transcript_hash,
            vault_sequence: 0,
            deposit_count_observed: 0,
            created_at_unix_ms: created_at,
            initialized: true,
        })
    }

    /// Codex M3a P1 (regression fix) + v3 (partial-finalize recovery): worker entrypoint for
    /// `/worker/v2/vault_state/init/finalize`.
    ///
    /// Background: pre-fix, each worker persisted its OWN per-slot `worker_transcript_hash` as
    /// `init_transcript_hash` in `vault_state_v2.json`. The coordinator then sent the FINAL
    /// aggregated init artifact transcriptHash (a DIFFERENT value, binding all 5 contributions
    /// + the FINAL_V1 domain) to every worker in MPCCA withdraw round1. The two values never
    /// matched → ALL legitimate withdraws failed closed with
    /// `vault_state_init_transcript_hash_mismatch`. This was a P1 prod regression.
    ///
    /// v2 fix (Codex M3a P1 round 1): introduced a finalize round so every worker re-derives
    /// the same final hash. Working — but had a critical recovery gap: if finalize succeeded
    /// on some slots but failed on others (network partition mid-fan-out), the finalized
    /// slots had `init_transcript_hash = finalHash`, and an init replay returned that final
    /// hash as `worker_transcript_hash` — breaking the coordinator's per-slot recomputation
    /// gate. There was NO normal recovery path.
    ///
    /// v3 fix (Codex M3a P1 round 2): separate `worker_transcript_hash` (frozen at init) from
    /// `init_transcript_hash` (set by finalize). Init replays return the FROZEN per-slot hash
    /// regardless of finalize state, so a coordinator can ALWAYS re-run init → collect
    /// per-slot hashes → recompute the FINAL_V1 transcript → re-fan-out finalize. Already-
    /// finalized slots accept the same final hash idempotently; not-yet-finalized slots
    /// finalize for the first time.
    ///
    /// What this entrypoint does:
    ///   1. Re-derives the final transcript hash locally from the supplied
    ///      `per_slot_contributions` (sorted by slot) + public inputs, using the SAME
    ///      `EUNOMA_VAULT_STATE_V2_FINAL_V1` domain and field order as the TS
    ///      `vaultStateV2InitFinalTranscriptHash` helper.
    ///   2. Asserts byte-equality between the locally-derived hash and the
    ///      `final_transcript_hash` claimed in the request body. A mismatch fails closed with
    ///      `InvalidDkgState("vault_state_v2_finalize_hash_mismatch")` — a coordinator that
    ///      lied about either the contributions or the digest cannot tamper this worker's
    ///      persisted state.
    ///   3. Cross-checks `per_slot_contributions[player_id].worker_transcript_hash` against
    ///      the worker's OWN FROZEN `existing.worker_transcript_hash` (read from disk — not
    ///      recomputed from current state, since `observe_deposit_v2` mutates the cursor and
    ///      a recomputation would diverge). A mismatch fails closed with
    ///      `vault_state_v2_finalize_self_contribution_mismatch`.
    ///   4. Sets `init_transcript_hash = Some(final_transcript_hash)` and persists the file
    ///      atomically. `worker_transcript_hash` and all other fields are preserved verbatim.
    ///   5. Re-binds the public inputs (dkg_epoch, vault_ek, etc.) against the persisted file
    ///      to refuse a finalize call against a state that was initialised for a different
    ///      vault.
    ///
    /// Idempotency: a re-finalize with the SAME `final_transcript_hash` returns `finalized=false`
    /// and leaves the file unchanged. A re-finalize with a DIFFERENT value fails closed with
    /// `vault_state_v2_finalize_already_pinned_with_different_value` so an operator cannot
    /// silently swap the canonical init binding mid-vault-lifetime.
    ///
    /// Partial-finalize recovery: the idempotent replay branch is what makes the recovery
    /// flow work. A coordinator can re-fan-out finalize to all 5 slots; the slots that
    /// already finalized return OK with `finalized=false`; the slots that didn't, finalize
    /// for the first time and return `finalized=true`. All 5 end up with the same
    /// `init_transcript_hash` and MPCCA withdraw rounds proceed.
    pub fn finalize_vault_state_v2(
        state_dir: &Path,
        req: &FinalizeRequest,
    ) -> WorkerResult<FinalizeResult> {
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.dkg_epoch.is_empty() || !req.dkg_epoch.chars().all(|c| c.is_ascii_digit()) {
            return Err(WorkerError::InvalidRequest(
                "dkg_epoch must be a non-empty decimal string".to_string(),
            ));
        }

        // Strict hex normalisation everywhere — same defense-in-depth posture as init.
        let ca_transcript = normalize_hex(&req.ca_dkg_transcript_hash, 32)?;
        let vault_ek_transcript = normalize_hex(&req.vault_ek_transcript_hash, 32)?;
        let registration_transcript = normalize_hex(&req.registration_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let vault_ek_hex = normalize_hex(&req.vault_ek, 32)?;
        let sender = normalize_hex(&req.sender_address, 32)?;
        let asset = normalize_hex(&req.asset_type, 32)?;
        let aggregate_commitment = normalize_hex(&req.aggregate_commitment, 32)?;
        let aggregate_response = normalize_hex(&req.aggregate_response, 32)?;
        let challenge = normalize_hex(&req.challenge, 32)?;
        let claimed_final = normalize_hex(&req.final_transcript_hash, 32)?;

        // Per-slot contributions: must have exactly DEOPERATOR_THRESHOLD entries; slot values
        // must equal `sorted` (no duplicates, no extras, no missing slots); hex fields
        // normalised. Sort defensively so the hash is order-independent on the wire.
        if req.per_slot_contributions.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "per_slot_contributions must have {DEOPERATOR_THRESHOLD} entries, got {}",
                req.per_slot_contributions.len()
            )));
        }
        let mut contribs: Vec<FinalizeContribution> = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for c in &req.per_slot_contributions {
            if !sorted.contains(&c.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "contribution slot {} not in selected_slots",
                    c.slot
                )));
            }
            contribs.push(FinalizeContribution {
                slot: c.slot,
                vault_state_hash: normalize_hex(&c.vault_state_hash, 32)?,
                worker_transcript_hash: normalize_hex(&c.worker_transcript_hash, 32)?,
                vault_sequence: c.vault_sequence,
                deposit_count_observed: c.deposit_count_observed,
                initialized: c.initialized,
            });
        }
        contribs.sort_by_key(|c| c.slot);
        // Reject duplicate slots: after sort, adjacent slots being equal is a duplicate.
        for window in contribs.windows(2) {
            if window[0].slot == window[1].slot {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate per_slot_contributions slot {}",
                    window[0].slot
                )));
            }
        }
        // Verify coverage: contribs slots match sorted selected slots exactly.
        for (i, slot) in sorted.iter().enumerate() {
            if contribs[i].slot != *slot {
                return Err(WorkerError::InvalidRequest(format!(
                    "per_slot_contributions slot {} at index {} does not match selected_slots[{}]={}",
                    contribs[i].slot, i, i, slot
                )));
            }
        }

        // KILLER cross-check: re-derive the final transcript hash from public inputs +
        // sorted contributions and assert byte-equality with the coordinator's claim.
        let local_final = final_transcript_hash(
            &req.dkg_epoch,
            &ca_transcript,
            &vault_ek_transcript,
            &registration_transcript,
            &roster_hash,
            &sorted,
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            &aggregate_commitment,
            &aggregate_response,
            &challenge,
            &contribs,
        );
        if local_final.to_lowercase() != claimed_final.to_lowercase() {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_finalize_hash_mismatch".to_string(),
            ));
        }

        // Load the persisted vault_state_v2.json. Missing → finalize is meaningless.
        let file_path = vault_state_file_path(state_dir);
        let existing = load_vault_state_v2(state_dir)?.ok_or_else(|| {
            WorkerError::InvalidDkgState("missing_vault_state_file".to_string())
        })?;
        // Provenance gate: refuse a finalize whose public inputs don't match the persisted
        // init bindings. This catches a coordinator that fans this finalize body to the wrong
        // worker or a state_dir initialised for a different vault.
        if existing.dkg_epoch != req.dkg_epoch
            || existing.slot != req.self_slot
            || existing.player_id != req.player_id
            || normalize_hex(&existing.ca_dkg_transcript_hash, 32)? != ca_transcript
            || normalize_hex(&existing.vault_ek_transcript_hash, 32)? != vault_ek_transcript
            || normalize_hex(&existing.registration_transcript_hash, 32)?
                != registration_transcript
            || normalize_hex(&existing.roster_hash, 32)? != roster_hash
            || existing.selected_slots != sorted
            || normalize_hex(&existing.vault_ek_hex, 32)? != vault_ek_hex
            || normalize_hex(&existing.sender_address, 32)? != sender
            || normalize_hex(&existing.asset_type, 32)? != asset
            || existing.chain_id != req.chain_id
            || normalize_hex(&existing.aggregate_commitment, 32)? != aggregate_commitment
            || normalize_hex(&existing.aggregate_response, 32)? != aggregate_response
            || normalize_hex(&existing.challenge, 32)? != challenge
        {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_finalize_provenance_mismatch".to_string(),
            ));
        }

        // Codex M3a P1 v3 (partial-finalize recovery): the self-slot contribution's
        // worker_transcript_hash MUST match the worker's OWN FROZEN value from disk. We do
        // NOT recompute the per-slot init hash from mutable state here — `observe_deposit_v2`
        // bumps `deposit_count_observed`, and a recomputation using current cursor values
        // would diverge from the value the worker returned at init time. The FROZEN field
        // captures the per-slot hash as it was at init, regardless of how many observe-
        // deposit calls landed between init and finalize.
        //
        // This is the load-bearing P2 fix: finalize replay is idempotent ACROSS observe-
        // deposit cursor bumps. Pre-v3, a finalize replay after even one observe-deposit
        // would fail closed with self_contribution_mismatch because the recomputed hash
        // differed from the original.
        let self_contrib = &contribs[req.player_id];
        if self_contrib.slot != req.self_slot {
            return Err(WorkerError::InvalidRequest(
                "self_slot_contribution_mismatch".to_string(),
            ));
        }
        let frozen_self_init = existing.worker_transcript_hash.to_lowercase();
        if self_contrib.worker_transcript_hash.to_lowercase() != frozen_self_init {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_finalize_self_contribution_mismatch".to_string(),
            ));
        }

        // Idempotency (Codex M3a P1 v3 partial-finalize recovery): the canonical state
        // machine has two terminal states for `init_transcript_hash`:
        //   - `None` (just-init, finalize hasn't landed yet) → write Some(claimed_final).
        //   - `Some(canonical)` (finalize landed at least once) → must equal the new claim.
        //     If equal → idempotent OK with `finalized=false`. If different → fail closed.
        //
        // The "different value" case CAN'T happen on a legitimate retry: a coordinator that
        // re-runs init after a partial finalize collects the SAME frozen per-slot hashes
        // from every slot, rebuilds the SAME canonical final hash, and re-fans-out finalize
        // with that value. A different claimed_final implies either operator surgery (e.g.
        // re-init under a new epoch — should have wiped this file) or coordinator tamper.
        // Both are rejected.
        match existing.init_transcript_hash.as_deref() {
            Some(persisted) if persisted.to_lowercase() == claimed_final.to_lowercase() => {
                // Idempotent replay: same canonical value. No write.
                // Codex M3a P1 v4 (canonical vault_state_hash): compute over the immutable
                // field subset rather than re-reading the file bytes. The immutable subset of
                // `existing` is unchanged between the first finalize write and this replay, so
                // the hash matches what the first finalize returned. The pre-v4 sha256(raw)
                // would also have matched here in isolation — but the broader cross-slot
                // partial-finalize recovery story required the canonical form everywhere.
                let vault_state_hash = compute_vault_state_hash_canonical(&existing);
                return Ok(FinalizeResult {
                    slot: req.self_slot,
                    player_id: req.player_id,
                    vault_state_path: file_path.display().to_string(),
                    vault_state_hash,
                    init_transcript_hash: claimed_final.to_lowercase(),
                    finalized: false,
                });
            }
            Some(_persisted) => {
                // Already-pinned with a DIFFERENT canonical value. Refuse to switch — a fresh
                // re-init (wipe the file) would be required. With the v3 layout there is no
                // ambiguity: `init_transcript_hash` ONLY ever holds the canonical FINAL_V1
                // hash, so a divergence here is a hard error.
                return Err(WorkerError::InvalidDkgState(
                    "vault_state_v2_finalize_already_pinned_with_different_value".to_string(),
                ));
            }
            None => {
                // Never finalized — write the canonical value for the first time.
            }
        }

        // Build the updated file. Only `init_transcript_hash` changes. The FROZEN
        // `worker_transcript_hash` is preserved verbatim.
        let updated = VaultStateFile {
            scheme: existing.scheme.clone(),
            slot: existing.slot,
            player_id: existing.player_id,
            dkg_epoch: existing.dkg_epoch.clone(),
            ca_dkg_transcript_hash: existing.ca_dkg_transcript_hash.clone(),
            vault_ek_transcript_hash: existing.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: existing.registration_transcript_hash.clone(),
            roster_hash: existing.roster_hash.clone(),
            selected_slots: existing.selected_slots.clone(),
            vault_ek_hex: existing.vault_ek_hex.clone(),
            sender_address: existing.sender_address.clone(),
            asset_type: existing.asset_type.clone(),
            chain_id: existing.chain_id,
            aggregate_commitment: existing.aggregate_commitment.clone(),
            aggregate_response: existing.aggregate_response.clone(),
            challenge: existing.challenge.clone(),
            vault_sequence: existing.vault_sequence,
            deposit_count_observed: existing.deposit_count_observed,
            created_at_unix_ms: existing.created_at_unix_ms,
            worker_transcript_hash: existing.worker_transcript_hash.clone(),
            init_transcript_hash: Some(claimed_final.to_lowercase()),
            // M11: finalize preserves any prior resync binding verbatim.
            last_bound_tx_hash: existing.last_bound_tx_hash.clone(),
            last_resync_at: existing.last_resync_at,
        };
        let bytes = serde_json::to_vec_pretty(&updated)
            .map_err(|err| WorkerError::Crypto(format!("encode vault_state_v2 file: {err}")))?;
        // Finalize OVERWRITES the existing file (the no-clobber primitive would reject this
        // by design). The provenance + identity gates above guarantee the new content is a
        // strict supersession that only touches `init_transcript_hash`.
        write_secret_file_replace(&file_path, &bytes)?;
        // Codex M3a P1 v4 (canonical vault_state_hash): compute over the IMMUTABLE field
        // subset of `updated`. `init_transcript_hash` is EXCLUDED from the canonical hash —
        // it just landed on this slot but other slots in the cluster may not have finalized
        // yet, and a coordinator re-running init must collect the SAME vault_state_hash from
        // every slot regardless of finalize state. See `compute_vault_state_hash_canonical`.
        let vault_state_hash = compute_vault_state_hash_canonical(&updated);
        Ok(FinalizeResult {
            slot: req.self_slot,
            player_id: req.player_id,
            vault_state_path: file_path.display().to_string(),
            vault_state_hash,
            init_transcript_hash: claimed_final.to_lowercase(),
            finalized: true,
        })
    }

    // ── M11: vault-state resync ────────────────────────────────────────────
    //
    // After a chain-confirmed `WithdrawEventV2`, the on-chain `BridgeVault.
    // vault_sequence` advances but the per-worker `vault_state_v2.json` does not
    // (no post-submit observe step existed pre-M11). The next withdraw round1
    // then trips `stale_vault_sequence`. This endpoint advances the worker's
    // persisted `vault_sequence` by re-fetching the withdraw tx, verifying the
    // emitted event binds to the trusted (package, vault) + the claimed
    // sequence, then writing the bump atomically.
    //
    // Sequence semantics (verified vs move/sources/eunoma_bridge.move): the
    // withdraw asserts `vault.vault_sequence == param` (pre-increment), bumps
    // `+= 1`, then emits `WithdrawEventV2.vault_sequence = param`. So the event
    // carries the PRE-increment value; the new chain value is `event_seq + 1`.
    // The request binds both; a fresh advance requires `existing == event_seq`
    // and moves the worker to `event_seq + 1`.
    //
    // Trust model: the node URL + bridge package/vault/asset are read from the
    // worker's env (passed in as `trusted_*`), NEVER the request body. The
    // request's package/vault/asset are cross-checked against the trusted config
    // and the event type is built from the trusted package — closing the same
    // chosen-target class as the M10-l balance-decrypt closures.

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VaultResyncRequest {
        pub dkg_epoch: String,
        pub request_id: String,
        pub tx_hash: String,
        /// Cross-checked vs trusted package; the event type is built from the
        /// trusted package, NOT this field.
        pub bridge_package: String,
        /// Cross-checked vs trusted `BRIDGE_VAULT_ADDRESS` (NOT `sender_address`).
        pub vault: String,
        /// Cross-checked vs trusted `BRIDGE_ASSET_TYPE`.
        pub asset_type: String,
        pub root: String,
        pub nullifier_hash: String,
        pub recipient_hash: String,
        pub request_hash: String,
        /// `event.data.vault_sequence` (pre-increment).
        pub event_vault_sequence: u64,
        /// MUST equal `event_vault_sequence + 1`.
        pub expected_next_sequence: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VaultResyncResponse {
        pub vault_sequence: u64,
        pub updated_at_ms: u64,
        pub idempotent: bool,
        /// true ONLY for the legacy-idempotent migration (worker already at the
        /// target sequence but `last_bound_tx_hash` was None; tx verified +
        /// backfilled without changing the sequence).
        pub legacy_backfill: bool,
    }

    /// Transport-agnostic error for the resync handler. `status_u16()` maps to
    /// the HTTP status the worker should return; `code()` is the stable machine
    /// code surfaced to the coordinator. Mirrors `BalanceDecryptError`'s split
    /// (400 / 404 / 502 / 503 / 500) without importing axum into this module.
    #[derive(Debug)]
    pub enum VaultResyncError {
        /// 400 — caller/binding fault (wrong_package, wrong_vault, wrong_asset,
        /// sequence_binding_invalid, rollback_rejected, sequence_mismatch,
        /// sequence_step_too_large, binding_conflict, binding_mismatch:<field>,
        /// event_sequence_mismatch, tx_not_successful, wrong_event,
        /// legacy_state_bound_tx_verification_failed).
        BadRequest(String),
        /// 404 — uninitialized slot (no vault_state_v2.json).
        NotFound(String),
        /// 503 — worker missing trusted bridge config at request time.
        Config(String),
        /// 502 — chain re-fetch failed (network/timeout/bad_status/bad_json/parse).
        ChainFetch(String),
        /// 500 — internal (state load / encode / write).
        Internal(String),
    }

    impl VaultResyncError {
        pub fn status_u16(&self) -> u16 {
            match self {
                VaultResyncError::BadRequest(_) => 400,
                VaultResyncError::NotFound(_) => 404,
                VaultResyncError::ChainFetch(_) => 502,
                VaultResyncError::Config(_) => 503,
                VaultResyncError::Internal(_) => 500,
            }
        }
        pub fn code(&self) -> &str {
            match self {
                VaultResyncError::BadRequest(s)
                | VaultResyncError::NotFound(s)
                | VaultResyncError::Config(s)
                | VaultResyncError::ChainFetch(s)
                | VaultResyncError::Internal(s) => s.as_str(),
            }
        }
    }

    /// Normalize an Aptos address to 64-hex lowercase (no 0x), left-padded.
    fn vault_resync_norm_addr(raw: &str) -> Option<String> {
        let s = raw
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        if s.is_empty() || s.len() > 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(format!("{:0>64}", s.to_ascii_lowercase()))
    }

    /// Lowercase + strip 0x for value comparison (no length enforcement).
    fn vault_resync_norm_hex(raw: &str) -> String {
        raw.trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase()
    }

    fn vault_resync_now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Core resync logic. `fetch_override` injects the parsed event for tests:
    /// `None` performs the real chain fetch+parse; `Some(Ok(ev))` uses `ev`;
    /// `Some(Err(e))` simulates a chain-fetch failure (→ 502).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_vault_resync_v2(
        state_dir: &Path,
        trusted_aptos_node_url: &str,
        trusted_bridge_package: &str,
        trusted_bridge_vault: &str,
        trusted_bridge_asset: &str,
        req: &VaultResyncRequest,
        fetch_override: Option<Result<crate::chain_fetch::TxWithdrawEventV2, String>>,
    ) -> Result<VaultResyncResponse, VaultResyncError> {
        use VaultResyncError as E;

        // 1. Field well-formedness + the request-internal sequence relationship.
        if req.dkg_epoch.is_empty() || req.request_id.is_empty() {
            return Err(E::BadRequest("dkg_epoch_and_request_id_required".to_string()));
        }
        if req.tx_hash.is_empty() {
            return Err(E::BadRequest("tx_hash_required".to_string()));
        }
        let expected_from_event = req
            .event_vault_sequence
            .checked_add(1)
            .ok_or_else(|| E::BadRequest("sequence_overflow".to_string()))?;
        if req.expected_next_sequence != expected_from_event {
            return Err(E::BadRequest("sequence_binding_invalid".to_string()));
        }

        // 2. Trusted-config preconditions (BEFORE any chain fetch). Never trust
        //    request-supplied identifiers; cross-check them against worker env.
        if trusted_aptos_node_url.is_empty()
            || trusted_bridge_package.is_empty()
            || trusted_bridge_vault.is_empty()
            || trusted_bridge_asset.is_empty()
        {
            return Err(E::Config("worker_missing_bridge_config".to_string()));
        }
        let want_pkg = vault_resync_norm_addr(trusted_bridge_package)
            .ok_or_else(|| E::Config("worker_bridge_package_config_invalid".to_string()))?;
        if vault_resync_norm_addr(&req.bridge_package).as_deref() != Some(want_pkg.as_str()) {
            return Err(E::BadRequest("wrong_package".to_string()));
        }
        let want_vault = vault_resync_norm_addr(trusted_bridge_vault)
            .ok_or_else(|| E::Config("worker_bridge_vault_config_invalid".to_string()))?;
        if vault_resync_norm_addr(&req.vault).as_deref() != Some(want_vault.as_str()) {
            return Err(E::BadRequest("wrong_vault".to_string()));
        }
        // Asset may be address- or struct-tag-shaped (same fallback as balance_decrypt).
        let asset_ok = match (
            vault_resync_norm_addr(trusted_bridge_asset),
            vault_resync_norm_addr(&req.asset_type),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => vault_resync_norm_hex(trusted_bridge_asset) == vault_resync_norm_hex(&req.asset_type),
        };
        if !asset_ok {
            return Err(E::BadRequest("wrong_asset".to_string()));
        }

        // 3. Load persisted vault state. Missing → uninitialized (non-quorum) slot.
        let existing = load_vault_state_v2(state_dir)
            .map_err(|e| E::Internal(format!("load_vault_state:{e:?}")))?
            .ok_or_else(|| E::NotFound("vault_state_not_found".to_string()))?;
        let existing_seq = existing.vault_sequence;

        // 4. Sequence state machine. `is_legacy_backfill` is assigned on every
        //    non-returning path below.
        let is_legacy_backfill;
        if existing_seq == req.expected_next_sequence {
            match existing.last_bound_tx_hash.as_deref() {
                Some(bound)
                    if vault_resync_norm_hex(bound) == vault_resync_norm_hex(&req.tx_hash) =>
                {
                    // Idempotent replay: same tx already bound this sequence.
                    return Ok(VaultResyncResponse {
                        vault_sequence: existing_seq,
                        updated_at_ms: vault_resync_now_ms(),
                        idempotent: true,
                        legacy_backfill: false,
                    });
                }
                Some(_other) => {
                    // A DIFFERENT tx already claims this sequence.
                    return Err(E::BadRequest("binding_conflict".to_string()));
                }
                None => {
                    // Legacy/manual state: do NOT silently accept. Verify the
                    // supplied tx (which must be the one that advanced chain to
                    // `existing_seq`) and backfill the binding, or fail closed.
                    is_legacy_backfill = true;
                }
            }
        } else if req.expected_next_sequence < existing_seq {
            return Err(E::BadRequest("rollback_rejected".to_string()));
        } else {
            // expected_next_sequence > existing_seq: fresh advance, single step,
            // worker positioned exactly at the event's pre-increment value.
            if req.expected_next_sequence != existing_seq + 1 {
                return Err(E::BadRequest("sequence_step_too_large".to_string()));
            }
            if existing_seq != req.event_vault_sequence {
                return Err(E::BadRequest("sequence_mismatch".to_string()));
            }
            is_legacy_backfill = false;
        }

        // 5. Chain re-fetch (TRUSTED node URL) + parse, or injected override.
        let event = match fetch_override {
            Some(Ok(ev)) => ev,
            Some(Err(e)) => return Err(E::ChainFetch(format!("chain_fetch_failed:{e}"))),
            None => {
                let tx_value =
                    crate::chain_fetch::fetch_tx_by_hash(trusted_aptos_node_url, &req.tx_hash)
                        .await
                        .map_err(|e| E::ChainFetch(format!("chain_fetch_failed:{e}")))?;
                crate::chain_fetch::parse_tx_withdraw_event_v2(&tx_value, trusted_bridge_package)
                    .map_err(|e| {
                        if e.contains("not found") {
                            E::BadRequest("wrong_event".to_string())
                        } else {
                            E::BadRequest(format!("event_parse_failed:{e}"))
                        }
                    })?
            }
        };

        // 6. Tx must have executed successfully.
        if !event.success {
            return Err(E::BadRequest("tx_not_successful".to_string()));
        }

        // 7. Full event binding. On the legacy path ANY failure here is the
        //    fail-closed `legacy_state_bound_tx_verification_failed`.
        let bind_err = |field: &str| -> VaultResyncError {
            if is_legacy_backfill {
                E::BadRequest("legacy_state_bound_tx_verification_failed".to_string())
            } else {
                E::BadRequest(format!("binding_mismatch:{field}"))
            }
        };
        if vault_resync_norm_hex(&event.root) != vault_resync_norm_hex(&req.root) {
            return Err(bind_err("root"));
        }
        if vault_resync_norm_hex(&event.nullifier_hash) != vault_resync_norm_hex(&req.nullifier_hash)
        {
            return Err(bind_err("nullifier_hash"));
        }
        if vault_resync_norm_hex(&event.recipient_hash) != vault_resync_norm_hex(&req.recipient_hash)
        {
            return Err(bind_err("recipient_hash"));
        }
        if vault_resync_norm_hex(&event.request_hash) != vault_resync_norm_hex(&req.request_hash) {
            return Err(bind_err("request_hash"));
        }
        if event.vault_sequence != req.event_vault_sequence {
            return Err(if is_legacy_backfill {
                E::BadRequest("legacy_state_bound_tx_verification_failed".to_string())
            } else {
                E::BadRequest("event_sequence_mismatch".to_string())
            });
        }

        // 8. Persist. Fresh advance moves to expected_next; legacy backfill keeps
        //    the sequence and only records the binding.
        let new_seq = if is_legacy_backfill {
            existing_seq
        } else {
            req.expected_next_sequence
        };
        let now = vault_resync_now_ms();
        let updated = VaultStateFile {
            vault_sequence: new_seq,
            last_bound_tx_hash: Some(vault_resync_norm_hex(&req.tx_hash)),
            last_resync_at: Some(now),
            scheme: existing.scheme.clone(),
            slot: existing.slot,
            player_id: existing.player_id,
            dkg_epoch: existing.dkg_epoch.clone(),
            ca_dkg_transcript_hash: existing.ca_dkg_transcript_hash.clone(),
            vault_ek_transcript_hash: existing.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: existing.registration_transcript_hash.clone(),
            roster_hash: existing.roster_hash.clone(),
            selected_slots: existing.selected_slots.clone(),
            vault_ek_hex: existing.vault_ek_hex.clone(),
            sender_address: existing.sender_address.clone(),
            asset_type: existing.asset_type.clone(),
            chain_id: existing.chain_id,
            aggregate_commitment: existing.aggregate_commitment.clone(),
            aggregate_response: existing.aggregate_response.clone(),
            challenge: existing.challenge.clone(),
            deposit_count_observed: existing.deposit_count_observed,
            created_at_unix_ms: existing.created_at_unix_ms,
            worker_transcript_hash: existing.worker_transcript_hash.clone(),
            init_transcript_hash: existing.init_transcript_hash.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&updated)
            .map_err(|e| E::Internal(format!("encode vault_state_v2:{e}")))?;
        let file_path = vault_state_file_path(state_dir);
        write_secret_file_replace(&file_path, &bytes)
            .map_err(|e| E::Internal(format!("write vault_state_v2:{e:?}")))?;

        Ok(VaultResyncResponse {
            vault_sequence: new_seq,
            updated_at_ms: now,
            // Legacy backfill leaves the sequence unchanged → report idempotent.
            idempotent: is_legacy_backfill,
            legacy_backfill: is_legacy_backfill,
        })
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VaultSequenceSyncRequest {
        pub dkg_epoch: String,
        pub request_id: String,
        /// Cross-checked vs trusted package. The worker reads the chain resource
        /// from trusted_bridge_package, not from this caller-supplied value.
        pub bridge_package: String,
        /// Cross-checked vs trusted `BRIDGE_VAULT_ADDRESS`.
        pub vault: String,
        /// Cross-checked vs trusted `BRIDGE_ASSET_TYPE`.
        pub asset_type: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct VaultSequenceSyncResponse {
        pub vault_sequence: u64,
        pub chain_vault_sequence: u64,
        pub previous_vault_sequence: u64,
        pub updated_at_ms: u64,
        pub idempotent: bool,
    }

    /// Generic sequence catch-up for entrypoints such as ragequit that advance
    /// VaultCoreV4.vault_sequence but do not emit the older WithdrawEventV2/V3
    /// sequence-binding fields. The worker fetches the current chain resource
    /// from its trusted Aptos node and only moves monotonically to that value.
    pub async fn run_vault_sequence_sync_v2(
        state_dir: &Path,
        trusted_aptos_node_url: &str,
        trusted_bridge_package: &str,
        trusted_bridge_vault: &str,
        trusted_bridge_asset: &str,
        req: &VaultSequenceSyncRequest,
        chain_sequence_override: Option<Result<u64, String>>,
    ) -> Result<VaultSequenceSyncResponse, VaultResyncError> {
        use VaultResyncError as E;

        if req.dkg_epoch.is_empty() || req.request_id.is_empty() {
            return Err(E::BadRequest("dkg_epoch_and_request_id_required".to_string()));
        }
        if trusted_aptos_node_url.is_empty()
            || trusted_bridge_package.is_empty()
            || trusted_bridge_vault.is_empty()
            || trusted_bridge_asset.is_empty()
        {
            return Err(E::Config("worker_missing_bridge_config".to_string()));
        }
        let want_pkg = vault_resync_norm_addr(trusted_bridge_package)
            .ok_or_else(|| E::Config("worker_bridge_package_config_invalid".to_string()))?;
        if vault_resync_norm_addr(&req.bridge_package).as_deref() != Some(want_pkg.as_str()) {
            return Err(E::BadRequest("wrong_package".to_string()));
        }
        let want_vault = vault_resync_norm_addr(trusted_bridge_vault)
            .ok_or_else(|| E::Config("worker_bridge_vault_config_invalid".to_string()))?;
        if vault_resync_norm_addr(&req.vault).as_deref() != Some(want_vault.as_str()) {
            return Err(E::BadRequest("wrong_vault".to_string()));
        }
        let asset_ok = match (
            vault_resync_norm_addr(trusted_bridge_asset),
            vault_resync_norm_addr(&req.asset_type),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => vault_resync_norm_hex(trusted_bridge_asset) == vault_resync_norm_hex(&req.asset_type),
        };
        if !asset_ok {
            return Err(E::BadRequest("wrong_asset".to_string()));
        }

        let existing = load_vault_state_v2(state_dir)
            .map_err(|e| E::Internal(format!("load_vault_state:{e:?}")))?
            .ok_or_else(|| E::NotFound("vault_state_not_found".to_string()))?;
        if existing.dkg_epoch != req.dkg_epoch {
            return Err(E::BadRequest("stale_dkg_epoch".to_string()));
        }
        let previous_seq = existing.vault_sequence;
        let chain_seq = match chain_sequence_override {
            Some(Ok(seq)) => seq,
            Some(Err(e)) => return Err(E::ChainFetch(format!("chain_fetch_failed:{e}"))),
            None => crate::chain_fetch::fetch_vault_core_sequence_from_chain(
                trusted_bridge_package,
                trusted_aptos_node_url,
            )
            .await
            .map_err(|e| E::ChainFetch(format!("chain_fetch_failed:{e}")))?,
        };
        if chain_seq < previous_seq {
            return Err(E::BadRequest("chain_sequence_behind_worker".to_string()));
        }
        let now = vault_resync_now_ms();
        if chain_seq == previous_seq {
            return Ok(VaultSequenceSyncResponse {
                vault_sequence: previous_seq,
                chain_vault_sequence: chain_seq,
                previous_vault_sequence: previous_seq,
                updated_at_ms: now,
                idempotent: true,
            });
        }

        let updated = VaultStateFile {
            vault_sequence: chain_seq,
            last_resync_at: Some(now),
            scheme: existing.scheme.clone(),
            slot: existing.slot,
            player_id: existing.player_id,
            dkg_epoch: existing.dkg_epoch.clone(),
            ca_dkg_transcript_hash: existing.ca_dkg_transcript_hash.clone(),
            vault_ek_transcript_hash: existing.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: existing.registration_transcript_hash.clone(),
            roster_hash: existing.roster_hash.clone(),
            selected_slots: existing.selected_slots.clone(),
            vault_ek_hex: existing.vault_ek_hex.clone(),
            sender_address: existing.sender_address.clone(),
            asset_type: existing.asset_type.clone(),
            chain_id: existing.chain_id,
            aggregate_commitment: existing.aggregate_commitment.clone(),
            aggregate_response: existing.aggregate_response.clone(),
            challenge: existing.challenge.clone(),
            deposit_count_observed: existing.deposit_count_observed,
            created_at_unix_ms: existing.created_at_unix_ms,
            worker_transcript_hash: existing.worker_transcript_hash.clone(),
            init_transcript_hash: existing.init_transcript_hash.clone(),
            last_bound_tx_hash: existing.last_bound_tx_hash.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&updated)
            .map_err(|e| E::Internal(format!("encode vault_state_v2:{e}")))?;
        let file_path = vault_state_file_path(state_dir);
        write_secret_file_replace(&file_path, &bytes)
            .map_err(|e| E::Internal(format!("write vault_state_v2:{e:?}")))?;

        Ok(VaultSequenceSyncResponse {
            vault_sequence: chain_seq,
            chain_vault_sequence: chain_seq,
            previous_vault_sequence: previous_seq,
            updated_at_ms: now,
            idempotent: false,
        })
    }

    /// Pure helper: read + parse the on-disk vault-state file for the given state_dir. Returns
    /// `Ok(None)` if the file does not exist; `Err` on any parse/IO failure. Used by 2b's
    /// observer to read the cursor without going through the HTTP endpoint.
    ///
    /// Codex M3a P1 v3 backwards-compat policy: the v3 layout adds a dedicated FROZEN
    /// `worker_transcript_hash` field separate from the canonical `init_transcript_hash`.
    /// Pre-v3 files have a single `init_transcript_hash: String` field that did double duty
    /// (per-slot init hash AND finalize-canonical hash, depending on lifecycle stage).
    /// Auto-migrating a pre-v3 file is risky:
    ///   - If the persisted value is the per-slot hash (init ran but finalize didn't), we
    ///     could backfill `worker_transcript_hash` and clear `init_transcript_hash` to None.
    ///   - If the persisted value is the canonical final hash (finalize ran), we have NO
    ///     way to recover the per-slot hash without re-running init from scratch.
    ///   - We can't reliably distinguish which case applies without external context.
    ///
    /// Since the prior v2 fix already required operators to re-init when fields were missing,
    /// we keep the same posture: reject the load with `vault_state_v2_legacy_layout_requires_reinit`.
    /// Operators upgrading from pre-v3 code MUST remove `vault_state_v2.json` and re-run
    /// `/v2/vault_state/init` followed by `/v2/vault_state/init/finalize`.
    ///
    /// Implementation: we deserialize into a permissive shape that accepts the legacy schema,
    /// detect the missing field, and fail closed.
    pub fn load_vault_state_v2(state_dir: &Path) -> WorkerResult<Option<VaultStateFile>> {
        let file_path = vault_state_file_path(state_dir);
        if !file_path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&file_path)
            .map_err(|err| WorkerError::Crypto(format!("read vault_state_v2 file: {err}")))?;
        // Use a probe shape to detect legacy layouts before the strict deserialize fails with
        // a cryptic "missing field" message. The probe captures only the fields we use for
        // backwards-compat detection.
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        struct LegacyProbe {
            #[serde(default)]
            scheme: Option<String>,
            #[serde(default)]
            worker_transcript_hash: Option<String>,
        }
        let probe: LegacyProbe = serde_json::from_slice(&raw).map_err(|err| {
            WorkerError::Crypto(format!("parse vault_state_v2 file: {err}"))
        })?;
        if probe.scheme.as_deref() != Some("vault_state_v2") {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_unexpected_scheme_on_disk".to_string(),
            ));
        }
        if probe.worker_transcript_hash.is_none() {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_legacy_layout_requires_reinit: vault_state_v2.json was written \
                 before the Codex M3a P1 v3 partial-finalize-recovery layout landed; remove the \
                 file and re-run /v2/vault_state/init followed by /v2/vault_state/init/finalize"
                    .to_string(),
            ));
        }
        let existing: VaultStateFile = serde_json::from_slice(&raw)
            .map_err(|err| WorkerError::Crypto(format!("parse vault_state_v2 file: {err}")))?;
        if existing.scheme != "vault_state_v2" {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_unexpected_scheme_on_disk".to_string(),
            ));
        }
        Ok(Some(existing))
    }

    // =============================================================================================
    // Milestone 2 sub-milestone 2b — confirmed-deposit observer endpoint.
    //
    // The off-chain observer polls the Aptos REST event handle for the bridge module's
    // DepositEventV2, parses each event, and posts to `/v2/vault_state/observe_deposit` on the
    // coordinator. The coordinator fans out `/worker/v2/vault_state/observe_deposit` to all 5
    // selected workers. Each worker:
    //   1. Validates id safety, decimal epoch, hex shapes (same defense-in-depth posture as
    //      Milestone 2a init: applies even though the coordinator already sanitises).
    //   2. Loads the persisted vault_state_v2.json. Missing → MISSING_VAULT_STATE_FILE
    //      (`InvalidDkgState("missing_vault_state_file")`).
    //   3. Provenance gate: existing.{dkg_epoch, slot, player_id, vault_ek_hex,
    //      sender_address, asset_type, chain_id, vault_ek_transcript_hash,
    //      registration_transcript_hash, roster_hash, selected_slots} MUST equal req.*.
    //      Otherwise InvalidDkgState("vault_state_v2_provenance_mismatch") and no cursor bump.
    //   4. Cursor monotonicity (KILLER, strict >): req.deposit_count > existing.deposit_count_observed.
    //      Equality is rejected — prevents an already-observed deposit from being replayed.
    //      InvalidRequest("stale_deposit_count: req=X existing=Y").
    //   5. Atomic update: read existing, set deposit_count_observed = req.deposit_count,
    //      re-serialise, atomic write via the same tmp + create_new + rename helper used by init.
    //      vault_sequence is NOT touched here — that's a separate cursor mirroring on-chain state.
    //   6. Recompute the worker transcript hash from public inputs and return it alongside the
    //      cursor delta. The coordinator re-derives the same hash and asserts byte equality
    //      (defense in depth — catches a deop-node tricked into proxying a forged response).
    //
    // No secret material reaches this endpoint: the request body contains only the (deposit
    // commitment, amount tag, CA payload hash, single-use deposit nonce, sequence_number,
    // tx_version, event GUID) tuple parsed from the chain event, plus the provenance + cursor
    // bindings. The forbidden-field guard at the deop-node + coordinator catches any extra
    // amount/blind/dk/share/nullifier/secret/etc. fields before they reach the worker.
    //
    // Transcript shape — byte-identical with `deop-protocol::vault_state_v2`:
    //   "EUNOMA_VAULT_STATE_V2_OBSERVE_V1"
    //   || ":" || session_id || ":" || request_id || ":" || dkg_epoch
    //   || ":" || joined(sorted_selected_slots, ",")
    //   || ":" || self_slot || ":" || player_id
    //   || ":" || vault_ek_transcript_hash (norm lower hex)
    //   || ":" || registration_transcript_hash (norm lower hex)
    //   || ":" || vault_ek (norm lower hex)
    //   || ":" || sender_address (norm lower hex)
    //   || ":" || asset_type (norm lower hex)
    //   || ":" || chain_id (decimal)
    //   || ":" || deposit_count (decimal)
    //   || ":" || commitment (norm lower hex)
    //   || ":" || amount_tag (norm lower hex)
    //   || ":" || ca_payload_hash (norm lower hex)
    //   || ":" || deposit_nonce (norm lower hex)
    //   || ":" || sequence_number (decimal passthrough)
    //   || ":" || tx_version (decimal passthrough)
    //   || ":" || event_guid (passthrough)
    //   || ":" || previous_deposit_count_observed (decimal)
    //   || ":" || new_deposit_count_observed (decimal)
    //   → sha256 → lowercase hex.
    // =============================================================================================

    pub(crate) const OBSERVE_TRANSCRIPT_DOMAIN: &str = "EUNOMA_VAULT_STATE_V2_OBSERVE_V1";

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ObserveDepositRequest {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub vault_ek_transcript_hash: String,
        pub registration_transcript_hash: String,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub deposit_count: u64,
        pub commitment: String,
        pub amount_tag: String,
        pub ca_payload_hash: String,
        pub deposit_nonce: String,
        pub sequence_number: String,
        pub tx_version: String,
        pub event_guid: String,
        pub previous_deposit_count_observed: u64,
        pub new_deposit_count_observed: u64,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ObserveDepositResult {
        pub slot: usize,
        pub player_id: usize,
        pub vault_state_path: String,
        pub vault_state_hash: String,
        pub worker_transcript_hash: String,
        pub previous_deposit_count_observed: u64,
        pub deposit_count_observed: u64,
        pub vault_sequence: u64,
        pub observed_at_unix_ms: u128,
        /// Always `true` on success. Distinguishes a successful observe-call response from
        /// the worker's other endpoints by introducing a load-bearing literal the coordinator's
        /// parser asserts on.
        pub observed: bool,
    }

    /// Compute the per-worker observe-deposit transcript hash. Byte-identical with the TS
    /// reconstructor in `deop-protocol::vault_state_v2::vaultStateV2ObserveWorkerTranscriptHash`.
    pub fn observe_worker_transcript_hash(
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        deposit_count: u64,
        commitment_hex: &str,
        amount_tag_hex: &str,
        ca_payload_hash_hex: &str,
        deposit_nonce_hex: &str,
        sequence_number: &str,
        tx_version: &str,
        event_guid: &str,
        previous_deposit_count_observed: u64,
        new_deposit_count_observed: u64,
    ) -> String {
        let joined = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(OBSERVE_TRANSCRIPT_DOMAIN.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(registration_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sender_address_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(asset_type_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(deposit_count.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(commitment_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(amount_tag_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ca_payload_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(deposit_nonce_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sequence_number.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(tx_version.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(event_guid.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(previous_deposit_count_observed.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(new_deposit_count_observed.to_string().as_bytes());
        sha256_hex(&bytes)
    }

    /// Worker entrypoint for `/worker/v2/vault_state/observe_deposit`.
    pub fn observe_deposit_v2(
        state_dir: &Path,
        req: &ObserveDepositRequest,
    ) -> WorkerResult<ObserveDepositResult> {
        // 1. Identifier safety + range validation. Defense in depth — the coordinator also
        //    sanitises but the worker is the final fence before the disk.
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.dkg_epoch.is_empty() || !req.dkg_epoch.chars().all(|c| c.is_ascii_digit()) {
            return Err(WorkerError::InvalidRequest(
                "dkg_epoch must be a non-empty decimal string".to_string(),
            ));
        }
        if req.sequence_number.is_empty()
            || !req.sequence_number.chars().all(|c| c.is_ascii_digit())
        {
            return Err(WorkerError::InvalidRequest(
                "sequence_number must be a non-empty decimal string".to_string(),
            ));
        }
        if req.tx_version.is_empty() || !req.tx_version.chars().all(|c| c.is_ascii_digit()) {
            return Err(WorkerError::InvalidRequest(
                "tx_version must be a non-empty decimal string".to_string(),
            ));
        }
        // eventGuid is opaque — we accept any non-empty string but bound its size + reject
        // newlines / control characters that could corrupt log output.
        if req.event_guid.is_empty() || req.event_guid.len() > 256 {
            return Err(WorkerError::InvalidRequest(
                "event_guid must be a non-empty string up to 256 chars".to_string(),
            ));
        }
        if req
            .event_guid
            .chars()
            .any(|c| c.is_control() || c == '\n' || c == '\r')
        {
            return Err(WorkerError::InvalidRequest(
                "event_guid must not contain control characters".to_string(),
            ));
        }
        if req.deposit_count == 0 {
            return Err(WorkerError::InvalidRequest(
                "deposit_count must be >= 1 (depositCount = sequence_number + 1, observer must \
                 not emit for sequence_number-less-than-zero)"
                    .to_string(),
            ));
        }
        if req.new_deposit_count_observed != req.deposit_count {
            return Err(WorkerError::InvalidRequest(format!(
                "new_deposit_count_observed {} must equal deposit_count {}",
                req.new_deposit_count_observed, req.deposit_count
            )));
        }

        // 2. Normalize hex fields (32-byte hex).
        let vault_ek_transcript_hash = normalize_hex(&req.vault_ek_transcript_hash, 32)?;
        let registration_transcript_hash = normalize_hex(&req.registration_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let vault_ek_hex = normalize_hex(&req.vault_ek, 32)?;
        let sender = normalize_hex(&req.sender_address, 32)?;
        let asset = normalize_hex(&req.asset_type, 32)?;
        let commitment = normalize_hex(&req.commitment, 32)?;
        let amount_tag = normalize_hex(&req.amount_tag, 32)?;
        let ca_payload_hash = normalize_hex(&req.ca_payload_hash, 32)?;
        let deposit_nonce = normalize_hex(&req.deposit_nonce, 32)?;

        // 3. Load the persisted state. Missing → fail closed.
        let existing = load_vault_state_v2(state_dir)?.ok_or_else(|| {
            WorkerError::InvalidDkgState("missing_vault_state_file".to_string())
        })?;

        // 4. Provenance gate. Every binding persisted by Milestone 2a's init MUST match the
        //    observe-deposit request — except cursor counters, which the cursor-monotonicity
        //    check below handles.
        let provenance_ok = existing.dkg_epoch == req.dkg_epoch
            && existing.slot == req.self_slot
            && existing.player_id == req.player_id
            && normalize_hex(&existing.vault_ek_transcript_hash, 32)? == vault_ek_transcript_hash
            && normalize_hex(&existing.registration_transcript_hash, 32)?
                == registration_transcript_hash
            && normalize_hex(&existing.roster_hash, 32)? == roster_hash
            && existing.selected_slots == sorted
            && normalize_hex(&existing.vault_ek_hex, 32)? == vault_ek_hex
            && normalize_hex(&existing.sender_address, 32)? == sender
            && normalize_hex(&existing.asset_type, 32)? == asset
            && existing.chain_id == req.chain_id;
        if !provenance_ok {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_v2_provenance_mismatch".to_string(),
            ));
        }

        // 5. Cursor monotonicity (KILLER). Strict greater-than: req.deposit_count must be
        //    strictly larger than the existing cursor. Equal is rejected (replay of an
        //    already-observed event). Less is also rejected (out-of-order observer).
        if !(req.deposit_count > existing.deposit_count_observed) {
            return Err(WorkerError::InvalidRequest(format!(
                "stale_deposit_count: req={} existing={}",
                req.deposit_count, existing.deposit_count_observed
            )));
        }
        if req.previous_deposit_count_observed != existing.deposit_count_observed {
            return Err(WorkerError::InvalidRequest(format!(
                "previous_deposit_count_observed_mismatch: req={} existing={}",
                req.previous_deposit_count_observed, existing.deposit_count_observed
            )));
        }

        // 6. Atomic update: rebuild the on-disk struct with the new cursor and write it via
        //    the same tmp + create_new + rename helper as init.
        let previous_cursor = existing.deposit_count_observed;
        let updated = VaultStateFile {
            scheme: existing.scheme.clone(),
            slot: existing.slot,
            player_id: existing.player_id,
            dkg_epoch: existing.dkg_epoch.clone(),
            ca_dkg_transcript_hash: existing.ca_dkg_transcript_hash.clone(),
            vault_ek_transcript_hash: existing.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: existing.registration_transcript_hash.clone(),
            roster_hash: existing.roster_hash.clone(),
            selected_slots: existing.selected_slots.clone(),
            vault_ek_hex: existing.vault_ek_hex.clone(),
            sender_address: existing.sender_address.clone(),
            asset_type: existing.asset_type.clone(),
            chain_id: existing.chain_id,
            aggregate_commitment: existing.aggregate_commitment.clone(),
            aggregate_response: existing.aggregate_response.clone(),
            challenge: existing.challenge.clone(),
            vault_sequence: existing.vault_sequence, // untouched by observe
            deposit_count_observed: req.deposit_count,
            created_at_unix_ms: existing.created_at_unix_ms,
            // Codex M3a P1 v3: preserve BOTH the frozen per-slot worker_transcript_hash and
            // the canonical init_transcript_hash (if finalize landed). Observe does not touch
            // identity, so both bindings remain valid across cursor bumps.
            worker_transcript_hash: existing.worker_transcript_hash.clone(),
            init_transcript_hash: existing.init_transcript_hash.clone(),
            // M11: observe-deposit preserves any prior resync binding verbatim.
            last_bound_tx_hash: existing.last_bound_tx_hash.clone(),
            last_resync_at: existing.last_resync_at,
        };
        let bytes = serde_json::to_vec_pretty(&updated)
            .map_err(|err| WorkerError::Crypto(format!("encode vault_state_v2 file: {err}")))?;
        let file_path = vault_state_file_path(state_dir);
        // Codex M3a P2 #2: observe INTENTIONALLY overwrites the existing vault_state_v2.json
        // with the new cursor — the no-clobber guard would reject this. Use the replace
        // variant. Provenance + cursor monotonicity gates above guarantee the new content
        // is a strict supersession of the existing file.
        write_secret_file_replace(&file_path, &bytes)?;

        // Codex M3a P1 v4 (canonical vault_state_hash): EXCLUDES `deposit_count_observed`,
        // so observe-deposit's cursor bump leaves `vault_state_hash` unchanged across calls.
        // The OBSERVE_TRANSCRIPT_DOMAIN-rooted `worker_transcript_hash` returned below DOES
        // bind the new cursor — that's the per-observe domain. The vault-state binding stays
        // stable for partial-finalize recovery.
        let vault_state_hash = compute_vault_state_hash_canonical(&updated);
        let worker_transcript_hash = observe_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &sorted,
            req.self_slot,
            req.player_id,
            &vault_ek_transcript_hash,
            &registration_transcript_hash,
            &vault_ek_hex,
            &sender,
            &asset,
            req.chain_id,
            req.deposit_count,
            &commitment,
            &amount_tag,
            &ca_payload_hash,
            &deposit_nonce,
            &req.sequence_number,
            &req.tx_version,
            &req.event_guid,
            previous_cursor,
            req.deposit_count,
        );
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        Ok(ObserveDepositResult {
            slot: req.self_slot,
            player_id: req.player_id,
            vault_state_path: file_path.display().to_string(),
            vault_state_hash,
            worker_transcript_hash,
            previous_deposit_count_observed: previous_cursor,
            deposit_count_observed: req.deposit_count,
            vault_sequence: existing.vault_sequence,
            observed_at_unix_ms: observed_at,
            observed: true,
        })
    }

    fn validate_selected_slots(slots: &[usize]) -> WorkerResult<()> {
        if slots.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "selected_slots must have {DEOPERATOR_THRESHOLD} entries, got {}",
                slots.len()
            )));
        }
        let mut seen = [false; DEOPERATOR_COUNT];
        for slot in slots {
            assert_slot(*slot)?;
            if seen[*slot] {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate selected_slots entry {slot}"
                )));
            }
            seen[*slot] = true;
        }
        Ok(())
    }

    fn sorted_unique_slots(slots: &[usize]) -> WorkerResult<Vec<usize>> {
        validate_selected_slots(slots)?;
        let mut copy = slots.to_vec();
        copy.sort_unstable();
        Ok(copy)
    }

    /// Codex M3a P2 #2: atomic write with no-clobber + byte-equality idempotency gate for
    /// the vault_state_v2.json fresh-init path. The caller (init_vault_state_v2) already
    /// gates on `file_path.exists()` upstream, so by the time we reach this function the
    /// destination should not exist. The no-clobber guard catches a race where two
    /// concurrent fresh-init callers both pass the upstream existence check; the loser
    /// fails closed with InvalidDkgState.
    fn write_secret_file(path: &Path, contents: &[u8]) -> WorkerResult<()> {
        crate::atomic_io::write_atomic_no_clobber(path, contents, "vault_state_v2")
    }

    /// Codex M3a P2 #2: atomic write WITH replace semantics for the vault_state_v2.json
    /// cursor bump path. observe_deposit_v2 INTENTIONALLY overwrites the existing file with
    /// the new cursor — the no-clobber guard would reject this. The upstream caller has
    /// already verified the provenance matches, so the replace is safe.
    pub(super) fn write_secret_file_replace(path: &Path, contents: &[u8]) -> WorkerResult<()> {
        crate::atomic_io::write_atomic_replace(path, contents, "vault_state_v2_observe")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
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

    fn normalize_hex(hex: &str, expected_bytes: usize) -> WorkerResult<String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != expected_bytes {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {expected_bytes}-byte hex, got {}",
                bytes.len()
            )));
        }
        Ok(hex_encode(&bytes))
    }
}

// =================================================================================================
// Milestone 3 sub-milestone 3a — MPCCA withdraw state machine scaffolding.
//
// The four rounds (`round1` nonce/commit, `round2` partial sigma, `prove` collaborative
// bulletproof, `finalize` aggregate) share an identical request envelope (provenance + identity
// + withdraw fields) modulo the chained-rounds extension (`previousRoundTranscriptHash` +
// `previousRoundCommitments`). Each per-round handler runs the FULL public-binding work:
//
//   1. validate id safety, decimal epoch, hex shapes (32-byte normalisation everywhere)
//   2. load the persisted `vault_state_v2.json`. Missing → `InvalidDkgState("missing_vault_state_file")`
//   3. provenance gate: every binding persisted by Milestone 2a's init MUST match the request
//      (dkg_epoch, slot, vault_ek_hex, vault_state_init_transcript_hash). Otherwise
//      InvalidDkgState("mpcca_withdraw_v2_provenance_mismatch") and no further work.
//   4. vault_sequence gate: existing.vault_sequence == req.vault_sequence. Otherwise
//      InvalidRequest("stale_vault_sequence"). This is the load-bearing replay-prevention
//      check at the MPCCA layer.
//   5. re-verify the Milestone 1 sigma against the persisted vault_state_v2.json's tuple.
//      If the persisted tuple no longer validates (impossible by Milestone 2a's invariants, but
//      defense-in-depth here), reject Crypto BEFORE returning NotImplemented.
//   6. recompute the worker_transcript_hash from public inputs.
//   7. persist a per-session state file at `state_dir/mpc-sessions/<requestId>__<sessionId>/
//      mpcca_withdraw_v2_round{N}.json` (atomic 0o600 via tmp + create_new + rename).
//   8. return `Err(WorkerError::NotImplemented("mpcca_withdraw_v2_round{N}_<phase>_pending_milestone4"))`.
//
// The KILLER design point: the public-binding work in steps 1-7 ALL RUNS before the
// NotImplemented step. A tampered request (wrong vault_ek, stale sigma, mismatched provenance)
// fails closed with a SPECIFIC validation error long before the NotImplemented surface. Milestone
// 4 fills in the crypto without touching steps 1-7 — those are load-bearing today.
//
// Why per-session state files: the four rounds are stateful — round2 reads round1's persisted
// outputs, prove reads round2's, finalize reads prove's. Even though the crypto is stubbed, we
// allocate the on-disk slot for milestone 4 so the file layout is committed.
// =================================================================================================
pub mod mpcca_withdraw_v2 {
    use crate::ca_dkg_v2::{load_ca_dkg_v2_share, load_hpke_keypair_for_slot, HpkeKeypairFile};
    use crate::h_ristretto;
    use crate::hpke_aead;
    pub use crate::hpke_aead::HpkeEnvelope;
    use crate::mpc_spdz_adapter::is_safe_id;
    use crate::registration_verifier::{
        lagrange_coefficients_at_zero, verify_registration_proof,
    };
    use crate::transfer_sigma_reference::{
        bcs_fiat_shamir_inputs, bcs_serialize_transfer_session, build_statement,
        sigma_fiat_shamir_seed,
        threshold::{derive_dk_base_points, DkBasePoint, COMMITMENT_LEN, WITNESS_LEN},
        DomainSeparator, Statement, TransferStatementInputs, APTOS_FRAMEWORK_ADDRESS, PROTOCOL_ID,
        TYPE_NAME,
    };
    use crate::vault_state_v2::{load_vault_state_v2, VaultStateFile};
    use crate::{assert_slot, WorkerError, WorkerResult, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroize;

    // One domain string per round + a final-transcript domain. Cross-round transcript replay is
    // impossible by construction because each domain is distinct.
    //
    // M1 (Threshold ElGamal Amount Ingress) bumped round1's domain from V1 to V2: the V2 hash
    // additionally binds (amount_commitment, per_share_commitments, ingress_envelopes_hash) so
    // any tampered ingress field flips the per-worker transcript hash. Stale V1 stub-mode
    // artifacts deserialised against the V2 domain will fail closed at the worker-hash mismatch
    // gate.
    pub(crate) const ROUND1_TRANSCRIPT_DOMAIN: &str = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND1_V2";
    /// M4 Commit 1: round2 binding now includes Aptos CA TransferV1 Statement input fields
    /// (recipient_ek + 6 ciphertext vectors). Bumped V1→V2 so any pre-M4 chained-round
    /// transcript artifact deserialised against the V2 binding fails closed at the
    /// worker-hash mismatch gate.
    pub(crate) const ROUND2_TRANSCRIPT_DOMAIN: &str = "EUNOMA_MPCCA_WITHDRAW_V2_ROUND2_V2";
    pub(crate) const PROVE_TRANSCRIPT_DOMAIN: &str = "EUNOMA_MPCCA_WITHDRAW_V2_PROVE_V1";
    pub(crate) const FINALIZE_TRANSCRIPT_DOMAIN: &str = "EUNOMA_MPCCA_WITHDRAW_V2_FINALIZE_V1";

    /// M4 Commit 1: round2 at-rest HPKE seal `info` string. LOCKED — any change is a
    /// wire-protocol break and must bump the version suffix.
    pub(crate) const HPKE_INFO_ROUND2_AT_REST: &[u8] = b"EUNOMA_M4_ROUND2_AT_REST_V1";

    /// Aptos CA TransferV1 chunked-balance parameter. Locked to ell=8, n=4 (no auditor).
    /// These values match the canonical M4a fixture + transfer_sigma_reference's threshold
    /// module + sigmaProtocolTransfer.ts.
    pub(crate) const ROUND2_ELL: usize = 8;
    pub(crate) const ROUND2_N: usize = 4;

    /// M1 AAD domain — byte-identical to the TS constant `EUNOMA_M1_AMOUNT_INGRESS_V1`.
    pub(crate) const M1_INGRESS_AAD_DOMAIN: &str = "EUNOMA_M1_AMOUNT_INGRESS_V1";

    // NotImplemented phase strings — surfaced by the milestone 3a stub to distinguish per-round
    // missing crypto. Milestone 4 removes each one as its round lands. Kept here as a
    // searchable registry of the historical stub strings; M4 commits 1 + 3 + 4 will retire
    // ROUND2/PROVE/FINALIZE in turn.
    #[allow(dead_code)]
    pub(crate) const ROUND1_NOT_IMPLEMENTED_PHASE: &str =
        "mpcca_withdraw_v2_round1_nonce_generation_pending_milestone4";
    #[allow(dead_code)]
    pub(crate) const ROUND2_NOT_IMPLEMENTED_PHASE: &str =
        "mpcca_withdraw_v2_round2_partial_sigma_pending_milestone4";
    pub(crate) const PROVE_NOT_IMPLEMENTED_PHASE: &str =
        "mpcca_withdraw_v2_prove_collaborative_bulletproof_pending_milestone4";
    /// M4 commit 3 retired the finalize NotImplemented surface. Kept as a searchable registry
    /// of the historical stub string.
    #[allow(dead_code)]
    pub(crate) const FINALIZE_NOT_IMPLEMENTED_PHASE: &str =
        "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4";

    /// Common provenance + identity envelope shared by all four rounds. Each round adds its own
    /// chained-round fields on top of this in the `Chained*` request structs.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1Request {
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub vault_ek_transcript_hash: String,
        pub registration_transcript_hash: String,
        pub vault_state_init_transcript_hash: String,
        pub observed_deposit_transcript_hashes: Vec<String>,
        /// Codex M3a P2 #1 v2 (regression fix): parallel cursor array for ordering
        /// enforcement. `observed_deposit_cursors[i]` is the depositCount that
        /// corresponds to `observed_deposit_transcript_hashes[i]`. The worker requires
        /// strict monotonic ordering starting at 1: cursors MUST equal [1, 2, …, depositCount].
        /// Pre-fix the worker only enforced length + duplicate-hash uniqueness — a
        /// coordinator that scrambled the cursor mapping could submit out-of-order
        /// observed transcripts without detection. With this field the worker rejects
        /// any wrong-order or wrong-cursor mapping at the round1 gate.
        #[serde(default)]
        pub observed_deposit_cursors: Vec<u64>,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub root: String,
        pub nullifier_hash: String,
        pub recipient: String,
        pub recipient_hash: String,
        pub amount_tag: String,
        pub vault_sequence: u64,
        pub expiry_secs: u64,
        pub request_hash: String,
        pub deposit_count: u64,
        /// Milestone 1 — Threshold ElGamal Amount Ingress fields. Empty under M3a stub
        /// (handled via serde default for backwards-test compatibility); populated by the
        /// coordinator's M1 fan-out in production. Worker validates per-share commitment
        /// + decrypts HPKE envelope[player_id] in `run_round1_v2` once Commit 3 lands the
        /// ingress crypto path. This commit only adds wire-shape acceptance + folds the
        /// fields into the V2 transcript hash so downstream tampering fails closed.
        #[serde(default)]
        pub amount_commitment: String,
        #[serde(default)]
        pub per_share_commitments: Vec<String>,
        #[serde(default)]
        pub ingress_envelopes: Vec<HpkeEnvelope>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ChainedRoundRequest {
        // Embed the round1 envelope verbatim — serde flattens at the wire layer.
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub vault_ek_transcript_hash: String,
        pub registration_transcript_hash: String,
        pub vault_state_init_transcript_hash: String,
        pub observed_deposit_transcript_hashes: Vec<String>,
        /// See Round1Request::observed_deposit_cursors. The chained rounds enforce the
        /// same shape so a tampered cursor mapping can't slip past round1 by being
        /// reintroduced at round2/prove/finalize.
        #[serde(default)]
        pub observed_deposit_cursors: Vec<u64>,
        pub roster_hash: String,
        pub selected_slots: Vec<usize>,
        pub self_slot: usize,
        pub player_id: usize,
        pub vault_ek: String,
        pub sender_address: String,
        pub asset_type: String,
        pub chain_id: u8,
        pub root: String,
        pub nullifier_hash: String,
        pub recipient: String,
        pub recipient_hash: String,
        pub amount_tag: String,
        pub vault_sequence: u64,
        pub expiry_secs: u64,
        pub request_hash: String,
        pub deposit_count: u64,
        pub previous_round_transcript_hash: String,
        pub previous_round_commitments: Vec<String>,
    }

    /// Round 2 (M4 commit 1) request. Extends `ChainedRoundRequest` with the Aptos CA
    /// `TransferV1` Statement input fields needed for the worker to (a) reconstruct the
    /// public Statement and (b) programmatically derive the BASE_DK_SET via psi_transfer
    /// inspection.
    ///
    /// Wire shape: every base ChainedRoundRequest field at top level (via `serde(flatten)`)
    /// plus the new Statement fields. The user's pre-computed sigma α-commitments / response
    /// shares / Bulletproof bytes are NOT carried here — those are M4 commit 2's coordinator-
    /// orchestration concern. Commit 1's worker contract is purely the dk-component partial.
    ///
    /// All hex fields MUST be 32-byte compressed Ristretto points (sender_ek = vault_ek is
    /// already validated by the chained-round provenance gate; recipient_ek + ciphertext
    /// vectors are new and validated in `build_transfer_statement_from_round2_request`).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2Request {
        #[serde(flatten)]
        pub base: ChainedRoundRequest,
        /// Recipient encryption key (`ek_rid`). 32-byte compressed Ristretto hex.
        pub recipient_ek: String,
        /// Old balance Pedersen commitments `C[i] = G·old_a[i] + H·old_r[i]`. 8 × 32-byte hex.
        pub old_balance_c: Vec<String>,
        /// Old balance ElGamal D-component `D[i] = ek_sid · old_r[i]`. 8 × 32-byte hex.
        pub old_balance_d: Vec<String>,
        /// New balance Pedersen commitments. 8 × 32-byte hex.
        pub new_balance_c: Vec<String>,
        /// New balance ElGamal D-component. 8 × 32-byte hex.
        pub new_balance_d: Vec<String>,
        /// Transfer-amount Pedersen commitments. 4 × 32-byte hex.
        pub transfer_amount_c: Vec<String>,
        /// Transfer-amount ElGamal D-component (sender). 4 × 32-byte hex.
        pub transfer_amount_d_sender: Vec<String>,
        /// Transfer-amount ElGamal D-component (recipient). 4 × 32-byte hex.
        pub transfer_amount_d_recipient: Vec<String>,
    }

    pub type ProveRequest = ChainedRoundRequest;

    /// Finalize (M4 commit 3) request. Wraps `ChainedRoundRequest` and adds:
    /// 1. The Aptos CA TransferV1 Statement input fields (same canonical lengths as round2;
    ///    coordinator MUST send the byte-identical values so the worker's round2 ↔ finalize
    ///    Statement-input binding holds).
    /// 2. The coordinator-aggregated 30-point sigma commitment vector `A_full`. Built by the
    ///    coordinator from the user-supplied 29-entry commitment vector plus the worker
    ///    partials at `BASE_DK_SET = {0, 17}` aggregated across the 5 selected slots.
    /// 3. The coordinator-computed Fiat-Shamir challenge `e`. Worker re-derives `e` locally
    ///    from `sigma_fiat_shamir_seed(BCS(domain, type_name, k=25, statement_x, statement_scalars, A_full))`
    ///    and asserts byte-equality. This makes a malicious coordinator that lies about `e`
    ///    fail closed at the worker.
    ///
    /// Wire shape: every base ChainedRoundRequest field at top level (via `serde(flatten)`),
    /// then the Statement input fields, then `aggregatedSigmaCommitments` (30 × 32-byte hex),
    /// then `challengeHex` (32-byte canonical Ed25519 scalar).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizeRequest {
        #[serde(flatten)]
        pub base: ChainedRoundRequest,
        /// Recipient encryption key (`ek_rid`). 32-byte compressed Ristretto hex.
        pub recipient_ek: String,
        /// Old balance Pedersen commitments. 8 × 32-byte hex.
        pub old_balance_c: Vec<String>,
        /// Old balance ElGamal D-component. 8 × 32-byte hex.
        pub old_balance_d: Vec<String>,
        /// New balance Pedersen commitments. 8 × 32-byte hex.
        pub new_balance_c: Vec<String>,
        /// New balance ElGamal D-component. 8 × 32-byte hex.
        pub new_balance_d: Vec<String>,
        /// Transfer-amount Pedersen commitments. 4 × 32-byte hex.
        pub transfer_amount_c: Vec<String>,
        /// Transfer-amount ElGamal D-component (sender). 4 × 32-byte hex.
        pub transfer_amount_d_sender: Vec<String>,
        /// Transfer-amount ElGamal D-component (recipient). 4 × 32-byte hex.
        pub transfer_amount_d_recipient: Vec<String>,
        /// Coordinator-aggregated 30-point sigma commitment vector `A_full`. Each entry is a
        /// 32-byte compressed Ristretto hex.
        pub aggregated_sigma_commitments: Vec<String>,
        /// Coordinator-computed Fiat-Shamir challenge `e`. 32-byte canonical Ed25519 scalar hex.
        pub challenge_hex: String,
    }

    /// Output of the per-round milestone 3a stub. The crypto-specific fields (round_commitment,
    /// partial_response, etc.) are `None` because the crypto is not implemented yet — but
    /// session_state_path, session_state_hash, and worker_transcript_hash are FULLY populated
    /// because the public-binding work happens BEFORE the NotImplemented surface. Milestone 4
    /// will swap the `None`s for `Some(...)` and `completed: true`. Round1 already returns
    /// `Round1IngressResult` under M1; the stub shape is preserved for rounds 2/prove/finalize.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct StubRoundResult {
        pub slot: usize,
        pub player_id: usize,
        pub session_state_path: String,
        pub session_state_hash: String,
        pub worker_transcript_hash: String,
        pub observed_at_unix_ms: u128,
        pub completed: bool, // always false for rounds 2/prove/finalize stub
        pub not_implemented_phase: String,
    }

    /// Milestone 1 round1 result: ingress (HPKE decrypt + per-share Pedersen verify + zero-
    /// share reject + HPKE-encrypted-at-rest persist) succeeded. Mirrors the TS
    /// `MpccaWithdrawRound1Response` shape used by `parseMpccaWithdrawRound1Response`.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round1IngressResult {
        pub slot: usize,
        pub player_id: usize,
        pub session_state_path: String,
        pub session_state_hash: String,
        pub worker_transcript_hash: String,
        pub observed_at_unix_ms: u128,
        pub completed: bool, // always true under M1
        /// Equals `worker_transcript_hash`. Named explicitly so the M1 binding contract is
        /// searchable across the codebase.
        pub ingress_transcript_hash: String,
    }

    /// M4 Commit 1 — worker's dk-base partial commitment at a single psi-output index.
    /// `commitment_hex` = `α_share_j[0] · base`, where `base` is the public point at the
    /// canonical BASE_DK_SET position (programmatically derived via `derive_dk_base_points`).
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2DkPartial {
        pub index: usize,
        pub commitment_hex: String,
    }

    /// M4 Commit 1 — round 2 result. The worker contributes ONLY the dk-component of the
    /// sigma commitment vector A. Returned points cover exactly the BASE_DK_SET indices
    /// (= {0, 17} for the canonical Aptos CA TransferV1 shape).
    ///
    /// `dk_base_indices_used` mirrors `partial_dk_commitments[*].index` so consumers can
    /// validate the canonical set without parsing per-entry.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2DkResult {
        pub slot: usize,
        pub player_id: usize,
        pub session_state_path: String,
        pub session_state_hash: String,
        pub worker_transcript_hash: String,
        pub observed_at_unix_ms: u128,
        pub completed: bool, // always true under M4 commit 1
        pub partial_dk_commitments: Vec<Round2DkPartial>,
        pub dk_base_indices_used: Vec<usize>,
    }

    /// M4 Commit 3 — finalize result. The worker contributes ONLY the dk-component of the
    /// sigma response vector `s`. Returned scalar is `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`,
    /// a single 32-byte canonical Ed25519 scalar hex. The coordinator aggregates the 5 selected
    /// workers' shares via `s[0] = Σ_j s_share_j` and combines with the user-supplied
    /// `s_user[1..25]` to assemble the full 25-vector sigma response.
    ///
    /// `dk_base_indices_used` mirrors round2's contract — re-derived from psi_transfer at
    /// finalize as defense-in-depth (a Statement-input drift between round2 and finalize would
    /// flip the recomputed BASE_DK_SET, surfacing as a `finalize_round2_state_dk_indices_mismatch`
    /// before the response share is computed).
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizeDkResult {
        pub slot: usize,
        pub player_id: usize,
        pub session_state_path: String,
        pub session_state_hash: String,
        pub worker_transcript_hash: String,
        pub observed_at_unix_ms: u128,
        pub completed: bool, // always true under M4 commit 3
        /// Single 32-byte canonical Ed25519 scalar hex: `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`.
        pub partial_response_dk_hex: String,
        /// Canonical BASE_DK_SET indices re-derived at finalize via psi_transfer inspection.
        pub dk_base_indices_used: Vec<usize>,
    }

    /// M4 Commit 3 — finalize binding pin. Written ATOMICALLY (via `write_atomic_no_clobber`
    /// = POSIX `link(2)`) BEFORE the worker decrypts `α_share_j[0]`. Captures the
    /// `(aggregated_commitments_hash, challenge_hex)` tuple that the FIRST finalize call
    /// committed to for this (request_id, session_id, slot).
    ///
    /// Security contract — this is the load-bearing defense against the α-share replay
    /// attack. A malicious coordinator that calls finalize twice with the SAME α-share but
    /// DIFFERENT `(A, e)` would receive two responses `s1 = α + e1·w` and `s2 = α + e2·w`,
    /// from which `w = (s2 - s1) · (e2 - e1)^-1` recovers the worker's Lagrange-weighted
    /// dk-share `λ_j · dk_share_j`. Five such recoveries (across the quorum) reconstruct
    /// `dk` itself. The pin makes the second call FAIL CLOSED before α is ever decrypted.
    ///
    /// Atomic-no-clobber semantics:
    ///   - First call: link(2) succeeds, pin persisted.
    ///   - Replay with byte-identical content: link(2) → EEXIST, file equality matches,
    ///     `write_atomic_no_clobber` returns Ok → finalize re-runs deterministically.
    ///   - Replay with different (A, e): link(2) → EEXIST, file equality fails,
    ///     `write_atomic_no_clobber` returns
    ///     `InvalidDkgState("mpcca_withdraw_v2_finalize_pin_already_exists_with_different_content")`
    ///     → α is NEVER decrypted, secret material is NEVER touched.
    ///
    /// The pin file has NO timestamp: byte-equality across legitimate replays is required.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    pub struct FinalizePinFile {
        pub scheme: String,
        pub slot: usize,
        pub player_id: usize,
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub aggregated_commitments_hash: String,
        pub challenge_hex: String,
        pub worker_transcript_hash: String,
    }

    /// File written by the worker after a successful M4 commit-1 round 2. Holds public
    /// partial dk-base commitments + an HPKE-encrypted-at-rest envelope sealing
    /// `α_share_j[0]` under the worker's own HPKE pubkey. M4 commit 3 (finalize) re-opens
    /// this file to consume `α_share_j[0]` for the response-share computation.
    ///
    /// Privacy contract: `α_share_j[0]` NEVER appears in plaintext on disk; only the
    /// HPKE seal lives here.
    ///
    /// `statement_inputs_hash` is the canonical sha256 hex of round2's Aptos CA TransferV1
    /// Statement input fields (recipient_ek + 6 ciphertext vectors). M4 commit 3's finalize
    /// handler cross-checks this against finalize's own statement_inputs_hash to catch a
    /// coordinator that tampered with Statement inputs between rounds. Defaulted to empty
    /// string for backwards-compat with pre-M4-c3 fixtures.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Round2StateFile {
        pub scheme: String,
        pub slot: usize,
        pub player_id: usize,
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub partial_dk_commitments: Vec<Round2DkPartial>,
        pub dk_base_indices_used: Vec<usize>,
        pub worker_transcript_hash: String,
        pub encrypted_alpha_envelope: HpkeEnvelope,
        pub created_at_unix_ms: u128,
        #[serde(default)]
        pub statement_inputs_hash: String,
    }

    /// On-disk per-session-per-round state file. Holds only public binding metadata + a copy of
    /// the worker_transcript_hash. Milestone 4 will extend with per-round crypto outputs.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub struct RoundStateFile {
        pub scheme: String,
        pub round: String,
        pub slot: usize,
        pub player_id: usize,
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub vault_ek_hex: String,
        pub vault_sequence: u64,
        pub deposit_count: u64,
        pub worker_transcript_hash: String,
        pub not_implemented_phase: String,
        pub created_at_unix_ms: u128,
        /// Codex M3a P2 #1: persist the full ordered vector of observe-deposit transcript
        /// hashes that the request body bound (length must equal deposit_count). Milestone 4's
        /// crypto reads this back to bind the full deposit ordering since the last withdraw.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub observed_deposit_transcript_hashes: Vec<String>,
    }

    /// Build the per-session directory path under the worker's state_dir. Caller-supplied
    /// `request_id` and `session_id` are sanitised via `is_safe_id` before being concatenated
    /// into the path — defense in depth even though the orchestrator already runs `isSafeId`.
    pub fn mpcca_withdraw_session_dir(
        state_dir: &Path,
        request_id: &str,
        session_id: &str,
    ) -> WorkerResult<PathBuf> {
        if !is_safe_id(request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id contains unsafe characters".to_string(),
            ));
        }
        if !is_safe_id(session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id contains unsafe characters".to_string(),
            ));
        }
        Ok(state_dir
            .join("mpc-sessions")
            .join(format!("{request_id}__{session_id}")))
    }

    /// Per-round file name. Round-specific so a misrouted persist call lands on a distinct slot.
    fn round_file_name(round: &str) -> String {
        format!("mpcca_withdraw_v2_{round}.json")
    }

    /// Byte-identical with the TS reconstructor in `deop-protocol::mpcca_withdraw_v2::
    /// mpccaWithdrawRound1WorkerTranscriptHash`. Round 1 V2 binds the three M1 ingress fields
    /// after the base envelope:
    ///   ... base_parts (V2 domain)
    ///   || ":" || amount_commitment_hex
    ///   || ":" || joined(per_share_commitments_hex, "|")
    ///   || ":" || ingress_envelopes_hash_hex
    #[allow(clippy::too_many_arguments)]
    pub fn round1_worker_transcript_hash(
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        vault_state_init_transcript_hash: &str,
        observed_deposit_transcript_hashes: &[String],
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        root_hex: &str,
        nullifier_hash_hex: &str,
        recipient_hex: &str,
        recipient_hash_hex: &str,
        amount_tag_hex: &str,
        vault_sequence: u64,
        expiry_secs: u64,
        request_hash_hex: &str,
        deposit_count: u64,
        amount_commitment_hex: &str,
        per_share_commitments_hex: &[String],
        ingress_envelopes_hash_hex: &str,
    ) -> String {
        let mut bytes = base_hash_parts(
            ROUND1_TRANSCRIPT_DOMAIN,
            session_id,
            request_id,
            dkg_epoch,
            vault_ek_transcript_hash,
            registration_transcript_hash,
            vault_state_init_transcript_hash,
            observed_deposit_transcript_hashes,
            roster_hash,
            sorted_selected_slots,
            self_slot,
            player_id,
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            root_hex,
            nullifier_hash_hex,
            recipient_hex,
            recipient_hash_hex,
            amount_tag_hex,
            vault_sequence,
            expiry_secs,
            request_hash_hex,
            deposit_count,
        );
        bytes.push(b':');
        bytes.extend_from_slice(amount_commitment_hex.as_bytes());
        bytes.push(b':');
        let joined = per_share_commitments_hex.join("|");
        bytes.extend_from_slice(joined.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(ingress_envelopes_hash_hex.as_bytes());
        sha256_hex(&bytes)
    }

    /// Compute the public `ingress_envelopes_hash` over the 5 envelopes in sorted-selectedSlots
    /// order. Byte-identical to TS `ingressEnvelopesHash(envelopes)`:
    ///   sha256_hex(concat(canonical_json(envelope_i) utf8 bytes for i in 0..5)).
    pub fn ingress_envelopes_hash(envelopes: &[HpkeEnvelope]) -> WorkerResult<String> {
        let mut hasher = Sha256::new();
        for env in envelopes {
            let canonical = canonical_envelope_json(env)?;
            hasher.update(canonical.as_bytes());
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Canonical JSON for an HpkeEnvelope, sorted keys: `aadHash`, `aead`, `ciphertext`, `enc`,
    /// `kdf`, `kem`. The encoding mirrors TS's `canonicalJsonStringify` byte-for-byte.
    fn canonical_envelope_json(env: &HpkeEnvelope) -> WorkerResult<String> {
        // We do NOT use serde_json's default ordering because the HpkeEnvelope struct's
        // field order is `kem,kdf,aead,enc,ciphertext,aadHash` (non-alphabetical). TS
        // canonicalJsonStringify sorts alphabetically: aadHash, aead, ciphertext, enc, kdf, kem.
        Ok(format!(
            "{{\"aadHash\":{},\"aead\":{},\"ciphertext\":{},\"enc\":{},\"kdf\":{},\"kem\":{}}}",
            json_string(&env.aad_hash),
            json_string(&env.aead),
            json_string(&env.ciphertext),
            json_string(&env.enc),
            json_string(&env.kdf),
            json_string(&env.kem),
        ))
    }

    fn json_string(s: &str) -> String {
        // Minimal JSON-string encoder mirroring TS `JSON.stringify(string)`. Hex strings + the
        // 3 ciphersuite labels are all ASCII with no special chars, so we only need to wrap
        // in quotes — but escape conservatively in case future fields aren't ASCII-clean.
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn base_hash_parts(
        domain: &str,
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        vault_state_init_transcript_hash: &str,
        observed_deposit_transcript_hashes: &[String],
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        root_hex: &str,
        nullifier_hash_hex: &str,
        recipient_hex: &str,
        recipient_hash_hex: &str,
        amount_tag_hex: &str,
        vault_sequence: u64,
        expiry_secs: u64,
        request_hash_hex: &str,
        deposit_count: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let joined_slots = sorted_selected_slots
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let joined_observed = observed_deposit_transcript_hashes.join(",");
        bytes.extend_from_slice(domain.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(dkg_epoch.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(registration_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_state_init_transcript_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined_observed.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(roster_hash.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(joined_slots.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self_slot.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(player_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_ek_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(sender_address_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(asset_type_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(chain_id.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(root_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(nullifier_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(recipient_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(recipient_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(amount_tag_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(vault_sequence.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(expiry_secs.to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(request_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(deposit_count.to_string().as_bytes());
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn chained_round_worker_hash(
        domain: &str,
        session_id: &str,
        request_id: &str,
        dkg_epoch: &str,
        vault_ek_transcript_hash: &str,
        registration_transcript_hash: &str,
        vault_state_init_transcript_hash: &str,
        observed_deposit_transcript_hashes: &[String],
        roster_hash: &str,
        sorted_selected_slots: &[usize],
        self_slot: usize,
        player_id: usize,
        vault_ek_hex: &str,
        sender_address_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
        root_hex: &str,
        nullifier_hash_hex: &str,
        recipient_hex: &str,
        recipient_hash_hex: &str,
        amount_tag_hex: &str,
        vault_sequence: u64,
        expiry_secs: u64,
        request_hash_hex: &str,
        deposit_count: u64,
        previous_round_transcript_hash: &str,
        previous_round_commitments: &[String],
    ) -> String {
        let mut bytes = base_hash_parts(
            domain,
            session_id,
            request_id,
            dkg_epoch,
            vault_ek_transcript_hash,
            registration_transcript_hash,
            vault_state_init_transcript_hash,
            observed_deposit_transcript_hashes,
            roster_hash,
            sorted_selected_slots,
            self_slot,
            player_id,
            vault_ek_hex,
            sender_address_hex,
            asset_type_hex,
            chain_id,
            root_hex,
            nullifier_hash_hex,
            recipient_hex,
            recipient_hash_hex,
            amount_tag_hex,
            vault_sequence,
            expiry_secs,
            request_hash_hex,
            deposit_count,
        );
        bytes.push(b':');
        bytes.extend_from_slice(previous_round_transcript_hash.as_bytes());
        bytes.push(b':');
        let joined = previous_round_commitments.join("|");
        bytes.extend_from_slice(joined.as_bytes());
        sha256_hex(&bytes)
    }

    /// Normalised + validated M1 ingress fields. Length-checked envelope and commitment counts,
    /// per-commitment hex shape. Pedersen verification + HPKE decrypt happen downstream in
    /// `process_m1_ingress`.
    pub(crate) struct NormalisedIngress {
        pub amount_commitment: String,
        pub per_share_commitments: Vec<String>,
        pub ingress_envelopes: Vec<HpkeEnvelope>,
        pub ingress_envelopes_hash: String,
    }

    /// File written by the worker after a successful M1 round1 ingress. Holds public
    /// commitments + an HPKE-encrypted-at-rest envelope sealing `(a_i || b_i)` under the
    /// worker's own HPKE pubkey. Downstream M4 rounds re-open this file (worker-local read,
    /// never leaves process) to consume the share for sigma + Bulletproof MPC.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IngressStateFile {
        pub scheme: String,
        pub slot: usize,
        pub player_id: usize,
        pub dkg_epoch: String,
        pub request_id: String,
        pub session_id: String,
        pub amount_commitment: String,
        pub per_share_commitments: Vec<String>,
        pub encrypted_share_envelope: HpkeEnvelope,
        pub created_at_unix_ms: u128,
    }

    /// `info` string for the on-wire HPKE seal (user → worker). LOCKED — any change is a
    /// wire-protocol break and must bump the AAD domain version.
    pub(crate) const HPKE_INFO_INGRESS: &[u8] = b"EUNOMA_M1_AMOUNT_INGRESS_V1";

    /// `info` string for the at-rest HPKE seal (worker self-seals the share). LOCKED.
    pub(crate) const HPKE_INFO_INGRESS_AT_REST: &[u8] = b"EUNOMA_M1_INGRESS_AT_REST_V1";

    /// Build the AAD bytes for the M1 ingress HPKE envelope. Byte-identical to TS
    /// `m1IngressAad(...)` — keys sorted alphabetically, no whitespace, all values as JSON
    /// strings (numeric fields are stringified before encoding).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn m1_ingress_aad(
        request_id: &str,
        session_id: &str,
        dkg_epoch: &str,
        self_slot: usize,
        player_id: usize,
        roster_hash_hex: &str,
        vault_ek_hex: &str,
        root_hex: &str,
        nullifier_hash_hex: &str,
        recipient_hash_hex: &str,
        amount_tag_hex: &str,
        vault_sequence: u64,
        deposit_count: u64,
        amount_commitment_hex: &str,
        per_share_commitments_hex: &[String],
    ) -> Vec<u8> {
        let per_share_commitments_hash = per_share_commitments_hash_hex(per_share_commitments_hex);
        // Keys MUST be alphabetically sorted to match TS `canonicalJsonStringify`.
        let mut s = String::new();
        s.push('{');
        push_field(&mut s, "amountCommitmentHex", amount_commitment_hex, true);
        push_field(&mut s, "amountTag", amount_tag_hex, false);
        push_field(&mut s, "depositCount", &deposit_count.to_string(), false);
        push_field(&mut s, "dkgEpoch", dkg_epoch, false);
        push_field(&mut s, "domain", M1_INGRESS_AAD_DOMAIN, false);
        push_field(&mut s, "nullifierHash", nullifier_hash_hex, false);
        push_field(
            &mut s,
            "perShareCommitmentsHashHex",
            &per_share_commitments_hash,
            false,
        );
        push_field(&mut s, "playerId", &player_id.to_string(), false);
        push_field(&mut s, "recipientHash", recipient_hash_hex, false);
        push_field(&mut s, "requestId", request_id, false);
        push_field(&mut s, "root", root_hex, false);
        push_field(&mut s, "rosterHash", roster_hash_hex, false);
        push_field(&mut s, "selfSlot", &self_slot.to_string(), false);
        push_field(&mut s, "sessionId", session_id, false);
        push_field(&mut s, "vaultEk", vault_ek_hex, false);
        push_field(&mut s, "vaultSequence", &vault_sequence.to_string(), false);
        s.push('}');
        s.into_bytes()
    }

    fn push_field(out: &mut String, key: &'static str, value: &str, first: bool) {
        if !first {
            out.push(',');
        }
        json_string_into(out, key);
        out.push(':');
        json_string_into(out, value);
    }

    fn json_string_into(out: &mut String, s: &str) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// sha256_hex over `concat(perShareCommitmentsHexBytes...)`. Byte-identical to TS
    /// `perShareCommitmentsHash(perShareCommitments)`.
    fn per_share_commitments_hash_hex(per_share_commitments_hex: &[String]) -> String {
        let mut hasher = Sha256::new();
        for c in per_share_commitments_hex {
            // Normalize to lowercase + no `0x` prefix to match TS `normalizeHex`.
            let normalised: String = c
                .strip_prefix("0x")
                .or_else(|| c.strip_prefix("0X"))
                .unwrap_or(c.as_str())
                .to_ascii_lowercase();
            hasher.update(normalised.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// AAD for the at-rest HPKE seal. Binds `(scheme, sessionId, requestId, selfSlot)` so the
    /// at-rest envelope cannot be misrouted across sessions.
    fn at_rest_aad(session_id: &str, request_id: &str, self_slot: usize) -> Vec<u8> {
        format!(
            "scheme=mpcca_withdraw_v2_ingress|session={session_id}|request={request_id}|slot={self_slot}"
        )
        .into_bytes()
    }

    /// HPKE-decrypt the M1 ingress envelope for this slot's player_id, validate the per-share
    /// Pedersen commitment, reject zero shares. Returns the recovered `(a_j, b_j)` pair.
    ///
    /// Error surface (all fail-closed BEFORE any persist):
    /// - `Crypto("ingress_hpke_decrypt_failed")` — HPKE open failed (wrong AAD / wrong key /
    ///   tampered envelope).
    /// - `Crypto("ingress_share_non_canonical_scalar")` — plaintext bytes don't decode to
    ///   canonical Ed25519 scalars.
    /// - `Crypto("ingress_zero_share_rejected")` — `a_j` or `b_j` is the zero scalar
    ///   (per goal.md decision #9).
    /// - `Crypto("ingress_share_commitment_mismatch")` — `G·a_j + H·b_j != C_j`.
    /// - `Crypto("ingress_invalid_per_share_commitment_encoding")` — non-canonical Ristretto
    ///   compressed bytes in `perShareCommitments[player_id]`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decrypt_and_verify_ingress_share(
        keypair: &HpkeKeypairFile,
        envelope: &HpkeEnvelope,
        per_share_commitment_hex: &str,
        aad: &[u8],
    ) -> WorkerResult<(Scalar, Scalar)> {
        let mut plaintext = hpke_aead::open(&keypair.private_key, HPKE_INFO_INGRESS, aad, envelope)
            .map_err(|_| WorkerError::Crypto("ingress_hpke_decrypt_failed".to_string()))?;
        if plaintext.len() != 64 {
            // Zero the plaintext before erroring.
            plaintext.zeroize();
            return Err(WorkerError::Crypto(
                "ingress_share_plaintext_wrong_length".to_string(),
            ));
        }
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&plaintext[0..32]);
        let mut b_bytes = [0u8; 32];
        b_bytes.copy_from_slice(&plaintext[32..64]);
        plaintext.zeroize();

        let a_opt = Scalar::from_canonical_bytes(a_bytes);
        let b_opt = Scalar::from_canonical_bytes(b_bytes);
        if a_opt.is_none().into() || b_opt.is_none().into() {
            a_bytes.zeroize();
            b_bytes.zeroize();
            return Err(WorkerError::Crypto(
                "ingress_share_non_canonical_scalar".to_string(),
            ));
        }
        let a = a_opt.unwrap();
        let b = b_opt.unwrap();
        a_bytes.zeroize();
        b_bytes.zeroize();

        // Zero-share rejection (goal.md decision #9). a == 0 makes per-share commitment
        // leak structural info; b == 0 is a weaker but still security-degraded case.
        if a == Scalar::ZERO || b == Scalar::ZERO {
            return Err(WorkerError::Crypto(
                "ingress_zero_share_rejected".to_string(),
            ));
        }

        // Decompress the claimed per-share commitment.
        let commit_raw = per_share_commitment_hex
            .strip_prefix("0x")
            .or_else(|| per_share_commitment_hex.strip_prefix("0X"))
            .unwrap_or(per_share_commitment_hex);
        if commit_raw.len() != 64 {
            return Err(WorkerError::Crypto(
                "ingress_invalid_per_share_commitment_encoding".to_string(),
            ));
        }
        let mut commit_bytes = [0u8; 32];
        for idx in 0..32 {
            commit_bytes[idx] =
                u8::from_str_radix(&commit_raw[idx * 2..idx * 2 + 2], 16).map_err(|_| {
                    WorkerError::Crypto(
                        "ingress_invalid_per_share_commitment_encoding".to_string(),
                    )
                })?;
        }
        let commit_decompressed = CompressedRistretto(commit_bytes).decompress().ok_or_else(
            || WorkerError::Crypto("ingress_invalid_per_share_commitment_encoding".to_string()),
        )?;
        let h = h_ristretto()?;
        let recomputed = RISTRETTO_BASEPOINT_POINT * a + h * b;
        if recomputed != commit_decompressed {
            return Err(WorkerError::Crypto(
                "ingress_share_commitment_mismatch".to_string(),
            ));
        }
        Ok((a, b))
    }

    /// Seal `(a_j || b_j)` under the slot's own HPKE pubkey with at-rest AAD; return the
    /// envelope ready for IngressStateFile.encrypted_share_envelope. The caller is responsible
    /// for zeroing `a` and `b` after this returns.
    pub(crate) fn seal_ingress_at_rest(
        keypair: &HpkeKeypairFile,
        session_id: &str,
        request_id: &str,
        self_slot: usize,
        a: &Scalar,
        b: &Scalar,
    ) -> WorkerResult<HpkeEnvelope> {
        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(&a.to_bytes());
        plaintext.extend_from_slice(&b.to_bytes());
        let aad = at_rest_aad(session_id, request_id, self_slot);
        let env =
            hpke_aead::seal(&keypair.public_key, HPKE_INFO_INGRESS_AT_REST, &aad, &plaintext)?;
        plaintext.zeroize();
        Ok(env)
    }

    /// Per-session-per-round file name for the M1 ingress state file (HPKE-encrypted-at-rest
    /// share container).
    fn ingress_state_file_name() -> &'static str {
        "mpcca_withdraw_v2_ingress.json"
    }

    /// Persist the M1 IngressStateFile to disk with mode 0o600. The file does NOT contain
    /// plaintext shares — only public commitments + the at-rest HPKE envelope.
    pub(crate) fn persist_ingress_state(
        session_dir: &Path,
        file: &IngressStateFile,
    ) -> WorkerResult<()> {
        let path = session_dir.join(ingress_state_file_name());
        let json = serde_json::to_string_pretty(file)
            .map_err(|err| WorkerError::Serde(err.to_string()))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, json.as_bytes()).map_err(|err| WorkerError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, permissions)
                .map_err(|err| WorkerError::Io(err.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(())
    }

    /// Test-friendly HPKE seal helper. Wraps `hpke_aead::seal` so integration tests + local
    /// smoke scripts can build wire-valid `ingress_envelopes` against a known worker pubkey
    /// without depending on internal module visibility. The `info` argument MUST be
    /// `HPKE_INFO_INGRESS` for envelopes the worker will decrypt under M1 ingress; using any
    /// other info string causes HPKE open to fail and surfaces `ingress_hpke_decrypt_failed`.
    pub fn seal_ingress_envelope_for_test(
        recipient_public_key_hex: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> WorkerResult<HpkeEnvelope> {
        hpke_aead::seal(recipient_public_key_hex, HPKE_INFO_INGRESS, aad, plaintext)
    }

    // =============================================================================================
    // M4 Commit 1 — round2 helpers (dk-component threshold contribution)
    // =============================================================================================

    /// Normalised public Aptos CA TransferV1 Statement input fields, validated for canonical
    /// 32-byte Ristretto compression and the canonical {ell=8, n=4} vector lengths.
    struct Round2StatementInputs {
        recipient_ek: String,
        old_balance_c: Vec<String>,
        old_balance_d: Vec<String>,
        new_balance_c: Vec<String>,
        new_balance_d: Vec<String>,
        transfer_amount_c: Vec<String>,
        transfer_amount_d_sender: Vec<String>,
        transfer_amount_d_recipient: Vec<String>,
    }

    fn normalise_round2_statement_inputs(req: &Round2Request) -> WorkerResult<Round2StatementInputs> {
        normalise_round2_statement_inputs_from_parts(
            &req.recipient_ek,
            &req.old_balance_c,
            &req.old_balance_d,
            &req.new_balance_c,
            &req.new_balance_d,
            &req.transfer_amount_c,
            &req.transfer_amount_d_sender,
            &req.transfer_amount_d_recipient,
        )
    }

    /// M4 Commit 3 — share the Statement-inputs normalisation between Round2Request and
    /// FinalizeRequest. Both rounds carry the same canonical Aptos CA TransferV1 Statement
    /// input fields; if a malicious coordinator sends different Statement inputs at finalize
    /// than at round2, the recomputed round2 worker_transcript_hash (built from finalize's
    /// inputs) won't match the `previousRoundTranscriptHash` and the worker fails closed.
    #[allow(clippy::too_many_arguments)]
    fn normalise_round2_statement_inputs_from_parts(
        recipient_ek: &str,
        old_balance_c: &[String],
        old_balance_d: &[String],
        new_balance_c: &[String],
        new_balance_d: &[String],
        transfer_amount_c: &[String],
        transfer_amount_d_sender: &[String],
        transfer_amount_d_recipient: &[String],
    ) -> WorkerResult<Round2StatementInputs> {
        let recipient_ek = normalize_hex(recipient_ek, 32)
            .map_err(|err| WorkerError::InvalidRequest(format!("round2 recipient_ek: {err:?}")))?;
        let old_balance_c = normalise_round2_hex_vec(old_balance_c, ROUND2_ELL, "old_balance_c")?;
        let old_balance_d = normalise_round2_hex_vec(old_balance_d, ROUND2_ELL, "old_balance_d")?;
        let new_balance_c = normalise_round2_hex_vec(new_balance_c, ROUND2_ELL, "new_balance_c")?;
        let new_balance_d = normalise_round2_hex_vec(new_balance_d, ROUND2_ELL, "new_balance_d")?;
        let transfer_amount_c =
            normalise_round2_hex_vec(transfer_amount_c, ROUND2_N, "transfer_amount_c")?;
        let transfer_amount_d_sender =
            normalise_round2_hex_vec(transfer_amount_d_sender, ROUND2_N, "transfer_amount_d_sender")?;
        let transfer_amount_d_recipient = normalise_round2_hex_vec(
            transfer_amount_d_recipient,
            ROUND2_N,
            "transfer_amount_d_recipient",
        )?;
        Ok(Round2StatementInputs {
            recipient_ek,
            old_balance_c,
            old_balance_d,
            new_balance_c,
            new_balance_d,
            transfer_amount_c,
            transfer_amount_d_sender,
            transfer_amount_d_recipient,
        })
    }

    /// Normalise the Statement input fields carried by a FinalizeRequest. Calls
    /// `normalise_round2_statement_inputs_from_parts` so the byte-shape rules are byte-identical
    /// to round2 (and the canonical hash matches the round2 worker_transcript_hash binding).
    fn normalise_finalize_statement_inputs(
        req: &FinalizeRequest,
    ) -> WorkerResult<Round2StatementInputs> {
        normalise_round2_statement_inputs_from_parts(
            &req.recipient_ek,
            &req.old_balance_c,
            &req.old_balance_d,
            &req.new_balance_c,
            &req.new_balance_d,
            &req.transfer_amount_c,
            &req.transfer_amount_d_sender,
            &req.transfer_amount_d_recipient,
        )
    }

    fn normalise_round2_hex_vec(
        items: &[String],
        expected_len: usize,
        label: &'static str,
    ) -> WorkerResult<Vec<String>> {
        if items.len() != expected_len {
            return Err(WorkerError::InvalidRequest(format!(
                "round2 {label}: expected {expected_len} entries, got {}",
                items.len()
            )));
        }
        let mut out = Vec::with_capacity(expected_len);
        for (i, hex) in items.iter().enumerate() {
            let norm = normalize_hex(hex, 32).map_err(|err| {
                WorkerError::InvalidRequest(format!("round2 {label}[{i}]: {err:?}"))
            })?;
            out.push(norm);
        }
        Ok(out)
    }

    /// Canonical sha256 hex of the normalised Round2 Statement input fields. Byte-equal
    /// across TS↔Rust so the coordinator's worker_transcript_hash cross-check holds.
    ///
    /// Layout (utf8 bytes, then sha256):
    /// ```text
    /// recipient_ek_hex
    /// || ":" || old_balance_c[0]|...|old_balance_c[7]
    /// || ":" || old_balance_d[0]|...|old_balance_d[7]
    /// || ":" || new_balance_c[0]|...|new_balance_c[7]
    /// || ":" || new_balance_d[0]|...|new_balance_d[7]
    /// || ":" || transfer_amount_c[0]|...|transfer_amount_c[3]
    /// || ":" || transfer_amount_d_sender[0]|...|transfer_amount_d_sender[3]
    /// || ":" || transfer_amount_d_recipient[0]|...|transfer_amount_d_recipient[3]
    /// ```
    fn statement_inputs_hash_hex(inputs: &Round2StatementInputs) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(inputs.recipient_ek.as_bytes());
        for group in [
            &inputs.old_balance_c,
            &inputs.old_balance_d,
            &inputs.new_balance_c,
            &inputs.new_balance_d,
            &inputs.transfer_amount_c,
            &inputs.transfer_amount_d_sender,
            &inputs.transfer_amount_d_recipient,
        ] {
            bytes.push(b':');
            let joined = group.join("|");
            bytes.extend_from_slice(joined.as_bytes());
        }
        sha256_hex(&bytes)
    }

    /// Round 2 (M4 commit 1) worker_transcript_hash = sha256(chained_hash || ":" || statement_inputs_hash).
    /// Byte-equal across TS↔Rust.
    fn round2_v2_worker_transcript_hash(chained_hash_hex: &str, statement_inputs_hash_hex: &str) -> String {
        let mut bytes = Vec::with_capacity(chained_hash_hex.len() + 1 + statement_inputs_hash_hex.len());
        bytes.extend_from_slice(chained_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(statement_inputs_hash_hex.as_bytes());
        sha256_hex(&bytes)
    }

    /// Canonical sha256 hex over the 30-entry aggregated sigma commitment vector. Each entry
    /// is the normalised 32-byte hex string; entries are joined by `|`. Byte-equal across
    /// TS↔Rust so the coordinator's per-worker transcript hash cross-check holds.
    fn aggregated_sigma_commitments_hash_hex(commitments_hex: &[String]) -> String {
        let joined = commitments_hex.join("|");
        sha256_hex(joined.as_bytes())
    }

    /// Finalize (M4 commit 3) worker_transcript_hash. Binds:
    ///   - the chained-round hash under the FINALIZE domain
    ///   - the Statement-inputs hash (same hash function as round2)
    ///   - the aggregated 30-point commitment vector hash
    ///   - the coordinator-supplied Fiat-Shamir challenge `e`
    ///
    /// Layout:
    ///   sha256(chained_hash || ":" || statement_inputs_hash || ":" || aggregated_commitments_hash || ":" || challenge_hex)
    fn finalize_v2_worker_transcript_hash(
        chained_hash_hex: &str,
        statement_inputs_hash_hex: &str,
        aggregated_commitments_hash_hex: &str,
        challenge_hex: &str,
    ) -> String {
        let mut bytes = Vec::with_capacity(
            chained_hash_hex.len()
                + 1
                + statement_inputs_hash_hex.len()
                + 1
                + aggregated_commitments_hash_hex.len()
                + 1
                + challenge_hex.len(),
        );
        bytes.extend_from_slice(chained_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(statement_inputs_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(aggregated_commitments_hash_hex.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(challenge_hex.as_bytes());
        sha256_hex(&bytes)
    }

    /// Test-friendly helper so TS↔Rust byte-parity tests can drive the finalize binding
    /// hashing without exposing internal structs.
    pub fn finalize_v2_worker_transcript_hash_hex_for_test(
        chained_hash_hex: &str,
        statement_inputs_hash_hex: &str,
        aggregated_commitments_hash_hex: &str,
        challenge_hex: &str,
    ) -> String {
        finalize_v2_worker_transcript_hash(
            chained_hash_hex,
            statement_inputs_hash_hex,
            aggregated_commitments_hash_hex,
            challenge_hex,
        )
    }

    /// Build the Aptos CA TransferV1 sigma-protocol DomainSeparator from public binding
    /// fields. The DomainSeparator's `session_id` is the BCS-serialised TransferSession
    /// (sender || recipient || asset || ell || n || has_effective_auditor=false ||
    /// num_volun_auditors=0). The constants `APTOS_FRAMEWORK_ADDRESS` and `PROTOCOL_ID`
    /// come from `transfer_sigma_reference` and are locked to Aptos SDK 1.1.1.
    fn build_finalize_domain_separator(
        sender_address_hex: &str,
        recipient_hex: &str,
        asset_type_hex: &str,
        chain_id: u8,
    ) -> WorkerResult<DomainSeparator> {
        let sender = hex_to_bytes32(sender_address_hex)?;
        let recipient = hex_to_bytes32(recipient_hex)?;
        let asset = hex_to_bytes32(asset_type_hex)?;
        let session = bcs_serialize_transfer_session(
            &sender,
            &recipient,
            &asset,
            ROUND2_ELL as u64,
            ROUND2_N as u64,
            false,
            0,
        );
        Ok(DomainSeparator {
            contract_address: APTOS_FRAMEWORK_ADDRESS,
            chain_id,
            protocol_id: PROTOCOL_ID.as_bytes().to_vec(),
            session_id: session,
        })
    }

    /// Validate + normalise the coordinator-supplied 30-point aggregated commitment vector.
    /// Asserts: length == 30, every entry is a canonical 32-byte compressed Ristretto hex,
    /// every entry decompresses successfully, no entry is the identity point (defense-in-depth
    /// — psi_transfer outputs are never identity unless the witness is zero, which is
    /// independently zero-rejected).
    fn normalise_aggregated_sigma_commitments(items: &[String]) -> WorkerResult<Vec<String>> {
        if items.len() != COMMITMENT_LEN {
            return Err(WorkerError::InvalidRequest(format!(
                "aggregated_sigma_commitments must have exactly {COMMITMENT_LEN} entries, got {}",
                items.len()
            )));
        }
        let mut out = Vec::with_capacity(COMMITMENT_LEN);
        for (i, hex) in items.iter().enumerate() {
            let norm = normalize_hex(hex, 32).map_err(|err| {
                WorkerError::InvalidRequest(format!(
                    "aggregated_sigma_commitments[{i}]: {err:?}"
                ))
            })?;
            let bytes = hex_to_bytes32(&norm)?;
            let pt = CompressedRistretto(bytes).decompress().ok_or_else(|| {
                WorkerError::InvalidRequest(format!(
                    "aggregated_sigma_commitments[{i}] is not a valid compressed Ristretto point"
                ))
            })?;
            if pt == RistrettoPoint::identity() {
                return Err(WorkerError::InvalidRequest(format!(
                    "aggregated_sigma_commitments[{i}] is the identity element"
                )));
            }
            out.push(norm);
        }
        Ok(out)
    }

    /// Decompress an already-normalised 30-entry compressed-hex commitment vector to
    /// `[u8; 32]` entries for `bcs_fiat_shamir_inputs`.
    fn decode_aggregated_commitments_bytes(
        normalised: &[String],
    ) -> WorkerResult<Vec<[u8; 32]>> {
        normalised
            .iter()
            .map(|hex| hex_to_bytes32(hex))
            .collect()
    }

    /// Build the public Statement for the Aptos CA TransferV1 sigma protocol from the normalised
    /// Round2 inputs. `sender_ek_hex` is the binding's vault_ek (already validated upstream).
    fn build_round2_statement(
        inputs: &Round2StatementInputs,
        sender_ek_hex: &str,
    ) -> WorkerResult<Statement> {
        let sender_ek = hex_to_bytes32(sender_ek_hex)?;
        let recipient_ek = hex_to_bytes32(&inputs.recipient_ek)?;
        let old_balance_c = hex_vec_to_bytes32_vec(&inputs.old_balance_c)?;
        let old_balance_d = hex_vec_to_bytes32_vec(&inputs.old_balance_d)?;
        let new_balance_c = hex_vec_to_bytes32_vec(&inputs.new_balance_c)?;
        let new_balance_d = hex_vec_to_bytes32_vec(&inputs.new_balance_d)?;
        let transfer_amount_c = hex_vec_to_bytes32_vec(&inputs.transfer_amount_c)?;
        let transfer_amount_d_sender = hex_vec_to_bytes32_vec(&inputs.transfer_amount_d_sender)?;
        let transfer_amount_d_recipient =
            hex_vec_to_bytes32_vec(&inputs.transfer_amount_d_recipient)?;
        let statement_inputs = TransferStatementInputs {
            sender_ek,
            recipient_ek,
            old_balance_c,
            old_balance_d,
            new_balance_c,
            new_balance_d,
            transfer_amount_c,
            transfer_amount_d_sender,
            transfer_amount_d_recipient,
        };
        build_statement(&statement_inputs)
    }

    fn hex_to_bytes32(hex: &str) -> WorkerResult<[u8; 32]> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != 32 {
            return Err(WorkerError::InvalidRequest(format!(
                "expected 32-byte hex, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    fn hex_vec_to_bytes32_vec(items: &[String]) -> WorkerResult<Vec<[u8; 32]>> {
        let mut out = Vec::with_capacity(items.len());
        for hex in items {
            out.push(hex_to_bytes32(hex)?);
        }
        Ok(out)
    }

    /// Canonical Ed25519 scalar decoder (rejects non-canonical encodings). Distinct name from
    /// `scalar_from_hex` in other modules to avoid cross-module symbol confusion.
    fn scalar_from_hex_local(hex: &str) -> WorkerResult<Scalar> {
        let bytes = hex_to_bytes32(hex)?;
        let opt = Scalar::from_canonical_bytes(bytes);
        if opt.is_none().into() {
            return Err(WorkerError::InvalidRequest(
                "non-canonical Ed25519 scalar".to_string(),
            ));
        }
        Ok(opt.unwrap())
    }

    /// CSPRNG-backed nonzero scalar. Rejection-samples zero; in practice the rejection branch
    /// never fires (probability ~2^-252) but the loop guarantees the guarantee.
    fn generate_nonzero_scalar(rng: &mut OsRng) -> Scalar {
        loop {
            let s = Scalar::random(rng);
            if s != Scalar::ZERO {
                return s;
            }
        }
    }

    /// AAD for the round2 at-rest HPKE seal. Binds `(scheme, sessionId, requestId, selfSlot)`
    /// so the at-rest envelope cannot be misrouted across sessions.
    fn round2_at_rest_aad(session_id: &str, request_id: &str, self_slot: usize) -> Vec<u8> {
        format!(
            "scheme=mpcca_withdraw_v2_round2|session={session_id}|request={request_id}|slot={self_slot}"
        )
        .into_bytes()
    }

    /// Seal `α_share_j[0]` under the slot's own HPKE pubkey with the round2 at-rest AAD.
    /// Returns the envelope ready for `Round2StateFile.encrypted_alpha_envelope`. The caller
    /// MUST zeroize the stack-frame copy of α after this returns.
    fn seal_round2_alpha_at_rest(
        keypair: &HpkeKeypairFile,
        session_id: &str,
        request_id: &str,
        self_slot: usize,
        alpha: &Scalar,
    ) -> WorkerResult<HpkeEnvelope> {
        let mut plaintext = Vec::with_capacity(32);
        plaintext.extend_from_slice(&alpha.to_bytes());
        let aad = round2_at_rest_aad(session_id, request_id, self_slot);
        let env = hpke_aead::seal(&keypair.public_key, HPKE_INFO_ROUND2_AT_REST, &aad, &plaintext)?;
        plaintext.zeroize();
        Ok(env)
    }

    /// Per-session file name for the M4 commit-1 round2 dk-state file.
    fn round2_dk_state_file_name() -> &'static str {
        "mpcca_withdraw_v2_round2_dk.json"
    }

    /// Persist the Round2StateFile to disk with mode 0o600. The file holds only public
    /// partial commitments + an HPKE-encrypted-at-rest envelope sealing `α_share_j[0]`.
    fn persist_round2_dk_state(
        session_dir: &Path,
        file: &Round2StateFile,
    ) -> WorkerResult<()> {
        let path = session_dir.join(round2_dk_state_file_name());
        let json = serde_json::to_string_pretty(file)
            .map_err(|err| WorkerError::Serde(err.to_string()))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, json.as_bytes()).map_err(|err| WorkerError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, permissions)
                .map_err(|err| WorkerError::Io(err.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(())
    }

    /// Per-session file name for the M4 commit-3 finalize binding pin.
    fn finalize_pin_file_name() -> &'static str {
        "mpcca_withdraw_v2_finalize_pin.json"
    }

    /// Persist the finalize binding pin via atomic-no-clobber. The pin is written BEFORE
    /// any secret material is loaded; if a second finalize call arrives with a different
    /// `(aggregated_commitments_hash, challenge_hex)` for the same `(request_id, session_id,
    /// slot)`, the no-clobber gate fails closed with
    /// `mpcca_withdraw_v2_finalize_pin_already_exists_with_different_content` and α-share is
    /// NEVER touched.
    fn persist_finalize_pin(session_dir: &Path, pin: &FinalizePinFile) -> WorkerResult<()> {
        let path = session_dir.join(finalize_pin_file_name());
        let bytes = serde_json::to_vec_pretty(pin).map_err(|err| {
            WorkerError::Crypto(format!("encode mpcca_withdraw_v2 finalize pin: {err}"))
        })?;
        crate::atomic_io::write_atomic_no_clobber(
            &path,
            &bytes,
            "mpcca_withdraw_v2_finalize_pin",
        )
    }

    /// Convenience read API for tests + replay-idempotency probes. Returns None if no
    /// finalize pin file exists at the per-session path.
    pub fn load_finalize_pin_file(
        session_dir: &Path,
    ) -> WorkerResult<Option<FinalizePinFile>> {
        let path = session_dir.join(finalize_pin_file_name());
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|err| {
            WorkerError::Crypto(format!("read finalize pin {}: {err}", path.display()))
        })?;
        let existing: FinalizePinFile = serde_json::from_slice(&raw).map_err(|err| {
            WorkerError::Crypto(format!("parse finalize pin {}: {err}", path.display()))
        })?;
        if existing.scheme != "mpcca_withdraw_v2_finalize_pin" {
            return Err(WorkerError::InvalidDkgState(
                "mpcca_withdraw_v2_finalize_pin_unexpected_scheme_on_disk".to_string(),
            ));
        }
        Ok(Some(existing))
    }

    /// Convenience read API for tests + M4 commit-3 finalize. Returns None if no round2
    /// dk-state file exists at the per-session path.
    pub fn load_round2_dk_state_file(
        session_dir: &Path,
    ) -> WorkerResult<Option<Round2StateFile>> {
        let path = session_dir.join(round2_dk_state_file_name());
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|err| {
            WorkerError::Crypto(format!("read mpcca round2 dk state {}: {err}", path.display()))
        })?;
        let existing: Round2StateFile = serde_json::from_slice(&raw).map_err(|err| {
            WorkerError::Crypto(format!(
                "parse mpcca round2 dk state {}: {err}",
                path.display()
            ))
        })?;
        if existing.scheme != "mpcca_withdraw_v2_round2_dk" {
            return Err(WorkerError::InvalidDkgState(
                "mpcca_withdraw_v2_round2_dk_unexpected_scheme_on_disk".to_string(),
            ));
        }
        Ok(Some(existing))
    }

    /// Test-friendly Round2 statement-inputs hash builder so TS↔Rust byte-parity tests can
    /// invoke the canonical hashing without exposing the internal struct.
    pub fn round2_statement_inputs_hash_hex_for_test(
        recipient_ek_hex: &str,
        old_balance_c: &[String],
        old_balance_d: &[String],
        new_balance_c: &[String],
        new_balance_d: &[String],
        transfer_amount_c: &[String],
        transfer_amount_d_sender: &[String],
        transfer_amount_d_recipient: &[String],
    ) -> WorkerResult<String> {
        let inputs = Round2StatementInputs {
            recipient_ek: normalize_hex(recipient_ek_hex, 32)?,
            old_balance_c: normalise_round2_hex_vec(old_balance_c, ROUND2_ELL, "old_balance_c")?,
            old_balance_d: normalise_round2_hex_vec(old_balance_d, ROUND2_ELL, "old_balance_d")?,
            new_balance_c: normalise_round2_hex_vec(new_balance_c, ROUND2_ELL, "new_balance_c")?,
            new_balance_d: normalise_round2_hex_vec(new_balance_d, ROUND2_ELL, "new_balance_d")?,
            transfer_amount_c: normalise_round2_hex_vec(
                transfer_amount_c,
                ROUND2_N,
                "transfer_amount_c",
            )?,
            transfer_amount_d_sender: normalise_round2_hex_vec(
                transfer_amount_d_sender,
                ROUND2_N,
                "transfer_amount_d_sender",
            )?,
            transfer_amount_d_recipient: normalise_round2_hex_vec(
                transfer_amount_d_recipient,
                ROUND2_N,
                "transfer_amount_d_recipient",
            )?,
        };
        Ok(statement_inputs_hash_hex(&inputs))
    }

    /// Test-friendly AAD builder. Re-exports the canonical AAD construction so integration
    /// tests can build the exact bytes used by `decrypt_and_verify_ingress_share`.
    #[allow(clippy::too_many_arguments)]
    pub fn m1_ingress_aad_for_test(
        request_id: &str,
        session_id: &str,
        dkg_epoch: &str,
        self_slot: usize,
        player_id: usize,
        roster_hash_hex: &str,
        vault_ek_hex: &str,
        root_hex: &str,
        nullifier_hash_hex: &str,
        recipient_hash_hex: &str,
        amount_tag_hex: &str,
        vault_sequence: u64,
        deposit_count: u64,
        amount_commitment_hex: &str,
        per_share_commitments_hex: &[String],
    ) -> Vec<u8> {
        m1_ingress_aad(
            request_id,
            session_id,
            dkg_epoch,
            self_slot,
            player_id,
            roster_hash_hex,
            vault_ek_hex,
            root_hex,
            nullifier_hash_hex,
            recipient_hash_hex,
            amount_tag_hex,
            vault_sequence,
            deposit_count,
            amount_commitment_hex,
            per_share_commitments_hex,
        )
    }

    /// Load the persisted M1 ingress state file (public-binding view only; secret bytes stay
    /// inside the HPKE envelope).
    pub fn load_ingress_state_file(session_dir: &Path) -> WorkerResult<Option<IngressStateFile>> {
        let path = session_dir.join(ingress_state_file_name());
        match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str::<IngressStateFile>(&s)
                .map(Some)
                .map_err(|err| WorkerError::Serde(err.to_string())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(WorkerError::Io(err.to_string())),
        }
    }

    /// Validate the wire shape of the M1 ingress fields:
    /// - per_share_commitments length == DEOPERATOR_THRESHOLD, each entry 32-byte hex
    /// - ingress_envelopes length == DEOPERATOR_THRESHOLD, each via hpke_aead::validate
    /// - amount_commitment is 32-byte hex
    /// Returns the normalised hex strings (lower-cased, no `0x` prefix) + the canonical
    /// ingress_envelopes_hash.
    pub(crate) fn normalise_ingress_fields(
        amount_commitment: &str,
        per_share_commitments: &[String],
        ingress_envelopes: &[HpkeEnvelope],
    ) -> WorkerResult<NormalisedIngress> {
        if per_share_commitments.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "per_share_commitments must have exactly {} entries, got {}",
                DEOPERATOR_THRESHOLD,
                per_share_commitments.len()
            )));
        }
        if ingress_envelopes.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "ingress_envelopes must have exactly {} entries, got {}",
                DEOPERATOR_THRESHOLD,
                ingress_envelopes.len()
            )));
        }
        let amount_commitment_norm = normalize_hex(amount_commitment, 32)?;
        let mut per_share_norm = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for (i, c) in per_share_commitments.iter().enumerate() {
            let n = normalize_hex(c, 32).map_err(|_| {
                WorkerError::InvalidRequest(format!(
                    "per_share_commitments[{i}] must be 32-byte hex (compressed Ristretto)"
                ))
            })?;
            per_share_norm.push(n);
        }
        for (i, env) in ingress_envelopes.iter().enumerate() {
            crate::hpke_aead::validate(env).map_err(|e| {
                WorkerError::InvalidRequest(format!(
                    "ingress_envelopes[{i}] failed HPKE shape validation: {e:?}"
                ))
            })?;
        }
        let ingress_envelopes_hash_hex = ingress_envelopes_hash(ingress_envelopes)?;
        Ok(NormalisedIngress {
            amount_commitment: amount_commitment_norm,
            per_share_commitments: per_share_norm,
            ingress_envelopes: ingress_envelopes.to_vec(),
            ingress_envelopes_hash: ingress_envelopes_hash_hex,
        })
    }

    /// Milestone 1 round1 worker entrypoint. Runs the full public binding gate, then validates
    /// M1 ingress envelope wire shape, then performs the M1 ingress crypto:
    ///   1. Load self HPKE keypair from state_dir.
    ///   2. Build AAD bytes (m1_ingress_aad) and HPKE-decrypt envelope[player_id].
    ///   3. Decode `(a_j, b_j)` from canonical Ed25519 scalar bytes; reject non-canonical.
    ///   4. Reject zero shares (a_j == 0 OR b_j == 0).
    ///   5. Verify `G·a_j + H·b_j == per_share_commitments[player_id]`; reject mismatch.
    ///   6. Seal `(a_j || b_j)` at-rest under self HPKE pubkey with at-rest AAD.
    ///   7. Persist `mpcca_withdraw_v2_ingress.json` (public commitments + at-rest envelope only).
    ///   8. Persist `mpcca_withdraw_v2_round1.json` carrying the V2 worker_transcript_hash.
    ///   9. Return `Ok(Round1IngressResult { completed: true, ingress_transcript_hash: ... })`.
    /// Any failure surfaces a SPECIFIC Crypto/InvalidRequest error and persists nothing.
    pub fn run_round1_v2(
        state_dir: &Path,
        req: &Round1Request,
    ) -> WorkerResult<Round1IngressResult> {
        let (normalised, _existing, session_dir) =
            common_public_binding_work(state_dir, req)?;
        let ingress = normalise_ingress_fields(
            &req.amount_commitment,
            &req.per_share_commitments,
            &req.ingress_envelopes,
        )?;
        let worker_transcript_hash = round1_worker_transcript_hash(
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &normalised.vault_ek_transcript_hash,
            &normalised.registration_transcript_hash,
            &normalised.vault_state_init_transcript_hash,
            &normalised.observed_deposit_transcript_hashes,
            &normalised.roster_hash,
            &normalised.sorted,
            req.self_slot,
            req.player_id,
            &normalised.vault_ek_hex,
            &normalised.sender_address,
            &normalised.asset_type,
            req.chain_id,
            &normalised.root,
            &normalised.nullifier_hash,
            &normalised.recipient,
            &normalised.recipient_hash,
            &normalised.amount_tag,
            req.vault_sequence,
            req.expiry_secs,
            &normalised.request_hash,
            req.deposit_count,
            &ingress.amount_commitment,
            &ingress.per_share_commitments,
            &ingress.ingress_envelopes_hash,
        );

        // Load HPKE keypair for self_slot.
        let keypair = load_hpke_keypair_for_slot(state_dir, req.self_slot)?;

        // Build M1 AAD bytes.
        let aad = m1_ingress_aad(
            &req.request_id,
            &req.session_id,
            &req.dkg_epoch,
            req.self_slot,
            req.player_id,
            &normalised.roster_hash,
            &normalised.vault_ek_hex,
            &normalised.root,
            &normalised.nullifier_hash,
            &normalised.recipient_hash,
            &normalised.amount_tag,
            req.vault_sequence,
            req.deposit_count,
            &ingress.amount_commitment,
            &ingress.per_share_commitments,
        );

        // Decrypt + verify the M1 ingress share for this slot.
        let envelope = &ingress.ingress_envelopes[req.player_id];
        let per_share_commitment_hex = &ingress.per_share_commitments[req.player_id];
        let (mut a, mut b) =
            decrypt_and_verify_ingress_share(&keypair, envelope, per_share_commitment_hex, &aad)?;

        // Seal the share at-rest under self HPKE pubkey.
        let encrypted_share_envelope = seal_ingress_at_rest(
            &keypair,
            &req.session_id,
            &req.request_id,
            req.self_slot,
            &a,
            &b,
        )?;
        // Stack-frame zeroize: drop the plaintext share now that it's been sealed at rest.
        a.zeroize();
        b.zeroize();

        // Persist the ingress state file (public commitments + at-rest envelope only).
        let ingress_file = IngressStateFile {
            scheme: "mpcca_withdraw_v2_ingress".to_string(),
            slot: req.self_slot,
            player_id: req.player_id,
            dkg_epoch: req.dkg_epoch.clone(),
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            amount_commitment: ingress.amount_commitment.clone(),
            per_share_commitments: ingress.per_share_commitments.clone(),
            encrypted_share_envelope,
            created_at_unix_ms: now_millis_local(),
        };
        // Create the session dir before writing.
        fs::create_dir_all(&session_dir).map_err(|err| WorkerError::Io(err.to_string()))?;
        persist_ingress_state(&session_dir, &ingress_file)?;

        // Persist the round1 state file (M1 success: completed = true, no NotImplemented phase).
        let session_state_path = persist_round_completed(
            &session_dir,
            "round1",
            req.self_slot,
            req.player_id,
            &req.dkg_epoch,
            &req.request_id,
            &req.session_id,
            &normalised.vault_ek_hex,
            req.vault_sequence,
            req.deposit_count,
            &worker_transcript_hash,
            &normalised.observed_deposit_transcript_hashes,
        )?;

        let session_state_hash = file_sha256_hex(&session_state_path)?;
        Ok(Round1IngressResult {
            slot: req.self_slot,
            player_id: req.player_id,
            session_state_path: session_state_path.display().to_string(),
            session_state_hash,
            worker_transcript_hash: worker_transcript_hash.clone(),
            observed_at_unix_ms: now_millis_local(),
            completed: true,
            ingress_transcript_hash: worker_transcript_hash,
        })
    }

    /// Local now-millis helper. The crate-root `now_millis` is private to ca_dkg_v2.
    fn now_millis_local() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    /// sha256 of a file's contents, hex-encoded.
    fn file_sha256_hex(path: &Path) -> WorkerResult<String> {
        let bytes = fs::read(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Persist a per-round RoundStateFile (M3a-shape compat) with `completed: true`
    /// (i.e. `not_implemented_phase = ""`). Returns the absolute path.
    ///
    /// Used by both M1 round1 (ingress) and M4 commit-1 round2 (dk-threshold). Each round's
    /// distinct phase semantics live in its own dedicated state file (e.g. IngressStateFile
    /// for round1, Round2StateFile for round2); this RoundStateFile carries only the public
    /// binding metadata that M3a's coordinator cross-check reads.
    #[allow(clippy::too_many_arguments)]
    fn persist_round_completed(
        session_dir: &Path,
        round_name: &str,
        self_slot: usize,
        player_id: usize,
        dkg_epoch: &str,
        request_id: &str,
        session_id: &str,
        vault_ek_hex: &str,
        vault_sequence: u64,
        deposit_count: u64,
        worker_transcript_hash: &str,
        observed_deposit_transcript_hashes: &[String],
    ) -> WorkerResult<PathBuf> {
        let file = RoundStateFile {
            scheme: "mpcca_withdraw_v2".to_string(),
            round: round_name.to_string(),
            slot: self_slot,
            player_id,
            dkg_epoch: dkg_epoch.to_string(),
            request_id: request_id.to_string(),
            session_id: session_id.to_string(),
            vault_ek_hex: vault_ek_hex.to_string(),
            vault_sequence,
            deposit_count,
            worker_transcript_hash: worker_transcript_hash.to_string(),
            // Empty string sentinel for "round completed, no NotImplemented phase".
            not_implemented_phase: String::new(),
            created_at_unix_ms: now_millis_local(),
            observed_deposit_transcript_hashes: observed_deposit_transcript_hashes.to_vec(),
        };
        let path = session_dir.join(round_file_name(round_name));
        let json =
            serde_json::to_string_pretty(&file).map_err(|err| WorkerError::Serde(err.to_string()))?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, json.as_bytes()).map_err(|err| WorkerError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, permissions)
                .map_err(|err| WorkerError::Io(err.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|err| WorkerError::Io(err.to_string()))?;
        Ok(path)
    }

    /// Round 2 entrypoint (M4 Commit 1) — dk-component threshold contribution.
    ///
    /// Worker contract:
    ///   1. Run the shared chained-round public binding (sigma re-verify, provenance gate,
    ///      vault_sequence gate, observed-deposit ordering enforcement).
    ///   2. Validate the user-supplied Aptos CA TransferV1 Statement input fields
    ///      (recipient_ek + 6 ciphertext vectors of the canonical lengths {8, 8, 8, 8, 4, 4, 4}).
    ///   3. Compute the round2 worker_transcript_hash that binds the base chained envelope
    ///      AND the Statement input fields (defense-in-depth: a tampered ciphertext at round2
    ///      changes the per-slot hash and the coordinator's cross-check rejects it).
    ///   4. Load `ca_dkg_share_v2.json` and validate `(slot, dkg_epoch)` match the request.
    ///   5. Recompute Lagrange λ_j at x=0 over sorted selectedSlots.
    ///   6. Build the public Statement from the request fields.
    ///   7. Programmatically derive BASE_DK_SET via `derive_dk_base_points` (psi_transfer
    ///      inspection over the unit witness vector α=[1,0,...,0]).
    ///   8. Generate `α_share_j[0]: Scalar` via CSPRNG. Zero-reject (goal.md decision #9).
    ///   9. For each (idx, base) in BASE_DK_SET, compute `α_share_j[0] · base` →
    ///      `partial_dk_commitments[idx]`. These aggregate (across the 5 selected workers)
    ///      into the dk-component of the full sigma commitment vector A.
    ///   10. HPKE-seal `α_share_j[0]` at-rest under the worker's own HPKE pubkey, with
    ///       info `EUNOMA_M4_ROUND2_AT_REST_V1` and AAD binding session/request/slot.
    ///       Zeroize the stack-frame copy of α_share_j[0] immediately after sealing.
    ///   11. Persist `mpcca_withdraw_v2_round2_dk.json` (public partials + at-rest envelope).
    ///   12. Persist `mpcca_withdraw_v2_round2.json` (RoundStateFile, completed=true).
    ///   13. Return `Round2DkResult` with the partial commitments and indices used.
    ///
    /// Privacy contract: `α_share_j[0]` NEVER appears in plaintext on disk; no plaintext
    /// witness component (chunks, amount, balance) reaches the worker. `dk_share_j` is
    /// read from disk and used in computing the worker's Lagrange-weighted dk-contribution
    /// only at M4 commit 3 (finalize). At commit 1 (round2), we only need the public bases
    /// derived from the Statement.
    pub fn run_round2_v2(
        state_dir: &Path,
        req: &Round2Request,
    ) -> WorkerResult<Round2DkResult> {
        // 1. Shared chained-round public binding.
        let binding = chained_round_public_binding(state_dir, &req.base)?;

        // 2. Validate Statement input fields (lengths + 32-byte hex canonicalisation).
        let stmt_inputs = normalise_round2_statement_inputs(req)?;

        // 3. Compute round2 worker_transcript_hash: base chained hash + Statement-inputs hash.
        let statement_inputs_hash_hex = statement_inputs_hash_hex(&stmt_inputs);
        let worker_transcript_hash =
            round2_v2_worker_transcript_hash(&binding.chained_hash, &statement_inputs_hash_hex);

        // 4. Load ca_dkg_share_v2.json + slot/dkg_epoch validation.
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.base.self_slot {
            return Err(WorkerError::InvalidDkgState(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.base.self_slot
            )));
        }
        if share.dkg_epoch != req.base.dkg_epoch {
            return Err(WorkerError::InvalidDkgState(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.base.dkg_epoch
            )));
        }
        // dk_share_j is loaded and verified by load_ca_dkg_v2_share (Pedersen-share verify).
        // We don't use it at round2 (only the public Lagrange coefficient is bound here for
        // defense-in-depth — M4 commit 3 will consume dk_share_j × λ_j in the response share).
        // Trigger the secret-byte read to surface a "missing share" failure here rather than
        // at finalize where rolling back is harder.
        let _dk_share_scalar = scalar_from_hex_local(&share.dk_share)
            .map_err(|_| WorkerError::Crypto("round2_dk_share_non_canonical".to_string()))?;

        // 5. Recompute Lagrange λ_j over sorted selectedSlots — sanity that the polynomial
        // is well-defined for the selected quorum (we don't use λ_j at round2 directly, but
        // failing here is preferable to surfacing the same problem at finalize).
        let lambdas = lagrange_coefficients_at_zero(&binding.normalised.sorted)?;
        let lambda_j = lambdas[req.base.player_id];
        if lambda_j == Scalar::ZERO {
            // Mathematically impossible for distinct slot ids in [0..7) but defends against
            // future refactors that mis-thread the player_id ↔ slot mapping.
            return Err(WorkerError::Crypto(
                "round2_lagrange_coefficient_zero".to_string(),
            ));
        }
        let _ = lambda_j; // used in commit 3, not commit 1

        // 6. Build the public Statement from request fields.
        let statement = build_round2_statement(&stmt_inputs, &binding.normalised.vault_ek_hex)?;

        // 7. Programmatically derive BASE_DK_SET (canonical positions {0, 17} for the
        // Aptos CA TransferV1 shape).
        let dk_bases = derive_dk_base_points(&statement, ROUND2_ELL, ROUND2_N, false, 0)?;
        if dk_bases.is_empty() {
            return Err(WorkerError::Crypto(
                "round2_dk_base_set_empty".to_string(),
            ));
        }

        // 8. Load α_share_j[0] from the M1-ingressed at-rest envelope (NOT fresh CSPRNG).
        //
        // M8-o: replacing the previous `generate_nonzero_scalar(&mut rng)` so that
        // aggregated commitment[0] = (Σ α_share_j) · ek_sid is predictable by the user
        // (= the canonical α[0] extracted from proveTransfer). Without this, e_chain
        // computed over aggregated commitments ≠ e_proveTransfer, and the user's
        // response[1..24] (computed against e_proveTransfer) fails Aptos CA TransferV1
        // Σ-verification with E_INVALID_TRANSFER_PROOF(0x10005).
        //
        // The M1 ingress at-rest envelope was sealed by run_round1_v2 (line 8870) using
        // HPKE_INFO_INGRESS_AT_REST + at_rest_aad over `a || b` (each 32 bytes). Round1
        // already Pedersen-validated (a, b) against the user-supplied amount commitment,
        // so reading it here inherits that binding.
        let ingress_state = load_ingress_state_file(&binding.session_dir)?.ok_or_else(|| {
            WorkerError::InvalidDkgState("round2_missing_ingress_state_file".to_string())
        })?;
        let keypair_for_ingress = load_hpke_keypair_for_slot(state_dir, req.base.self_slot)?;
        let ingress_aad = at_rest_aad(&req.base.session_id, &req.base.request_id, req.base.self_slot);
        let mut ingress_plaintext = hpke_aead::open(
            &keypair_for_ingress.private_key,
            HPKE_INFO_INGRESS_AT_REST,
            &ingress_aad,
            &ingress_state.encrypted_share_envelope,
        )
        .map_err(|_| WorkerError::Crypto("round2_ingress_envelope_open_failed".to_string()))?;
        if ingress_plaintext.len() != 64 {
            ingress_plaintext.zeroize();
            return Err(WorkerError::Crypto(
                "round2_ingress_plaintext_wrong_length".to_string(),
            ));
        }
        let mut alpha_share_bytes = [0_u8; 32];
        alpha_share_bytes.copy_from_slice(&ingress_plaintext[..32]);
        ingress_plaintext.zeroize();
        let alpha_share_opt = Scalar::from_canonical_bytes(alpha_share_bytes);
        alpha_share_bytes.zeroize();
        if alpha_share_opt.is_none().into() {
            return Err(WorkerError::Crypto(
                "round2_ingress_alpha_share_non_canonical".to_string(),
            ));
        }
        let mut alpha_share = alpha_share_opt.unwrap();
        if alpha_share == Scalar::ZERO {
            alpha_share.zeroize();
            return Err(WorkerError::Crypto(
                "round2_ingress_alpha_share_zero_rejected".to_string(),
            ));
        }

        // 9. Compute partial dk-base commitments: α_share_j[0] · base for each (idx, base).
        let mut partial_dk_commitments: Vec<Round2DkPartial> = Vec::with_capacity(dk_bases.len());
        let mut dk_base_indices_used: Vec<usize> = Vec::with_capacity(dk_bases.len());
        for DkBasePoint { index, base } in &dk_bases {
            let partial_point: RistrettoPoint = base * alpha_share;
            // Defense-in-depth: a zero partial means α_share or base was zero. Base is
            // public + non-identity (derive_dk_base_points filters identity), and α_share
            // already rejected zero — so this branch is impossible. We still surface a
            // distinct error to make any future regression visible.
            if partial_point == RistrettoPoint::identity() {
                alpha_share.zeroize();
                return Err(WorkerError::Crypto(
                    "round2_partial_dk_commitment_identity".to_string(),
                ));
            }
            let commitment_hex = hex_encode(partial_point.compress().as_bytes());
            partial_dk_commitments.push(Round2DkPartial {
                index: *index,
                commitment_hex,
            });
            dk_base_indices_used.push(*index);
        }

        // 10. HPKE-seal α_share_j[0] at-rest. Zeroize stack copy immediately after.
        let keypair = load_hpke_keypair_for_slot(state_dir, req.base.self_slot)?;
        let encrypted_alpha_envelope = seal_round2_alpha_at_rest(
            &keypair,
            &req.base.session_id,
            &req.base.request_id,
            req.base.self_slot,
            &alpha_share,
        )?;
        alpha_share.zeroize();

        // 11. Persist Round2StateFile (mpcca_withdraw_v2_round2_dk.json) with public partials
        // + at-rest envelope.
        let now = now_millis_local();
        let round2_state = Round2StateFile {
            scheme: "mpcca_withdraw_v2_round2_dk".to_string(),
            slot: req.base.self_slot,
            player_id: req.base.player_id,
            dkg_epoch: req.base.dkg_epoch.clone(),
            request_id: req.base.request_id.clone(),
            session_id: req.base.session_id.clone(),
            partial_dk_commitments: partial_dk_commitments.clone(),
            dk_base_indices_used: dk_base_indices_used.clone(),
            worker_transcript_hash: worker_transcript_hash.clone(),
            encrypted_alpha_envelope,
            created_at_unix_ms: now,
            // M4 commit 3 binding: store the canonical Statement-inputs hash so finalize can
            // cross-check round2 ↔ finalize Statement input drift directly.
            statement_inputs_hash: statement_inputs_hash_hex.clone(),
        };
        fs::create_dir_all(&binding.session_dir)
            .map_err(|err| WorkerError::Io(err.to_string()))?;
        persist_round2_dk_state(&binding.session_dir, &round2_state)?;

        // 12. Persist round2 RoundStateFile (M3a-shape compat, completed marker is empty
        // not_implemented_phase).
        let session_state_path = persist_round_completed(
            &binding.session_dir,
            "round2",
            req.base.self_slot,
            req.base.player_id,
            &req.base.dkg_epoch,
            &req.base.request_id,
            &req.base.session_id,
            &binding.normalised.vault_ek_hex,
            req.base.vault_sequence,
            req.base.deposit_count,
            &worker_transcript_hash,
            &binding.normalised.observed_deposit_transcript_hashes,
        )?;
        let session_state_hash = file_sha256_hex(&session_state_path)?;

        Ok(Round2DkResult {
            slot: req.base.self_slot,
            player_id: req.base.player_id,
            session_state_path: session_state_path.display().to_string(),
            session_state_hash,
            worker_transcript_hash,
            observed_at_unix_ms: now,
            completed: true,
            partial_dk_commitments,
            dk_base_indices_used,
        })
    }

    pub fn run_prove_v2(state_dir: &Path, req: &ProveRequest) -> WorkerResult<StubRoundResult> {
        run_chained_round(
            state_dir,
            req,
            "prove",
            PROVE_TRANSCRIPT_DOMAIN,
            PROVE_NOT_IMPLEMENTED_PHASE,
        )
    }

    /// Finalize entrypoint (M4 Commit 3) — dk-component threshold response share.
    ///
    /// Worker contract:
    ///   1. Run the shared chained-round public binding under FINALIZE domain (sigma re-verify,
    ///      provenance gate, vault_sequence gate, observed-deposit ordering enforcement).
    ///   2. Validate the Statement input fields (canonical lengths + 32-byte hex). These MUST
    ///      be byte-identical to round2's Statement inputs; the cross-check is enforced
    ///      indirectly via the recomputed round2 worker_transcript_hash equality with
    ///      `previous_round_transcript_hash` AND directly via byte-comparison to the persisted
    ///      Round2StateFile's `dk_base_indices_used` derived BASE_DK_SET at finalize.
    ///   3. Validate the aggregated 30-point sigma commitment vector + the challenge hex.
    ///   4. Re-derive the Fiat-Shamir challenge `e` locally via
    ///      `sigma_fiat_shamir_seed(bcs_fiat_shamir_inputs(dst, TYPE_NAME, k=25, statement.x,
    ///      statement.scalars, aggregated_commitments))`. Assert byte-equality with the
    ///      coordinator-supplied `challenge_hex`. A malicious coordinator that lies about `e`
    ///      fails closed here.
    ///   5. Load `ca_dkg_share_v2.json` and `Round2StateFile` for the per-session state.
    ///   6. Recompute Lagrange `λ_j` at x=0 over sorted selectedSlots (locally — do NOT trust
    ///      the coordinator).
    ///   7. HPKE-decrypt `α_share_j[0]` from the at-rest envelope under the worker's own HPKE
    ///      private key with the round2 at-rest AAD. Reject non-canonical or zero α.
    ///   8. Defense-in-depth: recompute round2 worker_transcript_hash from finalize's
    ///      Statement inputs and assert it equals the request's `previous_round_transcript_hash`.
    ///      A coordinator tampering with Statement inputs between rounds fails closed here.
    ///   9. Compute `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`. Zero-reject (goal.md
    ///      decision #9; mathematically impossible for honest inputs but defense-in-depth).
    ///  10. Zeroize `α_share_j[0]` and the `dk_share_j` stack copy after computing `s_share_j`.
    ///      `s_share_j` itself is a PUBLIC output (the worker's threshold response share).
    ///  11. Persist `mpcca_withdraw_v2_finalize.json` (RoundStateFile, completed=true) with the
    ///      bound worker_transcript_hash.
    ///  12. Return `FinalizeDkResult { partial_response_dk_hex, dk_base_indices_used, ... }`.
    ///
    /// Privacy contract: `α_share_j[0]` and `dk_share_j` never leave the worker process in
    /// plaintext; the only output is `s_share_j` (a single 32-byte canonical Ed25519 scalar),
    /// which is by-construction a PUBLIC sigma response share.
    pub fn run_finalize_v2(
        state_dir: &Path,
        req: &FinalizeRequest,
    ) -> WorkerResult<FinalizeDkResult> {
        // 1. Shared chained-round public binding. Returns a binding whose `chained_hash` is
        //    computed under ROUND2_TRANSCRIPT_DOMAIN; we re-hash under FINALIZE_TRANSCRIPT_DOMAIN
        //    below.
        let binding = chained_round_public_binding(state_dir, &req.base)?;

        // 2. Validate Statement input fields (lengths + 32-byte hex canonicalisation).
        let stmt_inputs = normalise_finalize_statement_inputs(req)?;
        let statement_inputs_hash = statement_inputs_hash_hex(&stmt_inputs);

        // 3. Validate aggregated commitments shape (length 30, canonical compressed Ristretto,
        //    non-identity) and the challenge hex (canonical Ed25519 scalar).
        let aggregated_commitments_norm =
            normalise_aggregated_sigma_commitments(&req.aggregated_sigma_commitments)?;
        let aggregated_commitments_hash =
            aggregated_sigma_commitments_hash_hex(&aggregated_commitments_norm);
        let challenge_hex_norm = normalize_hex(&req.challenge_hex, 32).map_err(|err| {
            WorkerError::InvalidRequest(format!("finalize challenge_hex: {err:?}"))
        })?;
        let coord_challenge = {
            let bytes = hex_to_bytes32(&challenge_hex_norm)?;
            let opt = Scalar::from_canonical_bytes(bytes);
            if opt.is_none().into() {
                return Err(WorkerError::InvalidRequest(
                    "finalize challenge_hex is not a canonical Ed25519 scalar".to_string(),
                ));
            }
            opt.unwrap()
        };
        if coord_challenge == Scalar::ZERO {
            return Err(WorkerError::Crypto(
                "finalize_challenge_zero_rejected".to_string(),
            ));
        }

        // 4. Build the public Statement and re-derive `e` locally.
        let statement = build_round2_statement(&stmt_inputs, &binding.normalised.vault_ek_hex)?;
        let dst = build_finalize_domain_separator(
            &binding.normalised.sender_address,
            &binding.normalised.recipient,
            &binding.normalised.asset_type,
            req.base.chain_id,
        )?;
        let aggregated_commitments_bytes =
            decode_aggregated_commitments_bytes(&aggregated_commitments_norm)?;
        let bcs = bcs_fiat_shamir_inputs(
            &dst,
            TYPE_NAME,
            WITNESS_LEN as u64,
            &statement.compressed_points,
            &statement.scalars,
            &aggregated_commitments_bytes,
        );
        let (e_local, _beta) = sigma_fiat_shamir_seed(&bcs);
        if e_local != coord_challenge {
            return Err(WorkerError::Crypto(
                "finalize_challenge_mismatch".to_string(),
            ));
        }

        // 5. Programmatically derive BASE_DK_SET from the public Statement (must match round2's).
        let dk_bases = derive_dk_base_points(&statement, ROUND2_ELL, ROUND2_N, false, 0)?;
        if dk_bases.is_empty() {
            return Err(WorkerError::Crypto(
                "finalize_dk_base_set_empty".to_string(),
            ));
        }
        let canonical_dk_indices: Vec<usize> = dk_bases.iter().map(|d| d.index).collect();

        // 6. Recompute the chained hash under FINALIZE_TRANSCRIPT_DOMAIN, then the
        //    finalize worker_transcript_hash that binds Statement inputs + aggregated A + e.
        let previous_round_transcript_hash =
            normalize_hex(&req.base.previous_round_transcript_hash, 32)?;
        let mut previous_round_commitments = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for c in &req.base.previous_round_commitments {
            previous_round_commitments.push(normalize_hex(c, 32)?);
        }
        let chained_hash_finalize = chained_round_worker_hash(
            FINALIZE_TRANSCRIPT_DOMAIN,
            &req.base.session_id,
            &req.base.request_id,
            &req.base.dkg_epoch,
            &binding.normalised.vault_ek_transcript_hash,
            &binding.normalised.registration_transcript_hash,
            &binding.normalised.vault_state_init_transcript_hash,
            &binding.normalised.observed_deposit_transcript_hashes,
            &binding.normalised.roster_hash,
            &binding.normalised.sorted,
            req.base.self_slot,
            req.base.player_id,
            &binding.normalised.vault_ek_hex,
            &binding.normalised.sender_address,
            &binding.normalised.asset_type,
            req.base.chain_id,
            &binding.normalised.root,
            &binding.normalised.nullifier_hash,
            &binding.normalised.recipient,
            &binding.normalised.recipient_hash,
            &binding.normalised.amount_tag,
            req.base.vault_sequence,
            req.base.expiry_secs,
            &binding.normalised.request_hash,
            req.base.deposit_count,
            &previous_round_transcript_hash,
            &previous_round_commitments,
        );
        let worker_transcript_hash = finalize_v2_worker_transcript_hash(
            &chained_hash_finalize,
            &statement_inputs_hash,
            &aggregated_commitments_hash,
            &challenge_hex_norm,
        );

        // 7. Load the Round2StateFile and validate provenance + previous_round_transcript_hash.
        //    Run all non-secret cross-checks BEFORE touching dk_share / α_share so we
        //    fail closed early.
        let round2_state =
            load_round2_dk_state_file(&binding.session_dir)?.ok_or_else(|| {
                WorkerError::InvalidDkgState(
                    "finalize_missing_round2_dk_state".to_string(),
                )
            })?;
        if round2_state.dkg_epoch != req.base.dkg_epoch
            || round2_state.request_id != req.base.request_id
            || round2_state.session_id != req.base.session_id
            || round2_state.slot != req.base.self_slot
            || round2_state.player_id != req.base.player_id
        {
            return Err(WorkerError::InvalidDkgState(
                "finalize_round2_state_provenance_mismatch".to_string(),
            ));
        }
        // Defense-in-depth: the persisted round2 worker_transcript_hash MUST equal the
        // coordinator-supplied previous_round_transcript_hash. This catches:
        //   (a) coordinator forwarded a stale or fabricated previousRoundTranscriptHash
        //   (b) Statement-input drift between round2 and finalize (round2 stored its
        //       Statement-bound transcript hash; finalize's previous_round_transcript_hash
        //       MUST match that stored value)
        if round2_state.worker_transcript_hash != previous_round_transcript_hash {
            return Err(WorkerError::InvalidDkgState(
                "finalize_round2_state_transcript_hash_mismatch".to_string(),
            ));
        }
        // BASE_DK_SET cross-check: round2's persisted indices must match this finalize's
        // re-derived canonical set. A psi-shape regression between rounds is impossible by
        // construction (psi is pure function of Statement points), but the check defends
        // against future refactors that decouple the derivation.
        if round2_state.dk_base_indices_used != canonical_dk_indices {
            return Err(WorkerError::InvalidDkgState(
                "finalize_round2_state_dk_indices_mismatch".to_string(),
            ));
        }
        // Defense-in-depth round2 ↔ finalize Statement-input binding: round2 persisted the
        // canonical `statement_inputs_hash` it bound; finalize must use byte-identical
        // Statement inputs. A coordinator that tampered with Statement inputs between rounds
        // surfaces here as `finalize_round2_state_statement_inputs_hash_mismatch`. This is
        // distinct from (and tighter than) the Fiat-Shamir challenge-mismatch guard, because
        // it catches the tampering BEFORE any α_share decryption.
        //
        // Backwards-compat: if `statement_inputs_hash` is empty (pre-M4-c3 round2 fixture),
        // skip this check — the Fiat-Shamir guard above remains the load-bearing defense.
        if !round2_state.statement_inputs_hash.is_empty()
            && round2_state.statement_inputs_hash != statement_inputs_hash
        {
            return Err(WorkerError::InvalidDkgState(
                "finalize_round2_state_statement_inputs_hash_mismatch".to_string(),
            ));
        }

        // 8. SECURITY GATE — atomically pin (aggregated_commitments_hash, challenge_hex)
        //    BEFORE any secret material is loaded.
        //
        //    Codex M4-c3 P1 #13 (α-share replay attack): without this gate, a malicious
        //    coordinator could call finalize twice with the SAME α-share (already at-rest
        //    from round2) but DIFFERENT (A, e):
        //      s1 = α + e1 · w
        //      s2 = α + e2 · w
        //      w  = (s2 − s1) · (e2 − e1)^-1     (where w = λ_j · dk_share_j)
        //    Five such recoveries across the quorum reconstruct `dk`, breaking the
        //    no-centralized-dk invariant. The pin makes the second call fail CLOSED at the
        //    no-clobber gate BEFORE α is ever decrypted.
        //
        //    `write_atomic_no_clobber` semantics (POSIX link(2)):
        //      - first call: link succeeds, pin persisted at the canonical path
        //      - replay with byte-identical content: link → EEXIST, file equality matches,
        //        returns Ok → finalize re-runs deterministically (replay-idempotent)
        //      - replay with different content (= different A or e): link → EEXIST, file
        //        equality fails → InvalidDkgState(
        //        "mpcca_withdraw_v2_finalize_pin_already_exists_with_different_content")
        fs::create_dir_all(&binding.session_dir)
            .map_err(|err| WorkerError::Io(err.to_string()))?;
        let pin = FinalizePinFile {
            scheme: "mpcca_withdraw_v2_finalize_pin".to_string(),
            slot: req.base.self_slot,
            player_id: req.base.player_id,
            dkg_epoch: req.base.dkg_epoch.clone(),
            request_id: req.base.request_id.clone(),
            session_id: req.base.session_id.clone(),
            aggregated_commitments_hash: aggregated_commitments_hash.clone(),
            challenge_hex: challenge_hex_norm.clone(),
            worker_transcript_hash: worker_transcript_hash.clone(),
        };
        persist_finalize_pin(&binding.session_dir, &pin)?;

        // 9. Load `ca_dkg_share_v2.json` and validate (slot, dkg_epoch) match the request.
        let share = load_ca_dkg_v2_share(state_dir)?;
        if share.slot != req.base.self_slot {
            return Err(WorkerError::InvalidDkgState(format!(
                "ca_dkg_share_v2 slot {} does not match self_slot {}",
                share.slot, req.base.self_slot
            )));
        }
        if share.dkg_epoch != req.base.dkg_epoch {
            return Err(WorkerError::InvalidDkgState(format!(
                "ca_dkg_share_v2 dkg_epoch {} does not match request {}",
                share.dkg_epoch, req.base.dkg_epoch
            )));
        }
        let mut dk_share_scalar = scalar_from_hex_local(&share.dk_share).map_err(|_| {
            WorkerError::Crypto("finalize_dk_share_non_canonical".to_string())
        })?;
        if dk_share_scalar == Scalar::ZERO {
            dk_share_scalar.zeroize();
            return Err(WorkerError::Crypto(
                "finalize_dk_share_zero_rejected".to_string(),
            ));
        }

        // 10. Recompute Lagrange λ_j at x=0 over sorted selectedSlots — locally, do not
        //     trust the coordinator.
        let lambdas = lagrange_coefficients_at_zero(&binding.normalised.sorted)?;
        let lambda_j = lambdas[req.base.player_id];
        if lambda_j == Scalar::ZERO {
            dk_share_scalar.zeroize();
            return Err(WorkerError::Crypto(
                "finalize_lagrange_coefficient_zero".to_string(),
            ));
        }

        // 11. HPKE-decrypt `α_share_j[0]` from the at-rest envelope. The AAD MUST match the
        //     round2 at-rest AAD byte-identically; the worker's own private key is the only
        //     key that can open this envelope.
        let keypair = match load_hpke_keypair_for_slot(state_dir, req.base.self_slot) {
            Ok(k) => k,
            Err(err) => {
                dk_share_scalar.zeroize();
                return Err(err);
            }
        };
        let aad =
            round2_at_rest_aad(&req.base.session_id, &req.base.request_id, req.base.self_slot);
        let mut alpha_plaintext = match hpke_aead::open(
            &keypair.private_key,
            HPKE_INFO_ROUND2_AT_REST,
            &aad,
            &round2_state.encrypted_alpha_envelope,
        ) {
            Ok(pt) => pt,
            Err(_) => {
                dk_share_scalar.zeroize();
                return Err(WorkerError::Crypto(
                    "finalize_alpha_envelope_open_failed".to_string(),
                ));
            }
        };
        if alpha_plaintext.len() != 32 {
            alpha_plaintext.zeroize();
            dk_share_scalar.zeroize();
            return Err(WorkerError::Crypto(
                "finalize_alpha_envelope_wrong_plaintext_length".to_string(),
            ));
        }
        let mut alpha_bytes = [0_u8; 32];
        alpha_bytes.copy_from_slice(&alpha_plaintext);
        alpha_plaintext.zeroize();
        let alpha_opt = Scalar::from_canonical_bytes(alpha_bytes);
        alpha_bytes.zeroize();
        if alpha_opt.is_none().into() {
            dk_share_scalar.zeroize();
            return Err(WorkerError::Crypto(
                "finalize_alpha_share_non_canonical".to_string(),
            ));
        }
        let mut alpha_share = alpha_opt.unwrap();
        if alpha_share == Scalar::ZERO {
            alpha_share.zeroize();
            dk_share_scalar.zeroize();
            return Err(WorkerError::Crypto(
                "finalize_alpha_share_zero_rejected".to_string(),
            ));
        }

        // 12. Compute `s_share_j = α_share_j[0] + e · (λ_j · dk_share_j)`. Zero-reject as
        //     defense-in-depth (mathematically impossible for honest inputs).
        let weighted_dk = lambda_j * dk_share_scalar;
        let s_share = alpha_share + coord_challenge * weighted_dk;

        // Zeroize secrets. `s_share` is a public output (threshold response share).
        alpha_share.zeroize();
        dk_share_scalar.zeroize();

        if s_share == Scalar::ZERO {
            return Err(WorkerError::Crypto(
                "finalize_zero_response_share_rejected".to_string(),
            ));
        }

        let partial_response_dk_hex = hex_encode(s_share.to_bytes().as_slice());

        // 13. Persist the finalize RoundStateFile (M3a-shape compat) — completed=true.
        let session_state_path = persist_round_completed(
            &binding.session_dir,
            "finalize",
            req.base.self_slot,
            req.base.player_id,
            &req.base.dkg_epoch,
            &req.base.request_id,
            &req.base.session_id,
            &binding.normalised.vault_ek_hex,
            req.base.vault_sequence,
            req.base.deposit_count,
            &worker_transcript_hash,
            &binding.normalised.observed_deposit_transcript_hashes,
        )?;
        let session_state_hash = file_sha256_hex(&session_state_path)?;

        Ok(FinalizeDkResult {
            slot: req.base.self_slot,
            player_id: req.base.player_id,
            session_state_path: session_state_path.display().to_string(),
            session_state_hash,
            worker_transcript_hash,
            observed_at_unix_ms: now_millis_local(),
            completed: true,
            partial_response_dk_hex,
            dk_base_indices_used: canonical_dk_indices,
        })
    }

    /// Normalised + validated public binding fields produced by the common-prefix validator.
    struct NormalisedBinding {
        vault_ek_transcript_hash: String,
        registration_transcript_hash: String,
        vault_state_init_transcript_hash: String,
        observed_deposit_transcript_hashes: Vec<String>,
        roster_hash: String,
        sorted: Vec<usize>,
        vault_ek_hex: String,
        sender_address: String,
        asset_type: String,
        root: String,
        nullifier_hash: String,
        recipient: String,
        recipient_hash: String,
        amount_tag: String,
        request_hash: String,
    }

    /// Common public-binding work shared by all four rounds. Returns the normalised hex fields,
    /// the loaded `vault_state_v2.json`, and the per-session directory path. Performs ALL of
    /// the load-bearing validation: id safety, hex normalisation, provenance gate, vault_sequence
    /// gate, sigma re-verify.
    fn common_public_binding_work(
        state_dir: &Path,
        req: &Round1Request,
    ) -> WorkerResult<(NormalisedBinding, VaultStateFile, PathBuf)> {
        // 1. Identifier safety + range validation.
        validate_selected_slots(&req.selected_slots)?;
        assert_slot(req.self_slot)?;
        if !req.selected_slots.contains(&req.self_slot) {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot {} not in selected_slots",
                req.self_slot
            )));
        }
        if req.player_id >= DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "player_id {} out of range 0..{}",
                req.player_id, DEOPERATOR_THRESHOLD
            )));
        }
        let sorted = sorted_unique_slots(&req.selected_slots)?;
        if sorted[req.player_id] != req.self_slot {
            return Err(WorkerError::InvalidRequest(format!(
                "self_slot_player_id_mismatch: sorted_slots[{}]={} != self_slot={}",
                req.player_id, sorted[req.player_id], req.self_slot
            )));
        }
        if req.request_id.is_empty() || !is_safe_id(&req.request_id) {
            return Err(WorkerError::InvalidRequest(
                "request_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.session_id.is_empty() || !is_safe_id(&req.session_id) {
            return Err(WorkerError::InvalidRequest(
                "session_id must be non-empty and contain only [A-Za-z0-9._-]".to_string(),
            ));
        }
        if req.dkg_epoch.is_empty() || !req.dkg_epoch.chars().all(|c| c.is_ascii_digit()) {
            return Err(WorkerError::InvalidRequest(
                "dkg_epoch must be a non-empty decimal string".to_string(),
            ));
        }

        // 2. Normalize hex fields (every 32-byte hex normalised + length-checked).
        let vault_ek_transcript_hash = normalize_hex(&req.vault_ek_transcript_hash, 32)?;
        let registration_transcript_hash = normalize_hex(&req.registration_transcript_hash, 32)?;
        let vault_state_init_transcript_hash =
            normalize_hex(&req.vault_state_init_transcript_hash, 32)?;
        let roster_hash = normalize_hex(&req.roster_hash, 32)?;
        let vault_ek_hex = normalize_hex(&req.vault_ek, 32)?;
        let sender_address = normalize_hex(&req.sender_address, 32)?;
        let asset_type = normalize_hex(&req.asset_type, 32)?;
        let root = normalize_hex(&req.root, 32)?;
        let nullifier_hash = normalize_hex(&req.nullifier_hash, 32)?;
        let recipient = normalize_hex(&req.recipient, 32)?;
        let recipient_hash = normalize_hex(&req.recipient_hash, 32)?;
        let amount_tag = normalize_hex(&req.amount_tag, 32)?;
        let request_hash = normalize_hex(&req.request_hash, 32)?;
        // Codex M3a P2 #1: observed_deposit_transcript_hashes is the ORDERED vector of every
        // Milestone 2b observe-deposit transcript hash from cursor 1..=deposit_count. The
        // coordinator builds this from <state_root>/coordinator/vault_state_v2_observed/ and
        // asserts strict completeness + uniqueness BEFORE fan-out; the worker re-enforces both
        // properties here as defense in depth. Milestone 4's crypto will bind these into the
        // partial sigma transcript so a tampered ordering is provably distinguishable from a
        // canonical run.
        if req.observed_deposit_transcript_hashes.len() as u64 != req.deposit_count {
            return Err(WorkerError::InvalidRequest(format!(
                "observed_deposit_transcript_hashes length {} does not match deposit_count {}",
                req.observed_deposit_transcript_hashes.len(),
                req.deposit_count,
            )));
        }
        let mut observed_deposit_transcript_hashes = Vec::with_capacity(
            req.observed_deposit_transcript_hashes.len(),
        );
        let mut seen_observed_hashes = std::collections::HashSet::with_capacity(
            req.observed_deposit_transcript_hashes.len(),
        );
        for h in &req.observed_deposit_transcript_hashes {
            let norm = normalize_hex(h, 32)?;
            if !seen_observed_hashes.insert(norm.clone()) {
                return Err(WorkerError::InvalidRequest(
                    "duplicate observed_deposit_transcript_hashes entry".to_string(),
                ));
            }
            observed_deposit_transcript_hashes.push(norm);
        }

        // Codex M3a P2 #1 v2 (ordering regression fix): enforce strict monotonic cursor
        // ordering on the observed deposit list. Pre-fix the worker checked length +
        // hash-set uniqueness — sufficient against a coordinator that DROPPED a cursor or
        // duplicated a hash, but BLIND to a coordinator that re-ORDERED entries within the
        // depositCount window. A re-ordering would change the canonical observed-vector
        // hash bound into the milestone 4 partial sigma transcript, so a tampered ordering
        // here would silently produce a different signed transcript than the canonical run.
        //
        // The new field `observedDepositCursors[i]` is the depositCount the coordinator
        // claims `observed_deposit_transcript_hashes[i]` was observed at. Worker enforces
        // cursors == [1, 2, …, depositCount] BYTE-FOR-BYTE. Any out-of-order, skipped, or
        // wrong-cursor mapping fails closed with `observed_deposit_cursors_*`.
        //
        // Empty-cursor backwards-compat: if the coordinator omits observedDepositCursors
        // entirely (Vec::default → empty), we accept only when deposit_count == 0. Any
        // depositCount >= 1 REQUIRES the parallel cursor array. This is a hard cutover —
        // legacy clients must upgrade before sending a non-zero deposit_count.
        if req.observed_deposit_cursors.is_empty() && req.deposit_count == 0 {
            // depositCount=0 + missing cursors is OK (the observed list is empty too).
        } else {
            if req.observed_deposit_cursors.len() as u64 != req.deposit_count {
                return Err(WorkerError::InvalidRequest(format!(
                    "observed_deposit_cursors length {} does not match deposit_count {}",
                    req.observed_deposit_cursors.len(),
                    req.deposit_count,
                )));
            }
            for (i, cursor) in req.observed_deposit_cursors.iter().enumerate() {
                let expected = (i as u64) + 1;
                if *cursor != expected {
                    return Err(WorkerError::InvalidRequest(format!(
                        "observed_deposit_cursors[{i}] = {cursor}, expected {expected} \
                         (cursors MUST be the strict monotonic sequence [1..=deposit_count])"
                    )));
                }
            }
        }

        // 3. Load persisted vault_state_v2.json. Missing → fail closed with a specific code.
        let existing = load_vault_state_v2(state_dir)?.ok_or_else(|| {
            WorkerError::InvalidDkgState("missing_vault_state_file".to_string())
        })?;

        // 4. Provenance gate. Every binding persisted by Milestone 2a's init MUST match the
        //    request. Cursor counters (deposit_count_observed) are NOT enforced here — that's
        //    the Milestone 2b observe-deposit endpoint's job. The MPCCA withdraw only enforces
        //    immutable provenance + vault_sequence (the on-chain mutable counter mirror).
        let provenance_ok = existing.dkg_epoch == req.dkg_epoch
            && existing.slot == req.self_slot
            && existing.player_id == req.player_id
            && normalize_hex(&existing.vault_ek_hex, 32)? == vault_ek_hex
            && normalize_hex(&existing.vault_ek_transcript_hash, 32)? == vault_ek_transcript_hash
            && normalize_hex(&existing.registration_transcript_hash, 32)?
                == registration_transcript_hash
            && normalize_hex(&existing.roster_hash, 32)? == roster_hash
            && existing.selected_slots == sorted
            && normalize_hex(&existing.sender_address, 32)? == sender_address
            && normalize_hex(&existing.asset_type, 32)? == asset_type
            && existing.chain_id == req.chain_id;
        if !provenance_ok {
            return Err(WorkerError::InvalidDkgState(
                "mpcca_withdraw_v2_provenance_mismatch".to_string(),
            ));
        }

        // Codex M3a P1 v3 (partial-finalize recovery): req.vault_state_init_transcript_hash
        // MUST equal the worker's persisted CANONICAL init_transcript_hash (set by
        // finalize_vault_state_v2) byte-for-byte.
        //
        // Two distinct error codes encode the two failure modes:
        //   - `vault_state_v2_not_finalized`: persisted init_transcript_hash is None — init
        //     ran but finalize hasn't landed on this slot. The coordinator should re-run the
        //     init finalize round (idempotent across slots that already finalized).
        //   - `vault_state_init_transcript_hash_mismatch`: persisted init_transcript_hash is
        //     Some(v) but v != req.vault_state_init_transcript_hash. Either tamper, or a
        //     coordinator that submitted the wrong canonical hash for this vault.
        //
        // These were a single error in v1/v2; splitting them lets the coordinator distinguish
        // "transient — retry finalize" from "permanent — investigate".
        let persisted_init_hash = existing.init_transcript_hash.as_deref().ok_or_else(|| {
            WorkerError::InvalidDkgState("vault_state_v2_not_finalized".to_string())
        })?;
        if persisted_init_hash.to_lowercase() != vault_state_init_transcript_hash.to_lowercase() {
            return Err(WorkerError::InvalidDkgState(
                "vault_state_init_transcript_hash_mismatch".to_string(),
            ));
        }

        // 5. vault_sequence gate. existing.vault_sequence MUST equal req.vault_sequence. A stale
        //    or future sequence is rejected here BEFORE any crypto work. Milestone 4's finalize
        //    will bump vault_sequence on success; for now it's read-only.
        if existing.vault_sequence != req.vault_sequence {
            return Err(WorkerError::InvalidRequest(format!(
                "stale_vault_sequence: req={} existing={}",
                req.vault_sequence, existing.vault_sequence
            )));
        }

        // 6. Re-verify the Milestone 1 sigma against the persisted vault_state_v2.json tuple +
        //    the request's vault_ek. The persisted tuple WAS verified at Milestone 2a init time,
        //    but defense-in-depth recheck here ensures a tampered request body containing a wrong
        //    vault_ek (with otherwise-matching provenance) still fails closed with a CRYPTO error
        //    before the NotImplemented surface.
        let aggregate_commitment = normalize_hex(&existing.aggregate_commitment, 32)?;
        let aggregate_response = normalize_hex(&existing.aggregate_response, 32)?;
        verify_registration_proof(
            &vault_ek_hex,
            &sender_address,
            &asset_type,
            req.chain_id,
            &aggregate_commitment,
            &aggregate_response,
        )?;

        // 7. Compute session dir path (id safety already validated above).
        let session_dir = mpcca_withdraw_session_dir(state_dir, &req.request_id, &req.session_id)?;

        Ok((
            NormalisedBinding {
                vault_ek_transcript_hash,
                registration_transcript_hash,
                vault_state_init_transcript_hash,
                observed_deposit_transcript_hashes,
                roster_hash,
                sorted,
                vault_ek_hex,
                sender_address,
                asset_type,
                root,
                nullifier_hash,
                recipient,
                recipient_hash,
                amount_tag,
                request_hash,
            },
            existing,
            session_dir,
        ))
    }

    /// Output of `chained_round_public_binding`: the normalised public binding fields, the
    /// loaded vault_state_v2.json, the per-session dir, and the BASE chained-round transcript
    /// hash computed against the **ROUND2 V1 domain** (used by ProveRequest + FinalizeRequest
    /// stub paths). Round2's M4 commit-1 path extends this base hash with the Statement-input
    /// fields to produce its final worker_transcript_hash.
    struct ChainedRoundBinding {
        normalised: NormalisedBinding,
        #[allow(dead_code)]
        existing: VaultStateFile,
        session_dir: PathBuf,
        /// SHA-256 hex of the chained-round transcript bytes including
        /// `previous_round_transcript_hash` and `previous_round_commitments`, hashed under
        /// the caller-supplied domain. Round2 extends this with the Statement-input hash;
        /// prove/finalize stubs persist this directly.
        chained_hash: String,
    }

    /// Run the shared chained-round binding work and compute the chained worker_transcript_hash
    /// for the given `domain`. Does NOT persist anything; the caller decides which file layout
    /// to write.
    fn chained_round_public_binding(
        state_dir: &Path,
        req: &ChainedRoundRequest,
    ) -> WorkerResult<ChainedRoundBinding> {
        let envelope = Round1Request {
            dkg_epoch: req.dkg_epoch.clone(),
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            vault_ek_transcript_hash: req.vault_ek_transcript_hash.clone(),
            registration_transcript_hash: req.registration_transcript_hash.clone(),
            vault_state_init_transcript_hash: req.vault_state_init_transcript_hash.clone(),
            observed_deposit_transcript_hashes: req.observed_deposit_transcript_hashes.clone(),
            observed_deposit_cursors: req.observed_deposit_cursors.clone(),
            roster_hash: req.roster_hash.clone(),
            selected_slots: req.selected_slots.clone(),
            self_slot: req.self_slot,
            player_id: req.player_id,
            vault_ek: req.vault_ek.clone(),
            sender_address: req.sender_address.clone(),
            asset_type: req.asset_type.clone(),
            chain_id: req.chain_id,
            root: req.root.clone(),
            nullifier_hash: req.nullifier_hash.clone(),
            recipient: req.recipient.clone(),
            recipient_hash: req.recipient_hash.clone(),
            amount_tag: req.amount_tag.clone(),
            vault_sequence: req.vault_sequence,
            expiry_secs: req.expiry_secs,
            request_hash: req.request_hash.clone(),
            deposit_count: req.deposit_count,
            amount_commitment: String::new(),
            per_share_commitments: Vec::new(),
            ingress_envelopes: Vec::new(),
        };
        let (normalised, existing, session_dir) = common_public_binding_work(state_dir, &envelope)?;
        let previous_round_transcript_hash =
            normalize_hex(&req.previous_round_transcript_hash, 32)?;
        if req.previous_round_commitments.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "previous_round_commitments must have {DEOPERATOR_THRESHOLD} entries, got {}",
                req.previous_round_commitments.len()
            )));
        }
        let mut previous_round_commitments = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for c in &req.previous_round_commitments {
            previous_round_commitments.push(normalize_hex(c, 32)?);
        }
        // The chained-round hash is computed under ROUND2_TRANSCRIPT_DOMAIN by default —
        // both round2 and the chained-round stub path use it. Round2 commit 1's worker hash
        // extends this with the Statement-input hash; the prove/finalize stub passes this
        // through to persist_and_stub directly (they additionally re-hash with their own
        // domain via run_chained_round, see below).
        let chained_hash = chained_round_worker_hash(
            ROUND2_TRANSCRIPT_DOMAIN,
            &req.session_id,
            &req.request_id,
            &req.dkg_epoch,
            &normalised.vault_ek_transcript_hash,
            &normalised.registration_transcript_hash,
            &normalised.vault_state_init_transcript_hash,
            &normalised.observed_deposit_transcript_hashes,
            &normalised.roster_hash,
            &normalised.sorted,
            req.self_slot,
            req.player_id,
            &normalised.vault_ek_hex,
            &normalised.sender_address,
            &normalised.asset_type,
            req.chain_id,
            &normalised.root,
            &normalised.nullifier_hash,
            &normalised.recipient,
            &normalised.recipient_hash,
            &normalised.amount_tag,
            req.vault_sequence,
            req.expiry_secs,
            &normalised.request_hash,
            req.deposit_count,
            &previous_round_transcript_hash,
            &previous_round_commitments,
        );
        Ok(ChainedRoundBinding {
            normalised,
            existing,
            session_dir,
            chained_hash,
        })
    }

    /// Shared chained-round stub entrypoint for prove + finalize (round2 has its own M4
    /// commit-1 path). Computes the per-round chained worker_transcript_hash under the
    /// caller-supplied domain, persists the M3a-shape RoundStateFile, and surfaces a
    /// NotImplemented signal so the coordinator's per-round handlers can fan out a 501.
    fn run_chained_round(
        state_dir: &Path,
        req: &ChainedRoundRequest,
        round_name: &str,
        domain: &str,
        not_implemented_phase: &'static str,
    ) -> WorkerResult<StubRoundResult> {
        let binding = chained_round_public_binding(state_dir, req)?;
        // Re-hash under the caller-supplied domain so each chained round has a distinct
        // worker_transcript_hash. The common binding helper returned the ROUND2 domain
        // hash; if the caller asked for PROVE or FINALIZE we recompute with their domain
        // by re-running chained_round_worker_hash with the same fields. The cost is one
        // SHA-256 — negligible.
        let previous_round_transcript_hash =
            normalize_hex(&req.previous_round_transcript_hash, 32)?;
        let mut previous_round_commitments = Vec::with_capacity(DEOPERATOR_THRESHOLD);
        for c in &req.previous_round_commitments {
            previous_round_commitments.push(normalize_hex(c, 32)?);
        }
        let worker_transcript_hash = if domain == ROUND2_TRANSCRIPT_DOMAIN {
            binding.chained_hash.clone()
        } else {
            chained_round_worker_hash(
                domain,
                &req.session_id,
                &req.request_id,
                &req.dkg_epoch,
                &binding.normalised.vault_ek_transcript_hash,
                &binding.normalised.registration_transcript_hash,
                &binding.normalised.vault_state_init_transcript_hash,
                &binding.normalised.observed_deposit_transcript_hashes,
                &binding.normalised.roster_hash,
                &binding.normalised.sorted,
                req.self_slot,
                req.player_id,
                &binding.normalised.vault_ek_hex,
                &binding.normalised.sender_address,
                &binding.normalised.asset_type,
                req.chain_id,
                &binding.normalised.root,
                &binding.normalised.nullifier_hash,
                &binding.normalised.recipient,
                &binding.normalised.recipient_hash,
                &binding.normalised.amount_tag,
                req.vault_sequence,
                req.expiry_secs,
                &binding.normalised.request_hash,
                req.deposit_count,
                &previous_round_transcript_hash,
                &previous_round_commitments,
            )
        };
        persist_and_stub(
            &binding.session_dir,
            round_name,
            req.self_slot,
            req.player_id,
            &req.dkg_epoch,
            &req.request_id,
            &req.session_id,
            &binding.normalised.vault_ek_hex,
            req.vault_sequence,
            req.deposit_count,
            &worker_transcript_hash,
            not_implemented_phase,
            &binding.normalised.observed_deposit_transcript_hashes,
        )?;
        Err(WorkerError::NotImplemented(not_implemented_phase))
    }

    /// Persist the per-session-per-round state file (atomic 0o600) and return the path + hash.
    /// Note: this is called BEFORE the NotImplemented surface so the persisted state captures
    /// the public binding work + worker hash. Milestone 4 will REPLACE this stub persist with
    /// a real per-round crypto state file (preserving the path layout).
    #[allow(clippy::too_many_arguments)]
    fn persist_and_stub(
        session_dir: &Path,
        round_name: &str,
        self_slot: usize,
        player_id: usize,
        dkg_epoch: &str,
        request_id: &str,
        session_id: &str,
        vault_ek_hex: &str,
        vault_sequence: u64,
        deposit_count: u64,
        worker_transcript_hash: &str,
        not_implemented_phase: &str,
        observed_deposit_transcript_hashes: &[String],
    ) -> WorkerResult<()> {
        let file_path = session_dir.join(round_file_name(round_name));
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // Codex M3a P2 #2: idempotent replay. If the file already exists with the SAME
        // worker_transcript_hash + round + slot + bindings, we preserve the original
        // `created_at_unix_ms` from the persisted file so the byte content matches across
        // replays. Without this, every replay would produce a different file (different
        // timestamp) and the no-clobber atomic write would reject it as a divergent
        // content collision.
        let created_at_persisted = if file_path.exists() {
            match load_round_state_file(session_dir, round_name)? {
                Some(existing) if existing.worker_transcript_hash == worker_transcript_hash
                    && existing.round == round_name
                    && existing.slot == self_slot
                    && existing.player_id == player_id =>
                {
                    Some(existing.created_at_unix_ms)
                }
                _ => None, // divergent — fall through and let no-clobber surface the collision
            }
        } else {
            None
        };
        let layout = RoundStateFile {
            scheme: "mpcca_withdraw_v2".to_string(),
            round: round_name.to_string(),
            slot: self_slot,
            player_id,
            dkg_epoch: dkg_epoch.to_string(),
            request_id: request_id.to_string(),
            session_id: session_id.to_string(),
            vault_ek_hex: vault_ek_hex.to_string(),
            vault_sequence,
            deposit_count,
            worker_transcript_hash: worker_transcript_hash.to_string(),
            not_implemented_phase: not_implemented_phase.to_string(),
            created_at_unix_ms: created_at_persisted.unwrap_or(created_at),
            observed_deposit_transcript_hashes: observed_deposit_transcript_hashes.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&layout).map_err(|err| {
            WorkerError::Crypto(format!("encode mpcca_withdraw_v2 round state: {err}"))
        })?;
        // Idempotent: if the file already exists byte-identically we no-op; if it exists
        // with different content the no-clobber guard fails closed.
        write_secret_file(&file_path, &bytes)?;
        Ok(())
    }

    /// Convenience read API for tests + milestone 4's chained round loaders. Returns None if
    /// no round state file exists at the per-session path.
    pub fn load_round_state_file(
        session_dir: &Path,
        round_name: &str,
    ) -> WorkerResult<Option<RoundStateFile>> {
        let path = session_dir.join(round_file_name(round_name));
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|err| {
            WorkerError::Crypto(format!("read mpcca round state {}: {err}", path.display()))
        })?;
        let existing: RoundStateFile = serde_json::from_slice(&raw).map_err(|err| {
            WorkerError::Crypto(format!(
                "parse mpcca round state {}: {err}",
                path.display()
            ))
        })?;
        if existing.scheme != "mpcca_withdraw_v2" {
            return Err(WorkerError::InvalidDkgState(
                "mpcca_withdraw_v2_unexpected_scheme_on_disk".to_string(),
            ));
        }
        Ok(Some(existing))
    }

    /// Hash a serialised RoundStateFile via sha256 of its JSON bytes. Used by tests + the
    /// session_state_hash returned by run_round{1,2,prove,finalize}_v2.
    pub fn round_state_file_hash_at(
        session_dir: &Path,
        round_name: &str,
    ) -> WorkerResult<Option<String>> {
        let path = session_dir.join(round_file_name(round_name));
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|err| {
            WorkerError::Crypto(format!("read mpcca round state {}: {err}", path.display()))
        })?;
        Ok(Some(sha256_hex(&raw)))
    }

    /// Sister API for the milestone 3a stub surface in `main.rs`: returns the (sessionStatePath,
    /// sessionStateHash) AFTER the run_round{N}_v2 entrypoint persisted the file. We return
    /// these alongside the 501 so the coordinator can persist its round-1 partial transcript.
    pub fn last_persisted_round_state(
        session_dir: &Path,
        round_name: &str,
    ) -> WorkerResult<(PathBuf, String)> {
        let path = session_dir.join(round_file_name(round_name));
        let raw = fs::read(&path).map_err(|err| {
            WorkerError::Crypto(format!(
                "read mpcca round state {}: {err}",
                path.display()
            ))
        })?;
        Ok((path, sha256_hex(&raw)))
    }

    fn validate_selected_slots(slots: &[usize]) -> WorkerResult<()> {
        if slots.len() != DEOPERATOR_THRESHOLD {
            return Err(WorkerError::InvalidRequest(format!(
                "selected_slots must have {DEOPERATOR_THRESHOLD} entries, got {}",
                slots.len()
            )));
        }
        let mut seen = [false; DEOPERATOR_COUNT];
        for slot in slots {
            assert_slot(*slot)?;
            if seen[*slot] {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate selected_slots entry {slot}"
                )));
            }
            seen[*slot] = true;
        }
        Ok(())
    }

    fn sorted_unique_slots(slots: &[usize]) -> WorkerResult<Vec<usize>> {
        validate_selected_slots(slots)?;
        let mut copy = slots.to_vec();
        copy.sort_unstable();
        Ok(copy)
    }

    /// Codex M3a P2 #2: atomic write with no-clobber + byte-equality idempotency gate for
    /// the mpcca_withdraw_v2 per-session-per-round state file. The caller (persist_and_stub)
    /// preserves the original `created_at_unix_ms` on replays so the byte content is stable;
    /// a divergent worker_transcript_hash + same path → InvalidDkgState collision.
    fn write_secret_file(path: &Path, contents: &[u8]) -> WorkerResult<()> {
        crate::atomic_io::write_atomic_no_clobber(
            path,
            contents,
            "mpcca_withdraw_v2_session_state",
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
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

    fn normalize_hex(hex: &str, expected_bytes: usize) -> WorkerResult<String> {
        let bytes = hex_decode(hex)?;
        if bytes.len() != expected_bytes {
            return Err(WorkerError::InvalidRequest(format!(
                "expected {expected_bytes}-byte hex, got {}",
                bytes.len()
            )));
        }
        Ok(hex_encode(&bytes))
    }
}

pub mod frost_dkg_v2 {
    use crate::hpke_aead::{self, HpkeEnvelope};
    use crate::local_state::slot_to_identifier;
    use crate::{
        assert_slot, assert_v2_threshold, validate_decimal_segment, WorkerError, WorkerResult,
        DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD,
    };
    use frost_ed25519 as frost;
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

    pub(crate) const FROST_KEY_PACKAGE_FILE: &str = "frost_key_package.json";
    pub(crate) const FROST_PUBLIC_PACKAGE_FILE: &str = "frost_public_package.json";
    pub(crate) const FROST_MANIFEST_FILE: &str = "frost_state_manifest.json";
    pub(crate) const HPKE_KEYPAIR_FILE: &str = "hpke_x25519_keypair_v2.json";
    pub(crate) const FROST_DKG_V2_DIR: &str = "frost_dkg_v2";
    pub(crate) const ROUND1_SELF_FILE: &str = "round1_self.json";
    pub(crate) const ROUND1_BROADCASTS_FILE: &str = "round1_broadcasts.json";
    pub(crate) const ROUND2_SECRET_FILE: &str = "round2_secret.json";
    pub(crate) const ROUND2_RECEIVED_DIR: &str = "round2_received";
    pub(crate) const STATE_FILE: &str = "state.json";

    // Cross-protocol replay safety: distinct HPKE info string vs. CA DKG V2.
    pub(crate) const HPKE_INFO: &[u8] = b"EUNOMA_FROST_DKG_V2_HPKE_INFO_V1";
    pub(crate) const HPKE_AAD_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_HPKE_AAD_V1";
    pub(crate) const ROUND1_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_R1";
    pub(crate) const ROUND2_SEND_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_R2_SEND";
    pub(crate) const ROUND2_RECEIVE_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_R2_RECEIVE";
    pub(crate) const FINALIZE_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_FINALIZE";
    pub(crate) const ROSTER_DOMAIN: &str = "EUNOMA_FROST_DKG_V2_ROSTER_V1";
    pub(crate) const COMPLAINT_DOMAIN: &[u8] = b"EUNOMA_FROST_DKG_V2_COMPLAINT";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostDkgV2Roster {
        pub operator_set_version: String,
        pub dkg_epoch: String,
        pub ca_dkg_scheme: String,
        pub threshold: usize,
        pub nodes: Vec<FrostDkgV2RosterNode>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostDkgV2RosterNode {
        pub slot: usize,
        pub node_id: String,
        pub endpoint: String,
        pub hpke_public_key: String,
        pub transcript_public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostRound1Broadcast {
        pub slot: usize,
        pub package_hex: String,
        pub package_hash: String,
        pub transcript_hash: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostRound2Envelope {
        pub dealer_slot: usize,
        pub to_slot: usize,
        pub package_commitment: String,
        pub hpke: HpkeEnvelope,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostDkgV2Complaint {
        pub accused_slot: usize,
        pub evidence_kind: String,
        pub evidence_hash: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostDkgV2RoundRequest {
        pub request_id: String,
        pub session_id: String,
        pub round: String,
        pub operator_set_version: String,
        pub dkg_epoch: String,
        pub frost_dkg_v2_roster_hash: String,
        pub threshold: usize,
        pub participant_slots: Vec<usize>,
        pub slot: usize,
        pub frost_dkg_v2_roster: Option<FrostDkgV2Roster>,
        #[serde(default)]
        pub frost_round1_broadcasts: Vec<FrostRound1Broadcast>,
        #[serde(default)]
        pub frost_round2_envelopes: Vec<FrostRound2Envelope>,
        pub transcript_hash: Option<String>,
        pub complaint: Option<Value>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FrostDkgV2RoundResult {
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
        pub frost_round1_broadcast: Option<FrostRound1Broadcast>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub frost_round2_envelopes: Vec<FrostRound2Envelope>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub group_public_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub frost_verifying_share: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub frost_key_package_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub frost_public_package_hash: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub complaints: Vec<FrostDkgV2Complaint>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub abort_evidence_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub finalized: Option<bool>,
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

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Round1Self {
        slot: usize,
        round1_secret: Value,
        round1_package: Value,
        package_hash: String,
    }

    pub fn run_round(
        state_dir: &Path,
        req: FrostDkgV2RoundRequest,
    ) -> WorkerResult<FrostDkgV2RoundResult> {
        validate_round_request(&req)?;
        match req.round.as_str() {
            "round1" => run_round1(state_dir, &req),
            "round2_send" => run_round2_send(state_dir, &req),
            "round2_receive" => run_round2_receive(state_dir, &req),
            "finalize" => run_finalize(state_dir, &req),
            "complaint" => run_complaint(&req),
            _ => Err(WorkerError::InvalidRequest(
                "invalid FROST DKG V2 round".to_string(),
            )),
        }
    }

    fn validate_round_request(req: &FrostDkgV2RoundRequest) -> WorkerResult<()> {
        assert_v2_threshold(req.threshold, req.participant_slots.len())?;
        assert_slot(req.slot)?;
        let expected = (0..DEOPERATOR_COUNT).collect::<Vec<_>>();
        if req.participant_slots != expected {
            return Err(WorkerError::InvalidRequest(
                "participantSlots must be [0,1,2,3,4,5,6]".to_string(),
            ));
        }
        validate_decimal_segment(&req.operator_set_version)?;
        validate_decimal_segment(&req.dkg_epoch)?;
        expect_hex_len(&req.frost_dkg_v2_roster_hash, 32)?;
        Ok(())
    }

    fn validate_roster(roster: &FrostDkgV2Roster) -> WorkerResult<()> {
        if roster.ca_dkg_scheme != "frost_dkg_v2" {
            return Err(WorkerError::InvalidRequest(
                "FROST DKG V2 roster scheme must be frost_dkg_v2".to_string(),
            ));
        }
        assert_v2_threshold(roster.threshold, roster.nodes.len())?;
        validate_decimal_segment(&roster.operator_set_version)?;
        validate_decimal_segment(&roster.dkg_epoch)?;
        let mut seen = BTreeSet::new();
        for node in &roster.nodes {
            assert_slot(node.slot)?;
            if !seen.insert(node.slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "duplicate FROST DKG V2 roster slot {}",
                    node.slot
                )));
            }
            expect_hex_len(&node.hpke_public_key, 32)?;
            expect_hex_len(&node.transcript_public_key, 32)?;
        }
        Ok(())
    }

    pub fn frost_dkg_v2_roster_hash(roster: &FrostDkgV2Roster) -> WorkerResult<String> {
        validate_roster(roster)?;
        let mut sorted = roster.nodes.clone();
        sorted.sort_by_key(|node| node.slot);
        let canonical = json!({
            "domain": ROSTER_DOMAIN,
            "operatorSetVersion": roster.operator_set_version,
            "dkgEpoch": roster.dkg_epoch,
            "caDkgScheme": roster.ca_dkg_scheme,
            "threshold": roster.threshold,
            "nodes": sorted.iter().map(|node| json!({
                "slot": node.slot,
                "nodeId": node.node_id,
                "endpoint": node.endpoint,
                "hpkePublicKey": normalize_hex(&node.hpke_public_key).unwrap_or_default(),
                "transcriptPublicKey": normalize_hex(&node.transcript_public_key).unwrap_or_default(),
            })).collect::<Vec<_>>(),
        });
        let bytes = canonical_json_bytes(&canonical)?;
        Ok(sha256_hex(&bytes))
    }

    fn run_round1(
        state_dir: &Path,
        req: &FrostDkgV2RoundRequest,
    ) -> WorkerResult<FrostDkgV2RoundResult> {
        let roster = req.frost_dkg_v2_roster.as_ref().ok_or_else(|| {
            WorkerError::InvalidRequest(
                "frostDkgV2Roster is required for FROST DKG V2 round1".to_string(),
            )
        })?;
        let computed_hash = frost_dkg_v2_roster_hash(roster)?;
        if computed_hash != normalize_hex(&req.frost_dkg_v2_roster_hash)? {
            return Err(WorkerError::InvalidRequest(
                "frostDkgV2RosterHash mismatch".to_string(),
            ));
        }
        if roster.operator_set_version != req.operator_set_version
            || roster.dkg_epoch != req.dkg_epoch
        {
            return Err(WorkerError::InvalidRequest(
                "roster operatorSetVersion/dkgEpoch must match request".to_string(),
            ));
        }

        let mut rng = OsRng;
        let identifier = slot_to_identifier(req.slot)?;
        let (round1_secret, round1_package) = frost::keys::dkg::part1(
            identifier,
            DEOPERATOR_COUNT as u16,
            DEOPERATOR_THRESHOLD as u16,
            &mut rng,
        )
        .map_err(|err| WorkerError::Crypto(err.to_string()))?;

        let round1_secret_json = to_json_value(&round1_secret)?;
        let round1_package_json = to_json_value(&round1_package)?;
        let package_bytes =
            serde_json::to_vec(&round1_package_json).map_err(|err| WorkerError::Serde(err.to_string()))?;
        let package_hex = hex_encode(&package_bytes);
        let package_hash = sha256_hex(&package_bytes);

        let round1_self = Round1Self {
            slot: req.slot,
            round1_secret: round1_secret_json,
            round1_package: round1_package_json,
            package_hash: package_hash.clone(),
        };
        let epoch_dir = epoch_dir(state_dir, req)?;
        create_private_dir(&epoch_dir)?;
        write_private_json(&epoch_dir.join(ROUND1_SELF_FILE), &to_json_value(&round1_self)?)?;
        write_state_json(&epoch_dir, req, "round1", &computed_hash)?;

        let transcript_hash = round1_transcript_hash(req, &package_hash)?;
        let artifact_hash = artifact_hash(req, &transcript_hash, &[b"round1", package_hash.as_bytes()]);
        let broadcast = FrostRound1Broadcast {
            slot: req.slot,
            package_hex,
            package_hash,
            transcript_hash: transcript_hash.clone(),
        };
        Ok(FrostDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "frost".to_string(),
            round: "round1".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash,
            artifact_hash,
            frost_round1_broadcast: Some(broadcast),
            frost_round2_envelopes: Vec::new(),
            group_public_key: None,
            frost_verifying_share: None,
            frost_key_package_hash: None,
            frost_public_package_hash: None,
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: None,
        })
    }

    fn run_round2_send(
        state_dir: &Path,
        req: &FrostDkgV2RoundRequest,
    ) -> WorkerResult<FrostDkgV2RoundResult> {
        let broadcasts = validate_round1_broadcasts(req)?;
        let epoch_dir = epoch_dir(state_dir, req)?;
        let round1_self_path = epoch_dir.join(ROUND1_SELF_FILE);
        let round1_self_value = read_json(&round1_self_path)?;
        let round1_self: Round1Self = from_json_value(round1_self_value)?;
        if round1_self.slot != req.slot {
            return Err(WorkerError::InvalidDkgState(
                "round1_self.json slot mismatch".to_string(),
            ));
        }
        let self_broadcast = broadcasts.get(&req.slot).ok_or_else(|| {
            WorkerError::InvalidRequest(
                "round2_send broadcasts must include this slot's round1 package".to_string(),
            )
        })?;
        if self_broadcast.package_hash != round1_self.package_hash {
            return Err(WorkerError::InvalidDkgState(
                "round1 broadcast for self does not match local round1_self".to_string(),
            ));
        }

        let round1_secret: frost::keys::dkg::round1::SecretPackage =
            from_json_value(round1_self.round1_secret.clone())?;
        let mut round1_packages_from_others: BTreeMap<
            frost::Identifier,
            frost::keys::dkg::round1::Package,
        > = BTreeMap::new();
        for (slot, broadcast) in broadcasts.iter() {
            if *slot == req.slot {
                continue;
            }
            let value = parse_round1_package_value(&broadcast.package_hex)?;
            let pkg: frost::keys::dkg::round1::Package = from_json_value(value)?;
            round1_packages_from_others.insert(slot_to_identifier(*slot)?, pkg);
        }

        let roster = load_roster_from_state(&epoch_dir)?;
        let (round2_secret, round2_packages) =
            frost::keys::dkg::part2(round1_secret, &round1_packages_from_others)
                .map_err(|err| WorkerError::Crypto(err.to_string()))?;

        let mut envelopes = Vec::with_capacity(DEOPERATOR_COUNT - 1);
        let mut envelope_commitments: Vec<String> = Vec::with_capacity(DEOPERATOR_COUNT - 1);
        for slot in 0..DEOPERATOR_COUNT {
            if slot == req.slot {
                continue;
            }
            let identifier = slot_to_identifier(slot)?;
            let package = round2_packages.get(&identifier).ok_or_else(|| {
                WorkerError::Crypto(format!("missing round2 package for slot {slot}"))
            })?;
            let plaintext = serde_json::to_vec(package)
                .map_err(|err| WorkerError::Serde(err.to_string()))?;
            let package_commitment = sha256_hex(&plaintext);
            let recipient_pk = roster
                .nodes
                .iter()
                .find(|node| node.slot == slot)
                .ok_or_else(|| {
                    WorkerError::InvalidDkgState(format!("missing roster node for slot {slot}"))
                })?
                .hpke_public_key
                .clone();
            let aad = build_hpke_aad(req, req.slot, slot)?;
            let hpke = hpke_aead::seal(&recipient_pk, HPKE_INFO, &aad, &plaintext)?;
            envelope_commitments.push(package_commitment.clone());
            envelopes.push(FrostRound2Envelope {
                dealer_slot: req.slot,
                to_slot: slot,
                package_commitment,
                hpke,
            });
        }

        let round2_secret_json = to_json_value(&round2_secret)?;
        write_private_json(
            &epoch_dir.join(ROUND2_SECRET_FILE),
            &round2_secret_json,
        )?;
        let broadcasts_json = to_json_value(&req.frost_round1_broadcasts)?;
        write_private_json(&epoch_dir.join(ROUND1_BROADCASTS_FILE), &broadcasts_json)?;
        // Cleanup: round1 secret has been consumed by part2.
        let _ = fs::remove_file(&round1_self_path);
        write_state_json(&epoch_dir, req, "round2_send", &normalize_hex(&req.frost_dkg_v2_roster_hash)?)?;

        let mut sorted_round1 = broadcasts.values().cloned().collect::<Vec<_>>();
        sorted_round1.sort_by_key(|b| b.slot);
        let mut sorted_envelopes = envelope_commitments.clone();
        sorted_envelopes.sort();
        let transcript_hash =
            round2_send_transcript_hash(req, &sorted_round1, &sorted_envelopes)?;
        let artifact_hash =
            artifact_hash(req, &transcript_hash, &[b"round2_send"]);

        Ok(FrostDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "frost".to_string(),
            round: "round2_send".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash,
            artifact_hash,
            frost_round1_broadcast: None,
            frost_round2_envelopes: envelopes,
            group_public_key: None,
            frost_verifying_share: None,
            frost_key_package_hash: None,
            frost_public_package_hash: None,
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: None,
        })
    }

    fn run_round2_receive(
        state_dir: &Path,
        req: &FrostDkgV2RoundRequest,
    ) -> WorkerResult<FrostDkgV2RoundResult> {
        let broadcasts = validate_round1_broadcasts(req)?;
        if req.frost_round2_envelopes.len() != DEOPERATOR_COUNT - 1 {
            return Err(WorkerError::InvalidRequest(format!(
                "round2_receive requires {} envelopes",
                DEOPERATOR_COUNT - 1
            )));
        }
        let mut seen_dealers = BTreeSet::new();
        for envelope in &req.frost_round2_envelopes {
            assert_slot(envelope.dealer_slot)?;
            assert_slot(envelope.to_slot)?;
            if envelope.to_slot != req.slot {
                return Err(WorkerError::InvalidRequest(
                    "round2 envelope receiver slot mismatch".to_string(),
                ));
            }
            if envelope.dealer_slot == req.slot {
                return Err(WorkerError::InvalidRequest(
                    "round2 envelope dealer must not equal receiver".to_string(),
                ));
            }
            if !seen_dealers.insert(envelope.dealer_slot) {
                return Err(WorkerError::InvalidRequest(
                    "duplicate round2 envelope dealer".to_string(),
                ));
            }
            hpke_aead::validate(&envelope.hpke)?;
            expect_hex_len(&envelope.package_commitment, 32)?;
        }
        for slot in 0..DEOPERATOR_COUNT {
            if slot == req.slot {
                continue;
            }
            if !seen_dealers.contains(&slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "round2_receive missing envelope from dealer slot {slot}"
                )));
            }
        }

        let epoch_dir = epoch_dir(state_dir, req)?;
        let keypair_path = state_dir.join(HPKE_KEYPAIR_FILE);
        let keypair_value = read_json(&keypair_path)?;
        let keypair: HpkeKeypairFile = from_json_value(keypair_value)?;
        if keypair.slot != req.slot {
            return Err(WorkerError::InvalidDkgState(
                "HPKE keypair slot mismatch".to_string(),
            ));
        }

        create_private_dir(&epoch_dir.join(ROUND2_RECEIVED_DIR))?;

        let mut complaints: Vec<FrostDkgV2Complaint> = Vec::new();
        let mut envelope_commitments: Vec<String> = Vec::new();
        for envelope in &req.frost_round2_envelopes {
            let aad = build_hpke_aad(req, envelope.dealer_slot, req.slot)?;
            if envelope.hpke.aad_hash != hpke_aead::sha256_hex(&aad) {
                complaints.push(complaint_at(envelope.dealer_slot, "bad-aad-hash"));
                continue;
            }
            let plaintext = match hpke_aead::open(&keypair.private_key, HPKE_INFO, &aad, &envelope.hpke) {
                Ok(bytes) => bytes,
                Err(_) => {
                    complaints.push(complaint_at(envelope.dealer_slot, "hpke-open-failed"));
                    continue;
                }
            };
            if sha256_hex(&plaintext) != normalize_hex(&envelope.package_commitment)? {
                complaints.push(complaint_at(envelope.dealer_slot, "commitment-mismatch"));
                continue;
            }
            let value: Value = match serde_json::from_slice(&plaintext) {
                Ok(value) => value,
                Err(_) => {
                    complaints.push(complaint_at(envelope.dealer_slot, "bad-plaintext"));
                    continue;
                }
            };
            if serde_json::from_value::<frost::keys::dkg::round2::Package>(value.clone()).is_err() {
                complaints.push(complaint_at(envelope.dealer_slot, "bad-round2-package"));
                continue;
            }
            let received_path = epoch_dir
                .join(ROUND2_RECEIVED_DIR)
                .join(format!("{}.json", envelope.dealer_slot));
            write_private_json(&received_path, &value)?;
            envelope_commitments.push(envelope.package_commitment.clone());
        }

        if !complaints.is_empty() {
            let abort_evidence = sha256_hex(
                serde_json::to_vec(&complaints)
                    .map_err(|err| WorkerError::Serde(err.to_string()))?
                    .as_slice(),
            );
            let transcript_hash = sha256_hex(abort_evidence.as_bytes());
            let artifact_hash = artifact_hash(req, &transcript_hash, &[b"round2_receive-abort"]);
            return Ok(FrostDkgV2RoundResult {
                request_id: req.request_id.clone(),
                session_id: req.session_id.clone(),
                protocol: "frost".to_string(),
                round: "round2_receive".to_string(),
                operator_set_version: req.operator_set_version.clone(),
                dkg_epoch: req.dkg_epoch.clone(),
                slot: req.slot,
                accepted: true,
                transcript_hash,
                artifact_hash,
                frost_round1_broadcast: None,
                frost_round2_envelopes: Vec::new(),
                group_public_key: None,
                frost_verifying_share: None,
                frost_key_package_hash: None,
                frost_public_package_hash: None,
                complaints,
                abort_evidence_hash: Some(abort_evidence),
                finalized: None,
            });
        }

        write_private_json(
            &epoch_dir.join(ROUND1_BROADCASTS_FILE),
            &to_json_value(&req.frost_round1_broadcasts)?,
        )?;
        write_state_json(
            &epoch_dir,
            req,
            "round2_receive",
            &normalize_hex(&req.frost_dkg_v2_roster_hash)?,
        )?;

        let mut sorted_round1 = broadcasts.values().cloned().collect::<Vec<_>>();
        sorted_round1.sort_by_key(|b| b.slot);
        envelope_commitments.sort();
        let transcript_hash =
            round2_receive_transcript_hash(req, &sorted_round1, &envelope_commitments)?;
        let artifact_hash = artifact_hash(req, &transcript_hash, &[b"round2_receive"]);

        Ok(FrostDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "frost".to_string(),
            round: "round2_receive".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash,
            artifact_hash,
            frost_round1_broadcast: None,
            frost_round2_envelopes: Vec::new(),
            group_public_key: None,
            frost_verifying_share: None,
            frost_key_package_hash: None,
            frost_public_package_hash: None,
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: None,
        })
    }

    fn run_finalize(
        state_dir: &Path,
        req: &FrostDkgV2RoundRequest,
    ) -> WorkerResult<FrostDkgV2RoundResult> {
        let request_transcript = req.transcript_hash.as_ref().ok_or_else(|| {
            WorkerError::InvalidRequest("finalize requires transcriptHash".to_string())
        })?;
        expect_hex_len(request_transcript, 32)?;
        let epoch_dir = epoch_dir(state_dir, req)?;
        let round2_secret_value = read_json(&epoch_dir.join(ROUND2_SECRET_FILE))?;
        let round2_secret: frost::keys::dkg::round2::SecretPackage =
            from_json_value(round2_secret_value)?;
        let broadcasts_value = read_json(&epoch_dir.join(ROUND1_BROADCASTS_FILE))?;
        let broadcasts: Vec<FrostRound1Broadcast> = from_json_value(broadcasts_value)?;
        if broadcasts.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidDkgState(
                "round1_broadcasts.json must contain 7 entries".to_string(),
            ));
        }

        let mut round1_packages_from_others: BTreeMap<
            frost::Identifier,
            frost::keys::dkg::round1::Package,
        > = BTreeMap::new();
        for broadcast in &broadcasts {
            if broadcast.slot == req.slot {
                continue;
            }
            let value = parse_round1_package_value(&broadcast.package_hex)?;
            let pkg: frost::keys::dkg::round1::Package = from_json_value(value)?;
            round1_packages_from_others.insert(slot_to_identifier(broadcast.slot)?, pkg);
        }

        let mut round2_packages_from_others: BTreeMap<
            frost::Identifier,
            frost::keys::dkg::round2::Package,
        > = BTreeMap::new();
        for slot in 0..DEOPERATOR_COUNT {
            if slot == req.slot {
                continue;
            }
            let path = epoch_dir
                .join(ROUND2_RECEIVED_DIR)
                .join(format!("{slot}.json"));
            let value = read_json(&path)?;
            let pkg: frost::keys::dkg::round2::Package = from_json_value(value)?;
            round2_packages_from_others.insert(slot_to_identifier(slot)?, pkg);
        }

        let (key_package, public_package) = frost::keys::dkg::part3(
            &round2_secret,
            &round1_packages_from_others,
            &round2_packages_from_others,
        )
        .map_err(|err| WorkerError::Crypto(err.to_string()))?;

        let key_package_json = to_json_value(&key_package)?;
        let public_package_json = to_json_value(&public_package)?;
        let group_public_key = key_str_or_canonical(&public_package_json, "verifying_key")?;
        let frost_verifying_share = key_str_or_canonical(&key_package_json, "verifying_share")?;

        let key_path = state_dir.join(FROST_KEY_PACKAGE_FILE);
        let public_path = state_dir.join(FROST_PUBLIC_PACKAGE_FILE);
        atomic_replace_private_json(&key_path, &key_package_json)?;
        atomic_replace_private_json(&public_path, &public_package_json)?;

        let key_hash = sha256_hex(&fs::read(&key_path).map_err(|err| WorkerError::Io(err.to_string()))?);
        let public_hash =
            sha256_hex(&fs::read(&public_path).map_err(|err| WorkerError::Io(err.to_string()))?);
        let manifest = json!({
            "slot": req.slot,
            "threshold": DEOPERATOR_THRESHOLD,
            "count": DEOPERATOR_COUNT,
            "dkgEpoch": req.dkg_epoch,
            "groupPublicKey": group_public_key,
            "frostVerifyingShare": frost_verifying_share,
            "frostKeyPackageHash": key_hash,
            "frostPublicPackageHash": public_hash,
            "createdAtUnixMs": now_millis(),
        });
        atomic_replace_private_json(&state_dir.join(FROST_MANIFEST_FILE), &manifest)?;

        // Cleanup: secrets consumed by part3.
        let _ = fs::remove_file(epoch_dir.join(ROUND2_SECRET_FILE));
        let _ = fs::remove_dir_all(epoch_dir.join(ROUND2_RECEIVED_DIR));
        write_state_json(
            &epoch_dir,
            req,
            "finalize",
            &normalize_hex(&req.frost_dkg_v2_roster_hash)?,
        )?;

        let transcript_hash = normalize_hex(request_transcript)?;
        let artifact_hash = artifact_hash(
            req,
            &transcript_hash,
            &[b"finalize", key_hash.as_bytes(), public_hash.as_bytes()],
        );

        Ok(FrostDkgV2RoundResult {
            request_id: req.request_id.clone(),
            session_id: req.session_id.clone(),
            protocol: "frost".to_string(),
            round: "finalize".to_string(),
            operator_set_version: req.operator_set_version.clone(),
            dkg_epoch: req.dkg_epoch.clone(),
            slot: req.slot,
            accepted: true,
            transcript_hash,
            artifact_hash,
            frost_round1_broadcast: None,
            frost_round2_envelopes: Vec::new(),
            group_public_key: Some(group_public_key),
            frost_verifying_share: Some(frost_verifying_share),
            frost_key_package_hash: Some(key_hash),
            frost_public_package_hash: Some(public_hash),
            complaints: Vec::new(),
            abort_evidence_hash: None,
            finalized: Some(true),
        })
    }

    fn run_complaint(req: &FrostDkgV2RoundRequest) -> WorkerResult<FrostDkgV2RoundResult> {
        let complaint = req.complaint.as_ref().ok_or_else(|| {
            WorkerError::InvalidRequest("complaint round requires complaint payload".to_string())
        })?;
        let evidence_hash = sha256_hex(
            serde_json::to_vec(complaint)
                .map_err(|err| WorkerError::Serde(err.to_string()))?
                .as_slice(),
        );
        let transcript_hash = sha256_hex(evidence_hash.as_bytes());
        let artifact_hash = artifact_hash(req, &transcript_hash, &[b"complaint"]);
        Err(WorkerError::Complaint(serde_json::to_string(&json!({
            "requestId": req.request_id,
            "sessionId": req.session_id,
            "slot": req.slot,
            "transcriptHash": transcript_hash,
            "artifactHash": artifact_hash,
            "evidenceHash": evidence_hash,
        }))
        .unwrap_or_default()))
    }

    fn validate_round1_broadcasts(
        req: &FrostDkgV2RoundRequest,
    ) -> WorkerResult<BTreeMap<usize, FrostRound1Broadcast>> {
        if req.frost_round1_broadcasts.len() != DEOPERATOR_COUNT {
            return Err(WorkerError::InvalidRequest(format!(
                "FROST DKG V2 round requires {DEOPERATOR_COUNT} round1 broadcasts"
            )));
        }
        let mut out: BTreeMap<usize, FrostRound1Broadcast> = BTreeMap::new();
        for broadcast in &req.frost_round1_broadcasts {
            assert_slot(broadcast.slot)?;
            expect_hex_len(&broadcast.package_hash, 32)?;
            expect_hex_len(&broadcast.transcript_hash, 32)?;
            let package_bytes = hex_decode(&broadcast.package_hex)?;
            let _value: Value = serde_json::from_slice(&package_bytes)
                .map_err(|err| WorkerError::Serde(err.to_string()))?;
            let computed_hash = sha256_hex(&package_bytes);
            if computed_hash != normalize_hex(&broadcast.package_hash)? {
                return Err(WorkerError::InvalidRequest(format!(
                    "round1 broadcast packageHash mismatch for slot {}",
                    broadcast.slot
                )));
            }
            let expected_transcript = round1_transcript_hash_for_slot(req, broadcast.slot, &computed_hash)?;
            if expected_transcript != broadcast.transcript_hash {
                return Err(WorkerError::InvalidRequest(format!(
                    "round1 broadcast transcriptHash mismatch for slot {}",
                    broadcast.slot
                )));
            }
            if out.insert(broadcast.slot, broadcast.clone()).is_some() {
                return Err(WorkerError::InvalidRequest(
                    "duplicate round1 broadcast slot".to_string(),
                ));
            }
        }
        for slot in 0..DEOPERATOR_COUNT {
            if !out.contains_key(&slot) {
                return Err(WorkerError::InvalidRequest(format!(
                    "missing round1 broadcast for slot {slot}"
                )));
            }
        }
        Ok(out)
    }

    fn load_roster_from_state(epoch_dir: &Path) -> WorkerResult<FrostDkgV2Roster> {
        let state_value = read_json(&epoch_dir.join(STATE_FILE))?;
        let roster_value = state_value
            .get("roster")
            .cloned()
            .ok_or_else(|| WorkerError::InvalidDkgState("state.json missing roster".to_string()))?;
        from_json_value(roster_value)
    }

    fn write_state_json(
        epoch_dir: &Path,
        req: &FrostDkgV2RoundRequest,
        status: &str,
        roster_hash: &str,
    ) -> WorkerResult<()> {
        let mut value = if epoch_dir.join(STATE_FILE).exists() {
            read_json(&epoch_dir.join(STATE_FILE))?
        } else {
            json!({})
        };
        let obj = value.as_object_mut().ok_or_else(|| {
            WorkerError::Serde("state.json must be a JSON object".to_string())
        })?;
        obj.insert("operatorSetVersion".to_string(), json!(req.operator_set_version));
        obj.insert("dkgEpoch".to_string(), json!(req.dkg_epoch));
        obj.insert(
            "frostDkgV2RosterHash".to_string(),
            json!(normalize_hex(roster_hash)?),
        );
        obj.insert("status".to_string(), json!(status));
        obj.insert("slot".to_string(), json!(req.slot));
        obj.insert(
            "participantSet".to_string(),
            json!(req.participant_slots.clone()),
        );
        if !obj.contains_key("roster") {
            if let Some(roster) = req.frost_dkg_v2_roster.as_ref() {
                obj.insert("roster".to_string(), to_json_value(roster)?);
            }
        }
        if !obj.contains_key("complaintLog") {
            obj.insert("complaintLog".to_string(), json!([]));
        }
        write_private_json(&epoch_dir.join(STATE_FILE), &value)
    }

    fn build_hpke_aad(
        req: &FrostDkgV2RoundRequest,
        dealer_slot: usize,
        to_slot: usize,
    ) -> WorkerResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(HPKE_AAD_DOMAIN);
        hasher.update(req.request_id.as_bytes());
        hasher.update(req.session_id.as_bytes());
        hasher.update(req.operator_set_version.as_bytes());
        hasher.update(req.dkg_epoch.as_bytes());
        hasher.update(normalize_hex(&req.frost_dkg_v2_roster_hash)?.as_bytes());
        hasher.update(&[dealer_slot as u8, to_slot as u8]);
        Ok(hasher.finalize().to_vec())
    }

    fn round1_transcript_hash(
        req: &FrostDkgV2RoundRequest,
        package_hash: &str,
    ) -> WorkerResult<String> {
        round1_transcript_hash_for_slot(req, req.slot, package_hash)
    }

    fn round1_transcript_hash_for_slot(
        req: &FrostDkgV2RoundRequest,
        slot: usize,
        package_hash: &str,
    ) -> WorkerResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(ROUND1_DOMAIN);
        hasher.update(req.request_id.as_bytes());
        hasher.update(req.session_id.as_bytes());
        hasher.update(req.operator_set_version.as_bytes());
        hasher.update(req.dkg_epoch.as_bytes());
        hasher.update(normalize_hex(&req.frost_dkg_v2_roster_hash)?.as_bytes());
        hasher.update(&[slot as u8]);
        hasher.update(normalize_hex(package_hash)?.as_bytes());
        Ok(hex_encode(&hasher.finalize()))
    }

    fn round2_send_transcript_hash(
        req: &FrostDkgV2RoundRequest,
        sorted_round1: &[FrostRound1Broadcast],
        sorted_envelope_commitments: &[String],
    ) -> WorkerResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(ROUND2_SEND_DOMAIN);
        hasher.update(req.request_id.as_bytes());
        hasher.update(req.session_id.as_bytes());
        hasher.update(req.operator_set_version.as_bytes());
        hasher.update(req.dkg_epoch.as_bytes());
        hasher.update(normalize_hex(&req.frost_dkg_v2_roster_hash)?.as_bytes());
        for broadcast in sorted_round1 {
            hasher.update(normalize_hex(&broadcast.package_hash)?.as_bytes());
        }
        for commitment in sorted_envelope_commitments {
            hasher.update(normalize_hex(commitment)?.as_bytes());
        }
        Ok(hex_encode(&hasher.finalize()))
    }

    fn round2_receive_transcript_hash(
        req: &FrostDkgV2RoundRequest,
        sorted_round1: &[FrostRound1Broadcast],
        sorted_envelope_commitments_received: &[String],
    ) -> WorkerResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(ROUND2_RECEIVE_DOMAIN);
        hasher.update(req.request_id.as_bytes());
        hasher.update(req.session_id.as_bytes());
        hasher.update(req.operator_set_version.as_bytes());
        hasher.update(req.dkg_epoch.as_bytes());
        hasher.update(normalize_hex(&req.frost_dkg_v2_roster_hash)?.as_bytes());
        for broadcast in sorted_round1 {
            hasher.update(normalize_hex(&broadcast.package_hash)?.as_bytes());
        }
        for commitment in sorted_envelope_commitments_received {
            hasher.update(normalize_hex(commitment)?.as_bytes());
        }
        Ok(hex_encode(&hasher.finalize()))
    }

    fn artifact_hash(req: &FrostDkgV2RoundRequest, transcript_hash: &str, parts: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(FINALIZE_DOMAIN);
        hasher.update(req.request_id.as_bytes());
        hasher.update(req.session_id.as_bytes());
        hasher.update(req.operator_set_version.as_bytes());
        hasher.update(req.dkg_epoch.as_bytes());
        hasher.update(&[req.slot as u8]);
        hasher.update(req.round.as_bytes());
        hasher.update(transcript_hash.as_bytes());
        for part in parts {
            hasher.update(part);
        }
        hex_encode(&hasher.finalize())
    }

    fn complaint_at(slot: usize, kind: &str) -> FrostDkgV2Complaint {
        let mut hasher = Sha256::new();
        hasher.update(COMPLAINT_DOMAIN);
        hasher.update(&[slot as u8]);
        hasher.update(kind.as_bytes());
        FrostDkgV2Complaint {
            accused_slot: slot,
            evidence_kind: kind.to_string(),
            evidence_hash: hex_encode(&hasher.finalize()),
        }
    }

    fn epoch_dir(state_dir: &Path, req: &FrostDkgV2RoundRequest) -> WorkerResult<PathBuf> {
        validate_decimal_segment(&req.operator_set_version)?;
        validate_decimal_segment(&req.dkg_epoch)?;
        Ok(state_dir
            .join(FROST_DKG_V2_DIR)
            .join(format!("{}-{}", req.operator_set_version, req.dkg_epoch)))
    }

    fn parse_round1_package_value(package_hex: &str) -> WorkerResult<Value> {
        let bytes = hex_decode(package_hex)?;
        serde_json::from_slice::<Value>(&bytes).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn key_str_or_canonical(value: &Value, field: &str) -> WorkerResult<String> {
        let inner = value
            .get(field)
            .ok_or_else(|| WorkerError::Serde(format!("missing field {field}")))?;
        if let Some(s) = inner.as_str() {
            return Ok(s.to_string());
        }
        canonical_json_string(inner)
    }

    fn atomic_replace_private_json(path: &Path, value: &Value) -> WorkerResult<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp_path = PathBuf::from(tmp);
        write_private_json(&tmp_path, value)?;
        fs::rename(&tmp_path, path).map_err(|err| WorkerError::Io(err.to_string()))
    }

    fn write_private_json(path: &Path, value: &Value) -> WorkerResult<()> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|err| WorkerError::Serde(err.to_string()))?;
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        fs::write(path, bytes).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_file_permissions(path)
    }

    fn create_private_dir(path: &Path) -> WorkerResult<()> {
        fs::create_dir_all(path).map_err(|err| WorkerError::Io(err.to_string()))?;
        set_private_dir_permissions(path)
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

    fn to_json_value<T: Serialize>(value: &T) -> WorkerResult<Value> {
        serde_json::to_value(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn from_json_value<T>(value: Value) -> WorkerResult<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn canonical_json_bytes(value: &Value) -> WorkerResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn canonical_json_string(value: &Value) -> WorkerResult<String> {
        serde_json::to_string(value).map_err(|err| WorkerError::Serde(err.to_string()))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
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

    #[test]
    fn frost_dkg_v2_online_roundtrip() {
        use crate::ca_dkg_v2::init_hpke_local;
        use crate::frost_dkg_v2::{
            frost_dkg_v2_roster_hash, run_round, FrostDkgV2Roster, FrostDkgV2RosterNode,
            FrostDkgV2RoundRequest, FROST_DKG_V2_DIR, FROST_KEY_PACKAGE_FILE,
            FROST_MANIFEST_FILE, FROST_PUBLIC_PACKAGE_FILE, HPKE_KEYPAIR_FILE,
            ROUND1_BROADCASTS_FILE, ROUND1_SELF_FILE, ROUND2_RECEIVED_DIR, ROUND2_SECRET_FILE,
            STATE_FILE,
        };
        use crate::local_state::{
            aggregate_frost_signature, create_frost_nonce_commitment, create_frost_partial_signature,
            FrostCommitmentInput, FrostSignatureShareInput,
        };
        use std::collections::{BTreeMap, HashSet};

        let root = std::env::temp_dir().join(format!(
            "eunoma-frost-dkg-v2-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let hpke = init_hpke_local(&root, false).expect("init HPKE keys");
        let operator_set_version = "1".to_string();
        let dkg_epoch = "9".to_string();
        let request_id = "frost-dkg-v2-test".to_string();
        let session_id = "frost-dkg-v2-session".to_string();
        let participant_slots = (0..DEOPERATOR_COUNT).collect::<Vec<_>>();
        let roster = FrostDkgV2Roster {
            operator_set_version: operator_set_version.clone(),
            dkg_epoch: dkg_epoch.clone(),
            ca_dkg_scheme: "frost_dkg_v2".to_string(),
            threshold: DEOPERATOR_THRESHOLD,
            nodes: hpke
                .slots
                .iter()
                .map(|slot| FrostDkgV2RosterNode {
                    slot: slot.slot,
                    node_id: format!("node-{}", slot.slot),
                    endpoint: format!("http://127.0.0.1:{}", 4100 + slot.slot),
                    hpke_public_key: slot.hpke_public_key.clone(),
                    transcript_public_key: "77".repeat(32),
                })
                .collect(),
        };
        let roster_hash = frost_dkg_v2_roster_hash(&roster).expect("roster hash");

        let mut round1_results = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "round1".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: Some(roster.clone()),
                    frost_round1_broadcasts: Vec::new(),
                    frost_round2_envelopes: Vec::new(),
                    transcript_hash: None,
                    complaint: None,
                },
            )
            .expect("round1");
            round1_results.push(result);
        }
        let round1_broadcasts: Vec<_> = round1_results
            .iter()
            .map(|r| r.frost_round1_broadcast.clone().expect("broadcast"))
            .collect();

        let mut round2_send_envelopes = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "round2_send".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: None,
                    frost_round1_broadcasts: round1_broadcasts.clone(),
                    frost_round2_envelopes: Vec::new(),
                    transcript_hash: None,
                    complaint: None,
                },
            )
            .expect("round2_send");
            assert_eq!(result.frost_round2_envelopes.len(), DEOPERATOR_COUNT - 1);
            assert!(!root
                .join(format!("slot-{slot}"))
                .join(FROST_DKG_V2_DIR)
                .join(format!("{operator_set_version}-{dkg_epoch}"))
                .join(ROUND1_SELF_FILE)
                .exists());
            round2_send_envelopes.push(result.frost_round2_envelopes);
        }

        let mut envelopes_by_receiver: BTreeMap<usize, Vec<_>> = BTreeMap::new();
        for env_list in &round2_send_envelopes {
            for env in env_list {
                envelopes_by_receiver
                    .entry(env.to_slot)
                    .or_default()
                    .push(env.clone());
            }
        }
        let mut round2_receive_transcripts: Vec<String> = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let envelopes = envelopes_by_receiver.get(&slot).cloned().unwrap_or_default();
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "round2_receive".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: None,
                    frost_round1_broadcasts: round1_broadcasts.clone(),
                    frost_round2_envelopes: envelopes,
                    transcript_hash: None,
                    complaint: None,
                },
            )
            .expect("round2_receive");
            assert!(result.complaints.is_empty());
            round2_receive_transcripts.push(result.transcript_hash);
        }
        let mut sorted_transcripts = round2_receive_transcripts.clone();
        sorted_transcripts.sort();
        let dkg_transcript_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for transcript in &sorted_transcripts {
                hasher.update(transcript.as_bytes());
            }
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        let mut finalize_group_keys = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    round: "finalize".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: None,
                    frost_round1_broadcasts: Vec::new(),
                    frost_round2_envelopes: Vec::new(),
                    transcript_hash: Some(dkg_transcript_hash.clone()),
                    complaint: None,
                },
            )
            .expect("finalize");
            assert_eq!(result.finalized, Some(true));
            finalize_group_keys.push(result.group_public_key.expect("group public key"));
        }
        let first_group_key = finalize_group_keys[0].clone();
        for key in &finalize_group_keys {
            assert_eq!(key, &first_group_key);
        }

        let expected_files: HashSet<&str> = [
            HPKE_KEYPAIR_FILE,
            FROST_KEY_PACKAGE_FILE,
            FROST_PUBLIC_PACKAGE_FILE,
            FROST_MANIFEST_FILE,
            FROST_DKG_V2_DIR,
        ]
        .into_iter()
        .collect();
        for slot in 0..DEOPERATOR_COUNT {
            let slot_dir = root.join(format!("slot-{slot}"));
            let entries: HashSet<String> = std::fs::read_dir(&slot_dir)
                .expect("read slot dir")
                .map(|entry| entry.expect("entry").file_name().into_string().expect("utf8"))
                .collect();
            for name in &expected_files {
                assert!(entries.contains(*name), "slot {slot} missing {name}");
            }
            for entry in &entries {
                assert!(
                    expected_files.contains(entry.as_str()),
                    "slot {slot} has unexpected entry {entry}"
                );
            }
            let epoch_dir = slot_dir
                .join(FROST_DKG_V2_DIR)
                .join(format!("{operator_set_version}-{dkg_epoch}"));
            assert!(epoch_dir.join(STATE_FILE).exists());
            assert!(!epoch_dir.join(ROUND1_SELF_FILE).exists());
            assert!(!epoch_dir.join(ROUND2_SECRET_FILE).exists());
            assert!(!epoch_dir.join(ROUND2_RECEIVED_DIR).exists());
            assert!(epoch_dir.join(ROUND1_BROADCASTS_FILE).exists());
        }

        let mut nonce_results = Vec::new();
        for slot in 0..DEOPERATOR_THRESHOLD {
            let state_dir = root.join(format!("slot-{slot}"));
            let nonce =
                create_frost_nonce_commitment(&state_dir, "rotated-sign").expect("nonce commit");
            nonce_results.push((slot, nonce));
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
            let partial = create_frost_partial_signature(
                &root.join(format!("slot-{slot}")),
                &nonce_result.nonce_id,
                "deadbeef",
                commitments.clone(),
            )
            .expect("partial");
            signature_shares.push(FrostSignatureShareInput {
                slot: *slot,
                signature_share: partial.signature_share,
            });
        }
        let aggregate = aggregate_frost_signature(
            &root.join("slot-0"),
            "deadbeef",
            commitments.clone(),
            signature_shares.clone(),
        )
        .expect("aggregate rotated signature");
        assert_eq!(aggregate.signature.len(), 128);

        let corrupted_root = std::env::temp_dir().join(format!(
            "eunoma-frost-dkg-v2-test-corrupt-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let hpke = init_hpke_local(&corrupted_root, false).expect("init HPKE keys");
        let corrupted_roster = FrostDkgV2Roster {
            operator_set_version: operator_set_version.clone(),
            dkg_epoch: dkg_epoch.clone(),
            ca_dkg_scheme: "frost_dkg_v2".to_string(),
            threshold: DEOPERATOR_THRESHOLD,
            nodes: hpke
                .slots
                .iter()
                .map(|slot| FrostDkgV2RosterNode {
                    slot: slot.slot,
                    node_id: format!("node-{}", slot.slot),
                    endpoint: format!("http://127.0.0.1:{}", 4100 + slot.slot),
                    hpke_public_key: slot.hpke_public_key.clone(),
                    transcript_public_key: "77".repeat(32),
                })
                .collect(),
        };
        let corrupted_roster_hash =
            frost_dkg_v2_roster_hash(&corrupted_roster).expect("roster hash");

        let mut corrupted_round1 = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &corrupted_root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: "corrupt-frost".to_string(),
                    session_id: "corrupt-session".to_string(),
                    round: "round1".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: corrupted_roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: Some(corrupted_roster.clone()),
                    frost_round1_broadcasts: Vec::new(),
                    frost_round2_envelopes: Vec::new(),
                    transcript_hash: None,
                    complaint: None,
                },
            )
            .expect("round1");
            corrupted_round1.push(result);
        }
        let corrupted_round1_broadcasts: Vec<_> = corrupted_round1
            .iter()
            .map(|r| r.frost_round1_broadcast.clone().expect("broadcast"))
            .collect();
        let mut corrupted_envelopes = Vec::new();
        for slot in 0..DEOPERATOR_COUNT {
            let result = run_round(
                &corrupted_root.join(format!("slot-{slot}")),
                FrostDkgV2RoundRequest {
                    request_id: "corrupt-frost".to_string(),
                    session_id: "corrupt-session".to_string(),
                    round: "round2_send".to_string(),
                    operator_set_version: operator_set_version.clone(),
                    dkg_epoch: dkg_epoch.clone(),
                    frost_dkg_v2_roster_hash: corrupted_roster_hash.clone(),
                    threshold: DEOPERATOR_THRESHOLD,
                    participant_slots: participant_slots.clone(),
                    slot,
                    frost_dkg_v2_roster: None,
                    frost_round1_broadcasts: corrupted_round1_broadcasts.clone(),
                    frost_round2_envelopes: Vec::new(),
                    transcript_hash: None,
                    complaint: None,
                },
            )
            .expect("round2_send");
            corrupted_envelopes.push(result.frost_round2_envelopes);
        }
        let mut corrupted_by_receiver: BTreeMap<usize, Vec<_>> = BTreeMap::new();
        for env_list in &corrupted_envelopes {
            for env in env_list {
                corrupted_by_receiver
                    .entry(env.to_slot)
                    .or_default()
                    .push(env.clone());
            }
        }
        let target = corrupted_by_receiver.get_mut(&0).expect("envelopes for slot 0");
        let original_first_byte = target[0]
            .hpke
            .ciphertext
            .chars()
            .next()
            .expect("ciphertext non-empty");
        let mut bytes: Vec<char> = target[0].hpke.ciphertext.chars().collect();
        bytes[0] = if original_first_byte == 'a' { 'b' } else { 'a' };
        target[0].hpke.ciphertext = bytes.into_iter().collect();

        let corrupt_result = run_round(
            &corrupted_root.join("slot-0"),
            FrostDkgV2RoundRequest {
                request_id: "corrupt-frost".to_string(),
                session_id: "corrupt-session".to_string(),
                round: "round2_receive".to_string(),
                operator_set_version: operator_set_version.clone(),
                dkg_epoch: dkg_epoch.clone(),
                frost_dkg_v2_roster_hash: corrupted_roster_hash.clone(),
                threshold: DEOPERATOR_THRESHOLD,
                participant_slots: participant_slots.clone(),
                slot: 0,
                frost_dkg_v2_roster: None,
                frost_round1_broadcasts: corrupted_round1_broadcasts.clone(),
                frost_round2_envelopes: corrupted_by_receiver.remove(&0).unwrap_or_default(),
                transcript_hash: None,
                complaint: None,
            },
        )
        .expect("complaint round runs");
        assert!(!corrupt_result.complaints.is_empty());
        assert!(corrupt_result.abort_evidence_hash.is_some());

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(corrupted_root);
    }
}
