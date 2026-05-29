export const DEOPERATOR_COUNT = 7;
export const DEOPERATOR_THRESHOLD = 5;
export const CA_DKG_SCHEME_V2 = "ca_dkg_v2";
export const CA_DKG_SCHEME_LOCAL = "ca_local";
export const FROST_DKG_SCHEME_V2 = "frost_dkg_v2";

// (B) deposit re-key: bumped V2→V3 — the deposit attestation message now binds user_addr. MUST
// match the on-chain DOMAIN_DEPOSIT_V2 const string in eunoma_bridge.move (also "..._V3"). Const
// name kept for minimal churn; the SIGNED STRING is the version of record.
export const DOMAIN_DEPOSIT_BIND_V2 = "EUNOMA_DEPOSIT_BIND_V3";
export const DOMAIN_WITHDRAW_ATTESTATION_V2 = "EUNOMA_WITHDRAW_ATTESTATION_V2";
export const DOMAIN_ROSTER_HASH_V2 = "EUNOMA_DEOP_ROSTER_V2";
export const DOMAIN_CA_DKG_V2_ROSTER_HASH = "EUNOMA_CA_DKG_V2_ROSTER";
export const DOMAIN_FROST_DKG_V2_ROSTER_HASH = "EUNOMA_FROST_DKG_V2_ROSTER_V1";
export const DOMAIN_HPKE_AAD_V2 = "EUNOMA_HPKE_AAD_V2";
export const DOMAIN_NORMALIZE_ALPHA_SHARE_V1 = "EUNOMA_NORMALIZE_ALPHA_SHARE_V1";
export const APTOS_CA_REGISTRATION_PROTOCOL_ID = "AptosConfidentialAsset/RegistrationV1";
export const APTOS_CA_TRANSFER_PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
export const APTOS_CA_REGISTRATION_TYPE_NAME =
  "0x1::sigma_protocol_registration::Registration";
export const APTOS_CA_TRANSFER_TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";

export const APTOS_TESTNET_CHAIN_CONFIG_V2 = {
  network: "testnet",
  chainId: 2,
  nodeUrl: "https://fullnode.testnet.aptoslabs.com/v1",
} as const;

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const FR_BYTES = 32;
