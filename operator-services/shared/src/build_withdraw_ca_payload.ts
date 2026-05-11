/**
 * Phase 2.X / W.2 — build CA payload for `confidential_bridge::withdraw_to_recipient`.
 *
 * Off-chain constructor of the 14 CA payload fields (sigma + range proofs)
 * for a vault → recipient `confidential_transfer_raw` dispatch. 90% mirror of
 * testnet_deposit_e2e.ts:189-275 (user → vault), with role swap.
 *
 * Reads:
 *   .vault-ek.json     — vault TwistedEd25519 keypair (vault DK signs sigma)
 *   .recipient-ek.json — recipient TwistedEd25519 EK (encrypts amount chunks)
 *   chain state       — vault.available_balance (sender ciphertext input)
 *
 * Returns the 14 payload fields + raw / Fr-safe ca_payload_hash. Caller is
 * responsible for tx assembly (build/sign/submit) and ca_payload_hash binding
 * into Groth16 proof + attestation msg.
 *
 * Module export only — no main() / direct CLI.
 */

import {
  Aptos,
  AptosConfig,
  Network,
  AccountAddress,
} from '@aptos-labs/ts-sdk';
import {
  ConfidentialAsset,
  ConfidentialTransfer,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
} from '@aptos-labs/confidential-asset';
import { hashConfidentialTransferPayload } from './keccak.js';
import { loadSecretHex } from './secrets.js';

export interface WithdrawCAPayloadInputs {
  vaultAddrHex: string;
  recipientAddrHex: string;
  amountOctas: bigint;
  assetTypeHex?: string; // default 0xa
  chainId?: number;       // default 2 (testnet)
  // W6.6 selective disclosure (self-audit): list of user-chosen voluntary
  // auditor TwistedEd25519 PUBLIC keys (32-byte each). Each entry gets a
  // slot in ek_volun_auds + a per-key encryption of the transfer amount in
  // amount_r_volun_auds. Defaults to empty.
  userAuditPksHex?: string[];
}

export interface WithdrawCAPayloadResult {
  // 14 fields matching `withdraw_to_recipient` arg positions 12-25:
  newBalanceP: Uint8Array[];
  newBalanceR: Uint8Array[];
  newBalanceREffAud: Uint8Array[];
  amountP: Uint8Array[];
  amountRSender: Uint8Array[];
  amountRRecip: Uint8Array[];
  amountREffAud: Uint8Array[];
  ekVolunAuds: Uint8Array[];
  amountRVolunAuds: Uint8Array[][];
  zkrpNewBalance: Uint8Array;
  zkrpAmount: Uint8Array;
  sigmaProtoComm: Uint8Array[];
  sigmaProtoResp: Uint8Array[];
  memo: Uint8Array;
  // Hashes
  caPayloadHashRaw: Uint8Array;       // keccak256(BCS(CAPayloadForHash{...}))
  caPayloadHashFrSafe: Uint8Array;    // high byte forced to 0 (matches Move's ca_payload_hash_to_fr_safe)
  // Diagnostics
  vaultAvailableOctasBefore: bigint;
  vaultAvailableOctasAfterDecrypted: bigint; // = before - amount (sanity check; use only if SDK getBalance works)
}

export async function buildWithdrawCAPayload(
  inputs: WithdrawCAPayloadInputs,
): Promise<WithdrawCAPayloadResult> {
  const assetTypeHex = inputs.assetTypeHex ?? '0xa';
  const chainId = inputs.chainId ?? 2;
  const vaultAddrBytes = AccountAddress.from(inputs.vaultAddrHex).toUint8Array();
  const recipientAddrBytes = AccountAddress.from(inputs.recipientAddrHex).toUint8Array();
  const assetTypeBytes = AccountAddress.from(assetTypeHex).toUint8Array();

  // ---- Load keys (from env; legacy JSON files migrated via migrate_json_secrets_to_env.ts) ----
  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));
  const recipientEk = recipientDk.publicKey();

  // ---- Setup SDK ----
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  // ---- Read vault available balance from chain ----
  const vaultBalance = await ca.getBalance({
    accountAddress: inputs.vaultAddrHex,
    tokenAddress: assetTypeHex,
    decryptionKey: vaultDk,
  });
  const vaultAvailableOctasBefore = vaultBalance.available.getAmount();
  if (vaultAvailableOctasBefore < inputs.amountOctas) {
    throw new Error(
      `vault.available (${vaultAvailableOctasBefore}) < amount (${inputs.amountOctas}); ` +
      `run operator_rollover_vault_pending or increase deposit`,
    );
  }

  // ---- Auditor query (testnet APT may have one) ----
  const assetAuditorEk = await ca.getAssetAuditorEncryptionKey({ tokenAddress: assetTypeHex });
  const hasEffectiveAuditor = !!assetAuditorEk;

  // W6.6: parse user voluntary audit pubkeys (self-disclosure channel).
  const userAuditPks: TwistedEd25519PublicKey[] = (inputs.userAuditPksHex ?? []).map(
    (hexStr) => new TwistedEd25519PublicKey(hexStr.replace(/^0x/, '')),
  );

  // Auditor list order: voluntary first, effective last. SDK's
  // ConfidentialTransfer mirrors this order in auditorTransferAmounts /
  // auditorNewBalances output (verified empirically against Aptos CA SDK
  // ConfidentialTransfer source).
  const auditorKeys = [
    ...userAuditPks,
    ...(assetAuditorEk ? [assetAuditorEk] : []),
  ];

  // ---- Build vault → recipient transfer payload ----
  const transfer = await ConfidentialTransfer.create({
    senderDecryptionKey: vaultDk,
    senderAvailableBalanceCipherText: vaultBalance.available.getCipherText(),
    amount: inputs.amountOctas,
    recipientEncryptionKey: recipientEk,
    hasEffectiveAuditor,
    auditorEncryptionKeys: auditorKeys,
    senderAddress: vaultAddrBytes,
    recipientAddress: recipientAddrBytes,
    tokenAddress: assetTypeBytes,
    chainId,
  });
  const [
    { sigmaProof, rangeProof },
    senderNewBal,
    recipAmount,
    auditorTransferAmounts,
    auditorNewBalances,
  ] = await transfer.authorizeTransfer();

  // ---- Map to 14 CA payload fields (mirror testnet_deposit_e2e.ts:218-247) ----
  const newBalanceP = senderNewBal.getCipherText().map((ct) => ct.C.toRawBytes());
  const newBalanceR = senderNewBal.getCipherText().map((ct) => ct.D.toRawBytes());

  const senderXfer = transfer.transferAmountEncryptedBySender;
  const amountP = senderXfer.getCipherText().map((ct) => ct.C.toRawBytes());
  const amountRSender = senderXfer.getCipherText().map((ct) => ct.D.toRawBytes());
  const amountRRecip = recipAmount.getCipherText().map((ct) => ct.D.toRawBytes());

  const newBalanceREffAud = hasEffectiveAuditor
    ? auditorNewBalances[auditorNewBalances.length - 1]
        .getCipherText()
        .map((ct) => ct.D.toRawBytes())
    : [];
  const amountREffAud = hasEffectiveAuditor
    ? auditorTransferAmounts[auditorTransferAmounts.length - 1]
        .getCipherText()
        .map((ct) => ct.D.toRawBytes())
    : [];

  // W6.6: voluntary auditors are at the FRONT of auditorKeys (indices
  // 0..userAuditPks.length-1). amount_r_volun_auds[i] = the D-component of
  // the transfer amount ciphertext encrypted to userAuditPks[i].
  const ekVolunAuds: Uint8Array[] = userAuditPks.map((pk) => pk.toUint8Array());
  const amountRVolunAuds: Uint8Array[][] = userAuditPks.map((_, i) =>
    auditorTransferAmounts[i].getCipherText().map((ct) => ct.D.toRawBytes()),
  );

  const zkrpNewBalance = rangeProof.rangeProofNewBalance;
  const zkrpAmount = rangeProof.rangeProofAmount;
  const sigmaProtoComm = sigmaProof.commitment;
  const sigmaProtoResp = sigmaProof.response;
  const memo = new Uint8Array(0);

  // ---- Compute ca_payload_hash ----
  // hashConfidentialTransferPayload signature mirrors Move's
  // `hash_confidential_transfer_payload(asset_type, dest_addr, ...)`. For
  // withdraw, the "dest" position is recipient (NOT vault, which is sender).
  const caPayloadHashRaw = hashConfidentialTransferPayload({
    asset_type: assetTypeBytes,
    vault_addr: recipientAddrBytes, // dest = recipient for withdraw
    new_balance_p: newBalanceP,
    new_balance_r: newBalanceR,
    new_balance_r_eff_aud: newBalanceREffAud,
    amount_p: amountP,
    amount_r_sender: amountRSender,
    amount_r_recip: amountRRecip,
    amount_r_eff_aud: amountREffAud,
    ek_volun_auds: ekVolunAuds,
    amount_r_volun_auds: amountRVolunAuds,
    zkrp_new_balance: zkrpNewBalance,
    zkrp_amount: zkrpAmount,
    sigma_proto_comm: sigmaProtoComm,
    sigma_proto_resp: sigmaProtoResp,
    memo,
  });

  // Fr-safe truncation: high byte forced to 0 so value fits BN254 Fr (~254 bits).
  // Mirrors Move's `ca_payload_hash_to_fr_safe`. Both sides MUST apply.
  const caPayloadHashFrSafe = new Uint8Array(32);
  caPayloadHashFrSafe.set(caPayloadHashRaw.slice(0, 31), 0);
  caPayloadHashFrSafe[31] = 0;

  return {
    newBalanceP,
    newBalanceR,
    newBalanceREffAud,
    amountP,
    amountRSender,
    amountRRecip,
    amountREffAud,
    ekVolunAuds,
    amountRVolunAuds,
    zkrpNewBalance,
    zkrpAmount,
    sigmaProtoComm,
    sigmaProtoResp,
    memo,
    caPayloadHashRaw,
    caPayloadHashFrSafe,
    vaultAvailableOctasBefore,
    vaultAvailableOctasAfterDecrypted: vaultAvailableOctasBefore - inputs.amountOctas,
  };
}
