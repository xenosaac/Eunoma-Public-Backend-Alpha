#!/usr/bin/env node
// =============================================================================================
// V2 depositor-side CLI driver — goal.md required-work item 2 + 5.
//
// End-to-end pipeline:
//   1. Bootstrap a depositor (fresh ed25519 keypair + fresh TwistedEd25519 CA key, funded
//      from testnet-mother profile if no existing state). Idempotent: re-uses persisted
//      state under .agent-local/eunoma-v2/depositor/state.json.
//   2. Register the depositor for CA (`confidential_asset::register`).
//   3. `ca.deposit` move regular APT into CA pending balance.
//   4. `ca.rolloverPendingBalance` pending -> available.
//   5. Build `ConfidentialTransfer` payload (sender = depositor, recipient = bridge vault).
//   6. Compute Fr-safe ca_payload_hash via @eunoma/deop-protocol.
//   7. Generate deposit-binding Groth16 proof against on-chain asset_id_fr / vault_addr_hash_fr.
//   8. POST coordinator /v2/deposit/frost-attest -> FROST group signature.
//   9. Submit `eunoma_bridge::deposit_with_commitment_v2` (24-arg).
//  10. Extract DepositConfirmedV2 event + persist depositor-only witness for later withdraw.
//
// Hard invariants preserved:
//  - Strict 5-of-7 FROST (coordinator route accepts only selectedSlots[5]).
//  - Plaintext amount/blind/secret/nullifier NEVER POSTed to coordinator.
//  - No centralized dk/inverse.
//  - No ca_local fixture path.
//
// Required env / args:
//   APTOS_TESTNET_NODE_URL        e.g. https://fullnode.testnet.aptoslabs.com
//   BRIDGE_PACKAGE_ADDRESS        0x-prefixed 32-byte hex
//   COORDINATOR_URL               e.g. http://127.0.0.1:4200
//   COORDINATOR_BEARER_TOKEN      bearer token for the coordinator
//   FROST_ROSTER_JSON_PATH        path to <stateRoot>/cluster/frost-dkg-v2-roster.json
//   CA_DKG_V2_ROSTER_JSON_PATH    path to <stateRoot>/cluster/ca-dkg-v2-roster.json
//   MOTHER_PROFILE                Aptos CLI profile name with funding source (default "testnet-mother")
//   ASSET_TYPE_ADDR               0x-prefixed 32-byte hex of the asset (default "0xa" — APT FA)
//   DEPOSIT_AMOUNT_OCTAS          decimal u64 (default "100")
//   FUND_DEPOSITOR_OCTAS          decimal u64 (default "20000000" = 0.2 APT — for register+deposit+gas)
//   CA_DEPOSIT_OCTAS              decimal u64 (default "10000" = 10000 octas into CA — ample
//                                 headroom over DEPOSIT_AMOUNT_OCTAS for testnet)
//
// Output: JSON to stdout (plus structured logs to stderr) with depositTxHash, depositCount,
// caPayloadHash, sender, asset_type, vault_addr, plus a depositor-only witness file path that
// the later MPCCA-withdraw step consumes.
// =============================================================================================
import { mkdirSync, existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";

import {
  Aptos,
  AptosConfig,
  Network,
  Account,
  Ed25519PrivateKey,
  AccountAddress,
} from "@aptos-labs/ts-sdk";
import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  ConfidentialAsset,
  ConfidentialTransfer,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
} from "@aptos-labs/confidential-asset";

import {
  bcsEncodeCAPayloadForHashV2,
  caPayloadHashFrV2,
  caPayloadHashRawV2,
  caPayloadHashRawToFrV2,
} from "@eunoma/deop-protocol";
import { bytesToHex, hexToBytes, keccak256 } from "@eunoma/shared";

// Stage 4 A6: deterministic Ristretto255 blinds for amount_p Pedersen commitments. Same secret
// → same amount_p bytes at deposit and withdraw → Move bridge amount_p_digest binding holds.
import { deriveAmountPBlinds } from "./_lib/amount_p_blinds.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

const stateRootDir = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const depositorStateDir = join(stateRootDir, "depositor");
mkdirSync(depositorStateDir, { recursive: true, mode: 0o700 });
chmodSync(depositorStateDir, 0o700);
const depositorStatePath = join(depositorStateDir, "state.json");

// ----- env / arg parsing -----
const args = process.argv.slice(2);
function flag(name, def) {
  const idx = args.indexOf(name);
  if (idx < 0) return def;
  return args[idx + 1];
}

const APTOS_NODE_URL =
  process.env.APTOS_TESTNET_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
const BRIDGE_PACKAGE_ADDRESS = required(
  process.env.BRIDGE_PACKAGE_ADDRESS,
  "BRIDGE_PACKAGE_ADDRESS",
);
const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "COORDINATOR_BEARER_TOKEN",
);
const CA_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.CA_DKG_V2_ROSTER_JSON_PATH,
  "CA_DKG_V2_ROSTER_JSON_PATH",
);
const MOTHER_PROFILE = process.env.MOTHER_PROFILE ?? "testnet-mother";
const ASSET_TYPE_ADDR = (process.env.ASSET_TYPE_ADDR ?? "0xa").toLowerCase();
const DEPOSIT_AMOUNT_OCTAS = BigInt(process.env.DEPOSIT_AMOUNT_OCTAS ?? "100");
const FUND_DEPOSITOR_OCTAS = BigInt(process.env.FUND_DEPOSITOR_OCTAS ?? "20000000");
const CA_DEPOSIT_OCTAS = BigInt(process.env.CA_DEPOSIT_OCTAS ?? "10000");

function required(value, name) {
  if (!value) {
    console.error(`required env var: ${name}`);
    process.exit(2);
  }
  return value;
}

function logStep(msg) {
  console.error(`[v2-deposit] ${msg}`);
}

function fr32FromRandom() {
  const r = randomBytes(31);
  const out = new Uint8Array(32);
  out.set(r, 0);
  return out;
}

function bufToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function addr32Bytes(hex) {
  const norm = String(hex).replace(/^0x/i, "").toLowerCase();
  const padded = norm.padStart(64, "0");
  if (padded.length !== 64) throw new Error(`address too long: ${hex}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ----- on-chain helpers -----
async function getResource(addr, type) {
  const url = `${APTOS_NODE_URL.replace(/\/+$/, "")}/v1/accounts/${addr}/resource/${encodeURIComponent(type)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`getResource ${type} -> ${res.status}: ${await res.text()}`);
  return res.json();
}

async function getMotherAccount() {
  // The aptos CLI is unhelpful here — `aptos config show-profiles` only reports `has_private_key`,
  // not the key itself. Read the YAML directly. Try the repo-root .aptos/config.yaml first (which
  // is where this project's profiles live), then $HOME/.aptos/config.yaml as a fallback.
  const homeAptos = `${process.env.HOME}/.aptos/config.yaml`;
  const eunomaAptos = resolve(repoRoot, ".aptos/config.yaml");
  for (const path of [eunomaAptos, homeAptos]) {
    if (!existsSync(path)) continue;
    const text = readFileSync(path, "utf8");
    const re = new RegExp(`\\s${MOTHER_PROFILE}:[\\s\\S]*?private_key:\\s*["']?([^\\s"']+)["']?`);
    const m = text.match(re);
    if (!m) continue;
    const raw = m[1].trim().replace(/^ed25519-priv-/, "");
    return Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(raw) });
  }
  throw new Error(`could not find ${MOTHER_PROFILE} private_key in any .aptos/config.yaml`);
}

// ----- bootstrap fresh depositor (idempotent via state.json) -----
async function bootstrapDepositor(aptos, ca) {
  let state;
  if (existsSync(depositorStatePath)) {
    state = JSON.parse(readFileSync(depositorStatePath, "utf8"));
    logStep(`re-using persisted depositor state at ${depositorStatePath} (addr=${state.depositorAddress})`);
  } else {
    // Fresh ed25519 + fresh TwistedEd25519. Persist to state.json (0o600).
    const depositorSeed = randomBytes(32);
    const depositorEd = new Ed25519PrivateKey(`0x${bufToHex(depositorSeed)}`);
    const depositorAccount = Account.fromPrivateKey({ privateKey: depositorEd });
    const caEncryptionSeed = randomBytes(32);
    const userDk = new TwistedEd25519PrivateKey(`0x${bufToHex(caEncryptionSeed)}`);
    state = {
      depositorPrivateKeyHex: `0x${bufToHex(depositorSeed)}`,
      depositorAddress: depositorAccount.accountAddress.toString(),
      userEncryptionKeyHex: `0x${bufToHex(caEncryptionSeed)}`,
      userEncryptionPublicKey: userDk.publicKey().toString(),
    };
    writeFileSync(depositorStatePath, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
    chmodSync(depositorStatePath, 0o600);
    logStep(`generated fresh depositor: addr=${state.depositorAddress}`);
  }

  const depositorAccount = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(state.depositorPrivateKeyHex),
  });
  const userDk = new TwistedEd25519PrivateKey(state.userEncryptionKeyHex);

  // Check whether the depositor account exists + is funded.
  let balance = 0n;
  try {
    const acctRes = await getResource(
      depositorAccount.accountAddress.toString(),
      "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
    );
    balance = BigInt(acctRes.data?.coin?.value ?? "0");
  } catch (err) {
    if (!/404|not found/i.test(String(err))) throw err;
  }
  if (balance < FUND_DEPOSITOR_OCTAS) {
    logStep(`funding depositor from ${MOTHER_PROFILE} (current=${balance} octas, need=${FUND_DEPOSITOR_OCTAS})`);
    const mother = await getMotherAccount();
    const fundTx = await aptos.transaction.build.simple({
      sender: mother.accountAddress,
      data: {
        function: "0x1::aptos_account::transfer",
        functionArguments: [depositorAccount.accountAddress, FUND_DEPOSITOR_OCTAS],
      },
      options: { maxGasAmount: 200000, gasUnitPrice: 100 },
    });
    const fundAuth = aptos.transaction.sign({ signer: mother, transaction: fundTx });
    const pending = await aptos.transaction.submit.simple({
      transaction: fundTx,
      senderAuthenticator: fundAuth,
    });
    const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
    if (!committed.success) {
      throw new Error(`funding tx failed: ${committed.vm_status}`);
    }
    logStep(`funded depositor with ${FUND_DEPOSITOR_OCTAS} octas (tx=${committed.hash})`);
  }

  // Register CA.
  const registered = await ca.hasUserRegistered({
    accountAddress: depositorAccount.accountAddress,
    tokenAddress: ASSET_TYPE_ADDR,
  });
  if (!registered) {
    logStep(`registering CA for asset=${ASSET_TYPE_ADDR}`);
    const regCommitted = await ca.registerBalance({
      signer: depositorAccount,
      tokenAddress: ASSET_TYPE_ADDR,
      decryptionKey: userDk,
      options: { maxGasAmount: 200000, gasUnitPrice: 100 },
    });
    if (!regCommitted.success) {
      throw new Error(`ca.registerBalance failed: ${regCommitted.vm_status}`);
    }
    logStep(`ca.registerBalance tx=${regCommitted.hash}`);
  } else {
    logStep("depositor already CA-registered");
  }

  // Check CA balance; if insufficient, deposit + rollover.
  let caBalance;
  try {
    caBalance = await ca.getBalance({
      accountAddress: depositorAccount.accountAddress,
      tokenAddress: ASSET_TYPE_ADDR,
      decryptionKey: userDk,
    });
  } catch (err) {
    logStep(`ca.getBalance threw (likely fresh / empty): ${err.message}`);
    caBalance = null;
  }
  if (caBalance) {
    logStep(`CA balance: available=${caBalance.available.getAmount().toString()} pending=${caBalance.pending.getAmount().toString()}`);
  }
  if (!caBalance || caBalance.available.getAmount() < DEPOSIT_AMOUNT_OCTAS) {
    logStep(`depositing ${CA_DEPOSIT_OCTAS} regular octas into CA pending balance`);
    const depTx = await ca.deposit({
      signer: depositorAccount,
      tokenAddress: ASSET_TYPE_ADDR,
      amount: CA_DEPOSIT_OCTAS,
      options: { maxGasAmount: 200000, gasUnitPrice: 100 },
    });
    if (!depTx.success) throw new Error(`ca.deposit failed: ${depTx.vm_status}`);
    logStep(`ca.deposit tx=${depTx.hash}`);
    logStep("rollover pending -> available");
    const rolloverTxs = await ca.rolloverPendingBalance({
      signer: depositorAccount,
      tokenAddress: ASSET_TYPE_ADDR,
      checkNormalized: false,
      options: { maxGasAmount: 200000, gasUnitPrice: 100 },
    });
    const last = rolloverTxs[rolloverTxs.length - 1];
    if (!last.success) throw new Error(`ca.rolloverPendingBalance failed: ${last.vm_status}`);
    logStep(`ca.rolloverPendingBalance tx=${last.hash}`);
    caBalance = await ca.getBalance({
      accountAddress: depositorAccount.accountAddress,
      tokenAddress: ASSET_TYPE_ADDR,
      decryptionKey: userDk,
    });
    logStep(`CA balance post-rollover: available=${caBalance.available.getAmount().toString()}`);
  }

  return { depositorAccount, userDk, caBalance };
}

// ----- main -----
async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  logStep(`bridge=${BRIDGE_PACKAGE_ADDRESS}`);
  logStep(`coordinator=${COORDINATOR_URL}`);
  logStep(`asset_type=${ASSET_TYPE_ADDR}`);

  // 1-4. Bootstrap depositor.
  const { depositorAccount, userDk, caBalance } = await bootstrapDepositor(aptos, ca);

  // Re-fetch balance + sanity-check.
  if (caBalance.available.getAmount() < DEPOSIT_AMOUNT_OCTAS) {
    throw new Error(
      `CA available (${caBalance.available.getAmount()}) < transfer amount (${DEPOSIT_AMOUNT_OCTAS})`,
    );
  }

  // Fetch on-chain config the deposit needs.
  logStep("fetching on-chain config");
  const bridgeAddr = BRIDGE_PACKAGE_ADDRESS;
  const bridgeVaultRes = await getResource(
    bridgeAddr,
    `${bridgeAddr}::eunoma_bridge::BridgeVault`,
  );
  const vaultAddr =
    typeof bridgeVaultRes.data.vault_addr === "string"
      ? bridgeVaultRes.data.vault_addr
      : bridgeVaultRes.data.vault_addr.inner;
  const bridgeAssetType =
    typeof bridgeVaultRes.data.asset_type === "string"
      ? bridgeVaultRes.data.asset_type
      : bridgeVaultRes.data.asset_type.inner;
  logStep(`bridge vault=${vaultAddr}, bridge asset_type=${bridgeAssetType}`);

  const cfgRes = await getResource(
    bridgeAddr,
    `${bridgeAddr}::eunoma_bridge::DeoperatorConfigV2`,
  );
  const cfg = cfgRes.data;
  const dkgEpoch = String(cfg.dkg_epoch);
  const operatorSetVersion = String(cfg.operator_set_version);
  const frostGroupPubkey = `0x${bufToHex(hexToBytes(cfg.frost_group_pubkey))}`;
  const rosterHashOnChain = `0x${bufToHex(hexToBytes(cfg.roster_hash))}`;

  // Compute circuit_versions_hash from DeoperatorConfigV2 contents. Move recipe:
  //   keccak256(bcs::to_bytes(CircuitVersionsForHash {
  //     deposit_circuit_version,
  //     withdraw_circuit_version,
  //     ca_payload_circuit_version,
  //   }))
  // BCS encodes each vector<u8> with a ULEB128 length prefix followed by the bytes,
  // so we MUST replicate that — naive concat skips the prefix and produces a different hash.
  function bcsVectorU8(hex) {
    const bytes = hexToBytes(hex);
    if (bytes.length > 0x7f) {
      throw new Error("BCS length > 0x7f needs multibyte ULEB128 — extend this helper.");
    }
    const out = new Uint8Array(1 + bytes.length);
    out[0] = bytes.length & 0xff;
    out.set(bytes, 1);
    return out;
  }
  const circuitVersionsBcs = (() => {
    const a = bcsVectorU8(cfg.deposit_circuit_version);
    const b = bcsVectorU8(cfg.withdraw_circuit_version);
    const c = bcsVectorU8(cfg.ca_payload_circuit_version);
    const out = new Uint8Array(a.length + b.length + c.length);
    out.set(a, 0);
    out.set(b, a.length);
    out.set(c, a.length + b.length);
    return out;
  })();
  const circuitVersionsHash = `0x${bytesToHex(keccak256(circuitVersionsBcs))}`;
  logStep(`dkgEpoch=${dkgEpoch}, opSetVersion=${operatorSetVersion}, circuitVersionsHash=${circuitVersionsHash}`);

  const vaultPubRes = await getResource(
    bridgeAddr,
    `${bridgeAddr}::eunoma_bridge::VaultPublicInputsV2`,
  );
  const assetIdHex = `0x${bufToHex(hexToBytes(vaultPubRes.data.asset_id_fr))}`;
  const vaultAddrHashHex = `0x${bufToHex(hexToBytes(vaultPubRes.data.vault_addr_hash_fr))}`;
  logStep(`asset_id=${assetIdHex.slice(0, 18)}..., vault_addr_hash=${vaultAddrHashHex.slice(0, 18)}...`);

  const caDkgRoster = JSON.parse(readFileSync(CA_DKG_V2_ROSTER_JSON_PATH, "utf8"));
  const selectedSlots = caDkgRoster.nodes
    .map((n) => Number(n.slot))
    .sort((a, b) => a - b)
    .slice(0, 5);
  logStep(`selectedSlots=${JSON.stringify(selectedSlots)}`);

  // 5. Build CA confidential_transfer payload.
  logStep("building ConfidentialTransfer payload");
  const vaultEkBytes = hexToBytes(cfg.vault_ek);
  const vaultEk = new TwistedEd25519PublicKey(vaultEkBytes);
  const assetAuditorEk = await ca.getAssetAuditorEncryptionKey({
    tokenAddress: ASSET_TYPE_ADDR,
  });
  const hasEffectiveAuditor = !!assetAuditorEk;
  const auditorKeys = assetAuditorEk ? [assetAuditorEk] : [];

  // Stage 4 A6: pre-allocate nullifier/secret/deposit_blind BEFORE the SDK call so we can
  // derive the deterministic transferAmountRandomness from `secretFr` and have the SDK use it
  // as the blinds for amount_p[0..3]. The SDK expects a length-`AVAILABLE_BALANCE_CHUNK_COUNT`
  // array but slices [0..TRANSFER_AMOUNT_CHUNK_COUNT) for the actual amount_p blinds (see
  // confidentialTransfer.ts:181,296,307). Pad the remaining slots with the HKDF-derived first
  // blind repeated — they're never read by the protocol, but a defined value avoids the SDK
  // ever falling through to `ed25519GenRandom` in some future refactor.
  const nullifier = fr32FromRandom();
  const secretFr = fr32FromRandom();
  const depositBlind = fr32FromRandom();
  const amountPBlinds = deriveAmountPBlinds(secretFr);
  if (amountPBlinds.length !== 4) {
    throw new Error(`deriveAmountPBlinds returned ${amountPBlinds.length} blinds, expected 4`);
  }
  const transferAmountRandomness = new Array(AVAILABLE_BALANCE_CHUNK_COUNT).fill(0n);
  for (let i = 0; i < 4; i += 1) transferAmountRandomness[i] = amountPBlinds[i];
  for (let i = 4; i < AVAILABLE_BALANCE_CHUNK_COUNT; i += 1) {
    transferAmountRandomness[i] = amountPBlinds[0];
  }

  const transfer = await ConfidentialTransfer.create({
    senderDecryptionKey: userDk,
    senderAvailableBalanceCipherText: caBalance.available.getCipherText(),
    amount: DEPOSIT_AMOUNT_OCTAS,
    recipientEncryptionKey: vaultEk,
    hasEffectiveAuditor,
    auditorEncryptionKeys: auditorKeys,
    senderAddress: depositorAccount.accountAddress.toUint8Array(),
    recipientAddress: addr32Bytes(vaultAddr),
    tokenAddress: addr32Bytes(ASSET_TYPE_ADDR),
    chainId: 2,
    transferAmountRandomness,
  });
  const [
    { sigmaProof, rangeProof },
    senderNewBal,
    recipAmount,
    auditorTransferAmounts,
    auditorNewBalances,
  ] = await transfer.authorizeTransfer();

  const newBalanceP = senderNewBal.getCipherText().map((ct) => ct.C.toRawBytes());
  const newBalanceR = senderNewBal.getCipherText().map((ct) => ct.D.toRawBytes());
  const senderXfer = transfer.transferAmountEncryptedBySender;
  const amountP = senderXfer.getCipherText().map((ct) => ct.C.toRawBytes());
  const amountRSender = senderXfer.getCipherText().map((ct) => ct.D.toRawBytes());
  const amountRRecip = recipAmount.getCipherText().map((ct) => ct.D.toRawBytes());
  const newBalanceREffAud = hasEffectiveAuditor
    ? auditorNewBalances[auditorNewBalances.length - 1].getCipherText().map((ct) => ct.D.toRawBytes())
    : [];
  const amountREffAud = hasEffectiveAuditor
    ? auditorTransferAmounts[auditorTransferAmounts.length - 1].getCipherText().map((ct) => ct.D.toRawBytes())
    : [];
  const ekVolunAuds = [];
  const amountRVolunAuds = [];
  const zkrpNewBalance = rangeProof.rangeProofNewBalance;
  const zkrpAmount = rangeProof.rangeProofAmount;
  const sigmaProtoComm = sigmaProof.commitment;
  const sigmaProtoResp = sigmaProof.response;
  const memo = new Uint8Array(0);

  // Pad short Aptos address forms (e.g. "0xa") to canonical 32-byte hex.
  const assetTypeHex = `0x${bufToHex(addr32Bytes(ASSET_TYPE_ADDR))}`;
  const vaultAddrHex = `0x${bufToHex(addr32Bytes(vaultAddr))}`;

  // 6. Compute Fr-safe caPayloadHash. Build the payload object matching
  // ConfidentialTransferRawPayloadV2 (hex-string fields).
  const caPayloadObj = {
    assetType: assetTypeHex,
    to: vaultAddrHex,
    newBalanceP: newBalanceP.map((b) => `0x${bufToHex(b)}`),
    newBalanceR: newBalanceR.map((b) => `0x${bufToHex(b)}`),
    newBalanceREffAud: newBalanceREffAud.map((b) => `0x${bufToHex(b)}`),
    amountP: amountP.map((b) => `0x${bufToHex(b)}`),
    amountRSender: amountRSender.map((b) => `0x${bufToHex(b)}`),
    amountRRecip: amountRRecip.map((b) => `0x${bufToHex(b)}`),
    amountREffAud: amountREffAud.map((b) => `0x${bufToHex(b)}`),
    ekVolunAuds: ekVolunAuds.map((b) => `0x${bufToHex(b)}`),
    amountRVolunAuds: amountRVolunAuds.map((row) => row.map((b) => `0x${bufToHex(b)}`)),
    zkrpNewBalance: `0x${bufToHex(zkrpNewBalance)}`,
    zkrpAmount: `0x${bufToHex(zkrpAmount)}`,
    sigmaProtoComm: sigmaProtoComm.map((b) => `0x${bufToHex(b)}`),
    sigmaProtoResp: sigmaProtoResp.map((b) => `0x${bufToHex(b)}`),
    memo: `0x${bufToHex(memo)}`,
  };
  const caPayloadHashFr = caPayloadHashFrV2(caPayloadObj);
  logStep(`caPayloadHashFr=0x${caPayloadHashFr}`);

  // 7. Generate deposit-binding witness + proof. Stage 4 A6: nullifier/secret/deposit_blind were
  // pre-allocated above so the SDK call could use the HKDF(secret)-derived amount_p blinds.
  // amount_p[0..3] = 4 × 32B compressed Ristretto points; concat into 256 hex chars and pass to
  // the witness builder so the deposit-binding circuit hashes amount_p_digest into commitment +
  // amount_tag (replacing the plaintext-amount fields from pre-A6).
  const amountPHex = amountP
    .map((b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(""))
    .join("");
  if (amountPHex.length !== 256) {
    throw new Error(`amountPHex must be 256 hex chars (4 × 32B), got ${amountPHex.length}`);
  }
  logStep(`amount_p concat hex (public, already in CA payload): ${amountPHex.slice(0, 24)}...`);

  const witnessPath = join(depositorStateDir, "witness.json");
  const proofPath = join(depositorStateDir, "proof.json");
  const witnessRes = spawnSync(
    "node",
    [
      resolve(repoRoot, "circuits/scripts/compute_deposit_witness.mjs"),
      "--nullifier-hex", `0x${bufToHex(nullifier)}`,
      "--secret-hex", `0x${bufToHex(secretFr)}`,
      "--amount-p-hex", `0x${amountPHex}`,
      "--deposit-blind-hex", `0x${bufToHex(depositBlind)}`,
      "--asset-id-hex", assetIdHex,
      "--vault-addr-hash-hex", vaultAddrHashHex,
      "--output", witnessPath,
    ],
    { encoding: "utf8" },
  );
  if (witnessRes.status !== 0) {
    throw new Error(`witness builder failed: ${witnessRes.stderr || witnessRes.stdout}`);
  }
  const witnessOut = JSON.parse(witnessRes.stdout);
  const commitmentHex = `0x${witnessOut.commitmentHex}`;
  const amountTagHex = `0x${witnessOut.amountTagHex}`;
  logStep(`commitment=${commitmentHex.slice(0, 18)}..., amount_tag=${amountTagHex.slice(0, 18)}...`);

  const proofRes = spawnSync(
    "node",
    [
      resolve(serviceRoot, "scripts/local_generate_deposit_proof.mjs"),
      "--witness-json", witnessPath,
      "--output", proofPath,
    ],
    { encoding: "utf8" },
  );
  if (proofRes.status !== 0) {
    throw new Error(`deposit proof generation failed: ${proofRes.stderr || proofRes.stdout}`);
  }
  const proofHex = proofRes.stdout.trim().split("\n").pop().trim();
  logStep(`deposit-binding proof bytes=${proofHex.length / 2}`);

  // A6 on Aptos testnet is split into two transactions to stay below the VM execution limit:
  // this tx verifies the Groth16 binding and caches commitment -> amount_p_digest on-chain;
  // deposit_with_commitment_v2 later consumes that cache and performs the CA transfer.
  logStep("building + submitting prepare_deposit_binding_v2 tx");
  const prepareTx = await aptos.transaction.build.simple({
    sender: depositorAccount.accountAddress,
    data: {
      function: `${bridgeAddr}::eunoma_bridge::prepare_deposit_binding_v2`,
      functionArguments: [
        hexToBytes(commitmentHex),
        hexToBytes(amountTagHex),
        amountP,
        hexToBytes(`0x${proofHex}`),
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const prepareAuth = aptos.transaction.sign({ signer: depositorAccount, transaction: prepareTx });
  const preparePending = await aptos.transaction.submit.simple({
    transaction: prepareTx,
    senderAuthenticator: prepareAuth,
  });
  logStep(`submitted prepare tx=${preparePending.hash}; waiting for confirmation...`);
  const prepareCommitted = await aptos.waitForTransaction({ transactionHash: preparePending.hash });
  if (!prepareCommitted.success) {
    throw new Error(`prepare_deposit_binding_v2 failed: ${prepareCommitted.vm_status}`);
  }
  logStep(`prepare SUCCESS tx=${prepareCommitted.hash} version=${prepareCommitted.version} gas=${prepareCommitted.gas_used}`);

  // 8. POST coordinator /v2/deposit/frost-attest.
  const depositNonce = randomBytes(32);
  const expirySecs = BigInt(Math.floor(Date.now() / 1000) + 60 * 60);
  const requestId = `dep-${Date.now()}-${bufToHex(randomBytes(4))}`;

  const attestBody = {
    requestId,
    dkgEpoch,
    rosterHash: rosterHashOnChain,
    selectedSlots,
    bridge: `0x${bufToHex(addr32Bytes(bridgeAddr))}`,
    vault: vaultAddrHex,
    assetType: assetTypeHex,
    chainId: 2,
    operatorSetVersion,
    frostGroupPubkey,
    circuitVersionsHash,
    commitment: commitmentHex,
    amountTag: amountTagHex,
    caPayloadHash: `0x${caPayloadHashFr}`,
    depositNonce: `0x${bufToHex(depositNonce)}`,
    expirySecs: expirySecs.toString(),
  };
  logStep(`POST ${COORDINATOR_URL}/v2/deposit/frost-attest (requestId=${requestId})`);
  const attestRes = await fetch(`${COORDINATOR_URL}/v2/deposit/frost-attest`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
    },
    body: JSON.stringify(attestBody),
  });
  const attestText = await attestRes.text();
  if (!attestRes.ok) {
    throw new Error(`coordinator /v2/deposit/frost-attest -> ${attestRes.status}: ${attestText}`);
  }
  const attest = JSON.parse(attestText);
  const groupSignature = attest.groupSignature;
  logStep(`FROST groupSignature=${groupSignature.slice(0, 18)}..., transcriptHash=${attest.attestationTranscriptHash.slice(0, 18)}...`);

  // 9. Submit deposit_with_commitment_v2 (24-arg).
  logStep("building + submitting deposit_with_commitment_v2 tx");
  const tx = await aptos.transaction.build.simple({
    sender: depositorAccount.accountAddress,
    data: {
      function: `${bridgeAddr}::eunoma_bridge::deposit_with_commitment_v2`,
      functionArguments: [
        // 1. commitment
        hexToBytes(commitmentHex),
        // 2. amount_tag
        hexToBytes(amountTagHex),
        // 3. ca_payload_hash
        hexToBytes(`0x${caPayloadHashFr}`),
        // 4. deposit_nonce
        depositNonce,
        // 5. deposit_binding_proof
        new Uint8Array(),
        // 6. expiry_secs
        expirySecs,
        // 7. group_signature
        hexToBytes(groupSignature),
        // 8. fallback_bitmap
        0,
        // 9. fallback_signatures
        [],
        // 10. new_balance_p
        newBalanceP,
        // 11. new_balance_r
        newBalanceR,
        // 12. new_balance_r_eff_aud
        newBalanceREffAud,
        // 13. amount_p
        amountP,
        // 14. amount_r_sender
        amountRSender,
        // 15. amount_r_recip
        amountRRecip,
        // 16. amount_r_eff_aud
        amountREffAud,
        // 17. ek_volun_auds
        ekVolunAuds,
        // 18. amount_r_volun_auds (vec<vec<vec<u8>>>)
        amountRVolunAuds,
        // 19. zkrp_new_balance
        zkrpNewBalance,
        // 20. zkrp_amount
        zkrpAmount,
        // 21. sigma_proto_comm
        sigmaProtoComm,
        // 22. sigma_proto_resp
        sigmaProtoResp,
        // 23. memo
        memo,
      ],
    },
    // 0.05 APT cap (500k * 100 = 50_000_000 octas) — enough for the CA verification + Groth16
    // pairing on chain (~50k-100k gas), well below the depositor's 0.2 APT funding.
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const txAuth = aptos.transaction.sign({ signer: depositorAccount, transaction: tx });
  const pending = await aptos.transaction.submit.simple({
    transaction: tx,
    senderAuthenticator: txAuth,
  });
  logStep(`submitted tx=${pending.hash}; waiting for confirmation...`);
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  if (!committed.success) {
    throw new Error(`deposit_with_commitment_v2 failed: ${committed.vm_status}`);
  }
  logStep(`SUCCESS tx=${committed.hash} version=${committed.version} gas=${committed.gas_used}`);

  // 10. Extract DepositConfirmedV2 event.
  const events = Array.isArray(committed.events) ? committed.events : [];
  const ev = events.find((e) => typeof e?.type === "string" && e.type.endsWith("::eunoma_bridge::DepositConfirmedV2"));
  if (!ev) {
    throw new Error(`tx succeeded but no DepositConfirmedV2 event found`);
  }
  const depositCount = String(ev.data.deposit_count);
  logStep(`DepositConfirmedV2: deposit_count=${depositCount}`);

  // 11. Persist depositor-only witness for the later MPCCA-withdraw step. NEVER POST this.
  // Stage 4 A6: amountPHex (4 × 32B Ristretto compressed points concat, 256 hex chars) MUST be
  // here so compute_withdraw_witness.mjs can recompute amount_p_digest. It is the public
  // ciphertext-C component already in the on-chain CA payload, so persisting it locally adds no
  // new privacy surface.
  const witnessForWithdraw = {
    schema: "v2_depositor_witness_v1",
    depositorAddress: depositorAccount.accountAddress.toString(),
    userEncryptionKeyHex: state(depositorStatePath).userEncryptionKeyHex,
    chainId: 2,
    poolId: 0,
    assetType: ASSET_TYPE_ADDR,
    assetIdHex,
    vaultAddrHashHex,
    vaultAddr,
    bridgePackageAddress: bridgeAddr,
    amountOctas: DEPOSIT_AMOUNT_OCTAS.toString(),
    nullifierHex: `0x${bufToHex(nullifier)}`,
    secretHex: `0x${bufToHex(secretFr)}`,
    depositBlindHex: `0x${bufToHex(depositBlind)}`,
    depositNonceHex: `0x${bufToHex(depositNonce)}`,
    commitmentHex,
    amountTagHex,
    amountPHex: `0x${amountPHex}`,
    caPayloadHashFr: `0x${caPayloadHashFr}`,
    depositTxHash: committed.hash,
    prepareDepositBindingTxHash: prepareCommitted.hash,
    depositCount,
    txVersion: String(committed.version),
    createdAtUnixMs: Date.now(),
  };
  const withdrawWitnessPath = join(depositorStateDir, `withdraw_witness_${committed.hash.slice(2, 10)}.json`);
  writeFileSync(withdrawWitnessPath, JSON.stringify(witnessForWithdraw, null, 2) + "\n", { mode: 0o600 });
  chmodSync(withdrawWitnessPath, 0o600);
  logStep(`wrote depositor-only withdraw witness to ${withdrawWitnessPath}`);

  // 12. Output summary JSON to stdout (consumable by testnet_e2e_v2 env exports).
  const summary = {
    ok: true,
    prepareDepositBindingTxHash: prepareCommitted.hash,
    depositTxHash: committed.hash,
    depositCount,
    txVersion: String(committed.version),
    caPayloadHashFr: `0x${caPayloadHashFr}`,
    senderAddress: depositorAccount.accountAddress.toString(),
    vaultAddr,
    assetType: ASSET_TYPE_ADDR,
    bridgePackageAddress: bridgeAddr,
    commitment: commitmentHex,
    amountTag: amountTagHex,
    depositNonce: `0x${bufToHex(depositNonce)}`,
    expirySecs: expirySecs.toString(),
    groupSignature,
    attestationTranscriptHash: attest.attestationTranscriptHash,
    withdrawWitnessPath,
  };
  console.log(JSON.stringify(summary, null, 2));
  process.exit(0);
}

function state(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

main().catch((err) => {
  console.error(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err), stack: err instanceof Error ? err.stack : undefined }, null, 2));
  process.exit(1);
});
