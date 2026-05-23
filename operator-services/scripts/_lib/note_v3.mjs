import { randomBytes } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { scrypt } from "@noble/hashes/scrypt";

const NOTE_V3_PREFIX = "eunoma-note-v3.";
const KDF_N = 131072;
const KDF_R = 8;
const KDF_P = 1;
const KEY_BYTES = 32;
const SALT_BYTES = 16;
const NONCE_BYTES = 24;

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function encodeBase64Url(value) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function decodeBase64Url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function headerAad(header) {
  return new TextEncoder().encode(
    JSON.stringify({
      version: header.version,
      kdf: {
        name: header.kdf.name,
        salt: header.kdf.salt,
        N: header.kdf.N,
        r: header.kdf.r,
        p: header.kdf.p,
      },
      aead: {
        name: header.aead.name,
        nonce: header.aead.nonce,
      },
    }),
  );
}

function assertPassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("EUNOMA_NOTE_PASSPHRASE is required for note-v3");
  }
}

function deriveKey(passphrase, salt) {
  return scrypt(new TextEncoder().encode(passphrase), salt, {
    N: KDF_N,
    r: KDF_R,
    p: KDF_P,
    dkLen: KEY_BYTES,
  });
}

function assertEnvelopeShape(envelope) {
  if (envelope?.header?.version !== 3) {
    throw new Error("unsupported note-v3 envelope version");
  }
  if (
    envelope.header.kdf?.name !== "scrypt" ||
    envelope.header.kdf.N !== KDF_N ||
    envelope.header.kdf.r !== KDF_R ||
    envelope.header.kdf.p !== KDF_P
  ) {
    throw new Error("unsupported note-v3 KDF parameters");
  }
  if (envelope.header.aead?.name !== "xchacha20poly1305") {
    throw new Error("unsupported note-v3 AEAD");
  }
  if (typeof envelope.ciphertext !== "string" || envelope.tag !== null) {
    throw new Error("invalid note-v3 payload");
  }
}

export function isNoteV3(value) {
  return typeof value === "string" && value.trim().startsWith(NOTE_V3_PREFIX);
}

export function encodeNoteV3(plaintext, passphrase) {
  assertPassphrase(passphrase);

  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const header = {
    version: 3,
    kdf: {
      name: "scrypt",
      salt: bytesToBase64(salt),
      N: KDF_N,
      r: KDF_R,
      p: KDF_P,
    },
    aead: {
      name: "xchacha20poly1305",
      nonce: bytesToBase64(nonce),
    },
  };
  const key = deriveKey(passphrase, salt);
  const ciphertext = xchacha20poly1305(key, nonce, headerAad(header)).encrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
  );
  const envelope = {
    header,
    ciphertext: bytesToBase64(ciphertext),
    tag: null,
  };
  return `${NOTE_V3_PREFIX}${encodeBase64Url(JSON.stringify(envelope))}`;
}

export function decodeNoteV3(value, passphrase) {
  const trimmed = value.trim();
  if (!trimmed.startsWith(NOTE_V3_PREFIX)) {
    throw new Error("note must start with eunoma-note-v3.");
  }
  assertPassphrase(passphrase);

  const envelope = JSON.parse(decodeBase64Url(trimmed.slice(NOTE_V3_PREFIX.length)));
  assertEnvelopeShape(envelope);
  const salt = base64ToBytes(envelope.header.kdf.salt);
  const nonce = base64ToBytes(envelope.header.aead.nonce);
  if (salt.length !== SALT_BYTES || nonce.length !== NONCE_BYTES) {
    throw new Error("invalid note-v3 header");
  }

  try {
    const key = deriveKey(passphrase, salt);
    const plaintext = xchacha20poly1305(key, nonce, headerAad(envelope.header)).decrypt(
      base64ToBytes(envelope.ciphertext),
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("unable to decrypt note-v3");
  }
}
