// Generate a new TwistedEd25519 keypair (used for vault / recipient / user
// ConfidentialAsset DK). Prints private + public hex to stdout — never writes
// to .env or any file.
//
// Usage:
//   npx tsx scripts/generate_twisted_ed25519_keypair.ts vault
//   npx tsx scripts/generate_twisted_ed25519_keypair.ts recipient
//   npx tsx scripts/generate_twisted_ed25519_keypair.ts user
//
// Then copy the printed line into your .env file.

import { TwistedEd25519PrivateKey } from '@aptos-labs/confidential-asset';

const ROLE_TO_ENV: Record<string, string> = {
  vault: 'VAULT_DECRYPTION_KEY_HEX',
  recipient: 'RECIPIENT_ENCRYPTION_KEY_HEX',
  user: 'USER_ENCRYPTION_KEY_HEX',
};

const role = process.argv[2];
if (!role || !ROLE_TO_ENV[role]) {
  console.error(`usage: npx tsx generate_twisted_ed25519_keypair.ts <vault|recipient|user>`);
  process.exit(1);
}

const sk = TwistedEd25519PrivateKey.generate();
const envName = ROLE_TO_ENV[role];

console.log(`# new ${role} TwistedEd25519 keypair`);
console.log(`# public key (for reference): ${sk.publicKey().toString()}`);
console.log(`${envName}=${sk.toString()}`);
