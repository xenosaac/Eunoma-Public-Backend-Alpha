#!/usr/bin/env node

const command = process.env.npm_lifecycle_event ?? "testnet:e2e";

console.error(JSON.stringify({
  ok: false,
  command,
  error: "mpcca_finalize_not_ready",
  message:
    "Testnet flows are disabled until MPCCA withdraw finalize produces an Aptos-verifiable transfer sigma proof and Bulletproof range proofs without centralized witness reconstruction.",
  localFixtureCommand: "npm run local:smoke",
}, null, 2));

process.exit(2);
