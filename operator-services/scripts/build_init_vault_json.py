#!/usr/bin/env python3
"""Build init_vault_with_ca_registration JSON-args file for `aptos move run --json-file`."""
import json, os, sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS = json.load(open(os.path.join(SCRIPT_DIR, ".operator-keys.json")))
BRIDGE_ADDR = "0x7825166d8376ba15d0accd7bee95be31a8d95c69450c35df116760ed231c5bbf"
APT_METADATA = "0xa"
VAULT_SEED_HEX = "0x636f6e666964656e7469616c2d627269646765"
VAULT_EK_HEX = "0x34c45300041a10ca5b1c6959e98a5433878f7eafdef24bd2ecd0052a443e8616"  # twisted-ed25519 pubkey (secret in .vault-ek.json)

# Convert pubkeys to "0x..." hex strings (CLI vector<vector<u8>> takes array-of-hex)
pubkeys = [k["public_key"] for k in KEYS]

payload = {
    "function_id": f"{BRIDGE_ADDR}::confidential_bridge::init_vault_with_ca_registration",
    "type_args": [],
    "args": [
        {"type": "address", "value": BRIDGE_ADDR},
        {"type": "address", "value": APT_METADATA},
        # vector<vector<u8>>: JSON array of hex strings
        {"type": "hex", "value": pubkeys},
        {"type": "u64", "value": "0"},
        {"type": "u64", "value": "4"},
        {"type": "hex", "value": VAULT_SEED_HEX},
        {"type": "hex", "value": VAULT_EK_HEX},
        {"type": "hex", "value": []},  # empty registration_sigma_proto_comm
        {"type": "hex", "value": []},  # empty registration_sigma_proto_resp
    ],
}
out = os.path.join(SCRIPT_DIR, "init_vault_args.json")
json.dump(payload, open(out, "w"), indent=2)
print(f"Wrote {out}")
