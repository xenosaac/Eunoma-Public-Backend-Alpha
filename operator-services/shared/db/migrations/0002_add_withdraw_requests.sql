-- 0002_add_withdraw_requests.sql — Phase P0 backend withdraw amount binding.
--
-- Holds prepare→finalize lifecycle state for /v1/withdraw/prepare and
-- /v1/withdraw/finalize. Server canonical fields (amount, blind, asset_id_le32,
-- recipient_hash, ca_payload_hash, vault_sequence) are committed at prepare
-- time and re-used unmodified at finalize so the main operator never signs
-- a WithdrawAttestationMessage built from client-supplied values.
--
-- IMPORTANT: deliberately no `UNIQUE (vault_addr, vault_sequence)` and no
-- partial unique index `WHERE status='PREPARED'`.
--   - vault_sequence is a chain-derived monotonic counter that only advances
--     on a successful on-chain withdraw. PREPARED rows that go FAILED /
--     EXPIRED / cosign-short leave the chain sequence unchanged; any DB-level
--     unique constraint on (vault_addr, vault_sequence) would permanently
--     block re-prepare at that sequence and self-DoS the vault.
--   - A partial unique `WHERE status='PREPARED'` is also unsafe: the predicate
--     can't include `expiry > now()` (Postgres rejects volatile functions in
--     partial-index predicates), so a stale-but-still-PREPARED row would
--     block fresh prepare until something flips it to EXPIRED.
-- Active-PREPARED uniqueness is enforced inside
-- `PostgresStore.insertWithdrawRequestActiveOnly` (single transaction:
-- expire-stale UPDATE + INSERT ... WHERE NOT EXISTS RETURNING).

CREATE TABLE IF NOT EXISTS withdraw_requests (
    request_id       TEXT PRIMARY KEY,
    status           TEXT NOT NULL,
    disclosed_amount BIGINT NOT NULL,
    withdraw_blind   BYTEA NOT NULL,
    recipient        BYTEA NOT NULL,
    recipient_hash   BYTEA NOT NULL,
    vault_addr       BYTEA NOT NULL,
    asset_type       BYTEA NOT NULL,
    asset_id_le32    BYTEA NOT NULL,
    chain_id         INTEGER NOT NULL,
    vault_sequence   BIGINT NOT NULL,
    ca_payload_hash  BYTEA NOT NULL,
    ca_payload_jsonb JSONB NOT NULL,
    expiry           BIGINT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_withdraw_requests_status         ON withdraw_requests (status);
CREATE INDEX IF NOT EXISTS idx_withdraw_requests_expiry         ON withdraw_requests (expiry);
CREATE INDEX IF NOT EXISTS idx_withdraw_requests_vault_seq      ON withdraw_requests (vault_addr, vault_sequence);
