-- 0001_init.sql — deposit-related tables for Gate 4c operator services.
--
-- Withdraw + maintenance tables defer to Gates 5/6.
-- Production: PostgreSQL. Tests: SQLite (use TEXT instead of BIGINT/JSONB).

CREATE TABLE IF NOT EXISTS operator_set_snapshots (
    operator_set_version BIGINT PRIMARY KEY,
    pubkeys BYTEA NOT NULL,
    main_index INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deposit_requests (
    request_id TEXT PRIMARY KEY,
    user_addr TEXT NOT NULL,
    vault_addr TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    amount BIGINT NOT NULL,
    deposit_blind BYTEA NOT NULL,
    amount_tag BYTEA NOT NULL,
    commitment BYTEA NOT NULL,
    deposit_binding_proof BYTEA NOT NULL,
    ca_payload_hash BYTEA NOT NULL,
    ca_payload_jsonb JSONB NOT NULL,
    deposit_nonce BYTEA NOT NULL UNIQUE,
    expiry BIGINT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deposit_requests_user ON deposit_requests (user_addr);
CREATE INDEX IF NOT EXISTS idx_deposit_requests_status ON deposit_requests (status);

CREATE TABLE IF NOT EXISTS attestation_signatures (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES deposit_requests(request_id),
    operator_slot INTEGER NOT NULL,
    signature_bytes BYTEA NOT NULL,
    message_bytes_hash BYTEA NOT NULL,
    verification_status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (request_id, operator_slot)
);

CREATE TABLE IF NOT EXISTS ca_payloads (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES deposit_requests(request_id),
    payload_jsonb JSONB NOT NULL,
    computed_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    request_id TEXT REFERENCES deposit_requests(request_id),
    event_type TEXT NOT NULL,
    payload_jsonb JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_request ON audit_logs (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON audit_logs (event_type);
