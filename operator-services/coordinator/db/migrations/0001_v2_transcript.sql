-- V2 fresh-cut coordinator schema.
--
-- Stores only public request metadata, HPKE ciphertext envelopes, transcript
-- hashes, public commitments, partial proof/signature shares, and abort
-- evidence. User witness values are intentionally absent.

CREATE TABLE IF NOT EXISTS deop_v2_requests (
    request_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    roster_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deop_v2_session_envelopes (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES deop_v2_requests(request_id),
    session_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    slot INTEGER NOT NULL,
    sender_hpke_public_key BYTEA NOT NULL,
    share_commitment BYTEA NOT NULL,
    hpke_aad_hash BYTEA NOT NULL,
    hpke_enc BYTEA NOT NULL,
    hpke_ciphertext BYTEA NOT NULL,
    transcript_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deop_v2_partial_artifacts (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES deop_v2_requests(request_id),
    session_id TEXT NOT NULL,
    slot INTEGER NOT NULL,
    artifact_kind TEXT NOT NULL,
    artifact_hash BYTEA NOT NULL,
    transcript_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deop_v2_abort_evidence (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES deop_v2_requests(request_id),
    session_id TEXT NOT NULL,
    accused_slot INTEGER NOT NULL,
    evidence_kind TEXT NOT NULL,
    evidence_hash BYTEA NOT NULL,
    transcript_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deop_v2_requests_status ON deop_v2_requests (status);
CREATE INDEX IF NOT EXISTS idx_deop_v2_session_request ON deop_v2_session_envelopes (request_id);
CREATE INDEX IF NOT EXISTS idx_deop_v2_artifacts_request ON deop_v2_partial_artifacts (request_id);
CREATE INDEX IF NOT EXISTS idx_deop_v2_abort_request ON deop_v2_abort_evidence (request_id);
