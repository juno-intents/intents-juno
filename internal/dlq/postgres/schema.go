package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS proof_dlq (
    job_id       BYTEA PRIMARY KEY,
    pipeline     TEXT NOT NULL,
    image_id     BYTEA NOT NULL,
    state        SMALLINT NOT NULL,
    error_code   TEXT NOT NULL,
    error_message TEXT,
    attempt_count INT NOT NULL DEFAULT 0,
    job_payload  BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    ack_at       TIMESTAMPTZ,
    CONSTRAINT proof_dlq_job_id_len CHECK (octet_length(job_id) = 32)
);
CREATE INDEX IF NOT EXISTS proof_dlq_error_code_idx ON proof_dlq (error_code);
CREATE INDEX IF NOT EXISTS proof_dlq_created_at_idx ON proof_dlq (created_at);
CREATE INDEX IF NOT EXISTS proof_dlq_ack_idx ON proof_dlq (acknowledged) WHERE NOT acknowledged;

CREATE TABLE IF NOT EXISTS deposit_batch_dlq (
    batch_id        BYTEA PRIMARY KEY,
    deposit_ids     BYTEA[] NOT NULL,
    items_count     INT NOT NULL,
    state           SMALLINT NOT NULL,
    failure_stage   TEXT NOT NULL,
    error_code      TEXT,
    error_message   TEXT,
    attempt_count   INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged    BOOLEAN NOT NULL DEFAULT false,
    ack_at          TIMESTAMPTZ,
    CONSTRAINT deposit_batch_dlq_id_len CHECK (octet_length(batch_id) = 32)
);
CREATE INDEX IF NOT EXISTS deposit_batch_dlq_stage_idx ON deposit_batch_dlq (failure_stage);
CREATE INDEX IF NOT EXISTS deposit_batch_dlq_created_at_idx ON deposit_batch_dlq (created_at);
CREATE INDEX IF NOT EXISTS deposit_batch_dlq_ack_idx ON deposit_batch_dlq (acknowledged) WHERE NOT acknowledged;

CREATE TABLE IF NOT EXISTS withdrawal_batch_dlq (
    batch_id              BYTEA PRIMARY KEY,
    withdrawal_ids        BYTEA[] NOT NULL,
    items_count           INT NOT NULL,
    state                 SMALLINT NOT NULL,
    failure_stage         TEXT NOT NULL,
    error_code            TEXT,
    error_message         TEXT,
    rebroadcast_attempts  INT NOT NULL DEFAULT 0,
    juno_tx_id            TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged          BOOLEAN NOT NULL DEFAULT false,
    ack_at                TIMESTAMPTZ,
    CONSTRAINT withdrawal_batch_dlq_id_len CHECK (octet_length(batch_id) = 32)
);
CREATE INDEX IF NOT EXISTS withdrawal_batch_dlq_stage_idx ON withdrawal_batch_dlq (failure_stage);
CREATE INDEX IF NOT EXISTS withdrawal_batch_dlq_created_at_idx ON withdrawal_batch_dlq (created_at);
CREATE INDEX IF NOT EXISTS withdrawal_batch_dlq_ack_idx ON withdrawal_batch_dlq (acknowledged) WHERE NOT acknowledged;
`
