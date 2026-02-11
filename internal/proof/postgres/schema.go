package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS proof_request_ids (
	chain_id BIGINT PRIMARY KEY,
	next_request_id BIGINT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT proof_request_ids_chain_positive CHECK (chain_id > 0),
	CONSTRAINT proof_request_ids_next_positive CHECK (next_request_id > 0)
);

CREATE TABLE IF NOT EXISTS proof_jobs (
	job_id BYTEA PRIMARY KEY,
	pipeline TEXT NOT NULL,
	image_id BYTEA NOT NULL,
	journal BYTEA NOT NULL,
	private_input BYTEA NOT NULL,
	deadline TIMESTAMPTZ NOT NULL,
	priority INTEGER NOT NULL,
	callback_expires_at TIMESTAMPTZ NOT NULL,

	request_id BIGINT UNIQUE,
	state SMALLINT NOT NULL,
	attempt_count INTEGER NOT NULL DEFAULT 0,

	processing_owner TEXT,
	processing_expires_at TIMESTAMPTZ,

	submission_path TEXT,
	seal BYTEA,
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

	retryable BOOLEAN NOT NULL DEFAULT FALSE,
	error_code TEXT,
	error_message TEXT,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT proof_jobs_job_id_len CHECK (octet_length(job_id) = 32),
	CONSTRAINT proof_jobs_image_id_len CHECK (octet_length(image_id) = 32),
	CONSTRAINT proof_jobs_request_id_positive CHECK (request_id IS NULL OR request_id > 0),
	CONSTRAINT proof_jobs_state_range CHECK (state >= 1 AND state <= 5),
	CONSTRAINT proof_jobs_attempt_nonneg CHECK (attempt_count >= 0),
	CONSTRAINT proof_jobs_processing_owner_nonempty CHECK (processing_owner IS NULL OR processing_owner <> '')
);

CREATE INDEX IF NOT EXISTS proof_jobs_state_idx ON proof_jobs (state);
CREATE INDEX IF NOT EXISTS proof_jobs_processing_idx ON proof_jobs (processing_expires_at);
CREATE INDEX IF NOT EXISTS proof_jobs_callback_expires_idx ON proof_jobs (callback_expires_at);

CREATE TABLE IF NOT EXISTS proof_events (
	event_id BIGSERIAL PRIMARY KEY,
	job_id BYTEA NOT NULL REFERENCES proof_jobs(job_id) ON DELETE CASCADE,
	event_type TEXT NOT NULL,
	payload JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT proof_events_job_id_len CHECK (octet_length(job_id) = 32),
	CONSTRAINT proof_events_type_nonempty CHECK (event_type <> '')
);

CREATE INDEX IF NOT EXISTS proof_events_job_created_idx ON proof_events (job_id, created_at);
`
