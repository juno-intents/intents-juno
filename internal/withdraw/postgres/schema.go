package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS withdrawal_requests (
	withdrawal_id BYTEA PRIMARY KEY,
	requester BYTEA NOT NULL,
	amount BIGINT NOT NULL,
	fee_bps INTEGER NOT NULL,
	recipient_ua BYTEA NOT NULL,
	expiry TIMESTAMPTZ NOT NULL,

	claimed_by TEXT,
	claim_expires_at TIMESTAMPTZ,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT withdrawal_id_len CHECK (octet_length(withdrawal_id) = 32),
	CONSTRAINT requester_len CHECK (octet_length(requester) = 20),
	CONSTRAINT amount_positive CHECK (amount > 0),
	CONSTRAINT fee_bps_range CHECK (fee_bps >= 0 AND fee_bps <= 10000),
	CONSTRAINT recipient_ua_nonempty CHECK (octet_length(recipient_ua) > 0),
	CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '')
);

CREATE INDEX IF NOT EXISTS withdrawal_requests_claim_idx ON withdrawal_requests (claim_expires_at);
CREATE INDEX IF NOT EXISTS withdrawal_requests_expiry_idx ON withdrawal_requests (expiry);

CREATE TABLE IF NOT EXISTS withdrawal_batches (
	batch_id BYTEA PRIMARY KEY,
	state SMALLINT NOT NULL,
	tx_plan BYTEA NOT NULL,
	signed_tx BYTEA,
	juno_txid TEXT,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT state_range CHECK (state >= 1 AND state <= 5),
	CONSTRAINT juno_txid_nonempty CHECK (juno_txid IS NULL OR juno_txid <> '')
);

CREATE INDEX IF NOT EXISTS withdrawal_batches_state_idx ON withdrawal_batches (state);

CREATE TABLE IF NOT EXISTS withdrawal_batch_items (
	batch_id BYTEA NOT NULL REFERENCES withdrawal_batches(batch_id) ON DELETE CASCADE,
	withdrawal_id BYTEA NOT NULL REFERENCES withdrawal_requests(withdrawal_id),
	position INTEGER NOT NULL,

	PRIMARY KEY (batch_id, withdrawal_id),

	CONSTRAINT wbi_batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT wbi_withdrawal_id_len CHECK (octet_length(withdrawal_id) = 32),
	CONSTRAINT position_nonneg CHECK (position >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS withdrawal_batch_items_withdrawal_uniq ON withdrawal_batch_items (withdrawal_id);
CREATE INDEX IF NOT EXISTS withdrawal_batch_items_batch_idx ON withdrawal_batch_items (batch_id, position);
`
