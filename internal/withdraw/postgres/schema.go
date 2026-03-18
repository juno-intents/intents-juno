package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS withdrawal_requests (
	withdrawal_id BYTEA PRIMARY KEY,
	requester BYTEA NOT NULL,
	amount BIGINT NOT NULL,
	fee_bps INTEGER NOT NULL,
	recipient_ua BYTEA NOT NULL,
	proof_witness_item BYTEA,
	expiry TIMESTAMPTZ NOT NULL,
	base_block_number BIGINT,
	base_block_hash BYTEA,
	base_tx_hash BYTEA,
	base_log_index BIGINT,
	base_finality_source TEXT,
	status SMALLINT NOT NULL DEFAULT 1,

	claimed_by TEXT,
	claim_lease_version BIGINT,
	claim_expires_at TIMESTAMPTZ,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT withdrawal_id_len CHECK (octet_length(withdrawal_id) = 32),
	CONSTRAINT requester_len CHECK (octet_length(requester) = 20),
	CONSTRAINT amount_positive CHECK (amount > 0),
	CONSTRAINT fee_bps_range CHECK (fee_bps >= 0 AND fee_bps <= 10000),
	CONSTRAINT withdrawal_status_range CHECK (status >= 1 AND status <= 4),
	CONSTRAINT recipient_ua_nonempty CHECK (octet_length(recipient_ua) > 0),
	CONSTRAINT base_block_hash_len CHECK (base_block_hash IS NULL OR octet_length(base_block_hash) = 32),
	CONSTRAINT base_tx_hash_len CHECK (base_tx_hash IS NULL OR octet_length(base_tx_hash) = 32),
	CONSTRAINT base_log_index_nonneg CHECK (base_log_index IS NULL OR base_log_index >= 0),
	CONSTRAINT base_finality_source_nonempty CHECK (base_finality_source IS NULL OR base_finality_source <> ''),
	CONSTRAINT proof_witness_item_len CHECK (proof_witness_item IS NULL OR octet_length(proof_witness_item) = 1923),
	CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> ''),
	CONSTRAINT claim_lease_version_positive CHECK (claim_lease_version IS NULL OR claim_lease_version > 0)
);

CREATE INDEX IF NOT EXISTS withdrawal_requests_claim_idx ON withdrawal_requests (claim_expires_at);
CREATE INDEX IF NOT EXISTS withdrawal_requests_expiry_idx ON withdrawal_requests (expiry);
CREATE INDEX IF NOT EXISTS withdrawal_requests_status_idx ON withdrawal_requests (status);
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS proof_witness_item BYTEA;
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS proof_witness_item_len;
ALTER TABLE withdrawal_requests ADD CONSTRAINT proof_witness_item_len CHECK (proof_witness_item IS NULL OR octet_length(proof_witness_item) = 1923);
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS base_block_number BIGINT;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS base_block_hash BYTEA;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS base_tx_hash BYTEA;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS base_log_index BIGINT;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS base_finality_source TEXT;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS status SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE withdrawal_requests ADD COLUMN IF NOT EXISTS claim_lease_version BIGINT;
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS withdrawal_status_range;
ALTER TABLE withdrawal_requests ADD CONSTRAINT withdrawal_status_range CHECK (status >= 1 AND status <= 4);
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS base_block_hash_len;
ALTER TABLE withdrawal_requests ADD CONSTRAINT base_block_hash_len CHECK (base_block_hash IS NULL OR octet_length(base_block_hash) = 32);
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS base_tx_hash_len;
ALTER TABLE withdrawal_requests ADD CONSTRAINT base_tx_hash_len CHECK (base_tx_hash IS NULL OR octet_length(base_tx_hash) = 32);
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS base_log_index_nonneg;
ALTER TABLE withdrawal_requests ADD CONSTRAINT base_log_index_nonneg CHECK (base_log_index IS NULL OR base_log_index >= 0);
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS base_finality_source_nonempty;
ALTER TABLE withdrawal_requests ADD CONSTRAINT base_finality_source_nonempty CHECK (base_finality_source IS NULL OR base_finality_source <> '');
ALTER TABLE withdrawal_requests DROP CONSTRAINT IF EXISTS claim_lease_version_positive;
ALTER TABLE withdrawal_requests ADD CONSTRAINT claim_lease_version_positive CHECK (claim_lease_version IS NULL OR claim_lease_version > 0);
CREATE INDEX IF NOT EXISTS withdrawal_requests_base_block_number_idx ON withdrawal_requests (base_block_number);

CREATE TABLE IF NOT EXISTS withdrawal_batches (
	batch_id BYTEA PRIMARY KEY,
	state SMALLINT NOT NULL,
	tx_plan BYTEA NOT NULL,
	signed_tx BYTEA,
	lease_owner TEXT,
	lease_version BIGINT,
	broadcast_locked_at TIMESTAMPTZ,
	juno_txid TEXT,
	juno_confirmed_at TIMESTAMPTZ,
	base_tx_hash TEXT,
	rebroadcast_attempts INTEGER NOT NULL DEFAULT 0,
	next_rebroadcast_at TIMESTAMPTZ,
	failure_count INTEGER NOT NULL DEFAULT 0,
	last_failure_stage TEXT,
	last_error_code TEXT,
	last_error_message TEXT,
	last_failed_at TIMESTAMPTZ,
	dlq_at TIMESTAMPTZ,
	mark_paid_failures INTEGER NOT NULL DEFAULT 0,
	last_mark_paid_error TEXT,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT state_range CHECK (state >= 1 AND state <= 7),
	CONSTRAINT lease_owner_nonempty CHECK (lease_owner IS NULL OR lease_owner <> ''),
	CONSTRAINT lease_version_positive CHECK (lease_version IS NULL OR lease_version > 0),
	CONSTRAINT juno_txid_nonempty CHECK (juno_txid IS NULL OR juno_txid <> ''),
	CONSTRAINT rebroadcast_attempts_nonneg CHECK (rebroadcast_attempts >= 0),
	CONSTRAINT failure_count_nonneg CHECK (failure_count >= 0),
	CONSTRAINT mark_paid_failures_nonneg CHECK (mark_paid_failures >= 0)
);

CREATE INDEX IF NOT EXISTS withdrawal_batches_state_idx ON withdrawal_batches (state) WHERE dlq_at IS NULL;

ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS base_tx_hash TEXT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS lease_version BIGINT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS broadcast_locked_at TIMESTAMPTZ;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS juno_confirmed_at TIMESTAMPTZ;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS rebroadcast_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS next_rebroadcast_at TIMESTAMPTZ;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS failure_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS last_failure_stage TEXT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS last_error_code TEXT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS last_error_message TEXT;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS dlq_at TIMESTAMPTZ;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS mark_paid_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE withdrawal_batches ADD COLUMN IF NOT EXISTS last_mark_paid_error TEXT;
ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS state_range;
ALTER TABLE withdrawal_batches ADD CONSTRAINT state_range CHECK (state >= 1 AND state <= 7);
ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS lease_owner_nonempty;
ALTER TABLE withdrawal_batches ADD CONSTRAINT lease_owner_nonempty CHECK (lease_owner IS NULL OR lease_owner <> '');
ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS lease_version_positive;
ALTER TABLE withdrawal_batches ADD CONSTRAINT lease_version_positive CHECK (lease_version IS NULL OR lease_version > 0);

ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS base_tx_hash_nonempty;
ALTER TABLE withdrawal_batches ADD CONSTRAINT base_tx_hash_nonempty CHECK (base_tx_hash IS NULL OR base_tx_hash <> '');

ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS base_tx_hash_requires_finalized;
ALTER TABLE withdrawal_batches ADD CONSTRAINT base_tx_hash_requires_finalized CHECK (base_tx_hash IS NULL OR state = 7);

ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS rebroadcast_attempts_nonneg;
ALTER TABLE withdrawal_batches ADD CONSTRAINT rebroadcast_attempts_nonneg CHECK (rebroadcast_attempts >= 0);
ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS failure_count_nonneg;
ALTER TABLE withdrawal_batches ADD CONSTRAINT failure_count_nonneg CHECK (failure_count >= 0);
ALTER TABLE withdrawal_batches DROP CONSTRAINT IF EXISTS mark_paid_failures_nonneg;
ALTER TABLE withdrawal_batches ADD CONSTRAINT mark_paid_failures_nonneg CHECK (mark_paid_failures >= 0);

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
UPDATE withdrawal_requests
SET status = 3
WHERE EXISTS (
	SELECT 1
	FROM withdrawal_batch_items wbi
	JOIN withdrawal_batches wb ON wb.batch_id = wbi.batch_id
	WHERE wbi.withdrawal_id = withdrawal_requests.withdrawal_id
	  AND wb.state >= 5
);
UPDATE withdrawal_requests
SET status = 2
WHERE status < 2
  AND EXISTS (
	SELECT 1
	FROM withdrawal_batch_items wbi
	WHERE wbi.withdrawal_id = withdrawal_requests.withdrawal_id
);
CREATE INDEX IF NOT EXISTS withdrawal_requests_requester_idx ON withdrawal_requests (requester);
CREATE INDEX IF NOT EXISTS withdrawal_batches_juno_txid_idx ON withdrawal_batches (juno_txid) WHERE juno_txid IS NOT NULL AND juno_txid <> '';
CREATE INDEX IF NOT EXISTS withdrawal_batches_base_tx_hash_idx ON withdrawal_batches (base_tx_hash) WHERE base_tx_hash IS NOT NULL AND base_tx_hash <> '';
CREATE INDEX IF NOT EXISTS withdrawal_batches_unconfirmed_idx ON withdrawal_batches (juno_confirmed_at) WHERE juno_confirmed_at IS NOT NULL AND dlq_at IS NULL;
`
