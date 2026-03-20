package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS deposit_jobs (
	deposit_id BYTEA PRIMARY KEY,
	commitment BYTEA NOT NULL,
	leaf_index BIGINT NOT NULL,
	amount BIGINT NOT NULL,
	base_recipient BYTEA NOT NULL,
	proof_witness_item BYTEA,
	juno_height BIGINT,

	state SMALLINT NOT NULL,

	checkpoint_height BIGINT,
	checkpoint_block_hash BYTEA,
	checkpoint_final_orchard_root BYTEA,
	checkpoint_base_chain_id BIGINT,
	checkpoint_bridge_contract BYTEA,

	proof_seal BYTEA,
	tx_hash BYTEA,
	rejection_reason TEXT,
	submit_batch_id BYTEA,
	claimed_by TEXT,
	claim_expires_at TIMESTAMPTZ,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT deposit_id_len CHECK (octet_length(deposit_id) = 32),
	CONSTRAINT commitment_len CHECK (octet_length(commitment) = 32),
	CONSTRAINT base_recipient_len CHECK (octet_length(base_recipient) = 20),
	CONSTRAINT proof_witness_item_len CHECK (proof_witness_item IS NULL OR octet_length(proof_witness_item) = 1848),
	CONSTRAINT leaf_index_nonneg CHECK (leaf_index >= 0),
	CONSTRAINT amount_nonneg CHECK (amount >= 0),
	CONSTRAINT state_range CHECK (state >= 1 AND state <= 7),
	CONSTRAINT checkpoint_block_hash_len CHECK (checkpoint_block_hash IS NULL OR octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT checkpoint_root_len CHECK (checkpoint_final_orchard_root IS NULL OR octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT checkpoint_bridge_len CHECK (checkpoint_bridge_contract IS NULL OR octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32),
	CONSTRAINT rejection_reason_nonempty CHECK (rejection_reason IS NULL OR rejection_reason <> ''),
	CONSTRAINT submit_batch_id_len CHECK (submit_batch_id IS NULL OR octet_length(submit_batch_id) = 32),
	CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '')
);

CREATE TABLE IF NOT EXISTS deposit_batch_attempts (
	batch_id BYTEA PRIMARY KEY,
	owner TEXT NOT NULL,
	epoch BIGINT NOT NULL,
	deposit_ids_json JSONB NOT NULL,

	checkpoint_height BIGINT NOT NULL,
	checkpoint_block_hash BYTEA NOT NULL,
	checkpoint_final_orchard_root BYTEA NOT NULL,
	checkpoint_base_chain_id BIGINT NOT NULL,
	checkpoint_bridge_contract BYTEA NOT NULL,

	operator_signatures_json JSONB NOT NULL,
	proof_seal BYTEA NOT NULL,
	tx_hash BYTEA,
	claimed_by TEXT,
	claim_expires_at TIMESTAMPTZ,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT deposit_batch_attempts_batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT deposit_batch_attempts_owner_nonempty CHECK (owner <> ''),
	CONSTRAINT deposit_batch_attempts_epoch_positive CHECK (epoch > 0),
	CONSTRAINT deposit_batch_attempts_block_hash_len CHECK (octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT deposit_batch_attempts_root_len CHECK (octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT deposit_batch_attempts_bridge_len CHECK (octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT deposit_batch_attempts_tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32),
	CONSTRAINT deposit_batch_attempts_claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '')
);

CREATE TABLE IF NOT EXISTS deposit_batches (
	batch_id BYTEA PRIMARY KEY,
	state SMALLINT NOT NULL,
	owner TEXT NOT NULL,
	lease_owner TEXT,
	lease_expires_at TIMESTAMPTZ,
	started_at TIMESTAMPTZ NOT NULL,
	closed_at TIMESTAMPTZ,
	failure_reason TEXT,

	checkpoint_height BIGINT,
	checkpoint_block_hash BYTEA,
	checkpoint_final_orchard_root BYTEA,
	checkpoint_base_chain_id BIGINT,
	checkpoint_bridge_contract BYTEA,

	proof_requested BOOLEAN NOT NULL DEFAULT FALSE,
	operator_signatures_json JSONB NOT NULL DEFAULT '[]'::jsonb,
	proof_seal BYTEA,
	tx_hash BYTEA,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT deposit_batches_batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT deposit_batches_state_range CHECK (state >= 1 AND state <= 7),
	CONSTRAINT deposit_batches_owner_nonempty CHECK (owner <> ''),
	CONSTRAINT deposit_batches_lease_owner_nonempty CHECK (lease_owner IS NULL OR lease_owner <> ''),
	CONSTRAINT deposit_batches_failure_reason_nonempty CHECK (failure_reason IS NULL OR failure_reason <> ''),
	CONSTRAINT deposit_batches_block_hash_len CHECK (checkpoint_block_hash IS NULL OR octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT deposit_batches_root_len CHECK (checkpoint_final_orchard_root IS NULL OR octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT deposit_batches_bridge_len CHECK (checkpoint_bridge_contract IS NULL OR octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT deposit_batches_tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32)
);

CREATE TABLE IF NOT EXISTS deposit_batch_items (
	batch_id BYTEA NOT NULL,
	deposit_id BYTEA NOT NULL,
	active BOOLEAN NOT NULL DEFAULT TRUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	PRIMARY KEY (batch_id, deposit_id),
	CONSTRAINT deposit_batch_items_batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT deposit_batch_items_deposit_id_len CHECK (octet_length(deposit_id) = 32)
);

CREATE TABLE IF NOT EXISTS deposit_source_events (
	chain_id BIGINT NOT NULL,
	tx_hash BYTEA NOT NULL,
	log_index BIGINT NOT NULL,
	deposit_id BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	PRIMARY KEY (chain_id, tx_hash, log_index),
	CONSTRAINT deposit_source_events_chain_id_positive CHECK (chain_id > 0),
	CONSTRAINT deposit_source_events_tx_hash_len CHECK (octet_length(tx_hash) = 32),
	CONSTRAINT deposit_source_events_log_index_nonneg CHECK (log_index >= 0),
	CONSTRAINT deposit_source_events_deposit_id_len CHECK (octet_length(deposit_id) = 32)
);

CREATE INDEX IF NOT EXISTS deposit_jobs_state_idx ON deposit_jobs (state);
CREATE INDEX IF NOT EXISTS deposit_jobs_claim_idx ON deposit_jobs (claim_expires_at);
CREATE INDEX IF NOT EXISTS deposit_jobs_submit_batch_idx ON deposit_jobs (submit_batch_id) WHERE submit_batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS deposit_jobs_juno_height_idx ON deposit_jobs (juno_height);
CREATE INDEX IF NOT EXISTS deposit_jobs_base_recipient_idx ON deposit_jobs (base_recipient);
CREATE INDEX IF NOT EXISTS deposit_jobs_tx_hash_idx ON deposit_jobs (tx_hash) WHERE tx_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS deposit_batch_attempts_claim_idx ON deposit_batch_attempts (claim_expires_at);
CREATE INDEX IF NOT EXISTS deposit_batch_attempts_tx_hash_idx ON deposit_batch_attempts (tx_hash) WHERE tx_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS deposit_batches_state_idx ON deposit_batches (state, started_at);
CREATE INDEX IF NOT EXISTS deposit_batches_lease_idx ON deposit_batches (lease_expires_at);
CREATE INDEX IF NOT EXISTS deposit_batch_items_batch_idx ON deposit_batch_items (batch_id, created_at, deposit_id) WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS deposit_batch_items_active_deposit_idx ON deposit_batch_items (deposit_id) WHERE active;
CREATE INDEX IF NOT EXISTS deposit_source_events_deposit_id_idx ON deposit_source_events (deposit_id);
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS proof_witness_item BYTEA;
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS submit_batch_id BYTEA;
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS rejection_reason TEXT;
ALTER TABLE deposit_jobs DROP CONSTRAINT IF EXISTS claim_owner_nonempty;
ALTER TABLE deposit_jobs ADD CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '');
ALTER TABLE deposit_jobs DROP CONSTRAINT IF EXISTS proof_witness_item_len;
ALTER TABLE deposit_jobs ADD CONSTRAINT proof_witness_item_len CHECK (proof_witness_item IS NULL OR octet_length(proof_witness_item) = 1848);
ALTER TABLE deposit_jobs DROP CONSTRAINT IF EXISTS submit_batch_id_len;
ALTER TABLE deposit_jobs ADD CONSTRAINT submit_batch_id_len CHECK (submit_batch_id IS NULL OR octet_length(submit_batch_id) = 32);
ALTER TABLE deposit_jobs DROP CONSTRAINT IF EXISTS rejection_reason_nonempty;
ALTER TABLE deposit_jobs ADD CONSTRAINT rejection_reason_nonempty CHECK (rejection_reason IS NULL OR rejection_reason <> '');
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS juno_height BIGINT;
ALTER TABLE deposit_batch_attempts ADD COLUMN IF NOT EXISTS tx_hash BYTEA;
ALTER TABLE deposit_batch_attempts ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE deposit_batch_attempts ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;
ALTER TABLE deposit_batch_attempts DROP CONSTRAINT IF EXISTS deposit_batch_attempts_claim_owner_nonempty;
ALTER TABLE deposit_batch_attempts ADD CONSTRAINT deposit_batch_attempts_claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '');
ALTER TABLE deposit_batch_attempts DROP CONSTRAINT IF EXISTS deposit_batch_attempts_tx_hash_len;
ALTER TABLE deposit_batch_attempts ADD CONSTRAINT deposit_batch_attempts_tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32);
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS failure_reason TEXT;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS proof_requested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS operator_signatures_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS proof_seal BYTEA;
ALTER TABLE deposit_batches ADD COLUMN IF NOT EXISTS tx_hash BYTEA;
ALTER TABLE deposit_batches DROP CONSTRAINT IF EXISTS deposit_batches_lease_owner_nonempty;
ALTER TABLE deposit_batches ADD CONSTRAINT deposit_batches_lease_owner_nonempty CHECK (lease_owner IS NULL OR lease_owner <> '');
ALTER TABLE deposit_batches DROP CONSTRAINT IF EXISTS deposit_batches_failure_reason_nonempty;
ALTER TABLE deposit_batches ADD CONSTRAINT deposit_batches_failure_reason_nonempty CHECK (failure_reason IS NULL OR failure_reason <> '');
ALTER TABLE deposit_batches DROP CONSTRAINT IF EXISTS deposit_batches_tx_hash_len;
ALTER TABLE deposit_batches ADD CONSTRAINT deposit_batches_tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32);
ALTER TABLE deposit_source_events DROP CONSTRAINT IF EXISTS deposit_source_events_chain_id_positive;
ALTER TABLE deposit_source_events ADD CONSTRAINT deposit_source_events_chain_id_positive CHECK (chain_id > 0);
ALTER TABLE deposit_source_events DROP CONSTRAINT IF EXISTS deposit_source_events_tx_hash_len;
ALTER TABLE deposit_source_events ADD CONSTRAINT deposit_source_events_tx_hash_len CHECK (octet_length(tx_hash) = 32);
ALTER TABLE deposit_source_events DROP CONSTRAINT IF EXISTS deposit_source_events_log_index_nonneg;
ALTER TABLE deposit_source_events ADD CONSTRAINT deposit_source_events_log_index_nonneg CHECK (log_index >= 0);
ALTER TABLE deposit_source_events DROP CONSTRAINT IF EXISTS deposit_source_events_deposit_id_len;
ALTER TABLE deposit_source_events ADD CONSTRAINT deposit_source_events_deposit_id_len CHECK (octet_length(deposit_id) = 32);
`
