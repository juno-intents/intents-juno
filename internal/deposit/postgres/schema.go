package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS deposit_jobs (
	deposit_id BYTEA PRIMARY KEY,
	commitment BYTEA NOT NULL,
	leaf_index BIGINT NOT NULL,
	amount BIGINT NOT NULL,
	base_recipient BYTEA NOT NULL,

	state SMALLINT NOT NULL,

	checkpoint_height BIGINT,
	checkpoint_block_hash BYTEA,
	checkpoint_final_orchard_root BYTEA,
	checkpoint_base_chain_id BIGINT,
	checkpoint_bridge_contract BYTEA,

	proof_seal BYTEA,
	tx_hash BYTEA,
	claimed_by TEXT,
	claim_expires_at TIMESTAMPTZ,

	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT deposit_id_len CHECK (octet_length(deposit_id) = 32),
	CONSTRAINT commitment_len CHECK (octet_length(commitment) = 32),
	CONSTRAINT base_recipient_len CHECK (octet_length(base_recipient) = 20),
	CONSTRAINT leaf_index_nonneg CHECK (leaf_index >= 0),
	CONSTRAINT amount_nonneg CHECK (amount >= 0),
	CONSTRAINT state_range CHECK (state >= 1 AND state <= 6),
	CONSTRAINT checkpoint_block_hash_len CHECK (checkpoint_block_hash IS NULL OR octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT checkpoint_root_len CHECK (checkpoint_final_orchard_root IS NULL OR octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT checkpoint_bridge_len CHECK (checkpoint_bridge_contract IS NULL OR octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT tx_hash_len CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32),
	CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '')
);

CREATE INDEX IF NOT EXISTS deposit_jobs_state_idx ON deposit_jobs (state);
CREATE INDEX IF NOT EXISTS deposit_jobs_claim_idx ON deposit_jobs (claim_expires_at);
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE deposit_jobs ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;
ALTER TABLE deposit_jobs DROP CONSTRAINT IF EXISTS claim_owner_nonempty;
ALTER TABLE deposit_jobs ADD CONSTRAINT claim_owner_nonempty CHECK (claimed_by IS NULL OR claimed_by <> '');
`
