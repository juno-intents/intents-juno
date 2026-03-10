package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS checkpoint_packages (
	digest BYTEA PRIMARY KEY,
	checkpoint_height BIGINT NOT NULL,
	checkpoint_block_hash BYTEA NOT NULL,
	checkpoint_final_orchard_root BYTEA NOT NULL,
	checkpoint_base_chain_id BIGINT NOT NULL,
	checkpoint_bridge_contract BYTEA NOT NULL,
	operator_set_hash BYTEA NOT NULL,
	ipfs_cid TEXT,
	s3_key TEXT,
	package_json BYTEA NOT NULL,
	state SMALLINT NOT NULL DEFAULT 1,
	persisted_at TIMESTAMPTZ NOT NULL,
	emitted_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT checkpoint_digest_len CHECK (octet_length(digest) = 32),
	CONSTRAINT checkpoint_block_hash_len CHECK (octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT checkpoint_root_len CHECK (octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT checkpoint_bridge_len CHECK (octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT checkpoint_operator_set_hash_len CHECK (octet_length(operator_set_hash) = 32),
	CONSTRAINT checkpoint_height_nonneg CHECK (checkpoint_height >= 0),
	CONSTRAINT checkpoint_base_chain_id_nonneg CHECK (checkpoint_base_chain_id >= 0),
	CONSTRAINT checkpoint_state_range CHECK (state >= 1 AND state <= 2),
	CONSTRAINT checkpoint_emitted_requires_emitted_state CHECK (emitted_at IS NULL OR state = 2)
);

ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS state SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS emitted_at TIMESTAMPTZ;
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_state_range;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_state_range CHECK (state >= 1 AND state <= 2);
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_emitted_requires_emitted_state;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_emitted_requires_emitted_state CHECK (emitted_at IS NULL OR state = 2);

CREATE INDEX IF NOT EXISTS checkpoint_packages_height_idx ON checkpoint_packages (checkpoint_height DESC);
CREATE INDEX IF NOT EXISTS checkpoint_packages_state_idx ON checkpoint_packages (state, persisted_at ASC);
`
