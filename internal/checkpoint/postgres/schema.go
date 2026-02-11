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
	persisted_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT checkpoint_digest_len CHECK (octet_length(digest) = 32),
	CONSTRAINT checkpoint_block_hash_len CHECK (octet_length(checkpoint_block_hash) = 32),
	CONSTRAINT checkpoint_root_len CHECK (octet_length(checkpoint_final_orchard_root) = 32),
	CONSTRAINT checkpoint_bridge_len CHECK (octet_length(checkpoint_bridge_contract) = 20),
	CONSTRAINT checkpoint_operator_set_hash_len CHECK (octet_length(operator_set_hash) = 32),
	CONSTRAINT checkpoint_height_nonneg CHECK (checkpoint_height >= 0),
	CONSTRAINT checkpoint_base_chain_id_nonneg CHECK (checkpoint_base_chain_id >= 0)
);

CREATE INDEX IF NOT EXISTS checkpoint_packages_height_idx ON checkpoint_packages (checkpoint_height DESC);
`
