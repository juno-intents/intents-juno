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
	pin_state SMALLINT NOT NULL DEFAULT 1,
	pin_attempts INTEGER NOT NULL DEFAULT 0,
	pin_last_error TEXT NOT NULL DEFAULT '',
	pin_last_attempt_at TIMESTAMPTZ,
	pin_next_attempt_at TIMESTAMPTZ,
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
	CONSTRAINT checkpoint_pin_state_range CHECK (pin_state >= 1 AND pin_state <= 4),
	CONSTRAINT checkpoint_pin_attempts_nonneg CHECK (pin_attempts >= 0),
	CONSTRAINT checkpoint_emitted_requires_emitted_state CHECK (emitted_at IS NULL OR state = 2)
);

ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS state SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS emitted_at TIMESTAMPTZ;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS pin_state SMALLINT;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS pin_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS pin_last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS pin_last_attempt_at TIMESTAMPTZ;
ALTER TABLE checkpoint_packages ADD COLUMN IF NOT EXISTS pin_next_attempt_at TIMESTAMPTZ;
UPDATE checkpoint_packages
SET pin_state = CASE
	WHEN pin_state IS NOT NULL THEN pin_state
	WHEN COALESCE(NULLIF(BTRIM(ipfs_cid), ''), '') <> '' THEN 3
	ELSE 1
END
WHERE pin_state IS NULL;
ALTER TABLE checkpoint_packages ALTER COLUMN pin_state SET DEFAULT 1;
ALTER TABLE checkpoint_packages ALTER COLUMN pin_state SET NOT NULL;
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_state_range;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_state_range CHECK (state >= 1 AND state <= 2);
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_pin_state_range;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_pin_state_range CHECK (pin_state >= 1 AND pin_state <= 4);
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_pin_attempts_nonneg;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_pin_attempts_nonneg CHECK (pin_attempts >= 0);
ALTER TABLE checkpoint_packages DROP CONSTRAINT IF EXISTS checkpoint_emitted_requires_emitted_state;
ALTER TABLE checkpoint_packages ADD CONSTRAINT checkpoint_emitted_requires_emitted_state CHECK (emitted_at IS NULL OR state = 2);

CREATE INDEX IF NOT EXISTS checkpoint_packages_height_idx ON checkpoint_packages (checkpoint_height DESC);
CREATE INDEX IF NOT EXISTS checkpoint_packages_state_idx ON checkpoint_packages (state, persisted_at ASC);
CREATE INDEX IF NOT EXISTS checkpoint_packages_pin_idx ON checkpoint_packages (pin_state, pin_next_attempt_at ASC, persisted_at ASC);

CREATE TABLE IF NOT EXISTS checkpoint_signer_commitments (
	base_chain_id BIGINT NOT NULL,
	bridge_contract BYTEA NOT NULL,
	operator BYTEA NOT NULL,
	checkpoint_height BIGINT NOT NULL,
	digest BYTEA NOT NULL,
	signed_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	PRIMARY KEY (base_chain_id, bridge_contract, operator, checkpoint_height),
	CONSTRAINT checkpoint_commitment_bridge_len CHECK (octet_length(bridge_contract) = 20),
	CONSTRAINT checkpoint_commitment_operator_len CHECK (octet_length(operator) = 20),
	CONSTRAINT checkpoint_commitment_digest_len CHECK (octet_length(digest) = 32),
	CONSTRAINT checkpoint_commitment_base_chain_id_nonneg CHECK (base_chain_id >= 0),
	CONSTRAINT checkpoint_commitment_height_nonneg CHECK (checkpoint_height >= 0)
);
`
