package chainscanner

const schemaSQL = `
CREATE TABLE IF NOT EXISTS event_scanner_state (
	service_name          TEXT PRIMARY KEY,
	last_processed_height BIGINT NOT NULL,
	last_processed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS event_scanner_block_refs (
	service_name TEXT NOT NULL,
	height       BIGINT NOT NULL,
	block_hash   BYTEA NOT NULL,
	parent_hash  BYTEA NOT NULL,
	processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (service_name, height)
);
`
