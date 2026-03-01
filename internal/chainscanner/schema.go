package chainscanner

const schemaSQL = `
CREATE TABLE IF NOT EXISTS event_scanner_state (
	service_name          TEXT PRIMARY KEY,
	last_processed_height BIGINT NOT NULL,
	last_processed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
`
