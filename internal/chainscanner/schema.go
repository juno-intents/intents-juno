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

CREATE TABLE IF NOT EXISTS event_scanner_pending_withdraw_events (
	service_name     TEXT NOT NULL,
	withdrawal_id    BYTEA NOT NULL,
	requester        BYTEA NOT NULL,
	amount_decimal   TEXT NOT NULL,
	recipient_ua     BYTEA NOT NULL,
	expiry           BIGINT NOT NULL,
	fee_bps          BIGINT NOT NULL,
	block_number     BIGINT NOT NULL,
	block_hash       BYTEA NOT NULL,
	tx_hash          BYTEA NOT NULL,
	log_index        BIGINT NOT NULL,
	finality_source  TEXT NOT NULL,
	staged_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (service_name, tx_hash, log_index)
);
`
