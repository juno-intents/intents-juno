package postgres

const schemaSQL = `
CREATE TABLE IF NOT EXISTS leases (
	name TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	version BIGINT NOT NULL DEFAULT 1,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE leases ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS leases_expires_at_idx ON leases (expires_at);
`
