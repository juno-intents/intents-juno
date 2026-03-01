package alerts

const schemaSQL = `
CREATE TABLE IF NOT EXISTS backoffice_alerts (
    id             BIGSERIAL    PRIMARY KEY,
    rule_id        TEXT         NOT NULL,
    severity       TEXT         NOT NULL DEFAULT 'warning',
    title          TEXT         NOT NULL,
    detail         TEXT,
    fired_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_backoffice_alerts_active
    ON backoffice_alerts (rule_id) WHERE resolved_at IS NULL;
`
