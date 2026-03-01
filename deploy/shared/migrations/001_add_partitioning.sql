-- Migration 001: Convert proof_events to a range-partitioned table
--
-- Context
-- -------
-- New deployments get a partitioned proof_events table directly from
-- EnsureSchema() in internal/proof/postgres/schema.go.  This script
-- exists only for EXISTING deployments that already have a
-- non-partitioned proof_events table.
--
-- PostgreSQL does not support ALTER TABLE ... SET PARTITION BY, so we
-- must swap the table:
--   1. Rename the old table
--   2. Create a new partitioned table with the same schema
--   3. Create a default partition (catches rows outside any daily range)
--   4. Copy data from the old table
--   5. Reset the sequence so new event_id values don't collide
--   6. Drop the old table (commented out -- uncomment after verification)
--
-- Requirements
-- -----------
-- * PostgreSQL 12+ (FK from partitioned table to non-partitioned parent)
-- * proof_jobs table must already exist (FK target)
-- * Run during a maintenance window -- the table is unavailable between
--   the RENAME and the end of the INSERT...SELECT
-- * Verify row counts match before uncommenting the DROP TABLE
--
-- After this migration, use the partition manager
-- (internal/partitions.Manager) to create daily partitions ahead of
-- time and to clean up old partitions beyond the retention window.

BEGIN;

-- Step 1: Rename the existing non-partitioned table.
-- If proof_events does not exist (fresh deploy), this is a no-op via
-- IF EXISTS.
ALTER TABLE IF EXISTS proof_events RENAME TO proof_events_old;

-- Also rename the old index so it does not conflict.
ALTER INDEX IF EXISTS proof_events_job_created_idx RENAME TO proof_events_old_job_created_idx;
ALTER INDEX IF EXISTS proof_events_pkey RENAME TO proof_events_old_pkey;

-- Step 2: Create the new partitioned table with the same columns.
-- The PRIMARY KEY must include the partition key (created_at).
CREATE TABLE IF NOT EXISTS proof_events (
    event_id    BIGSERIAL,
    job_id      BYTEA NOT NULL REFERENCES proof_jobs(job_id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, created_at),
    CONSTRAINT proof_events_job_id_len CHECK (octet_length(job_id) = 32),
    CONSTRAINT proof_events_type_nonempty CHECK (event_type <> '')
) PARTITION BY RANGE (created_at);

-- Step 3: Create a default partition so that rows not matching any
-- daily partition are still accepted.
CREATE TABLE IF NOT EXISTS proof_events_default PARTITION OF proof_events DEFAULT;

-- Step 4: Re-create the composite index on the partitioned table.
CREATE INDEX IF NOT EXISTS proof_events_job_created_idx
    ON proof_events (job_id, created_at);

-- Step 5: Copy all existing data.
-- The old table may be empty on a fresh deploy; that is fine.
INSERT INTO proof_events (event_id, job_id, event_type, payload, created_at)
SELECT event_id, job_id, event_type, payload, created_at
FROM proof_events_old;

-- Step 6: Reset the sequence so new event_id values pick up where the
-- old data left off.  COALESCE handles empty tables.
SELECT setval(
    'proof_events_event_id_seq',
    (SELECT COALESCE(MAX(event_id), 0) FROM proof_events)
);

COMMIT;

-- Step 7: Drop the old table AFTER verifying the migration.
-- Run these checks first:
--
--   SELECT count(*) FROM proof_events;
--   SELECT count(*) FROM proof_events_old;
--   -- Both counts should match.
--
-- Then uncomment and execute:
-- DROP TABLE proof_events_old;
