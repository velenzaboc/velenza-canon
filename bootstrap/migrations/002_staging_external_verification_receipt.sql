-- Adds the process-minted external byte/locator receipt carried from
-- spec_graph_staging_load through no-refetch spec_graph_staging_promote.
--
-- Existing databases created before this column landed require this DDL
-- before deploying the corresponding binary. Fresh databases receive the
-- column from bootstrap/schema_v2.sql and must not apply this migration.

ALTER TABLE staging_concepts ADD COLUMN source_verification_receipt JSON;
