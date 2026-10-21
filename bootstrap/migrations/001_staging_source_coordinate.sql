-- Adds the structured OOD Graph source coordinate carried from
-- spec_graph_staging_load through spec_graph_staging_promote.
--
-- Existing databases created before this column landed require this DDL
-- before deploying the corresponding binary. Fresh databases receive the
-- column from bootstrap/schema_v2.sql and must not apply this migration.

ALTER TABLE staging_concepts ADD COLUMN source_coordinate JSON;
