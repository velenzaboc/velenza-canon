-- Adds the immutable API-element role and evidence-locator root fields to an
-- existing schema_v2 OODGraphObjects table. These fields are not an admission
-- path: the current runtime refuses API-role materialization until the OOD8
-- graph-fact-locator and relationship-evidence verifier is available.
--
-- Existing databases created before this column pair landed require this DDL
-- before deploying the corresponding binary. Fresh databases receive the
-- columns and index from bootstrap/schema_v2.sql and must not apply this
-- migration. Do not run this file through spec_graph init.

ALTER TABLE OODGraphObjects ADD COLUMN api_element_role STRING(64);
ALTER TABLE OODGraphObjects ADD COLUMN api_element_role_locator_manifest_hash STRING(64);

CREATE NULL_FILTERED INDEX OODGraphObjectsByApiRoleLocatorManifest
  ON OODGraphObjects (organization_id, api_element_role_locator_manifest_hash, graph_object_id)
  WHERE api_element_role_locator_manifest_hash IS NOT NULL;
