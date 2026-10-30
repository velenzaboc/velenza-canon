# Schema-v2 additive migrations

These files are for an already-initialized experimental OODGraph schema only.
Apply each applicable migration once, in numeric order, through the authorized
Spanner DDL operator; `spec_graph init` consumes `bootstrap/schema_v2.sql` for
a fresh database and must not replay these files.

`003_ood_graph_api_role_locator.sql` is required before a binary that reads or
writes the API-role columns starts against an existing schema-v2 database. The
startup schema probe refuses the substrate with `ErrSchemaNotApplied` while
either column is absent, rather than allowing a later write/read failure.

The columns do not authorize API-role graph materialization. That remains
refused until the OOD8 owner supplies graph-fact-locator, relationship-evidence,
receipt, and completeness-certificate verification.
