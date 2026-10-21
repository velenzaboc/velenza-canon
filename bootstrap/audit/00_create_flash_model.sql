-- bootstrap/audit/00_create_flash_model.sql
--
-- One-time DDL: register Gemini 2.5 Flash as a Spanner remote model on the
-- doc-graph database so audit recipes can invoke it via ML.PREDICT instead
-- of extracting graph state into local files and looping a CLI over it.
--
-- This is the substrate-side compute path Vision Principle 7
-- (binary_is_never_sot) + Principle 12 (matryoshka mandate / discovery-
-- before-creation) prescribe: don't pull data out to compute on it; push
-- the compute (Flash call) to where the data lives (Spanner).
--
-- The model expects one INPUT column `prompt STRING(MAX)` and returns one
-- OUTPUT column `content STRING(MAX)` carrying the generated text directly
-- (GoogleSQL flavor). For Gemini, `default_batch_size = 1` matches the
-- generative model's no-batch contract.
--
-- Same-project (example-gcp-project → Vertex AI in example-gcp-project) requires no
-- extra IAM grants: Spanner grants the appropriate permissions automatically
-- when the database and the Vertex AI endpoint live in the same project.
--
-- Apply once via:
--
--   gcloud spanner databases ddl update doc-graph \
--     --instance=example-spanner-instance \
--     --project=example-gcp-project \
--     --ddl-file=bootstrap/audit/00_create_flash_model.sql
--
-- Re-application is rejected by Spanner if the model already exists; that
-- is the intended behavior — this DDL declares end-state, not migration.

CREATE MODEL r6_flash
  INPUT (prompt STRING(MAX))
  OUTPUT (content STRING(MAX))
  REMOTE
  OPTIONS (
    endpoint = '//aiplatform.googleapis.com/projects/example-gcp-project/locations/us-central1/publishers/google/models/gemini-2.5-flash',
    default_batch_size = 1
  );
