-- Connector kind becomes free text, resolved against the in-code registry.
--
-- Prisma's generated version DROPPED both columns and re-added them, which would have discarded
-- every connection and every event's provenance. An enum-to-text change is loss-free with an
-- explicit USING cast, so that is what this does: the column is converted in place and the values
-- survive. Written by hand for exactly that reason — see the generated diff in git history.

ALTER TABLE "Connection"
  ALTER COLUMN "kind" TYPE TEXT USING "kind"::TEXT;

ALTER TABLE "Event"
  ALTER COLUMN "source" TYPE TEXT USING "source"::TEXT;

DROP TYPE "SourceKind";

-- The index is recreated only if the type change dropped it; IF NOT EXISTS keeps this idempotent.
CREATE INDEX IF NOT EXISTS "Connection_tenantId_kind_idx" ON "Connection"("tenantId", "kind");
