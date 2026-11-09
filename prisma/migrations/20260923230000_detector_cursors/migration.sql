-- Read marks for the event-driven detectors (sensitive code change, deploy regression), so each
-- event is folded into a finding once rather than on every tick. No backfill: a missing row means
-- "scan the lookback window", which is what a first run should do.

-- CreateTable
CREATE TABLE "DetectorCursor" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "detector" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectorCursor_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DetectorCursor_tenantId_detector_key" ON "DetectorCursor"("tenantId", "detector");

-- AddForeignKey
ALTER TABLE "DetectorCursor" ADD CONSTRAINT "DetectorCursor_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

