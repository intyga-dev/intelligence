CREATE TABLE "Service" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "tenantId" UUID NOT NULL,
  "name" TEXT NOT NULL,
  "description" TEXT NOT NULL DEFAULT '',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Service_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "Service_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "Service_tenantId_name_key" ON "Service"("tenantId", "name");
ALTER TABLE "Connection" ADD COLUMN "serviceId" UUID REFERENCES "Service"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Event" ADD COLUMN "serviceId" UUID REFERENCES "Service"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Finding" ADD COLUMN "serviceId" UUID REFERENCES "Service"("id") ON DELETE SET NULL ON UPDATE CASCADE;
CREATE INDEX "Event_tenantId_serviceId_at_idx" ON "Event"("tenantId", "serviceId", "at");
CREATE INDEX "Finding_tenantId_serviceId_status_lastSeenAt_idx" ON "Finding"("tenantId", "serviceId", "status", "lastSeenAt");
