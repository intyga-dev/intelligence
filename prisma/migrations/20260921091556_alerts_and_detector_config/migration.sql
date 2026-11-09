-- CreateEnum
CREATE TYPE "AlertChannel" AS ENUM ('webhook', 'slack', 'email');

-- CreateTable
CREATE TABLE "AlertRule" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "minSeverity" "Severity" NOT NULL DEFAULT 'high',
    "categories" "Category"[] DEFAULT ARRAY[]::"Category"[],
    "channel" "AlertChannel" NOT NULL,
    "targetCipher" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "cooldownMinutes" INTEGER NOT NULL DEFAULT 60,
    "lastFiredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AlertRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectorConfig" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "detector" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "settings" JSONB NOT NULL DEFAULT '{}',
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectorConfig_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AlertRule_tenantId_active_idx" ON "AlertRule"("tenantId", "active");

-- CreateIndex
CREATE UNIQUE INDEX "DetectorConfig_tenantId_detector_key" ON "DetectorConfig"("tenantId", "detector");

-- AddForeignKey
ALTER TABLE "AlertRule" ADD CONSTRAINT "AlertRule_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DetectorConfig" ADD CONSTRAINT "DetectorConfig_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
