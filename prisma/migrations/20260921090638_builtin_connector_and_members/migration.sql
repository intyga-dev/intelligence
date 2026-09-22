-- AlterTable
ALTER TABLE "Connection" ADD COLUMN     "activatedAt" TIMESTAMP(3),
ADD COLUMN     "activationReceipt" TEXT,
ADD COLUMN     "builtIn" BOOLEAN NOT NULL DEFAULT false,
ALTER COLUMN "active" SET DEFAULT false;

-- CreateTable
CREATE TABLE "Member" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "externalId" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "enrolledAt" TIMESTAMP(3),
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Member_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Member_tenantId_active_idx" ON "Member"("tenantId", "active");

-- CreateIndex
CREATE UNIQUE INDEX "Member_tenantId_externalId_key" ON "Member"("tenantId", "externalId");

-- AddForeignKey
ALTER TABLE "Member" ADD CONSTRAINT "Member_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
