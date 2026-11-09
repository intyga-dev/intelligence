-- CreateEnum
CREATE TYPE "PendingActionStatus" AS ENUM ('AWAITING_SIGNATURE', 'APPLIED', 'REFUSED', 'EXPIRED');

-- CreateTable
CREATE TABLE "PendingAction" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "nonce" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "params" JSONB NOT NULL,
    "payloadHash" TEXT NOT NULL,
    "actorExternalId" TEXT NOT NULL,
    "status" "PendingActionStatus" NOT NULL DEFAULT 'AWAITING_SIGNATURE',
    "receiptSeq" INTEGER,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "appliedAt" TIMESTAMP(3),

    CONSTRAINT "PendingAction_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PendingAction_nonce_key" ON "PendingAction"("nonce");

-- CreateIndex
CREATE INDEX "PendingAction_tenantId_status_idx" ON "PendingAction"("tenantId", "status");

-- CreateIndex
CREATE INDEX "PendingAction_expiresAt_idx" ON "PendingAction"("expiresAt");
