-- CreateEnum
CREATE TYPE "SourceKind" AS ENUM ('intyga', 'github');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- CreateEnum
CREATE TYPE "Category" AS ENUM ('security', 'engineering', 'product', 'customer', 'business');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('new', 'investigating', 'resolved', 'dismissed');

-- CreateEnum
CREATE TYPE "JudgmentStatus" AS ENUM ('PENDING', 'SENDING', 'DONE', 'FAILED', 'EXHAUSTED');

-- CreateEnum
CREATE TYPE "Verdict" AS ENUM ('useful', 'not_useful', 'investigating', 'expected', 'false_positive', 'fixed');

-- CreateTable
CREATE TABLE "Tenant" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Connection" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "kind" "SourceKind" NOT NULL,
    "label" TEXT NOT NULL,
    "config" JSONB NOT NULL DEFAULT '{}',
    "secretCiphertext" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Connection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RawEvent" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "connectionId" UUID NOT NULL,
    "sourceId" TEXT NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "body" JSONB NOT NULL,
    "normalizedAt" TIMESTAMP(3),
    "normalizeError" TEXT,

    CONSTRAINT "RawEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Event" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "source" "SourceKind" NOT NULL,
    "sourceId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "subjectRef" TEXT,
    "correlationRef" TEXT,
    "attrs" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Deployment" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "repo" TEXT NOT NULL,
    "runId" TEXT NOT NULL,
    "workflow" TEXT NOT NULL,
    "environment" TEXT NOT NULL,
    "sha" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "conclusion" TEXT NOT NULL,

    CONSTRAINT "Deployment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CodeChange" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "repo" TEXT NOT NULL,
    "number" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "headSha" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "mergedAt" TIMESTAMP(3),
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "paths" JSONB NOT NULL DEFAULT '[]',
    "additions" INTEGER NOT NULL DEFAULT 0,
    "deletions" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "CodeChange_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "category" "Category" NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "summary" TEXT,
    "confidence" DOUBLE PRECISION,
    "detectedAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 1,
    "status" "FindingStatus" NOT NULL DEFAULT 'new',
    "dedupeKey" TEXT NOT NULL,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Evidence" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "findingId" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "ordinal" INTEGER NOT NULL,
    "data" JSONB NOT NULL,

    CONSTRAINT "Evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "JudgmentRequest" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "findingId" UUID NOT NULL,
    "questionSet" TEXT NOT NULL,
    "status" "JudgmentStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastError" TEXT,
    "sentState" JSONB,
    "stateDigest" TEXT,
    "response" JSONB,
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "JudgmentRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingFeedback" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "findingId" UUID NOT NULL,
    "actor" TEXT NOT NULL,
    "verdict" "Verdict" NOT NULL,
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingFeedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SourceCursor" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "connectionId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SourceCursor_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");

-- CreateIndex
CREATE INDEX "Connection_tenantId_kind_idx" ON "Connection"("tenantId", "kind");

-- CreateIndex
CREATE INDEX "RawEvent_connectionId_receivedAt_idx" ON "RawEvent"("connectionId", "receivedAt");

-- CreateIndex
CREATE INDEX "RawEvent_normalizedAt_idx" ON "RawEvent"("normalizedAt");

-- CreateIndex
CREATE UNIQUE INDEX "RawEvent_connectionId_sourceId_key" ON "RawEvent"("connectionId", "sourceId");

-- CreateIndex
CREATE INDEX "Event_connectionId_subjectRef_kind_at_idx" ON "Event"("connectionId", "subjectRef", "kind", "at");

-- CreateIndex
CREATE INDEX "Event_tenantId_kind_at_idx" ON "Event"("tenantId", "kind", "at");

-- CreateIndex
CREATE INDEX "Event_tenantId_at_idx" ON "Event"("tenantId", "at");

-- CreateIndex
CREATE INDEX "Event_correlationRef_idx" ON "Event"("correlationRef");

-- CreateIndex
CREATE UNIQUE INDEX "Event_connectionId_sourceId_key" ON "Event"("connectionId", "sourceId");

-- CreateIndex
CREATE INDEX "Deployment_tenantId_at_idx" ON "Deployment"("tenantId", "at");

-- CreateIndex
CREATE INDEX "Deployment_tenantId_environment_at_idx" ON "Deployment"("tenantId", "environment", "at");

-- CreateIndex
CREATE INDEX "Deployment_sha_idx" ON "Deployment"("sha");

-- CreateIndex
CREATE UNIQUE INDEX "Deployment_connectionId_runId_key" ON "Deployment"("connectionId", "runId");

-- CreateIndex
CREATE INDEX "CodeChange_tenantId_observedAt_idx" ON "CodeChange"("tenantId", "observedAt");

-- CreateIndex
CREATE INDEX "CodeChange_headSha_idx" ON "CodeChange"("headSha");

-- CreateIndex
CREATE UNIQUE INDEX "CodeChange_connectionId_repo_number_headSha_key" ON "CodeChange"("connectionId", "repo", "number", "headSha");

-- CreateIndex
CREATE INDEX "Finding_tenantId_status_severity_lastSeenAt_idx" ON "Finding"("tenantId", "status", "severity", "lastSeenAt");

-- CreateIndex
CREATE INDEX "Finding_tenantId_detectedAt_idx" ON "Finding"("tenantId", "detectedAt");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_tenantId_dedupeKey_key" ON "Finding"("tenantId", "dedupeKey");

-- CreateIndex
CREATE INDEX "Evidence_findingId_ordinal_idx" ON "Evidence"("findingId", "ordinal");

-- CreateIndex
CREATE INDEX "JudgmentRequest_status_nextAttemptAt_idx" ON "JudgmentRequest"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "JudgmentRequest_findingId_idx" ON "JudgmentRequest"("findingId");

-- CreateIndex
CREATE INDEX "FindingFeedback_findingId_createdAt_idx" ON "FindingFeedback"("findingId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SourceCursor_connectionId_name_key" ON "SourceCursor"("connectionId", "name");

-- AddForeignKey
ALTER TABLE "Connection" ADD CONSTRAINT "Connection_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RawEvent" ADD CONSTRAINT "RawEvent_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "Connection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "Connection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Deployment" ADD CONSTRAINT "Deployment_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Deployment" ADD CONSTRAINT "Deployment_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "Connection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CodeChange" ADD CONSTRAINT "CodeChange_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CodeChange" ADD CONSTRAINT "CodeChange_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "Connection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "JudgmentRequest" ADD CONSTRAINT "JudgmentRequest_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingFeedback" ADD CONSTRAINT "FindingFeedback_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SourceCursor" ADD CONSTRAINT "SourceCursor_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "Connection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
