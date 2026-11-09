CREATE TABLE "ReviewProvider" (
  "tenantId" UUID NOT NULL REFERENCES "Tenant"("id") ON DELETE CASCADE,
  "provider" TEXT NOT NULL,
  "model" TEXT NOT NULL,
  "secretCiphertext" TEXT,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "dailyRequestLimit" INTEGER NOT NULL DEFAULT 20 CHECK ("dailyRequestLimit" BETWEEN 1 AND 1000),
  "maxOutputTokens" INTEGER NOT NULL DEFAULT 2048 CHECK ("maxOutputTokens" BETWEEN 512 AND 8192),
  "timeoutMs" INTEGER NOT NULL DEFAULT 10000 CHECK ("timeoutMs" BETWEEN 1000 AND 30000),
  PRIMARY KEY ("tenantId", "provider")
);
ALTER TABLE "JudgmentRequest" ADD COLUMN "provider" TEXT NOT NULL DEFAULT 'typesafe';
ALTER TABLE "JudgmentRequest" ADD COLUMN "model" TEXT;
CREATE INDEX "JudgmentRequest_tenantId_provider_createdAt_idx" ON "JudgmentRequest"("tenantId", "provider", "createdAt");
