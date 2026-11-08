ALTER TABLE "Connection" ADD COLUMN "removedAt" TIMESTAMP(3);
ALTER TABLE "PendingAction" ADD COLUMN "secretCiphertext" TEXT;
