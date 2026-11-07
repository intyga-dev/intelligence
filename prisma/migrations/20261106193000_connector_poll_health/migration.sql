ALTER TABLE "Connection"
  ADD COLUMN "lastPolledAt" TIMESTAMP(3),
  ADD COLUMN "lastPollSuccessAt" TIMESTAMP(3),
  ADD COLUMN "lastPollError" TEXT;
