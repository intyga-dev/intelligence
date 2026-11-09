-- Alert rules start delivering findings to their destination. Until now nothing read them, so a rule
-- marked active had never sent anything. Turning one on is now a signed action, because that is the
-- moment finding data starts leaving the host (the same rule connectors follow).
--
-- Backfill: every existing rule is switched OFF. None was ever activated by a signature, and none
-- has a signing secret or a recorded destination host, so none can be delivered as-is — recreate
-- them from /alerts. `targetHost` is '' for these rows because the destination is only stored
-- encrypted and cannot be parsed in SQL.

-- AlterTable
ALTER TABLE "AlertRule" ADD COLUMN     "activatedAt" TIMESTAMP(3),
ADD COLUMN     "activationReceipt" TEXT,
ADD COLUMN     "lastAttemptAt" TIMESTAMP(3),
ADD COLUMN     "lastError" TEXT,
ADD COLUMN     "signingSecretCipher" TEXT,
ADD COLUMN     "targetHost" TEXT NOT NULL DEFAULT '',
ALTER COLUMN "active" SET DEFAULT false;


UPDATE "AlertRule" SET "active" = false;
