-- Enrolment is gated by an admin-issued, single-use invite instead of by "a member with this
-- externalId exists". The id is not a secret, so the old check let anyone bind their own passkey to
-- any administrator. See the MemberInvite comment in schema.prisma.
--
-- No backfill. Members who have not enrolled yet need a fresh invite (scripts/invite-member.ts);
-- enrolment ceremonies in flight at deploy time have no inviteId and will be refused on completion,
-- which is the intended outcome for a ceremony started under the old rule.

-- AlterTable
ALTER TABLE "AuthCeremony" ADD COLUMN     "inviteId" UUID;

-- CreateTable
CREATE TABLE "MemberInvite" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "tenantId" UUID NOT NULL,
    "memberId" UUID NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "MemberInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "MemberInvite_tokenHash_key" ON "MemberInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "MemberInvite_memberId_consumedAt_idx" ON "MemberInvite"("memberId", "consumedAt");

-- CreateIndex
CREATE INDEX "MemberInvite_expiresAt_idx" ON "MemberInvite"("expiresAt");

-- CreateIndex
CREATE INDEX "AuthCeremony_inviteId_idx" ON "AuthCeremony"("inviteId");

-- AddForeignKey
ALTER TABLE "MemberInvite" ADD CONSTRAINT "MemberInvite_memberId_fkey" FOREIGN KEY ("memberId") REFERENCES "Member"("id") ON DELETE CASCADE ON UPDATE CASCADE;

