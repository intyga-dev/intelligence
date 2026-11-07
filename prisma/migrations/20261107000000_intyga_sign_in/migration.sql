-- INTYGA sign-in and SDK approvals (core ADR 030, 7 Nov 2026).
--
-- Intelligence no longer runs on INTYGA's platform plane. Sign-in is OpenID Connect against the
-- bound workspace (its members are Intelligence's users; its ADMINs its administrators), and every
-- privileged action is an ordinary approval through POST /authorize with a SERVICE key, verified
-- against the trust anchor the workspace exported. The platform relying-party binding, the local
-- passkey ceremonies and the invite links therefore go.
--
-- BREAKING for an existing instance: every member row was a platform subject keyed by an opaque
-- id and cannot sign in under the new model, so members are deactivated and sessions and pending
-- approvals are cleared. People reappear, with their workspace role, at their first INTYGA sign-in.
-- Re-connect the workspace (service key, OIDC client id, trust anchor) in Settings afterwards.

ALTER TABLE "Tenant" RENAME COLUMN "intygaOrigin" TO "publicOrigin";
ALTER TABLE "Tenant"
  DROP COLUMN "intygaClientId",
  DROP COLUMN "intygaKeyCipher",
  DROP COLUMN "intygaRpId",
  ADD COLUMN "intygaConsoleUrl" TEXT,
  ADD COLUMN "intygaWorkspaceId" TEXT,
  ADD COLUMN "intygaOidcClientId" TEXT,
  ADD COLUMN "intygaServiceClientId" TEXT,
  ADD COLUMN "intygaServiceSecretCipher" TEXT,
  ADD COLUMN "intygaTrustAnchor" JSONB,
  ADD COLUMN "intygaTrustAnchorAt" TIMESTAMP(3);

DELETE FROM "Session";
DELETE FROM "PendingAction";
UPDATE "Member" SET "active" = false;

ALTER TABLE "Member"
  DROP COLUMN "enrolledAt",
  ADD COLUMN "role" TEXT NOT NULL DEFAULT 'MEMBER',
  ADD COLUMN "lastLoginAt" TIMESTAMP(3);

ALTER TABLE "PendingAction"
  DROP COLUMN "payloadHash",
  ADD COLUMN "target" TEXT NOT NULL,
  ADD COLUMN "approveUrl" TEXT NOT NULL;

DROP TABLE "MemberInvite";
DROP TABLE "AuthCeremony";
