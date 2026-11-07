-- Connection authority now lives in deployment configuration. Expire the old binding's state.
DELETE FROM "Session";
DELETE FROM "PendingAction";
UPDATE "Member" SET active = false;
ALTER TABLE "Session" ADD COLUMN "bindingId" TEXT NOT NULL;
ALTER TABLE "PendingAction" ADD COLUMN "bindingId" TEXT NOT NULL;
ALTER TABLE "Tenant"
  DROP COLUMN "intygaBaseUrl",
  DROP COLUMN "intygaConsoleUrl",
  DROP COLUMN "intygaWorkspaceId",
  DROP COLUMN "intygaOidcClientId",
  DROP COLUMN "intygaServiceClientId",
  DROP COLUMN "intygaServiceSecretCipher",
  DROP COLUMN "intygaTrustAnchor",
  DROP COLUMN "intygaTrustAnchorAt",
  DROP COLUMN "publicOrigin";
