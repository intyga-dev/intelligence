import crypto from "node:crypto"
import {
  canonicalIntentPayload,
  type ApprovalReceipt,
  type TrustAnchorFile,
  verificationCode,
} from "@intyga/sdk"
import Fastify from "fastify"
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from "jose"

// Local protocol peer. Tests exercise the installed SDK and real JWT/receipt verification;
// only the remote gateway and human signer are replaced.
export const WORKSPACE = "workspace-test"
export const CLIENT_ID = "oidc_test"
export const ORIGIN = "http://localhost:4100"
const signer = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const signerDid = "did:intyga:test-approver"
export const anchor: TrustAnchorFile = {
  type: "intyga-trust-anchor",
  v: 1,
  purpose: "online",
  epoch: 1,
  tenantId: WORKSPACE,
  approvers: [{ did: signerDid, publicKeys: [publicKey] }],
  webauthn: { origin: "https://console.example.test", rpId: "console.example.test" },
}
export interface Action {
  target: string
  actionType: string
  params: Record<string, unknown>
}
export function signedReceipt(nonce: string, action: Action): ApprovalReceipt {
  const requester = { did: "did:intyga:test-service", attestation: null }
  const canonicalPayload = canonicalIntentPayload({
    ...action,
    tenantId: WORKSPACE,
    display: "Approve the test action",
    requester,
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: false,
      signerClass: "human",
    },
    nonce,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  })
  return {
    ...action,
    canonicalPayload,
    actionDescription: "Approve the test action",
    requester,
    signerDid,
    signerPublicKey: publicKey,
    sigAlg: "ES256",
    signature: crypto
      .sign("sha256", Buffer.from(canonicalPayload), { key: signer.privateKey, dsaEncoding: "ieee-p1363" })
      .toString("base64"),
    verificationCode: verificationCode(canonicalPayload),
  }
}

export async function stubGateway() {
  const keys = await generateKeyPair("RS256")
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: "test-key", alg: "RS256", use: "sig" }
  const app = Fastify()
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) =>
    done(null, new URLSearchParams(String(body))),
  )
  const state = {
    claims: {} as JWTPayload,
    tokenStatus: 200,
    statusCode: 200,
    status: "PENDING",
    receipt: undefined as unknown,
    consumeOk: true,
    consumeCalls: [] as unknown[],
    authorizeCalls: [] as Action[],
    tokenCalls: [] as URLSearchParams[],
    requests: [] as string[],
    nonce: "approval-test-nonce",
    embeddedRole: "MEMBER",
    embeddedCredentialId: "embedded-test-credential",
  }
  app.addHook("onRequest", async (req) => {
    state.requests.push(req.url)
  })
  let baseUrl = ""
  app.get("/oauth/jwks", async () => ({ keys: [jwk] }))
  app.post("/oauth/token", async (req, reply) => {
    if (state.tokenStatus !== 200) return reply.code(state.tokenStatus).send({ error: "refused" })
    if (req.headers.authorization) return { access_token: "service-test-token", expires_in: 900 }
    state.tokenCalls.push(req.body as URLSearchParams)
    return {
      id_token: await new SignJWT(state.claims)
        .setProtectedHeader({ alg: "RS256", kid: "test-key" })
        .sign(keys.privateKey),
    }
  })
  app.post("/authorize", async (req) => {
    state.authorizeCalls.push(req.body as Action)
    return { nonce: state.nonce }
  })
  app.get("/authorize/:nonce", async (_req, reply) =>
    reply.code(state.statusCode).send({ status: state.status, receipt: state.receipt }),
  )
  app.post("/authorize/verify", async (req, reply) => {
    state.consumeCalls.push(req.body)
    return reply
      .code(state.consumeOk ? 200 : 409)
      .send({ ok: state.consumeOk, reason: state.consumeOk ? undefined : "already consumed" })
  })
  app.post("/embedded/applications/:applicationId/approval-member", async () => ({
    members: [
      {
        sub: "123e4567-e89b-42d3-a456-426614174001",
        membershipId: "123e4567-e89b-42d3-a456-426614174002",
        role: state.embeddedRole,
        email: "member@example.test",
        name: "Workspace member",
        did: signerDid,
        credentialId: state.embeddedCredentialId,
      },
    ],
  }))
  baseUrl = await app.listen({ port: 0, host: "127.0.0.1" })
  function reset() {
    state.claims = {
      sub: "person-test",
      email: "ADMIN@example.test",
      name: "Test Admin",
      tenant_id: WORKSPACE,
      role: "ADMIN",
      iss: baseUrl,
      aud: CLIENT_ID,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
    }
    state.tokenStatus = 200
    state.statusCode = 200
    state.status = "PENDING"
    state.receipt = undefined
    state.consumeOk = true
    state.consumeCalls = []
    state.authorizeCalls = []
    state.tokenCalls = []
    state.requests = []
    state.nonce = crypto.randomUUID()
  }
  reset()
  return {
    app,
    state,
    baseUrl,
    reset,
    binding: { baseUrl, clientId: CLIENT_ID, workspaceId: WORKSPACE },
    config: {
      baseUrl,
      consoleUrl: anchor.webauthn?.origin ?? "",
      workspaceId: WORKSPACE,
      serviceClientId: "service-test",
      serviceSecret: "test-secret",
      trustAnchor: anchor,
    },
  }
}
