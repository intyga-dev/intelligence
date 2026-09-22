import crypto from "node:crypto"
import { config } from "../config.ts"

// AES-256-GCM for per-connection secrets at rest.
//
// What is stored here is a webhook SIGNING key — it verifies inbound requests and cannot call
// anything. It is still encrypted, because a read of this table should not hand someone the ability
// to forge a feed into the detectors and manufacture findings.
//
// Format: v1.<iv-b64>.<tag-b64>.<ciphertext-b64>. Versioned so the scheme can be rotated without
// guessing at what an old row was encrypted with.

const VERSION = "v1"
const IV_BYTES = 12

/** 32 bytes from the configured key. A short dev placeholder is padded; production rejects those. */
function keyBytes(): Buffer {
  const raw = config.secretsEncKey
  // A base64 32-byte key is the intended production shape; anything else is hashed to length so a
  // dev value still works rather than crashing with a cipher-level error nobody can read.
  const decoded = Buffer.from(raw, "base64")
  if (decoded.length === 32) return decoded
  return crypto.createHash("sha256").update(raw).digest()
}

export function encryptSecret(plaintext: string): string {
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBytes(), iv)
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return [VERSION, iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(".")
}

/** Returns null rather than throwing: an undecryptable row is an operational fact to handle. */
export function decryptSecret(stored: string): string | null {
  try {
    const [version, ivB64, tagB64, ctB64] = stored.split(".")
    if (version !== VERSION || !ivB64 || !tagB64 || !ctB64) return null
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes(), Buffer.from(ivB64, "base64"))
    decipher.setAuthTag(Buffer.from(tagB64, "base64"))
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64")), decipher.final()]).toString("utf8")
  } catch {
    // Wrong key, tampered ciphertext, or a row from a previous scheme. All three mean "cannot use".
    return null
  }
}
