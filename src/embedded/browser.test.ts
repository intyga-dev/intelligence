import assert from "node:assert/strict"
import { test } from "node:test"
import { createContext, runInContext } from "node:vm"
import { EMBEDDED_BROWSER_JS } from "./browser.ts"

for (const userHandle of [null, new ArrayBuffer(0), new Uint8Array([251, 255]).buffer]) {
  test(`passkey assertions serialize ${userHandle === null ? "missing" : userHandle.byteLength === 0 ? "empty" : "present"} user handles for the gateway`, async () => {
    const bytes = new Uint8Array([251, 255]).buffer
    const context = createContext({
      Uint8Array,
      atob,
      btoa,
      navigator: {
        credentials: {
          get: async () => ({
            id: "-_8",
            rawId: bytes,
            type: "public-key",
            response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes, userHandle },
            getClientExtensionResults: () => ({}),
          }),
        },
      },
    })
    runInContext(EMBEDDED_BROWSER_JS, context)
    const result = JSON.parse(
      JSON.stringify(await runInContext('embeddedPasskey({challenge:"-_8"},false)', context)),
    )
    assert.deepEqual(result, {
      id: "-_8",
      rawId: "-_8",
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: "-_8",
        authenticatorData: "-_8",
        signature: "-_8",
        ...(userHandle?.byteLength ? { userHandle: "-_8" } : {}),
      },
    })
  })
}
