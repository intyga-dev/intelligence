import { writeFile } from "node:fs/promises"
import { setTimeout as delay } from "node:timers/promises"
import { pathToFileURL } from "node:url"

export async function scheduledTick(
  url: string,
  token: string,
  fetcher: typeof fetch = fetch,
): Promise<boolean> {
  const response = await fetcher(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(300_000),
    redirect: "error",
  })
  if (!response.ok) return false
  const body = (await response.json()) as { ok?: unknown }
  return body.ok === true
}

async function main(): Promise<void> {
  const target = process.env.TICK_URL
  const token = process.env.TICK_TOKEN
  if (!target || !token) throw new Error("TICK_URL and TICK_TOKEN are required")
  let stopping = false
  const stop = new AbortController()
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => {
      stopping = true
      stop.abort()
    })
  while (!stopping) {
    const start = Date.now()
    try {
      if (await scheduledTick(target, token)) {
        await writeFile("/tmp/intelligence-last-tick", String(Date.now()))
        console.log("Detection tick completed")
      } else console.error("Detection tick refused or unsuccessful; check the app logs")
    } catch {
      // Never log the request or an upstream body: the scheduler holds a bearer token.
      console.error("Detection tick could not complete; retrying on the next interval")
    }
    if (!stopping)
      await delay(Math.max(1000, 60_000 - (Date.now() - start)), undefined, { signal: stop.signal }).catch(
        () => {},
      )
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: Error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
