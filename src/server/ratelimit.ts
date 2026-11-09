// Cost guards for the unauthenticated surface.
//
// `/ingest/:kind/:connectionId` is internet-facing by definition — a webhook URL is only useful if
// a stranger's server can reach it — and it does real work before it knows whether the caller is
// legitimate: a DB lookup for the connection, an AES decrypt of the stored secret, and an HMAC over
// the body. That is free CPU and free rows for anyone who learns a URL, or invents one.
//
// This is a COST GUARD, not an authentication control. The HMAC is what decides whether a delivery
// is real; the buckets only decide how much it costs us to find out. Two of them, because they
// bound different things:
//
//   · a per-connection bucket bounds one legitimate-but-runaway sender (a retry storm, a replay),
//     and keeps one noisy tenant from consuming the whole instance's headroom
//   · a global ingest bucket bounds the aggregate, including callers whose connection id is
//     invented and therefore has no meaningful key of its own
//
// Deliberately NOT keyed on the client address. Fastify's `trustProxy` is off, so `req.ip` is the
// socket peer — behind any reverse proxy or PaaS router that is the proxy, identically for every
// client, and a per-IP bucket keyed on it is one shared bucket wearing a misleading name. Turning
// `trustProxy` on to fix that would let anyone reaching the origin directly spoof the header and
// so the bucket. The two buckets here are honest about what they actually bound.
//
// In-process, so per-instance. Intelligence is a single-instance self-hosted service; if that ever
// stops being true, these become per-replica allowances rather than a cluster-wide one — which
// degrades the guard, and never the correctness of ingest.

/** One refilling token bucket. */
interface Bucket {
  tokens: number
  updatedAt: number
}

export interface LimiterOptions {
  /** Sustained rate, tokens per minute. */
  ratePerMinute: number
  /** Maximum burst — how many tokens the bucket can hold. */
  burst: number
  /**
   * Cap on distinct keys held.
   *
   * Without it the key map is itself the attack: invented connection ids are unlimited and each one
   * would allocate an entry. At the cap we stop admitting NEW keys and let the global bucket carry
   * them, which is the correct place for traffic we cannot attribute anyway.
   */
  maxKeys: number
}

export interface Limiter {
  /** Spend one token. `false` means the caller is over its allowance. */
  take(key: string): boolean
  /** Seconds until at least one token is available for `key`. For `retry-after`. */
  retryAfter(key: string): number
  /** Test seam: entries currently held. */
  size(): number
}

export function createLimiter(opts: LimiterOptions, now: () => number = Date.now): Limiter {
  const buckets = new Map<string, Bucket>()
  const perMs = opts.ratePerMinute / 60_000

  /** Refill in place and return the bucket, or null when a new key cannot be admitted. */
  function resolve(key: string, admit: boolean): Bucket | null {
    const t = now()
    const existing = buckets.get(key)
    if (existing) {
      const refilled = Math.min(opts.burst, existing.tokens + (t - existing.updatedAt) * perMs)
      existing.tokens = refilled
      existing.updatedAt = t
      return existing
    }
    if (!admit) return null

    // Evict idle keys before admitting a new one. A bucket that has refilled to full has no memory
    // worth keeping — dropping it and re-creating it later is indistinguishable from holding it.
    if (buckets.size >= opts.maxKeys) {
      for (const [k, b] of buckets) {
        if (b.tokens + (t - b.updatedAt) * perMs >= opts.burst) buckets.delete(k)
      }
      if (buckets.size >= opts.maxKeys) return null
    }

    const fresh: Bucket = { tokens: opts.burst, updatedAt: t }
    buckets.set(key, fresh)
    return fresh
  }

  return {
    take(key) {
      const b = resolve(key, true)
      // Unadmittable key: not our decision to make here. The global bucket is what bounds it.
      if (!b) return true
      if (b.tokens < 1) return false
      b.tokens -= 1
      return true
    },
    retryAfter(key) {
      const b = resolve(key, false)
      if (!b || b.tokens >= 1) return 1
      return Math.max(1, Math.ceil((1 - b.tokens) / perMs / 1000))
    },
    size: () => buckets.size,
  }
}
