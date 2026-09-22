// RFC 8785 JSON Canonicalization Scheme.
//
// Needed because the digest we hand Intyga must be reproducible by anyone re-deriving it from the
// same object. Two spellings of one payload would be two different digests, and the whole gate
// rests on "the human signed THIS action" — so the serialization has to be canonical, not merely
// deterministic-in-practice.
//
// Implemented here rather than depended upon: it is about forty lines, it is the input to a
// security decision, and the alternative is trusting a transitive dependency with the one function
// whose correctness the gate's meaning depends on.

/** JSON string escaping per RFC 8785 §3.2.2.2 — shortest form, lowercase \uXXXX for controls. */
function escapeString(s: string): string {
  let out = '"'
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0
    switch (ch) {
      case '"':
        out += '\\"'
        break
      case "\\":
        out += "\\\\"
        break
      case "\b":
        out += "\\b"
        break
      case "\f":
        out += "\\f"
        break
      case "\n":
        out += "\\n"
        break
      case "\r":
        out += "\\r"
        break
      case "\t":
        out += "\\t"
        break
      default:
        out += c < 0x20 ? `\\u${c.toString(16).padStart(4, "0")}` : ch
    }
  }
  return `${out}"`
}

/**
 * RFC 8785 §3.2.2.3: numbers serialize as ECMAScript `Number::toString`, which is what JSON.stringify
 * already does. Non-finite values have no JSON representation and are refused rather than silently
 * becoming null — a null where a number was meant is a different signed payload.
 */
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new TypeError(`cannot canonicalize non-finite number: ${n}`)
  // -0 serializes as "0": RFC 8785 requires the ES Number::toString result, and that is "0".
  if (Object.is(n, -0)) return "0"
  return JSON.stringify(n)
}

/**
 * Canonicalize a JSON value.
 *
 * Object keys are sorted by UTF-16 code unit, which is what `Array.prototype.sort` does by default
 * and what RFC 8785 §3.2.3 specifies. `undefined` properties are dropped exactly as JSON.stringify
 * drops them, so an optional field that is absent and one that is explicitly undefined produce the
 * same bytes — which is the behaviour a caller building a params object expects.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null"

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false"
    case "number":
      return serializeNumber(value)
    case "string":
      return escapeString(value)
    case "object":
      break
    default:
      throw new TypeError(`cannot canonicalize ${typeof value}`)
  }

  if (Array.isArray(value)) {
    // Array order is significant and preserved; an undefined element becomes null, as in JSON.
    return `[${value.map((v) => (v === undefined ? "null" : canonicalize(v))).join(",")}]`
  }

  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
  return `{${keys.map((k) => `${escapeString(k)}:${canonicalize(obj[k])}`).join(",")}}`
}
