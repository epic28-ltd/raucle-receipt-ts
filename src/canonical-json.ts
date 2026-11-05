/**
 * Canonical JSON serialisation, matching the Raucle spec v1 §4.3.
 *
 * Requirements (must match Python's
 * ``json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)``):
 *
 * 1. Keys at every depth are sorted lexicographically.
 * 2. Separators are ``,`` and ``:`` with no whitespace.
 * 3. Output is UTF-8 (the caller encodes; this module returns a string).
 * 4. Non-ASCII strings are NOT escaped — they appear as their raw codepoints.
 * 5. Numbers use the minimal lossless representation.
 *
 * JavaScript's ``JSON.stringify`` does not natively support sorted keys or
 * the ``ensure_ascii=False`` semantics; this module implements both.
 */

/**
 * Deterministic code-unit comparator for strings (RFC 8785 / UTF-16 code-unit
 * order). Explicitly given to Array#sort so key ordering never depends on the
 * implicit default-sort behaviour.
 */
export function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) {
    throw new TypeError("canonical JSON cannot encode undefined");
  }
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return canonicalNumber(value as number);
  if (t === "bigint") {
    throw new TypeError("canonical JSON cannot encode bigint");
  }
  if (t === "string") return canonicalString(value as string);
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalize(item)).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(compareStrings);
    const parts: string[] = [];
    for (const key of keys) {
      const v = obj[key];
      if (v === undefined) continue; // matches Python: missing fields are omitted
      parts.push(canonicalString(key) + ":" + canonicalize(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new TypeError(`canonical JSON cannot encode value of type ${t}`);
}

/**
 * Match Python's ``ensure_ascii=False`` behaviour: pass non-ASCII codepoints
 * through unescaped, but still escape the JSON control characters required
 * by RFC 8259.
 */
function canonicalString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    switch (s.codePointAt(i)) {
      case 0x22:
        out += String.raw`\"`;
        break;
      case 0x5c:
        out += String.raw`\\`;
        break;
      case 0x08:
        out += String.raw`\b`;
        break;
      case 0x0c:
        out += String.raw`\f`;
        break;
      case 0x0a:
        out += String.raw`\n`;
        break;
      case 0x0d:
        out += String.raw`\r`;
        break;
      case 0x09:
        out += String.raw`\t`;
        break;
      default: {
        const code = s.codePointAt(i)!;
        if (code < 0x20) {
          out += String.raw`\u` + code.toString(16).padStart(4, "0");
        } else {
          // Includes all printable ASCII and ALL non-ASCII codepoints.
          // Surrogate pairs pass through as the source string carries them —
          // this matches Python's behaviour with ensure_ascii=False.
          out += s[i];
        }
      }
    }
  }
  return out + '"';
}

/**
 * Match Python's ``json.dumps`` number serialisation closely enough for our
 * receipt fields. Receipts only contain integers in `iat` / `issued_at` /
 * `confidence` — no edge cases like NaN, Infinity, scientific notation
 * beyond what default JSON produces.
 */
function canonicalNumber(n: number): string {
  if (Number.isNaN(n) || !Number.isFinite(n)) {
    throw new TypeError("canonical JSON cannot encode NaN or Infinity");
  }
  if (Number.isInteger(n)) return n.toString();
  // For floats, JS's String() produces a minimal representation that matches
  // Python's repr for most receipt-relevant values. If receipts ever carry
  // pathological floats, this function needs sharpening (but the spec only
  // requires "minimal lossless representation").
  return n.toString();
}

export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
