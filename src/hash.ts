/**
 * SHA-256 helpers conforming to Raucle spec §7 (content addressing).
 *
 * All hash strings are prefixed ``sha256:`` followed by lowercase hex.
 */

import { createHash } from "node:crypto";

import { canonicalizeBytes } from "./canonical-json.js";

export function sha256Hex(data: Uint8Array | string): string {
  const h = createHash("sha256");
  h.update(data);
  return h.digest("hex");
}

/** Hash an input or output string per spec §7. */
export function hashText(s: string): string {
  return "sha256:" + sha256Hex(new TextEncoder().encode(s));
}

/** Hash an arbitrary JSON-serialisable object per spec §7. */
export function hashObj(o: unknown): string {
  return "sha256:" + sha256Hex(canonicalizeBytes(o));
}
