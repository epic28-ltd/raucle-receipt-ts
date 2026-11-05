/**
 * Base64url encode/decode (RFC 4648 §5), no padding.
 *
 * Browser-safe path uses ``btoa`` / ``atob``; Node path uses ``Buffer``.
 * Either way the output is the unpadded URL-safe alphabet.
 */

export function b64urlEncode(data: Uint8Array): string {
  // Node ≥ 16 has Buffer.toString("base64url"); browsers don't.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("base64url");
  }
  // Browser fallback
  let bin = "";
  for (const byte of data) {
    bin += String.fromCodePoint(byte);
  }
  // `btoa` emits standard base64 with "=" padding; padding sits only at the
  // tail, so cutting at the first "=" yields the unpadded form.
  const b64 = btoa(bin);
  const unpadded = b64.includes("=") ? b64.slice(0, b64.indexOf("=")) : b64;
  return unpadded.replaceAll("+", "-").replaceAll("/", "_");
}

export function b64urlDecode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64url"));
  }
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replaceAll("-", "+").replaceAll("_", "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.codePointAt(i)!;
  return out;
}
