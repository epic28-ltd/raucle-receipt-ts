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
  for (let i = 0; i < data.length; i++) {
    bin += String.fromCharCode(data[i]!);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64url"));
  }
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
