/**
 * @raucle/receipt — TypeScript reference implementation of the
 * Raucle Provenance Receipt v1 spec.
 *
 * Spec: https://raucle.com/spec/provenance/v1
 *
 * Quick start::
 *
 *     import { AgentIdentity, ProvenanceReceipt, hashText } from "@raucle/receipt";
 *
 *     const id = AgentIdentity.generate({
 *       agentId: "agent:my-service",
 *       allowedModels: ["claude-sonnet-4-6"],
 *     });
 *
 *     const root = new ProvenanceReceipt({
 *       agentId: id.agentId,
 *       agentKeyId: id.keyId,
 *       operation: "user_input",
 *       inputHash: hashText("Hello"),
 *       taint: ["external_user"],
 *       issuedAt: Math.floor(Date.now() / 1000),
 *     });
 *     root.sign(id);
 *     console.log(root.jws);          // compact JWS string
 *     console.log(root.receiptHash);  // sha256:...
 */

export { canonicalize, canonicalizeBytes } from "./canonical-json.js";
export { b64urlDecode, b64urlEncode } from "./base64url.js";
export { hashObj, hashText, sha256Hex } from "./hash.js";

export {
  AgentIdentity,
  CapabilityStatement,
  loadPublicKey,
  validateAgentId,
} from "./identity.js";
export type { CapabilityStatementJSON } from "./identity.js";

export {
  ISSUER,
  OPERATIONS,
  ProvenanceReceipt,
  RAUCLE_VERSION_TAG,
  RECEIPT_TYP,
} from "./receipt.js";
export type { Operation, ReceiptInit } from "./receipt.js";

export { ProvenanceVerifier } from "./verifier.js";
export type { VerificationReport } from "./verifier.js";

export const SPEC_URL = "https://raucle.com/spec/provenance/v1";
export const SPEC_VERSION = "raucle-provenance-receipt/v1";
