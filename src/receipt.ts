/**
 * Provenance receipt per Raucle spec v1 §4.
 *
 * A receipt is a compact JWS over a canonical-JSON payload. The receipt's
 * own hash (``sha256:<hex>`` of the compact JWS string) is the value
 * descendants cite in their ``parents`` list.
 */

import { b64urlDecode, b64urlEncode } from "./base64url.js";
import { canonicalizeBytes, compareStrings } from "./canonical-json.js";
import { sha256Hex } from "./hash.js";
import type { AgentIdentity } from "./identity.js";

export const RECEIPT_TYP = "provenance-receipt/v1";
export const RAUCLE_VERSION_TAG = "raucle/v1";
export const ISSUER = "raucle-detect/provenance";

export type Operation =
  | "user_input"
  | "model_call"
  | "tool_call"
  | "retrieval"
  | "guardrail_scan"
  | "agent_handoff"
  | "sanitisation"
  | "merge";

export const OPERATIONS: readonly Operation[] = [
  "user_input",
  "model_call",
  "tool_call",
  "retrieval",
  "guardrail_scan",
  "agent_handoff",
  "sanitisation",
  "merge",
] as const;

export interface ReceiptInit {
  agentId: string;
  agentKeyId: string;
  operation: Operation;
  parents?: string[];
  inputHash?: string;
  outputHash?: string;
  model?: string;
  tool?: string;
  corpus?: string;
  rulesetHash?: string;
  guardrailVerdict?: string;
  taint?: string[];
  tenant?: string | null;
  issuedAt: number;
}

export class ProvenanceReceipt {
  agentId: string;
  agentKeyId: string;
  operation: Operation;
  parents: string[];
  inputHash: string;
  outputHash: string;
  model: string;
  tool: string;
  corpus: string;
  rulesetHash: string;
  guardrailVerdict: string;
  taint: string[];
  tenant: string | null;
  issuedAt: number;

  /** Populated after ``sign()`` or ``fromJws()``. */
  jws: string = "";
  receiptHash: string = "";

  constructor(init: ReceiptInit) {
    this.agentId = init.agentId;
    this.agentKeyId = init.agentKeyId;
    this.operation = init.operation;
    this.parents = [...(init.parents ?? [])];
    this.inputHash = init.inputHash ?? "";
    this.outputHash = init.outputHash ?? "";
    this.model = init.model ?? "";
    this.tool = init.tool ?? "";
    this.corpus = init.corpus ?? "";
    this.rulesetHash = init.rulesetHash ?? "";
    this.guardrailVerdict = init.guardrailVerdict ?? "";
    this.taint = [...(init.taint ?? [])];
    this.tenant = init.tenant ?? null;
    this.issuedAt = init.issuedAt;
  }

  /** Build the canonical signed-payload object per spec §4.2. */
  payload(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      iss: ISSUER,
      typ: RECEIPT_TYP,
      iat: this.issuedAt,
      agent_id: this.agentId,
      agent_key_id: this.agentKeyId,
      operation: this.operation,
      parents: [...this.parents].sort(compareStrings),
      taint: [...this.taint].sort(compareStrings),
    };
    if (this.inputHash) out["input_hash"] = this.inputHash;
    if (this.outputHash) out["output_hash"] = this.outputHash;
    if (this.model) out["model"] = this.model;
    if (this.tool) out["tool"] = this.tool;
    if (this.corpus) out["corpus"] = this.corpus;
    if (this.rulesetHash) out["ruleset_hash"] = this.rulesetHash;
    if (this.guardrailVerdict) out["guardrail_verdict"] = this.guardrailVerdict;
    if (this.tenant !== null && this.tenant !== undefined) {
      out["tenant"] = this.tenant;
    }
    return out;
  }

  /**
   * Sign with *identity*; populate ``jws`` and ``receiptHash``.
   * Returns the compact JWS string.
   */
  sign(identity: AgentIdentity): string {
    const header = {
      alg: "EdDSA",
      typ: RECEIPT_TYP,
      kid: identity.keyId,
      crit: [RAUCLE_VERSION_TAG],
      [RAUCLE_VERSION_TAG]: "provenance",
    };
    const headerB64 = b64urlEncode(canonicalizeBytes(header));
    const payloadB64 = b64urlEncode(canonicalizeBytes(this.payload()));
    const signingInput = new TextEncoder().encode(headerB64 + "." + payloadB64);
    const sig = identity.sign(signingInput);
    this.jws = headerB64 + "." + payloadB64 + "." + b64urlEncode(sig);
    this.receiptHash = "sha256:" + sha256Hex(new TextEncoder().encode(this.jws));
    return this.jws;
  }

  /**
   * Parse a compact JWS string back into a receipt. Does NOT verify the
   * signature — use ``ProvenanceVerifier`` for that.
   */
  static fromJws(jws: string): ProvenanceReceipt {
    const parts = jws.split(".");
    if (parts.length !== 3) {
      throw new Error("malformed JWS — expected three dot-separated segments");
    }
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]!)));
    const op = payload.operation as Operation;
    if (!OPERATIONS.includes(op)) {
      throw new Error(`unknown operation ${JSON.stringify(op)}`);
    }
    const receipt = new ProvenanceReceipt({
      agentId: payload.agent_id,
      agentKeyId: payload.agent_key_id,
      operation: op,
      parents: payload.parents ?? [],
      inputHash: payload.input_hash ?? "",
      outputHash: payload.output_hash ?? "",
      model: payload.model ?? "",
      tool: payload.tool ?? "",
      corpus: payload.corpus ?? "",
      rulesetHash: payload.ruleset_hash ?? "",
      guardrailVerdict: payload.guardrail_verdict ?? "",
      taint: payload.taint ?? [],
      tenant: payload.tenant ?? null,
      issuedAt: payload.iat ?? 0,
    });
    receipt.jws = jws;
    receipt.receiptHash = "sha256:" + sha256Hex(new TextEncoder().encode(jws));
    return receipt;
  }

  /** Serialise to the JSONL on-disk shape: payload + ``receipt_hash`` + ``jws``. */
  toLogLine(): Record<string, unknown> {
    return {
      ...this.payload(),
      receipt_hash: this.receiptHash,
      jws: this.jws,
    };
  }
}
