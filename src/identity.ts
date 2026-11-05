/**
 * Agent identity per Raucle Provenance Receipt v1 §5.
 *
 * An agent is identified by:
 *   - a stable ``agent_id`` matching ``^agent:[a-z0-9][a-z0-9_\-./]{0,127}$``,
 *   - an Ed25519 keypair,
 *   - a signed capability statement listing permitted models / tools.
 */

import {
  type KeyObject,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import { canonicalizeBytes, compareStrings } from "./canonical-json.js";
import { sha256Hex } from "./hash.js";

const AGENT_ID_RE = /^agent:[a-z0-9][a-z0-9_\-./]{0,127}$/;

export function validateAgentId(agentId: string): void {
  if (!AGENT_ID_RE.test(agentId)) {
    throw new Error(
      `agent_id ${JSON.stringify(agentId)} must match ${AGENT_ID_RE} ` +
        "(lowercase, alphanumeric + _-./, 1-128 chars, prefix 'agent:')",
    );
  }
}

export interface CapabilityStatementJSON {
  agent_id: string;
  key_id: string;
  public_key_pem: string;
  allowed_models: string[];
  allowed_tools: string[];
  data_classifications: string[];
  issuer: string;
  issued_at: number;
  expires_at: number | null;
  signature: string; // base64 (standard alphabet) over canonical-JSON of body
}

export class CapabilityStatement {
  agentId: string;
  keyId: string;
  publicKeyPem: string;
  allowedModels: string[];
  allowedTools: string[];
  dataClassifications: string[];
  issuer: string;
  issuedAt: number;
  expiresAt: number | null;
  signature: string;

  constructor(init: CapabilityStatementJSON) {
    this.agentId = init.agent_id;
    this.keyId = init.key_id;
    this.publicKeyPem = init.public_key_pem;
    this.allowedModels = [...init.allowed_models];
    this.allowedTools = [...init.allowed_tools];
    this.dataClassifications = [...init.data_classifications];
    this.issuer = init.issuer;
    this.issuedAt = init.issued_at;
    this.expiresAt = init.expires_at;
    this.signature = init.signature;
  }

  static fromJSON(d: CapabilityStatementJSON): CapabilityStatement {
    return new CapabilityStatement(d);
  }

  /** Canonical body that gets signed (excludes ``signature``). */
  body(): Record<string, unknown> {
    return {
      agent_id: this.agentId,
      key_id: this.keyId,
      public_key_pem: this.publicKeyPem,
      allowed_models: [...this.allowedModels].sort(compareStrings),
      allowed_tools: [...this.allowedTools].sort(compareStrings),
      data_classifications: [...this.dataClassifications].sort(compareStrings),
      issuer: this.issuer,
      issued_at: this.issuedAt,
      expires_at: this.expiresAt,
    };
  }

  toJSON(): CapabilityStatementJSON {
    return {
      ...(this.body() as Omit<CapabilityStatementJSON, "signature">),
      signature: this.signature,
    } as CapabilityStatementJSON;
  }

  permitsModel(model: string): boolean {
    return this.allowedModels.length === 0 || this.allowedModels.includes(model);
  }

  permitsTool(tool: string): boolean {
    return this.allowedTools.length === 0 || this.allowedTools.includes(tool);
  }
}

export class AgentIdentity {
  readonly agentId: string;
  readonly statement: CapabilityStatement;
  /** Private key object — never serialised; the holder retains it locally. */
  readonly privateKey: KeyObject;

  constructor(agentId: string, privateKey: KeyObject, statement: CapabilityStatement) {
    validateAgentId(agentId);
    this.agentId = agentId;
    this.privateKey = privateKey;
    this.statement = statement;
  }

  get keyId(): string {
    return this.statement.keyId;
  }

  publicKeyPem(): string {
    return this.statement.publicKeyPem;
  }

  sign(data: Uint8Array): Uint8Array {
    // Ed25519 signing: passing ``null`` as the algorithm tells Node to use the
    // key's native algorithm — required for Ed25519 since it has no separate
    // hashing step.
    return new Uint8Array(cryptoSign(null, data, this.privateKey));
  }

  /**
   * Generate a fresh keypair + self-signed capability statement.
   *
   * In OSS mode the agent self-signs its statement with its own key; in
   * commercial deployments an authority key would sign instead.
   */
  static generate(opts: {
    agentId: string;
    allowedModels?: string[];
    allowedTools?: string[];
    dataClassifications?: string[];
    issuer?: string;
    ttlSeconds?: number;
  }): AgentIdentity {
    validateAgentId(opts.agentId);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pubPem = publicKey.export({ format: "pem", type: "spki" }).toString();
    const keyId = sha256Hex(new TextEncoder().encode(pubPem)).slice(0, 16);
    const now = Math.floor(Date.now() / 1000);
    const stmt = new CapabilityStatement({
      agent_id: opts.agentId,
      key_id: keyId,
      public_key_pem: pubPem,
      allowed_models: opts.allowedModels ?? [],
      allowed_tools: opts.allowedTools ?? [],
      data_classifications: opts.dataClassifications ?? [],
      issuer: opts.issuer ?? "raucle-detect",
      issued_at: now,
      expires_at: opts.ttlSeconds ? now + opts.ttlSeconds : null,
      signature: "",
    });
    // Self-sign the statement
    const sigBytes = cryptoSign(null, canonicalizeBytes(stmt.body()), privateKey);
    stmt.signature = Buffer.from(sigBytes).toString("base64");
    return new AgentIdentity(opts.agentId, privateKey, stmt);
  }

  /** Load an identity from a stored private-key PEM + capability statement. */
  static load(privateKeyPem: string, statement: CapabilityStatement): AgentIdentity {
    const privateKey = createPrivateKey({ key: privateKeyPem, format: "pem" });
    return new AgentIdentity(statement.agentId, privateKey, statement);
  }
}

/** Build a Node ``KeyObject`` from a PEM-encoded Ed25519 public key. */
export function loadPublicKey(pem: string): KeyObject {
  return createPublicKey({ key: pem, format: "pem" });
}

/** Used by tests; keeps canonicalize handy at the boundary. */
export { canonicalize } from "./canonical-json.js";
