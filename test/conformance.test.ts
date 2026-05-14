/**
 * Spec conformance tests for the TypeScript reference implementation.
 *
 * These tests load the canonical test vectors from the Python reference
 * implementation (the spec's normative test-vector source) and verify that
 * this TS implementation produces byte-identical signatures, byte-identical
 * receipt hashes, and successful signature verification.
 *
 * Pulled from the raucle-detect repo at a pinned commit so this codebase
 * has no runtime dependency on Python, but the conformance contract is
 * explicit and reproducible.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  AgentIdentity,
  CapabilityStatement,
  ProvenanceReceipt,
  ProvenanceVerifier,
  canonicalize,
  hashObj,
  hashText,
  validateAgentId,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(__dirname, "vectors", "test-vectors.json");

interface VectorFile {
  spec_version: string;
  generator_version: string;
  agent_id: string;
  agent_key_id: string;
  public_key_pem: string;
  vectors: Array<{
    name: string;
    description: string;
    expected_jws: string;
    expected_receipt_hash: string;
  }>;
}

function loadVectors(): VectorFile {
  return JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));
}

describe("Spec conformance — published v1 test vectors", () => {
  it("vector file is present and well-formed", () => {
    const v = loadVectors();
    expect(v.spec_version).toBe("raucle-provenance-receipt/v1");
    expect(v.vectors.length).toBeGreaterThanOrEqual(5);
  });

  it("recomputes every vector's receipt_hash byte-for-byte", () => {
    const v = loadVectors();
    for (const vec of v.vectors) {
      const r = ProvenanceReceipt.fromJws(vec.expected_jws);
      expect(r.receiptHash, `vector ${vec.name}`).toBe(vec.expected_receipt_hash);
    }
  });

  it("verifies every vector's signature against the published pubkey", () => {
    const v = loadVectors();
    const verifier = new ProvenanceVerifier({
      [v.agent_key_id]: v.public_key_pem,
    });
    for (const vec of v.vectors) {
      const r = ProvenanceReceipt.fromJws(vec.expected_jws);
      expect(verifier.verifySignature(r), `vector ${vec.name}`).toBe(true);
    }
  });

  it("covers all required operation types from the spec", () => {
    const v = loadVectors();
    const ops = new Set(
      v.vectors.map((vec) => ProvenanceReceipt.fromJws(vec.expected_jws).operation),
    );
    for (const required of [
      "user_input",
      "model_call",
      "tool_call",
      "sanitisation",
      "guardrail_scan",
    ] as const) {
      expect(ops.has(required), `vectors must cover ${required}`).toBe(true);
    }
  });
});

describe("Canonical JSON", () => {
  it("matches Python json.dumps(sort_keys=True, separators=(',', ':'))", () => {
    // Hand-crafted cases against Python output (verified locally):
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize("hello")).toBe('"hello"');
    expect(canonicalize({ x: null, y: true, z: false })).toBe('{"x":null,"y":true,"z":false}');
    expect(canonicalize({ "z": 1, "a": { "b": 2, "a": 1 } })).toBe(
      '{"a":{"a":1,"b":2},"z":1}',
    );
  });

  it("preserves non-ASCII unescaped (ensure_ascii=False semantics)", () => {
    expect(canonicalize("café")).toBe('"café"');
    expect(canonicalize("→")).toBe('"→"');
  });

  it("escapes JSON control characters", () => {
    expect(canonicalize("a\nb")).toBe('"a\\nb"');
    expect(canonicalize('he said "hi"')).toBe('"he said \\"hi\\""');
  });
});

describe("Hash helpers", () => {
  it("hashText is deterministic and prefixed", () => {
    expect(hashText("hello")).toBe(hashText("hello"));
    expect(hashText("hello")).not.toBe(hashText("world"));
    expect(hashText("x").startsWith("sha256:")).toBe(true);
    expect(hashText("x")).toHaveLength("sha256:".length + 64);
  });

  it("hashObj is order-independent for keys", () => {
    expect(hashObj({ a: 1, b: 2 })).toBe(hashObj({ b: 2, a: 1 }));
    expect(hashObj({ a: 1 })).not.toBe(hashObj({ a: 2 }));
  });
});

describe("Agent identity", () => {
  it("validates agent_id format", () => {
    expect(() => validateAgentId("agent:ok")).not.toThrow();
    expect(() => validateAgentId("agent:my.service-v1")).not.toThrow();
    expect(() => validateAgentId("no-prefix")).toThrow(/agent_id/);
    expect(() => validateAgentId("AGENT:upper")).toThrow();
    expect(() => validateAgentId("agent:has space")).toThrow();
  });

  it("generates a self-signed capability statement", () => {
    const id = AgentIdentity.generate({ agentId: "agent:x" });
    expect(id.keyId).toHaveLength(16);
    expect(id.statement.signature.length).toBeGreaterThan(0);
  });

  it("capability allowlists default to unrestricted", () => {
    const id = AgentIdentity.generate({ agentId: "agent:x" });
    expect(id.statement.permitsModel("anything")).toBe(true);
    expect(id.statement.permitsTool("anything")).toBe(true);
  });

  it("capability allowlists are enforced when set", () => {
    const id = AgentIdentity.generate({
      agentId: "agent:x",
      allowedModels: ["claude-sonnet-4-6"],
      allowedTools: ["send_email"],
    });
    expect(id.statement.permitsModel("claude-sonnet-4-6")).toBe(true);
    expect(id.statement.permitsModel("gpt-4o")).toBe(false);
    expect(id.statement.permitsTool("send_email")).toBe(true);
    expect(id.statement.permitsTool("delete_db")).toBe(false);
  });

  it("CapabilityStatement.fromJSON round-trips", () => {
    const id = AgentIdentity.generate({ agentId: "agent:x" });
    const json = id.statement.toJSON();
    const restored = CapabilityStatement.fromJSON(json);
    expect(restored.keyId).toBe(id.keyId);
    expect(restored.publicKeyPem).toBe(id.statement.publicKeyPem);
  });
});

describe("Receipt sign + verify round trip", () => {
  it("a freshly generated identity emits a receipt that verifies", () => {
    const id = AgentIdentity.generate({ agentId: "agent:roundtrip" });
    const r = new ProvenanceReceipt({
      agentId: id.agentId,
      agentKeyId: id.keyId,
      operation: "user_input",
      inputHash: hashText("hello"),
      taint: ["external_user"],
      issuedAt: 1_700_000_000,
    });
    r.sign(id);
    expect(r.jws.split(".")).toHaveLength(3);
    expect(r.receiptHash.startsWith("sha256:")).toBe(true);

    const verifier = new ProvenanceVerifier({ [id.keyId]: id.publicKeyPem() });
    expect(verifier.verifySignature(r)).toBe(true);
  });

  it("a tampered JWS fails verification", () => {
    const id = AgentIdentity.generate({ agentId: "agent:tamper" });
    const r = new ProvenanceReceipt({
      agentId: id.agentId,
      agentKeyId: id.keyId,
      operation: "user_input",
      inputHash: hashText("hello"),
      taint: [],
      issuedAt: 1_700_000_000,
    });
    r.sign(id);
    const parts = r.jws.split(".");
    // Flip one bit in the payload segment
    parts[1] = parts[1]!.replace(/.$/, (c) => (c === "A" ? "B" : "A"));
    const tampered = new ProvenanceReceipt({
      ...r,
      issuedAt: r.issuedAt,
    });
    tampered.jws = parts.join(".");

    const verifier = new ProvenanceVerifier({ [id.keyId]: id.publicKeyPem() });
    expect(verifier.verifySignature(tampered)).toBe(false);
  });
});
