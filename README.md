# @raucle/receipt

[![CI](https://github.com/craigamcw/raucle-receipt-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/craigamcw/raucle-receipt-ts/actions/workflows/ci.yml)
[![Spec v1](https://img.shields.io/badge/spec-provenance--receipt%2Fv1-blue)](https://raucle.com/spec/provenance/v1)

**TypeScript reference implementation of the Raucle Provenance Receipt v1 spec** — cryptographic chain-of-custody for AI workflows.

Every step in a multi-agent / multi-tool LLM workflow can emit a signed receipt that composes into a Merkle DAG. Given any output, you can reconstruct the entire causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of [Sigstore](https://www.sigstore.dev/) for software artifacts.

- **Spec**: <https://raucle.com/spec/provenance/v1>
- **Spec version**: `raucle-provenance-receipt/v1`
- **Crypto**: Ed25519 (EdDSA, RFC 8037), compact JWS (RFC 7515)
- **Dependencies**: zero runtime deps — uses Node's built-in `node:crypto`
- **License**: MIT

## Install

```bash
npm install @raucle/receipt
```

Requires Node 18+. Works in Bun and Deno that expose the Node `node:crypto` compatibility surface.

## Quick start

```typescript
import {
  AgentIdentity,
  ProvenanceReceipt,
  ProvenanceVerifier,
  hashText,
} from "@raucle/receipt";

// 1. Generate an agent identity (do this once at deploy time)
const identity = AgentIdentity.generate({
  agentId: "agent:customer-support",
  allowedModels: ["claude-sonnet-4-6"],
  allowedTools: ["lookup_order", "send_email"],
  ttlSeconds: 365 * 24 * 60 * 60,
});

// 2. Emit a root receipt when untrusted input enters the graph
const root = new ProvenanceReceipt({
  agentId: identity.agentId,
  agentKeyId: identity.keyId,
  operation: "user_input",
  inputHash: hashText("Please send me my last invoice."),
  taint: ["external_user"],
  issuedAt: Math.floor(Date.now() / 1000),
});
root.sign(identity);

// 3. Each later step (model call, tool call, retrieval, etc.) cites parents
const modelCall = new ProvenanceReceipt({
  agentId: identity.agentId,
  agentKeyId: identity.keyId,
  operation: "model_call",
  parents: [root.receiptHash],
  model: "claude-sonnet-4-6",
  inputHash: hashText("..."),
  outputHash: hashText("..."),
  taint: ["external_user"], // descendants must carry parent taint
  issuedAt: Math.floor(Date.now() / 1000),
});
modelCall.sign(identity);

// 4. Verify any chain later
const verifier = new ProvenanceVerifier({
  [identity.keyId]: identity.publicKeyPem(),
});
const chainText =
  JSON.stringify(root.toLogLine()) +
  "\n" +
  JSON.stringify(modelCall.toLogLine()) +
  "\n";
const report = verifier.verifyChainText(chainText);
console.log(report.valid); // true
```

## What's verified

Three classes of check, all must pass for `valid=true`:

1. **Signature**: every receipt's JWS verifies against its declared `agent_key_id`.
2. **DAG integrity**: every parent referenced by a receipt exists in the chain; receipt hashes match recomputed bytes (catches tampering).
3. **Taint monotonicity**: descendant taint ⊇ union(parent taints), unless a `sanitisation` operation explicitly lists removed tags.

## Receipt format

Compact JWS (`alg=EdDSA`, `typ=provenance-receipt/v1`). The `crit=["raucle/v1"]` header prevents JWT-compatible libraries from silently accepting these as bearer tokens.

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

Payload fields (canonical-JSON, sorted keys, no whitespace, UTF-8):

| Field | Description |
|---|---|
| `iss`, `typ`, `iat` | Issuer, receipt-type tag, issue timestamp |
| `agent_id`, `agent_key_id` | Who emitted this step |
| `operation` | One of 8 types: `user_input`, `model_call`, `tool_call`, `retrieval`, `guardrail_scan`, `agent_handoff`, `sanitisation`, `merge` |
| `parents` | Receipt hashes of immediate predecessors (sorted) |
| `taint` | Sorted set of provenance tags for untrusted data |
| `input_hash`, `output_hash` | SHA-256 of step inputs/outputs (`sha256:` prefix + hex). Hashes only — receipts never embed raw content. |
| `model`, `tool`, `corpus` | Operation-specific identifiers |
| `ruleset_hash`, `guardrail_verdict` | Set for `guardrail_scan` operations |
| `tenant` | Optional multi-tenant SaaS label |

A receipt's *own* hash — cited by descendants in `parents` — is `sha256:` + hex of `sha256(compact_jws_string)`. Content-addressed, deterministic.

See the full spec at <https://raucle.com/spec/provenance/v1>.

## Conformance

This package ships [the official v1 test vectors](./test/vectors/test-vectors.json) in its test suite. CI runs them on every PR — divergence from the spec is caught immediately. The vectors are sourced from the canonical Python reference at <https://github.com/craigamcw/raucle-detect>.

To verify conformance yourself:

```bash
npm install
npm test
```

## Implementing the spec in another language?

This codebase is small (≈ 600 LoC of TypeScript) and dependency-free. The structure is:

| File | Responsibility |
|---|---|
| `src/canonical-json.ts` | Canonical JSON serialisation (sorted keys, no whitespace, `ensure_ascii=False` semantics) |
| `src/base64url.ts` | RFC 4648 §5 base64url, no padding |
| `src/hash.ts` | SHA-256 helpers with `sha256:` prefix |
| `src/identity.ts` | Agent keypair + capability statement |
| `src/receipt.ts` | JWS sign + parse |
| `src/verifier.ts` | Chain verification (signature + DAG + taint) |

Any conforming implementation must reproduce [the test vectors](./test/vectors/test-vectors.json) byte-for-byte. If you're building one, please open an issue here — we'll cross-link it from the spec.

## Reference implementations

| Language | Repo | Status |
|---|---|---|
| Python | [craigamcw/raucle-detect](https://github.com/craigamcw/raucle-detect) | Canonical |
| TypeScript | this repo | v0.1.0 |
| Go | `craigamcw/raucle-receipt-go` | Coming |
| Rust | `craigamcw/raucle-receipt-rs` | Coming |

## Security model

The receipt format defends against tampering with past receipts, forging receipts without the agent's private key, silent taint-laundering, and invocation of disallowed models/tools.

It does NOT defend against a compromised private key, a lying agent that records one hash while passing different content to the model (mitigation: pair with TEE-attested inference), or replay (mitigation: include `iat` + content hashes; replay-window enforcement is the caller's responsibility).

See [§11 Security considerations](https://raucle.com/spec/provenance/v1#11-security-considerations) in the spec for the full threat model.

## Contributing

PRs welcome. The label `spec` is applied to anything that requires a spec change; spec changes require a 14-day public comment period before merge.

## License

MIT — see [LICENSE](./LICENSE).
