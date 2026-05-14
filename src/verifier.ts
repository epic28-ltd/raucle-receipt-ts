/**
 * Provenance chain verifier per Raucle spec v1 §10.
 *
 * Three classes of check, all of which must pass for ``valid=true``:
 *  1. Signature verifies for each receipt against its declared ``agent_key_id``.
 *  2. Every ``parent`` referenced by a receipt exists in the chain, and the
 *     receipt's stored hash matches a recompute from the JWS bytes
 *     (tampering detection).
 *  3. Taint monotonicity (non-sanitisation receipts ⊇ union(parents);
 *     sanitisation receipts = inherited \\ explicitly-removed tags).
 */

import { readFileSync } from "node:fs";

import { type KeyObject, verify as cryptoVerify } from "node:crypto";

import { sha256Hex } from "./hash.js";
import { loadPublicKey } from "./identity.js";
import { ProvenanceReceipt } from "./receipt.js";

export interface VerificationReport {
  valid: boolean;
  receiptCount: number;
  signatureFailures: number;
  parentLinkFailures: number;
  taintMonotonicityFailures: number;
  tamperedReceipts: string[];
  errors: string[];
}

export class ProvenanceVerifier {
  private readonly keys: Map<string, KeyObject>;

  constructor(publicKeysPem: Record<string, string>) {
    this.keys = new Map();
    for (const [kid, pem] of Object.entries(publicKeysPem)) {
      this.keys.set(kid, loadPublicKey(pem));
    }
  }

  /** Verify a JSONL chain file. */
  verifyChainFile(path: string): VerificationReport {
    const text = readFileSync(path, "utf-8");
    return this.verifyChainText(text);
  }

  /** Verify a JSONL chain given as a string (one record per line). */
  verifyChainText(text: string): VerificationReport {
    const report: VerificationReport = {
      valid: true,
      receiptCount: 0,
      signatureFailures: 0,
      parentLinkFailures: 0,
      taintMonotonicityFailures: 0,
      tamperedReceipts: [],
      errors: [],
    };

    const lines = text.split(/\r?\n/);
    const byHash = new Map<string, ProvenanceReceipt>();
    const storedHashByJws = new Map<string, string>();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.trim();
      if (!line) continue;
      let raw: Record<string, unknown>;
      try {
        raw = JSON.parse(line);
      } catch (e) {
        report.errors.push(`line ${i + 1}: invalid JSON: ${(e as Error).message}`);
        report.valid = false;
        continue;
      }
      const jws = raw["jws"];
      if (typeof jws !== "string") {
        report.errors.push(`line ${i + 1}: record has no string 'jws' field`);
        report.valid = false;
        continue;
      }
      let receipt: ProvenanceReceipt;
      try {
        receipt = ProvenanceReceipt.fromJws(jws);
      } catch (e) {
        report.errors.push(`line ${i + 1}: malformed receipt: ${(e as Error).message}`);
        report.valid = false;
        continue;
      }

      // Tampering: stored receipt_hash must match recomputed
      const stored = raw["receipt_hash"];
      if (typeof stored === "string" && stored !== receipt.receiptHash) {
        report.tamperedReceipts.push(receipt.receiptHash);
        report.errors.push(
          `line ${i + 1}: receipt_hash mismatch — record tampered`,
        );
        report.valid = false;
      }
      storedHashByJws.set(jws, typeof stored === "string" ? stored : receipt.receiptHash);

      // Signature
      if (!this.verifySignature(receipt)) {
        report.signatureFailures += 1;
        report.errors.push(
          `line ${i + 1}: signature verification failed for ` +
            `agent_key_id=${receipt.agentKeyId}`,
        );
        report.valid = false;
      }

      byHash.set(receipt.receiptHash, receipt);
      report.receiptCount += 1;
    }

    // DAG integrity + taint monotonicity
    for (const receipt of byHash.values()) {
      for (const parentHash of receipt.parents) {
        if (!byHash.has(parentHash)) {
          report.parentLinkFailures += 1;
          report.errors.push(
            `receipt ${receipt.receiptHash}: parent ${parentHash} not in chain`,
          );
          report.valid = false;
        }
      }
      this.checkTaint(receipt, byHash, report);
    }

    return report;
  }

  /** Walk the DAG backwards from ``receiptHash`` to all roots. */
  trace(receiptHash: string, chainText: string): ProvenanceReceipt[] {
    const all = this.loadAll(chainText);
    if (!all.has(receiptHash)) {
      throw new Error(`receipt ${receiptHash} not found in chain`);
    }
    const visited = new Set<string>();
    const out: ProvenanceReceipt[] = [];
    const queue: string[] = [receiptHash];
    while (queue.length) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      const r = all.get(current);
      if (!r) continue;
      out.push(r);
      queue.push(...r.parents);
    }
    return out;
  }

  /** Public for tests; verifies the EdDSA signature against the loaded key. */
  verifySignature(receipt: ProvenanceReceipt): boolean {
    const key = this.keys.get(receipt.agentKeyId);
    if (!key) return false;
    const parts = receipt.jws.split(".");
    if (parts.length !== 3) return false;
    const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const sig = Buffer.from(parts[2]!, "base64url");
    try {
      return cryptoVerify(null, signingInput, key, sig);
    } catch {
      return false;
    }
  }

  private checkTaint(
    receipt: ProvenanceReceipt,
    byHash: Map<string, ProvenanceReceipt>,
    report: VerificationReport,
  ): void {
    if (receipt.parents.length === 0) return;
    const inherited = new Set<string>();
    for (const p of receipt.parents) {
      const parent = byHash.get(p);
      if (parent) for (const t of parent.taint) inherited.add(t);
    }
    const mine = new Set(receipt.taint);

    if (receipt.operation === "sanitisation") {
      let removed = new Set<string>();
      if (receipt.corpus.startsWith("removed:")) {
        removed = new Set(
          receipt.corpus.slice("removed:".length).split(",").filter(Boolean),
        );
      }
      const expected = new Set<string>();
      for (const t of inherited) if (!removed.has(t)) expected.add(t);
      if (!setsEqual(expected, mine)) {
        report.taintMonotonicityFailures += 1;
        report.errors.push(
          `receipt ${receipt.receiptHash}: sanitisation taint mismatch`,
        );
        report.valid = false;
      }
    } else {
      const missing = [...inherited].filter((t) => !mine.has(t));
      if (missing.length > 0) {
        report.taintMonotonicityFailures += 1;
        report.errors.push(
          `receipt ${receipt.receiptHash}: taint not monotonic — ` +
            `dropped ${JSON.stringify(missing)} without a sanitisation step`,
        );
        report.valid = false;
      }
    }
  }

  private loadAll(chainText: string): Map<string, ProvenanceReceipt> {
    const out = new Map<string, ProvenanceReceipt>();
    for (const line of chainText.split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      try {
        const raw = JSON.parse(t);
        const r = ProvenanceReceipt.fromJws(raw.jws);
        out.set(r.receiptHash, r);
      } catch {
        // skip
      }
    }
    return out;
  }
}

function setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}
