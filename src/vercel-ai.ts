/**
 * Raucle integration for the Vercel AI SDK (``ai`` ≥ 3.0).
 *
 * Vercel AI SDK exposes tools via the ``tool({ description, parameters,
 * execute })`` factory. We wrap the ``execute`` callback so each
 * invocation:
 *
 *   1. Optionally checks an integrator-supplied capability hook.
 *   2. Emits a signed Raucle Provenance Receipt
 *      (``operation: "tool_call"``) chained to the previous receipt.
 *   3. Either calls the original handler (allow) or throws a
 *      ``ToolDeniedError`` (deny).
 *
 * Quick start
 * -----------
 *
 *     import { generateText, tool } from "ai";
 *     import { z } from "zod";
 *     import { openai } from "@ai-sdk/openai";
 *     import { AgentIdentity, wrapTools, InMemorySink } from "@raucle/receipt";
 *
 *     const id = AgentIdentity.generate({
 *       agentId: "agent:my-service",
 *       allowedModels: ["gpt-4o"],
 *     });
 *     const sink = new InMemorySink();
 *
 *     const tools = wrapTools(
 *       {
 *         lookupCustomer: tool({
 *           description: "Look up a customer by id",
 *           parameters: z.object({ customerId: z.string() }),
 *           execute: async ({ customerId }) => fetchCustomer(customerId),
 *         }),
 *       },
 *       { identity: id, sink },
 *     );
 *
 *     const result = await generateText({
 *       model: openai("gpt-4o"),
 *       prompt: "Get email for customer 12345",
 *       tools,
 *     });
 *
 * Receipts are appended to the sink; the latest receipt hash is
 * available as ``sink.lastReceiptHash`` so subsequent calls chain.
 *
 * Capability hook
 * ---------------
 *
 * Pass ``capabilityCheck`` to gate calls. If it returns ``{ allow:
 * false, reason }``, the tool throws ``ToolDeniedError`` without
 * invoking the underlying handler. A DENY receipt is still emitted.
 *
 * .. code-block:: typescript
 *
 *     const tools = wrapTools(rawTools, {
 *       identity: id,
 *       sink,
 *       capabilityCheck: ({ tool, args }) => {
 *         if (tool === "lookupCustomer" && args.customerId === "99999") {
 *           return { allow: false, reason: "blocked customer id" };
 *         }
 *         return { allow: true };
 *       },
 *     });
 */

import { AgentIdentity } from "./identity.js";
import { ProvenanceReceipt } from "./receipt.js";
import { hashObj } from "./hash.js";

export class ToolDeniedError extends Error {
  readonly tool: string;
  readonly reason: string;
  constructor(tool: string, reason: string) {
    super(`raucle denied tool '${tool}': ${reason}`);
    this.name = "ToolDeniedError";
    this.tool = tool;
    this.reason = reason;
  }
}

/** Minimum surface a sink needs for the adapter. */
export interface ReceiptSink {
  append(receipt: ProvenanceReceipt): void | Promise<void>;
  lastReceiptHash?: string;
}

/** In-memory sink useful for tests + getting started. */
export class InMemorySink implements ReceiptSink {
  readonly receipts: ProvenanceReceipt[] = [];
  lastReceiptHash: string = "";
  append(receipt: ProvenanceReceipt): void {
    this.receipts.push(receipt);
    this.lastReceiptHash = receipt.receiptHash;
  }
}

export type CapabilityVerdict = { allow: true } | { allow: false; reason: string };

export interface CapabilityCheck {
  (ctx: { tool: string; args: Record<string, unknown> }): CapabilityVerdict;
}

export interface WrapToolsOptions {
  identity: AgentIdentity;
  sink: ReceiptSink;
  /** Optional gate; absent = allow-all (receipts still emitted). */
  capabilityCheck?: CapabilityCheck;
  /** Override the model tag stamped into receipts. Default: "". */
  model?: string;
  /**
   * When false, denials emit a receipt but still call the handler.
   * Useful for shadow-mode rollouts. Default true.
   */
  raiseOnDeny?: boolean;
  /** Tenant tag for multi-tenant deployments. */
  tenant?: string | null;
}

// A Vercel AI SDK "tool" — duck-typed against the shape from `ai`. We
// don't import the package to avoid a hard runtime dependency; users
// can wrap whatever they pass to `tool()` from 'ai' (or compatible).
interface VercelTool {
  description?: string;
  parameters?: unknown;
  execute?: (
    args: Record<string, unknown>,
    options?: unknown,
  ) => Promise<unknown> | unknown;
  // Pass-through for unknown extras (e.g. `experimental_toToolResultContent`).
  [k: string]: unknown;
}

/**
 * Wrap a tools record so every call emits a signed receipt and
 * (optionally) is gated by ``capabilityCheck``.
 *
 * The returned record is a *new* object — the originals are not
 * mutated. Tools without an ``execute`` (e.g. client-side tools) are
 * passed through unchanged with no receipt.
 */
export function wrapTools<T extends Record<string, VercelTool>>(
  tools: T,
  opts: WrapToolsOptions,
): T {
  const out: Record<string, VercelTool> = {};
  for (const [name, t] of Object.entries(tools)) {
    out[name] = wrapTool(name, t, opts);
  }
  return out as T;
}

/** Wrap one tool. Exported for advanced use; most callers want ``wrapTools``. */
export function wrapTool(
  name: string,
  original: VercelTool,
  opts: WrapToolsOptions,
): VercelTool {
  if (typeof original.execute !== "function") {
    return original;
  }
  const innerExecute = original.execute;
  const wrapped: VercelTool = { ...original };

  wrapped.execute = async (
    args: Record<string, unknown>,
    options?: unknown,
  ): Promise<unknown> => {
    const verdict: CapabilityVerdict = opts.capabilityCheck
      ? opts.capabilityCheck({ tool: name, args })
      : { allow: true };

    const receipt = new ProvenanceReceipt({
      agentId: opts.identity.agentId,
      agentKeyId: opts.identity.keyId,
      operation: "tool_call",
      tool: name,
      model: opts.model ?? "",
      inputHash: hashObj(args),
      parents: opts.sink.lastReceiptHash ? [opts.sink.lastReceiptHash] : [],
      guardrailVerdict: verdict.allow ? "ALLOW" : `DENY:${verdict.reason}`,
      tenant: opts.tenant ?? null,
      issuedAt: Math.floor(Date.now() / 1000),
    });
    receipt.sign(opts.identity);
    await Promise.resolve(opts.sink.append(receipt));

    if (!verdict.allow) {
      if (opts.raiseOnDeny !== false) {
        throw new ToolDeniedError(name, verdict.reason);
      }
      // shadow-mode: emit warning, proceed.
      // (No console.warn — users may want silent shadow.)
    }

    return innerExecute(args, options);
  };

  return wrapped;
}
