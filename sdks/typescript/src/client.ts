// SPDX-License-Identifier: Apache-2.0
// AuthZEN 1.0 Access Evaluation client for the decern PDP.

/** An AuthZEN entity, e.g. {@code {type: "Principal", id: "corp"}}. */
export interface Entity {
  type?: string;
  id?: string;
  [k: string]: unknown;
}

/** An action: a bare name, or an object like {@code {name: "Read"}}. */
export type Action = string | { name?: string; [k: string]: unknown };

/** The parsed outcome of an evaluation. */
export interface Decision {
  allowed: boolean;
  reasons: string[];
  errors: string[];
  context?: Record<string, unknown>;
}

/** Arguments to {@link Client.evaluate}. */
export interface EvaluateArgs {
  subject: Entity;
  action: Action;
  resource: Entity;
  context?: Record<string, unknown>;
}

export interface ClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  /** Injectable fetch (for tests); defaults to the global fetch. */
  fetch?: typeof fetch;
}

const MAX_ERROR_BODY_LEN = 512;

// Caps how much of a non-2xx response body the client buffers. base_url can
// point at an intermediary (see deployment guidance), so an error body's
// size isn't bounded by decern-serve's own behavior.
const MAX_ERROR_BODY_BYTES = 64 * 1024; // 64 KiB

/** Transport failure or non-2xx response from the PDP. */
export class DecernError extends Error {
  readonly status?: number;
  readonly body?: string;
  /** True when `body` was cut off at MAX_ERROR_BODY_BYTES. */
  readonly truncated?: boolean;

  constructor(message: string, status?: number, body?: string, truncated?: boolean) {
    super(message);
    this.name = "DecernError";
    this.status = status;
    this.body = body;
    this.truncated = truncated;
  }
}

// Reads at most maxBytes of a response body, decoding as UTF-8, and cancels
// the stream once the cap is hit instead of buffering the rest. Falls back
// to a full read when the runtime's fetch doesn't expose a streamable body.
async function readCapped(res: Response, maxBytes: number): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) {
    return { text: await res.text(), truncated: false };
  }

  const decoder = new TextDecoder();
  let text = "";
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    if (total + value.length > maxBytes) {
      text += decoder.decode(value.subarray(0, maxBytes - total), { stream: true });
      total = maxBytes;
      await reader.cancel();
      text += decoder.decode();
      return { text, truncated: true };
    }

    text += decoder.decode(value, { stream: true });
    total += value.length;
  }

  text += decoder.decode();
  return { text, truncated: false };
}

function buildHttpError(
  method: string,
  path: string,
  res: Response,
  raw: string,
  bodyTruncated: boolean,
): DecernError {
  const bodyStr = raw.trim();
  let trunc = bodyStr;
  let truncated = bodyTruncated;
  if (bodyStr.length > MAX_ERROR_BODY_LEN) {
    const cps = Array.from(bodyStr);
    if (cps.length > MAX_ERROR_BODY_LEN) {
      trunc = cps.slice(0, MAX_ERROR_BODY_LEN).join("");
      truncated = true;
    }
  }
  if (truncated) trunc += "...";
  const msg = bodyStr
    ? `${method} ${path} -> ${res.status} ${res.statusText}: ${trunc}`
    : `${method} ${path} -> ${res.status} ${res.statusText}`;
  return new DecernError(msg, res.status, raw, truncated);
}

/** Client for a decern PDP speaking AuthZEN 1.0 Access Evaluation. */
export class Client {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  fetch: typeof fetch;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "http://127.0.0.1:8080").replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.fetch = opts.fetch ?? globalThis.fetch;
  }

  private async request(method: string, path: string, body?: unknown): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetch(this.baseUrl + path, {
        method,
        headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (!res.ok) {
        const { text: raw, truncated } = await readCapped(res, MAX_ERROR_BODY_BYTES);
        throw buildHttpError(method, path, res, raw, truncated);
      }
      return await res.text();
    } catch (e) {
      if (e instanceof DecernError) throw e;
      throw new DecernError(`${method} ${path} failed: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  async evaluate({ subject, action, resource, context }: EvaluateArgs): Promise<Decision> {
    const act = typeof action === "string" ? { name: action } : action;
    const body: Record<string, unknown> = { subject, action: act, resource };
    if (context !== undefined) body.context = context;

    const resp = JSON.parse(await this.request("POST", "/access/v1/evaluation", body)) as {
      decision?: boolean;
      context?: Record<string, unknown>;
    };
    const ctx = resp.context ?? undefined;
    const reasons = ctx && Array.isArray(ctx.reasons) ? (ctx.reasons as string[]) : [];
    const errors = ctx && Array.isArray(ctx.errors) ? (ctx.errors as string[]) : [];
    return { allowed: Boolean(resp.decision), reasons, errors, context: ctx };
  }

  async pubkey(): Promise<string> {
    return (JSON.parse(await this.request("GET", "/pubkey")) as { kid: string }).kid;
  }

  async healthy(): Promise<boolean> {
    try {
      return (await this.request("GET", "/healthz")).trim() === "ok";
    } catch {
      return false;
    }
  }
}
