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

/** Transport failure or non-2xx response from the PDP. */
export class DecernError extends Error {
  readonly status?: number;
  readonly body?: string;

  constructor(message: string, status?: number, body?: string) {
    super(message);
    this.name = "DecernError";
    this.status = status;
    this.body = body;
  }
}

function buildHttpError(method: string, path: string, res: Response, raw: string): DecernError {
  const bodyStr = raw.trim();
  let trunc = bodyStr;
  if (bodyStr.length > MAX_ERROR_BODY_LEN) {
    const cps = Array.from(bodyStr);
    if (cps.length > MAX_ERROR_BODY_LEN) {
      trunc = cps.slice(0, MAX_ERROR_BODY_LEN).join("") + "...";
    }
  }
  const msg = bodyStr
    ? `${method} ${path} -> ${res.status} ${res.statusText}: ${trunc}`
    : `${method} ${path} -> ${res.status} ${res.statusText}`;
  return new DecernError(msg, res.status, raw);
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
      const raw = await res.text();
      if (!res.ok) {
        throw buildHttpError(method, path, res, raw);
      }
      return raw;
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
