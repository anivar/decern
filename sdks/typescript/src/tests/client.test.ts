// SPDX-License-Identifier: Apache-2.0
// Tests for the decern client. No network/server required.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Client, DecernError } from "../index.js";

interface Call {
  url: string;
  init: RequestInit;
}

/** A fake fetch recording calls and returning a queued response. */
function fakeFetch(
  status: number,
  raw: string,
  calls: Call[],
): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? "OK" : "Error",
      text: async () => raw,
    };
  }) as unknown as typeof fetch;
}

function clientWith(status: number, raw: string): { c: Client; calls: Call[] } {
  const calls: Call[] = [];
  const c = new Client({ fetch: fakeFetch(status, raw, calls) });
  return { c, calls };
}

test("builds exact AuthZEN body: string action wrapped, context included", async () => {
  const { c, calls } = clientWith(200, '{"decision": true}');
  await c.evaluate({
    subject: { type: "Principal", id: "corp" },
    action: "Read",
    resource: { type: "Resource", id: "claim1" },
    context: { now: 100 },
  });
  assert.equal(calls[0].init.method, "POST");
  assert.ok(calls[0].url.endsWith("/access/v1/evaluation"));
  assert.deepEqual(JSON.parse(calls[0].init.body as string), {
    subject: { type: "Principal", id: "corp" },
    action: { name: "Read" },
    resource: { type: "Resource", id: "claim1" },
    context: { now: 100 },
  });
});

test("dict action passthrough and context omitted when undefined", async () => {
  const { c, calls } = clientWith(200, '{"decision": false}');
  await c.evaluate({
    subject: { type: "Principal", id: "corp" },
    action: { name: "Write", extra: 1 },
    resource: { type: "Resource", id: "r" },
  });
  const body = JSON.parse(calls[0].init.body as string);
  assert.deepEqual(body.action, { name: "Write", extra: 1 });
  assert.ok(!("context" in body));
});

test("allow with reasons", async () => {
  const { c } = clientWith(200, JSON.stringify({ decision: true, context: { reasons: ["policy0"] } }));
  const d = await c.evaluate({ subject: { id: "a" }, action: "Read", resource: { id: "b" } });
  assert.equal(d.allowed, true);
  assert.deepEqual(d.reasons, ["policy0"]);
  assert.deepEqual(d.errors, []);
});

test("deny with errors", async () => {
  const { c } = clientWith(200, JSON.stringify({ decision: false, context: { errors: ["no_policy"] } }));
  const d = await c.evaluate({ subject: { id: "a" }, action: "Read", resource: { id: "b" } });
  assert.equal(d.allowed, false);
  assert.deepEqual(d.errors, ["no_policy"]);
  assert.deepEqual(d.reasons, []);
});

test("bare decision leaves context undefined", async () => {
  const { c } = clientWith(200, '{"decision": true}');
  const d = await c.evaluate({ subject: { id: "a" }, action: "Read", resource: { id: "b" } });
  assert.equal(d.allowed, true);
  assert.equal(d.context, undefined);
});

test("non-2xx throws DecernError", async () => {
  const { c } = clientWith(500, "boom");
  await assert.rejects(
    () => c.evaluate({ subject: { id: "a" }, action: "Read", resource: { id: "b" } }),
    DecernError,
  );
});

test("pubkey returns kid", async () => {
  const { c } = clientWith(200, '{"kid": "deadbeef"}');
  assert.equal(await c.pubkey(), "deadbeef");
});

test("healthy true on ok", async () => {
  const { c } = clientWith(200, "ok");
  assert.equal(await c.healthy(), true);
});

test("healthy false on bad body", async () => {
  const { c } = clientWith(200, "nope");
  assert.equal(await c.healthy(), false);
});

test("healthy false on transport error", async () => {
  const { c } = clientWith(503, "down");
  assert.equal(await c.healthy(), false);
});
