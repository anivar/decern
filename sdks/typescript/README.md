# decern TypeScript SDK

Dependency-free TypeScript client for the decern PDP, speaking
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) Access Evaluation.
Uses the global `fetch` — no axios/node-fetch/undici. Node >= 22.

## Install

```sh
npm install decern
```

## Usage

Start the PDP, then:

```ts
import { Client } from "decern";

const c = new Client({ baseUrl: "http://127.0.0.1:8080" });

const d = await c.evaluate({
  subject: { type: "Principal", id: "corp" },
  action: "Read", // or { name: "Read" }
  resource: { type: "Resource", id: "claim1" },
  context: { now: 100 }, // optional; PDP injects `now` if omitted
});

console.log(d.allowed); // true / false
console.log(d.reasons); // e.g. ["policy0"] on allow
console.log(d.errors); // e.g. ["no_policy"] on deny

await c.pubkey(); // ed25519 public key id (hex)
await c.healthy(); // true if /healthz == "ok"
```

Non-2xx responses and transport failures throw `DecernError`. Each request is
bounded by `timeoutMs` (default 5000) via an `AbortController`.

## Test

```sh
cd sdks/typescript
npm install
npm run build
npm test
```
