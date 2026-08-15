<!-- SPDX-License-Identifier: Apache-2.0 -->
# A caller that proves possession of its key on every request

decern's bearer mode (`--bearer-issuer`) verifies an RFC 9068 access token: a real check,
but a *bearer* check. Whoever holds the bytes may use them until they expire, so a token
captured in a log, a proxy, or a crash dump is replayable as-is by whoever captured it.

This example runs the other mode. `--signed-agent-key` requires an
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message Signature over the
request itself, made with the key an
[RFC 7800](https://www.rfc-editor.org/rfc/rfc7800.html) `cnf` claim binds to the presented
token. Holding the token is no longer sufficient — the caller must sign *this* request,
now, with the key the token confirms.

```
agent ──Signature-Key:   <token bound to a key via cnf.jwk>──▶ decern-serve ──▶ ledger
        Signature-Input: ("@method" "@authority" "@path"       (--signed-agent-key
                          "content-digest" "signature-key");    agent-1=<hex>)
                         created=…   [content-digest on POST]
        Content-Digest:  sha-256=:<SHA-256 of the body>:
        Signature:       sig1=:<Ed25519 over the base>:
```

The token travels in `Signature-Key`, per
[`draft-hardt-httpbis-signature-key`](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/),
and is itself one of the covered components — so tampering with any claim inside it
invalidates the outer signature. That is why decern does not separately verify the token's
own JWS signature: the outer signature already covers it, and a second check would prove
nothing the first does not. POST also covers `content-digest` (RFC 9530, `sha-256` of the
body bytes the handler will see), so a captured signature over one JSON body cannot
authorize a different one at the same path. GET is unchanged: it has no body to cover.
Verbatim replay of the *same* captured signature (same path, same body) is not separately
prevented — no nonce cache — and verifies again within the freshness window.

## Run it

```sh
examples/signed-request/run.sh      # needs cargo, uv, jq, python3, curl
```

Nine beats: a correctly signed request allowed and recorded; **the same token refused when
the signature comes from a different key**; a signature refused for age alone; the same
signature refused when replayed against a different path; **the same signature refused when
replayed against a different body**; no credentials refused; the deployment disclosing its
own caller posture; and the ledger naming the caller the server verified.

Beat 3 is the one worth reading twice. The token there is byte-identical to the one that
just succeeded — same `sub`, same `aud`, same `cnf`, unexpired. Only the signature differs,
because the caller holds the token but not the private key it confirms. A bearer credential
would accept that request. This mode refuses it, and that difference is the entire point.

## What the keys here are

`sign.py` uses **fixed, public** Ed25519 seeds so the walkthrough is reproducible. Every
reader of the file holds the private keys, which is the loudest available way to say these
requests prove nothing outside this example. It is a key that signs, not an issuer: there
is no metadata document, no token endpoint, and none will be added.

## What this shows, and what it does not

It shows that on the one request that was allowed, the caller proved possession of a
configured key, and that the record says so — `asserted_by` carries the identity the
server itself verified, not one the request asserted about itself.

It does not show that `agent-1` is who its operator believes it is. decern accepts an
identifier only if that identifier already has a key in `--signed-agent-key`; keys are
configured, never fetched, so a decision never waits on a third party being reachable. The
judgement about *which* key belongs to *which* agent is made before this binary starts, by
whoever wrote the flag — and nothing here can audit that choice.
