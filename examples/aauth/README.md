<!-- SPDX-License-Identifier: Apache-2.0 -->
# An AAuth agent, verified against pinned provider keys

decern can establish its caller from an AAuth agent token
([`draft-hardt-oauth-aauth-protocol`](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)),
verified against the keys of an agent provider configured at startup. This example runs that
posture end to end with no agent provider and no network — `mint.py` writes the key set and
signs both the agent token and the request, so it works from a fresh checkout.

```
agent ──Signature-Key: sig=jwt;jwt="<aa-agent+jwt>"──▶ decern-serve ──▶ ledger
        Signature-Input: sig=("@method" "@authority"       (--aauth-provider
                          "@path" "content-digest"           ISS=jwks.json
                          "signature-key");created=…         --aauth-audience AUTHORITY)
        Content-Digest:  sha-256=:<SHA-256 of the body>:
        Signature:       sig=:<Ed25519 over the base>:
```

## Run it

```sh
examples/aauth/run.sh      # needs cargo, uv, jq, python3, curl
```

Thirteen asserted beats: a valid agent token allowed **as itself** and recorded; **the same
agent refused when asking as `corp`**; **the same token refused when the request is signed by
a different key**; **a POST refused for covering only the draft's own component list**; a
token from an unconfigured provider refused; a token signed by a key the pinned provider does
not hold refused; **a token whose header names the polymorphic `EdDSA` refused**; a signature
refused for age alone; **a request minted for a different deployment refused**; no
credentials refused; the deployment disclosing `mode: aauth` and `bind: self`; and the ledger
naming the agent decern verified.

## Which mode of AAuth this is

**Agent identity access** (§4.2.1 of draft -11), the resource's half: the resource applies its
own policy to a verified agent identity. Person identity access is not implemented.
Resource-managed access has the resource run its own authorization interaction, and PS
authorization and federated access need it to work with a Person Server's resource tokens.
decern runs no interaction and issues no token — it decides and records; it does not broker
consent.

## Where this deployment departs from the draft

Stated here rather than discovered as a `401`.

**The signature profile is draft -11's, narrowed in three ways an agent learns of only from a
response body.** The token's header names `Ed25519`, never the polymorphic `EdDSA` (beat 8);
every key names its `alg`, consistent with `kty` and `crv`; the token is taken from the
`Signature-Key` member under the signature's own label; the covered components need only include
the required ones, in any order; an `alg` signature parameter is not read and `expires` is
honoured; and `created` may be up to 60 seconds either side of this clock. The narrowings:
`content-digest` is required on a request with a body, below; `nonce` and `tag` signature
parameters are refused; and a `Signature-Key` carrying a second `jwt`-scheme member is refused,
so the label cannot choose the agent recorded. A signature failure other than clock skew carries
no `Signature-Error` code, and the response body is not problem details.
[`.agent/standards/registry.yaml`](../../.agent/standards/registry.yaml) lists every departure.

**Providers are pinned, never discovered.** The draft has a verifier discover the issuer's JWKS
at `{iss}/.well-known/{dwk}`. decern checks that `dwk` names that document and then selects a
key from a JWK Set the operator supplied — it makes no outbound request, because a decision must
not depend on a third party being reachable. That departs from the draft, which gives a resource
no such option, and the consequence is an interoperability limit: an agent whose provider this
deployment was never told about is refused before any cryptography runs (beat 6).

**`content-digest` is required on a request with a body.** The draft requires a resource's
requests to cover `@method`, `@authority`, `@path` and `signature-key`, and not the body. Every
AuthZEN evaluation is a POST, so accepting that list would mean one captured signature
authorizing any body at the same path. RFC 9421 §1.4 assigns component requirements to the
application profile, and the draft lets a resource require further components, so requiring the
digest is conformant rather than a departure. This deployment publishes no resource metadata,
and the refusal names the missing component only in its response body, which the draft tells an
agent not to depend on (§11.9.1).
An AAuth agent must sign it to talk to decern (beat 5).

## Why there is an `--aauth-audience`

An agent token carries no `aud` — the draft defines none. The only thing tying a request to a
destination is `@authority`, and that is the authority the caller sent — its `Host`, or the
target of an absolute-form request line — so on its own it binds the signature to a *claimed*
authority rather than to this server. Without a configured authority to compare against, a
correctly signed request from a pinned provider would verify at **any** deployment pinning the
same provider. `--aauth-audience` is therefore required, and the request's authority must equal
it. Beat 10 is that refusal.

## Why the token's own signature is verified here

The signed-request posture deliberately does *not* verify its bound token's own JWS: the token
travels inside `Signature-Key`, which the outer signature covers, and the deployment already
pins the agent's key, so a second check would establish nothing.

AAuth is the other shape. The token is the **provider's** assertion about which key the agent
holds, so the provider's signature over it is what makes `cnf` trustworthy. Without that check
a caller could mint itself any `sub` and any `cnf` and sign consistently. Beat 7 is that
refusal.

## What is recorded, and what is not

`asserted_by` carries the agent decern verified and the provider whose key verified it —
derived from the token, never from anything the request asserted about itself.

Two claims are deliberately *not* acted on:

- **`jti`** is required by the draft and shape-checked here, and the draft offers it for replay
  detection. decern has no nonce cache, so a captured request verifies again inside the
  freshness window — the same limit the signed-request posture states. The claim is not used
  for replay detection, and saying so is better than implying the purpose is honoured.
- **`parent_agent`** marks a sub-agent when present. It is the provider's assertion about a
  relationship this server cannot verify, so it is shape-checked and never reaches the kernel.

## What the keys here are

`mint.py` uses **fixed, public** Ed25519 seeds so the walkthrough is reproducible. Every reader
of the file holds the private keys, which is the loudest available way to say these requests
prove nothing outside this example. It is a key that signs, not an agent provider: there is no
metadata document, no `dwk` endpoint, and none will be added.

## What this shows, and what it does not

It shows that on the one request that was allowed, an agent proved possession of the key its
provider's token confirms, named only itself, covered the body it sent, and addressed this
deployment — and that the record says so.

It does not show that the agent is who its provider believes it is. decern accepts an agent
only if its provider's keys are configured here; the judgement about which provider to trust is
made before this binary starts, by whoever wrote the flag, and nothing here can audit that
choice.
