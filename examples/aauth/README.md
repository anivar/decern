<!-- SPDX-License-Identifier: Apache-2.0 -->
# An AAuth agent, verified against pinned provider keys

decern can establish its caller from an AAuth agent token
([`draft-hardt-oauth-aauth-protocol`](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)),
verified against the keys of an agent provider configured at startup. This example runs that
posture end to end with no agent provider and no network — `mint.py` writes the key set and
signs both the agent token and the request, so it works from a fresh checkout.

```
agent ──Signature-Key: sig=jwt; jwt="<aa-agent+jwt>"──▶ decern-serve ──▶ ledger
        Signature-Input: ("@method" "@authority" "@path"   (--aauth-provider
                          "content-digest" "signature-key")  ISS=jwks.json
        Content-Digest:  sha-256=:<SHA-256 of the body>:     --aauth-audience HOST)
        Signature:       sig1=:<Ed25519 over the base>:
```

## Run it

```sh
examples/aauth/run.sh      # needs cargo, uv, jq, python3, curl
```

Twelve asserted beats: a valid agent token allowed **as itself** and recorded; **the same
agent refused when asking as `corp`**; **the same token refused when the request is signed by
a different key**; **a POST refused for covering only the draft's own component list**; a
token from an unconfigured provider refused; a token signed by a key the pinned provider does
not hold refused; a signature refused for age alone; **a request minted for a different
deployment refused**; no credentials refused; the deployment disclosing `mode: aauth` and
`bind: self`; and the ledger naming the agent decern verified.

## Which mode of AAuth this is

**Identity-based access**, the mode where the resource applies its own policy to a verified
agent identity and no Person Server is involved. The PS-asserted and federated modes require a
Person Server, which decern does not implement and does not intend to — it decides and records;
it does not broker consent.

## Two things this deployment does that the draft does not require

Both are stated here rather than discovered as a `401`.

**Providers are pinned, never discovered.** The draft's verification list says to discover the
issuer's JWKS at `{iss}/.well-known/{dwk}`. decern checks that `dwk` names that document and
then selects a key from a JWK Set the operator supplied — it makes no outbound request, because
a decision must not depend on a third party being reachable. The draft contemplates exactly
this where it notes that a resource pre-caching a provider's keys does not need the fetch. The
consequence is a real interoperability limit: an agent whose provider this deployment was never
told about is refused before any cryptography runs (beat 6).

**`content-digest` is required on a request with a body.** The draft's example component list
covers `@method`, `@authority`, `@path` and `signature-key`, and not the body. Every AuthZEN
evaluation is a POST, so accepting that list would mean one captured signature authorizing any
body at the same path — the defect decern closed in 0.3.0. RFC 9421 §1.4 assigns component
requirements to the application profile, so requiring the digest is conformant rather than a
departure. An AAuth agent must sign it to talk to decern (beat 5).

## Why there is an `--aauth-audience`

An agent token carries no `aud` — the draft defines none. The only thing tying a request to a
destination is `@authority`, and that is the `Host` the caller sent, so on its own it binds the
signature to a *claimed* authority rather than to this server. Without a configured authority
to compare against, a correctly signed request from a pinned provider would verify at **any**
deployment pinning the same provider. `--aauth-audience` is therefore required, and the `Host`
must equal it. Beat 9 is that refusal.

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
