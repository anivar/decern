<!-- SPDX-License-Identifier: Apache-2.0 -->
# A caller identified by a SPIFFE JWT-SVID

decern can establish its caller from a [SPIFFE](https://spiffe.io) JWT-SVID, verified
against a trust bundle pinned at startup. This example runs that posture end to end with
no SPIRE daemon and no network — `mint.py` writes the bundle and signs the SVIDs, so the
walkthrough works from a fresh checkout.

```
workload ──Authorization: Bearer <JWT-SVID>──▶ decern-serve ──▶ ledger
           sub: spiffe://example.org/ns/…      (--spiffe-trust-domain
                                                 example.org=bundle.json)
```

## Run it

```sh
examples/spiffe/run.sh      # needs cargo, uv, jq, python3, curl
```

Eleven beats: a valid SVID allowed **asking about itself** and recorded; **the same SVID
refused when asking as `corp`**; **the same SVID refused when approving a Mission as
`corp`**; an SVID from a trust domain that merely *looks* like the configured one refused;
an RS256 SVID refused on the algorithm; an expired SVID refused; an SVID minted for another
service refused; a missing credential answered with the RFC 6750 challenge; the deployment
disclosing its trust domains and `bind: self`; and the ledger naming the workload decern
verified.

## Two things worth knowing before you deploy this

**`ES256` only, and that is a real interoperability limit.** JWT-SVID permits nine
algorithms. `RS*` and `PS*` need the `rsa` crate, which carries
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) — a timing
side-channel that can recover the private key, **with no patched version**. decern's
supply-chain gate runs with no advisory exceptions, so admitting RSA would mean writing one
for a known key-recovery bug. A SPIRE deployment issuing RSA SVIDs will not work here.
That is a genuine limit, and it is stated rather than softened.

**A workload speaks only for itself.** Like a signed-request agent, a verified SVID may
only name itself as AuthZEN `subject`, mission `approver`, stored approver on terminate, and
directory principal — unless it is listed in `--pep`. A mismatch is `403 caller_mismatch`.
Without this the posture would reopen an escalation the signed-request posture already
closes: any valid SVID could mint a Mission under someone else's authority.

**Recorded, never minted — which is not the same as never declared.** decern does not create
a principal for a verified SVID: `spiffe://` is a reserved namespace in decern's identity
crate, held for a verified-provenance mint path that does not exist. But an **operator** may
declare a principal whose id *is* a SPIFFE ID, which is exactly what this example's model
does, and is what lets the workload Allow when asking about itself. Against a model that
declares no SPIFFE principals — the builtin, for one — this posture is fail-closed by
construction: every subject it is permitted to name is unknown, so every decision denies.

## Where the record's `iss` comes from

JWT-SVID requires only `sub`, `aud` and `exp` — there is no mandatory `iss` claim. So the
issuer on the record is derived from the trust domain inside the **verified** `sub`, never
read from the token. A caller cannot name its own issuer.

## What the keys here are

`mint.py` uses **fixed, public** P-256 scalars so the walkthrough is reproducible. Every
reader of the file holds the private keys, which is the loudest available way to say these
SVIDs prove nothing outside this example. It is a key that signs, not a SPIFFE control
plane: there is no attestation, no Workload API, and none will be added.
