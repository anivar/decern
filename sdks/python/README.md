# decern — Python client

[![PyPI](https://img.shields.io/pypi/v/decern?color=0E7C6B)](https://pypi.org/project/decern/)
[![License](https://img.shields.io/badge/license-Apache--2.0-0E7C6B)](https://github.com/anivar/decern/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21848620.svg)](https://doi.org/10.5281/zenodo.21848620)

[Website](https://decern.anivar.net/) · [Repository](https://github.com/anivar/decern) ·
[Commands](https://github.com/anivar/decern/blob/main/docs/CLI.md) ·
[Issues](https://github.com/anivar/decern/issues)

Ask whether an action is allowed, and get an answer somebody can check afterwards.

[decern](https://github.com/anivar/decern) is an authorization server: your application asks it
"may this subject do this action to this resource?", it answers, and it writes that decision to an
append-only, signed log. The point of the log is that a third party — an auditor, the person the
decision was about — can verify what was decided without trusting whoever ran the server. A
decision that cannot be recorded is refused rather than allowed.

This package is the Python client for that server. It speaks
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) Access Evaluation using the
standard library only — no `requests`, no `httpx`. Python >= 3.11.

## Install

```sh
uv add decern
```

You also need a running server. From the same project:

```sh
cargo install decern-server && decern-serve
```

## Usage

```python
from decern import Client

c = Client("http://127.0.0.1:8080")

d = c.evaluate(
    subject={"type": "Principal", "id": "corp"},
    action="Read",  # or {"name": "Read"}
    resource={"type": "Resource", "id": "claim1"},
    context={"now": 100},  # optional; the server injects `now` if omitted
)

d.allowed   # True / False
d.reasons   # the policies that decided it, on allow
d.errors    # why not, on deny

c.pubkey()   # the ed25519 key id the log is signed with
c.healthy()  # True if /healthz is ok
```

`context` is advisory. The server overrides anything it derives itself — the clock, the
accountable owner — so a caller cannot talk its way into a decision by supplying them.

A non-2xx response or a transport failure raises `DecernError`, carrying the HTTP status and the
response body so a denial is distinguishable from a misconfigured endpoint.

## Verifying what was decided

The client asks questions; checking the answers is the server's CLI:

```sh
decern verify --ledger <file> --pubkey <key>   # the chain and every signature
decern explain --ledger <file> --seq 12        # one decision, in full
```

Obtain the public key out of band. A verification against a key handed over by the party being
audited establishes nothing.

## Releases

Published from CI by OIDC with no stored credential.

## Test

```sh
cd sdks/python
python -m unittest discover -v
```

Apache-2.0.
