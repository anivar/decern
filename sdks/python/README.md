# decern — Python client

[![PyPI](https://anivar.net/badge?src=pypi&name=decern)](https://pypi.org/project/decern/)
[![License](https://anivar.net/badge?label=license&value=Apache-2.0)](https://github.com/anivar/decern/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21848620.svg)](https://doi.org/10.5281/zenodo.21848620)

[Website](https://decern.anivar.net/) · [Repository](https://github.com/anivar/decern) ·
[Commands](https://github.com/anivar/decern/blob/main/docs/CLI.md) ·
[Issues](https://github.com/anivar/decern/issues)

Ask whether an action is allowed, and get an answer somebody can check afterwards.
Standard library only — no `requests`, no `httpx`. Python ≥ 3.11.

```sh
uv add decern
# and a server to ask:
cargo install decern-server && decern-serve --trust-proxy
```

```python
from decern import Client

c = Client("http://127.0.0.1:8080")

d = c.evaluate(
    subject={"type": "Principal", "id": "corp"},
    action="Read",  # or {"name": "Read"}
    resource={"type": "Resource", "id": "claim1"},
)

d.allowed   # True / False
d.reasons   # the policies that decided it, on allow
d.errors    # why not, on deny
```

Also on the client: `c.pubkey()` (the Ed25519 key id the log is signed with) and
`c.healthy()`. A non-2xx response or transport failure raises `DecernError` with the HTTP
status and body, so a denial is distinguishable from a misconfigured endpoint. `context` is
advisory — the server overrides anything it derives itself (the clock, the accountable
owner), so a caller cannot talk its way into a decision by supplying them.

## What the server gives you

[decern](https://github.com/anivar/decern) is an [AuthZEN
1.0](https://openid.net/specs/authorization-api-1_0.html) authorization server whose safety
rules are machine-checked over every input, and whose decisions land in an append-only,
signed, hash-chained log **before** they are served — a decision that cannot be recorded is
refused, and a third party can verify what was decided without trusting the operator:

```sh
decern verify --ledger <file> --pubkey <key>   # the chain and every signature
decern explain --ledger <file> --seq 12        # one decision, in full
```

Obtain the public key out of band; a key handed over by the party being audited
establishes nothing.

## Test

```sh
cd sdks/python && python -m unittest discover -v
```

Apache-2.0. Published from CI by OIDC with no stored credential.
