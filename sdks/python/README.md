# decern Python SDK

Dependency-free Python client for the decern PDP, speaking
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) Access Evaluation.
Standard library only — no `requests`/`httpx`.

## Install

```sh
uv pip install .
```

## Usage

Start the PDP:

```sh
decern-serve
```

Then:

```python
from decern import Client

c = Client("http://127.0.0.1:8080")

d = c.evaluate(
    subject={"type": "Principal", "id": "corp"},
    action="Read",  # or {"name": "Read"}
    resource={"type": "Resource", "id": "claim1"},
    context={"now": 100},  # optional; PDP injects `now` if omitted
)

print(d.allowed)   # True / False
print(d.reasons)   # e.g. ["policy0"] on allow
print(d.errors)    # e.g. ["no_policy"] on deny

c.pubkey()   # ed25519 public key id (hex)
c.healthy()  # True if /healthz == "ok"
```

## Test

```sh
cd sdks/python
python -m unittest discover -v
```
