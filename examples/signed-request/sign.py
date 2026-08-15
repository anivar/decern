# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
# SPDX-License-Identifier: Apache-2.0
#
# Builds one sender-constrained request for the walkthrough: a key-bound access token
# (RFC 7800 `cnf`) plus the RFC 9421 headers that prove possession of that key over
# this exact request. POST also emits Content-Digest (RFC 9530, sha-256) and covers
# it, so a captured signature over one body cannot authorize a different one.
#
# Like examples/mcp/mint.py, the seeds here are FIXED and PUBLIC so the walkthrough is
# reproducible. That is the whole of its honesty: these are keys that sign, not an
# issuer. There is no token endpoint and none will be added.
#
#   uv run sign.py <agent-id> <audience> <method> <authority> <path> [--body JSON]
#                  [--wrong-key] [--stale]
#
# --body is required for POST (the bytes hashed into Content-Digest). GET ignores it.
# --wrong-key signs the request with a key that is NOT the one the token confirms, which
# is exactly what a caller who stole the token but not the private key could produce.
# --stale backdates `created` past the acceptance window, so an otherwise perfect
# signature is refused for age alone.
# Prints {"token", "pub_hex", "signature_input", "signature", "content_digest"} on stdout.
# content_digest is null for GET.

import base64
import hashlib
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISSUER = "https://agent-provider.example/"

# The agent's own key. Deliberately public: every reader of this file holds it, which is
# the loudest possible way to say these requests prove nothing outside this walkthrough.
AGENT_SEED = bytes([11] * 32)
# A second key, used only by --wrong-key. Stands in for a caller who replayed a token
# they captured but cannot sign with.
ATTACKER_SEED = bytes([12] * 32)
# The token issuer's key. Separate from the agent's on purpose: in a real deployment an
# identity provider signs the token, and the agent only holds the confirmed key.
ISSUER_SEED = bytes([13] * 32)

QUOTE = '"'


# RFC 9421 uses TWO different base64 alphabets here, and reaching for the wrong one fails
# silently with a signature that simply does not verify:
#   - the JWS segments and the `cnf.jwk.x` key material are base64url, UNPADDED
#   - the `Signature` header's value, and RFC 9530 Content-Digest, are STANDARD base64,
#     PADDED, wrapped in colons
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64std(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


print("sign.py: fixed public demo keys, no issuer, no TLS. Never deploy.", file=sys.stderr)

FLAGS = ("--wrong-key", "--stale")
argv = sys.argv[1:]
wrong_key = "--wrong-key" in argv
stale = "--stale" in argv
body = None
if "--body" in argv:
    i = argv.index("--body")
    body = argv[i + 1]
    del argv[i : i + 2]
positional = [a for a in argv if a not in FLAGS]
agent_id, audience, method, authority, path = positional

agent = Ed25519PrivateKey.from_private_bytes(AGENT_SEED)
issuer = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED)
agent_pub = agent.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

now = int(time.time())

# The token binds an identity to a key: `sub` names the agent, and `cnf.jwk` names the ONE
# public key whose holder may present this token (RFC 7800 §3.2).
header = {"typ": "dpop-bound+jwt", "alg": "EdDSA"}
claims = {
    "sub": agent_id,
    "iss": ISSUER,
    "aud": audience,
    "iat": now,
    "exp": now + 3600,
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(agent_pub)}},
}
h = b64url(json.dumps(header).encode())
p = b64url(json.dumps(claims).encode())
# decern never verifies this inner signature, deliberately — the token travels verbatim
# inside `Signature-Key`, which is itself a component covered by the outer signature, so
# tampering with any claim invalidates that outer signature. It is signed here anyway
# because a real issuer would sign it, and an example that skipped it would teach the
# wrong shape.
token = f"{h}.{p}.{b64url(issuer.sign(f'{h}.{p}'.encode()))}"

# RFC 9421 §2.5 signature base: one `"name": value` line per covered component, then the
# `"@signature-params"` line, with NO trailing newline after it. `@method` is uppercased
# and `@authority` lowercased, per §2.2.1 and §2.2.3.
label = "sig1"
method_u = method.upper()
content_digest = None
if method_u == "POST":
    if body is None:
        sys.exit("POST requires --body so Content-Digest covers the bytes that will be sent")
    content_digest = f"sha-256=:{b64std(hashlib.sha256(body.encode()).digest())}:"
    components = ["@method", "@authority", "@path", "content-digest", "signature-key"]
    values = [method_u, authority.lower(), path, content_digest, token]
else:
    components = ["@method", "@authority", "@path", "signature-key"]
    values = [method_u, authority.lower(), path, token]

component_list = " ".join(f"{QUOTE}{c}{QUOTE}" for c in components)
# A signature proves possession for ONE request, so it is accepted only briefly after
# `created`. --stale backdates past that window on purpose.
created = now - 3600 if stale else now
params = f"({component_list});created={created}"

lines = [f"{QUOTE}{name}{QUOTE}: {value}" for name, value in zip(components, values)]
lines.append(f"{QUOTE}@signature-params{QUOTE}: {params}")
base = "\n".join(lines)

signer = Ed25519PrivateKey.from_private_bytes(ATTACKER_SEED if wrong_key else AGENT_SEED)

print(
    json.dumps(
        {
            "token": token,
            # The hex the server pins with --signed-agent-key. Always the AGENT's key,
            # never the attacker's: --wrong-key changes who signs, not who is trusted.
            "pub_hex": agent_pub.hex(),
            "signature_input": f"{label}={params}",
            "signature": f"{label}=:{b64std(signer.sign(base.encode()))}:",
            "content_digest": content_digest,
        }
    )
)
