# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
# SPDX-License-Identifier: Apache-2.0
#
# A stand-in issuer for the walkthrough: signs RFC 9068 access tokens with a FIXED,
# PUBLIC Ed25519 key so the demo is reproducible. That is the whole of its honesty:
# it is a key that signs, not an authorization server. There is no metadata document,
# no token endpoint, no client authentication, and none will be added — a working
# stand-in /token endpoint is exactly the thing someone ships.
#
#   uv run mint.py <sub> <aud> [scope ...]
#
# Prints {"token": ..., "pub_hex": ...} on stdout; the warning goes to stderr.

import base64
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ISSUER = "https://issuer.example/"

# Fixed demo seed. Deliberately public: every reader of this file holds the private
# key, which is the loudest possible way to say these tokens prove nothing outside
# this walkthrough.
DEMO_SEED = bytes([7] * 32)

print("mint.py: demo issuer — fixed public key, no TLS, no endpoints. Never deploy.", file=sys.stderr)

sub, aud, *scopes = sys.argv[1:]
key = Ed25519PrivateKey.from_private_bytes(DEMO_SEED)
pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


now = int(time.time())
claims = {
    "iss": ISSUER,
    "aud": aud,
    "sub": sub,
    "client_id": "mcp-demo-client",
    "iat": now,
    "exp": now + 3600,
    "jti": f"demo-{now}",
}
if scopes:
    claims["scope"] = " ".join(scopes)

header = b64(json.dumps({"typ": "at+jwt", "alg": "EdDSA"}).encode())
payload = b64(json.dumps(claims).encode())
signature = key.sign(f"{header}.{payload}".encode())
print(json.dumps({"token": f"{header}.{payload}.{b64(signature)}", "pub_hex": pub.hex()}))
