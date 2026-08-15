# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
# SPDX-License-Identifier: Apache-2.0
#
# A stand-in SPIFFE issuer for the walkthrough: writes a trust bundle and mints ES256
# JWT-SVIDs against it, so the example runs with no SPIRE daemon and no network.
#
# Like examples/mcp/mint.py, the key is FIXED and PUBLIC so the walkthrough is
# reproducible. That is the whole of its honesty: it is a key that signs, not a SPIFFE
# control plane. There is no attestation, no Workload API, and none will be added —
# a working stand-in issuer is exactly the thing someone ships by mistake.
#
#   uv run mint.py bundle <path> [--second-key]
#   uv run mint.py svid <spiffe-id> <audience> [--kid K] [--expired] [--alg A] [--no-kid]
#
# `bundle` writes the JWK Set. `svid` prints the token on stdout.

import base64
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

print("mint.py: fixed public demo key, no attestation, no TLS. Never deploy.", file=sys.stderr)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# Fixed demo scalars. Deliberately public — every reader of this file holds them.
def key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


KEYS = {"k1": key(0x5EED01), "k2": key(0x5EED02)}


def jwk(kid: str) -> dict:
    nums = KEYS[kid].public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        # SPIFFE JWT-SVID §6.1: every bundle entry sets `use` to `jwt-svid` and carries a
        # `kid`. decern refuses a bundle that does not, at startup rather than at request
        # time.
        "use": "jwt-svid",
        "kid": kid,
        "x": b64(nums.x.to_bytes(32, "big")),
        "y": b64(nums.y.to_bytes(32, "big")),
    }


def sign_es256(k: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    # JOSE wants the raw r||s pair; `cryptography` returns DER, so unpack it. Getting this
    # wrong yields a signature that simply never verifies.
    r, s = decode_dss_signature(k.sign(msg, ec.ECDSA(SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


cmd, *rest = sys.argv[1:]

if cmd == "bundle":
    path = rest[0]
    kids = ["k1", "k2"] if "--second-key" in rest else ["k1"]
    with open(path, "w") as f:
        json.dump({"keys": [jwk(k) for k in kids]}, f)
    print(json.dumps({"bundle": path, "kids": kids}))

elif cmd == "svid":
    flags = [a for a in rest if a.startswith("--")]
    args = [a for a in rest if not a.startswith("--")]
    spiffe_id, audience = args[0], args[1]

    kid = "k1"
    if "--kid" in rest:
        kid = rest[rest.index("--kid") + 1]

    header = {"alg": "ES256", "kid": kid}
    if "--no-kid" in flags:
        del header["kid"]
    if "--alg" in rest:
        header["alg"] = rest[rest.index("--alg") + 1]

    now = int(time.time())
    # §3.1-3.3: sub, aud and exp are the required claims. No `iss` — the spec does not
    # mandate one, and decern derives the issuer from the verified trust domain instead.
    claims = {
        "sub": spiffe_id,
        "aud": audience,
        "exp": now - 60 if "--expired" in flags else now + 3600,
    }
    h = b64(json.dumps(header).encode())
    p = b64(json.dumps(claims).encode())
    signing_kid = kid if kid in KEYS else "k1"
    print(f"{h}.{p}.{b64(sign_es256(KEYS[signing_kid], f'{h}.{p}'.encode()))}")

else:
    print(f"unknown command {cmd}", file=sys.stderr)
    sys.exit(2)
