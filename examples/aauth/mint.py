# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
# SPDX-License-Identifier: Apache-2.0
#
# Builds one AAuth request for the walkthrough: an `aa-agent+jwt` agent token as an agent
# provider would mint it, plus the RFC 9421 headers proving possession of the key the
# token's `cnf` confirms over this exact request.
#
# Two differences from examples/signed-request/sign.py are worth knowing, because they are
# the differences between the two postures:
#
#   1. decern DOES verify this token's own signature, against the provider key it was
#      configured with. There the token is self-carried and the outer signature already
#      covers it; here the token is the provider's assertion about which key the agent
#      holds, so the provider's signature over it is what makes `cnf` trustworthy.
#   2. There is no `aud` claim — the draft defines none. What pins a request to one
#      deployment is `--aauth-audience` against the request's Host.
#
# decern's profile requires `content-digest` on a bodied request, which the draft's own
# example component list does not carry. --no-digest omits it, so the walkthrough can show
# that refusal rather than describe it.
#
# The seeds are FIXED and PUBLIC, like every other example here. That is the whole of their
# honesty: these are keys that sign, not an agent provider. There is no metadata document
# and none will be added — decern never fetches one.
#
#   uv run mint.py --jwks
#   uv run mint.py <agent-id> <method> <authority> <path> [--body JSON]
#                  [--wrong-key] [--wrong-provider] [--stale] [--no-digest] [--iss URL]
#
# Prints the provider JWK Set with --jwks, otherwise
# {"token", "signature_key", "signature_input", "signature", "content_digest"}.

import base64
import hashlib
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROVIDER = "https://agent-provider.example"
KID = "provider-key-1"
DWK = "aauth-agent.json"

# The agent's own key: the one `cnf` confirms and the one that signs the request.
AGENT_SEED = bytes([21] * 32)
# A caller who captured the token but cannot sign with the confirmed key.
ATTACKER_SEED = bytes([22] * 32)
# The agent provider's signing key. decern pins the public half.
PROVIDER_SEED = bytes([23] * 32)
# A provider decern was never configured with.
ROGUE_PROVIDER_SEED = bytes([24] * 32)

QUOTE = '"'


# RFC 9421 uses two different base64 alphabets, and reaching for the wrong one fails
# silently with a signature that simply does not verify:
#   - JWS segments and `cnf.jwk.x` / JWK `x` are base64url, UNPADDED
#   - the `Signature` header value and RFC 9530 Content-Digest are STANDARD base64,
#     PADDED, wrapped in colons
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64std(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


print("mint.py: fixed public demo keys, no agent provider, no TLS. Never deploy.", file=sys.stderr)

argv = sys.argv[1:]

# The key set an operator pins with --aauth-provider. `use: sig` and a `kid` are both
# present because decern requires a kid on every signing key it will select from.
if "--jwks" in argv:
    provider = Ed25519PrivateKey.from_private_bytes(PROVIDER_SEED)
    print(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "use": "sig",
                        "kid": KID,
                        "x": b64url(raw_pub(provider)),
                    }
                ]
            }
        )
    )
    sys.exit(0)

FLAGS = ("--wrong-key", "--wrong-provider", "--stale", "--no-digest")
wrong_key = "--wrong-key" in argv
wrong_provider = "--wrong-provider" in argv
stale = "--stale" in argv
no_digest = "--no-digest" in argv
body = None
if "--body" in argv:
    i = argv.index("--body")
    body = argv[i + 1]
    del argv[i : i + 2]
iss = PROVIDER
if "--iss" in argv:
    i = argv.index("--iss")
    iss = argv[i + 1]
    del argv[i : i + 2]
positional = [a for a in argv if a not in FLAGS]
agent_id, method, authority, path = positional

agent = Ed25519PrivateKey.from_private_bytes(AGENT_SEED)
signing_provider = Ed25519PrivateKey.from_private_bytes(
    ROGUE_PROVIDER_SEED if wrong_provider else PROVIDER_SEED
)

now = int(time.time())

# The agent token, per the draft's payload: `iss` names the provider, `dwk` names the
# metadata document (decern checks the name and never dereferences it), `sub` is the agent,
# `jti` is required, and `cnf.jwk` names the one key whose holder may present this token.
# Note the absence of `aud` — the draft defines none for an agent token.
header = {"typ": "aa-agent+jwt", "alg": "EdDSA", "kid": KID}
claims = {
    "iss": iss,
    "dwk": DWK,
    "sub": agent_id,
    "jti": f"demo-{now}",
    "iat": now,
    "exp": now + 3600,
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw_pub(agent))}},
}
h = b64url(json.dumps(header).encode())
p = b64url(json.dumps(claims).encode())
token = f"{h}.{p}.{b64url(signing_provider.sign(f'{h}.{p}'.encode()))}"

# The presentation the draft specifies. The whole header value is what the signature
# covers, so it is emitted verbatim and signed as-is.
signature_key = f'sig=jwt; jwt="{token}"'

label = "sig1"
method_u = method.upper()
content_digest = None
if method_u == "POST" and not no_digest:
    if body is None:
        sys.exit("POST requires --body so Content-Digest covers the bytes that will be sent")
    content_digest = f"sha-256=:{b64std(hashlib.sha256(body.encode()).digest())}:"
    components = ["@method", "@authority", "@path", "content-digest", "signature-key"]
    values = [method_u, authority.lower(), path, content_digest, signature_key]
else:
    # The draft's own component list. On a POST this is what decern's profile refuses.
    components = ["@method", "@authority", "@path", "signature-key"]
    values = [method_u, authority.lower(), path, signature_key]

component_list = " ".join(f"{QUOTE}{c}{QUOTE}" for c in components)
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
            "signature_key": signature_key,
            "signature_input": f"{label}={params}",
            "signature": f"{label}=:{b64std(signer.sign(base.encode()))}:",
            "content_digest": content_digest,
        }
    )
)
