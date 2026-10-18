"""Shared fixtures for the OIDC API tests: an issuer key, its JWKS and tokens."""

import time
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://iam.aslamel.net/auth/v1/"
UI_ORIGIN = "https://cognee.int.aslamel.net"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWKS = {
    "keys": [
        {
            **RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True),
            "kid": "test-k1",
            "alg": "RS256",
            "use": "sig",
        }
    ]
}

ENV_FILE = Path(__file__).with_name("oidc.env")
OIDC_ENV = dict(
    line.split("=", 1)
    for line in ENV_FILE.read_text().splitlines()
    if line and not line.startswith("#")
)


async def fake_fetch_jwks(url):
    assert url == f"{ISSUER}oidc/certs"
    return JWKS


def mint(groups, sub=None, email=None, typ="Bearer", aud="cognee", lifetime=600):
    sub = sub or f"sub-{uuid4()}"
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": aud,
        "azp": "cognee",
        "typ": typ,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "email": email or f"{sub}@aslamel.net",
        "groups": groups,
        "scope": "openid profile email groups",
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-k1"})
