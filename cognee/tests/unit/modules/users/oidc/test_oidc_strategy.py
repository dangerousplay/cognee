"""Rauthy access tokens as cognee credentials.

The strategy accepts a token only when Rauthy signed it (RS256, key from the
JWKS), it was issued by exactly the configured issuer, one of its audiences is
ours, it is current, and it is an access token. Anything else is "no user"
(401). A valid token is handed to the sync step, whose result is the user.
"""

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm

from cognee.modules.users.authentication.oidc.config import OIDCSettings
from cognee.modules.users.authentication.oidc.context import requested_tenant_var
from cognee.modules.users.authentication.oidc.oidc_strategy import OIDCStrategy

ISSUER = "https://iam.aslamel.net/auth/v1/"
SETTINGS = OIDCSettings(
    issuer=ISSUER,
    audiences=("cognee", "https://cognee-mcp.int.aslamel.net/mcp"),
    allowed_tenant_groups=("nova-terra", "cookiebot"),
    superuser_group="platform",
    client_id="cognee",
    client_secret="",
    redirect_uri="",
    allowed_return_to=(),
)
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _Keys:
    def __init__(self):
        jwk = RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True)
        jwk.update({"kid": "k1", "alg": "RS256"})
        self.keys = {"k1": PyJWK(jwk)}

    async def get_key(self, kid):
        return self.keys.get(kid)


class _Sync:
    def __init__(self):
        self.calls = []
        self.user = SimpleNamespace(id="user-1")

    async def __call__(self, claims, requested_tenant):
        self.calls.append((claims, requested_tenant))
        return self.user


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "rauthy-user-1",
        "aud": "cognee",
        "azp": "cognee",
        "typ": "Bearer",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "email": "dev@aslamel.net",
        "groups": ["nova-terra"],
    }
    claims.update(overrides)
    return claims


def _token(claims, key=PRIVATE_KEY, kid="k1", algorithm="RS256"):
    if algorithm == "HS256":
        return jwt.encode(
            claims, "shared-secret-0123456789abcdef0123", algorithm="HS256", headers={"kid": kid}
        )
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})


@pytest.fixture
def sync():
    return _Sync()


@pytest.fixture
def strategy(sync):
    return OIDCStrategy(settings=SETTINGS, jwks=_Keys(), sync=sync)


@pytest.mark.asyncio
async def test_valid_access_token_returns_the_synced_user(strategy, sync):
    token = _token(_claims())

    user = await strategy.read_token(token, user_manager=None)

    assert user is sync.user
    claims, requested_tenant = sync.calls[0]
    assert claims["sub"] == "rauthy-user-1"
    assert claims["email"] == "dev@aslamel.net"
    assert requested_tenant is None


@pytest.mark.asyncio
async def test_list_audience_with_the_mcp_resource_is_accepted(strategy, sync):
    token = _token(_claims(aud=["cognee-mcp-claude", "https://cognee-mcp.int.aslamel.net/mcp"]))

    assert await strategy.read_token(token, user_manager=None) is sync.user


@pytest.mark.parametrize(
    "case, token",
    [
        ("expired", _token(_claims(exp=int(time.time()) - 120))),
        ("not yet valid", _token(_claims(nbf=int(time.time()) + 120))),
        ("wrong issuer", _token(_claims(iss="https://evil.example/auth/v1/"))),
        ("issuer without trailing slash", _token(_claims(iss=ISSUER.rstrip("/")))),
        ("wrong audience", _token(_claims(aud="grafana"))),
        ("id token", _token(_claims(typ="Id"))),
        ("no typ", _token({k: v for k, v in _claims().items() if k != "typ"})),
        ("hs256", _token(_claims(), algorithm="HS256")),
        ("unknown kid", _token(_claims(), kid="k9")),
        ("signed by another key", _token(_claims(), key=OTHER_KEY)),
        ("garbage", "not-a-jwt"),
    ],
)
@pytest.mark.asyncio
async def test_rejected_tokens_yield_no_user_and_skip_sync(strategy, sync, case, token):
    assert await strategy.read_token(token, user_manager=None) is None, case
    assert sync.calls == []


@pytest.mark.asyncio
async def test_token_within_30_second_leeway_is_accepted(strategy, sync):
    token = _token(_claims(exp=int(time.time()) - 10))

    assert await strategy.read_token(token, user_manager=None) is sync.user


@pytest.mark.asyncio
async def test_dpop_access_token_is_accepted(strategy, sync):
    assert await strategy.read_token(_token(_claims(typ="DPoP")), user_manager=None) is sync.user


@pytest.mark.asyncio
async def test_requested_tenant_is_passed_to_sync(sync):
    strategy = OIDCStrategy(settings=SETTINGS, jwks=_Keys(), sync=sync)

    await strategy.read_token(_token(_claims()), user_manager=None, requested_tenant="cookiebot")

    assert sync.calls[0][1] == "cookiebot"


@pytest.mark.asyncio
async def test_strategy_never_mints_tokens(strategy):
    with pytest.raises(NotImplementedError):
        await strategy.write_token(SimpleNamespace(id="user-1"))


@pytest.mark.asyncio
async def test_requested_tenant_defaults_to_the_header_context(strategy, sync):
    token = requested_tenant_var.set("nova-terra")
    try:
        await strategy.read_token(_token(_claims()), user_manager=None)
    finally:
        requested_tenant_var.reset(token)

    assert sync.calls[0][1] == "nova-terra"
