"""The JWKS cache behind OIDC token validation.

Rauthy rotates signing keys; a token signed with a key the cache has not seen
must trigger one refetch, but a flood of tokens with made-up kids must not turn
into a flood of requests to the issuer. An unreachable issuer with no cached
key means the token cannot be verified, so the lookup yields nothing (401).
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cognee.modules.users.authentication.oidc.config import get_oidc_settings
from cognee.modules.users.authentication.oidc.jwks import JWKSCache


def _jwk(kid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


class _Fetcher:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    async def __call__(self, url):
        self.calls += 1
        response = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(response, Exception):
            raise response
        return response


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _cache(fetcher, clock):
    return JWKSCache("https://iam.example/auth/v1/oidc/certs", fetch=fetcher, clock=clock)


@pytest.mark.asyncio
async def test_known_kid_is_served_from_cache_without_a_second_fetch():
    fetcher = _Fetcher({"keys": [_jwk("k1")]})
    cache = _cache(fetcher, _Clock())

    first = await cache.get_key("k1")
    second = await cache.get_key("k1")

    assert first is not None and first.key_id == "k1"
    assert second is first
    assert fetcher.calls == 1


@pytest.mark.asyncio
async def test_unknown_kid_triggers_one_refetch_that_finds_a_rotated_key():
    fetcher = _Fetcher({"keys": [_jwk("k1")]}, {"keys": [_jwk("k1"), _jwk("k2")]})
    clock = _Clock()
    cache = _cache(fetcher, clock)
    await cache.get_key("k1")

    clock.now += 31
    rotated = await cache.get_key("k2")

    assert rotated is not None and rotated.key_id == "k2"
    assert fetcher.calls == 2


@pytest.mark.asyncio
async def test_second_unknown_kid_within_30_seconds_does_not_refetch():
    fetcher = _Fetcher({"keys": [_jwk("k1")]})
    clock = _Clock()
    cache = _cache(fetcher, clock)

    assert await cache.get_key("missing-1") is None
    clock.now += 10
    assert await cache.get_key("missing-2") is None

    assert fetcher.calls == 1


@pytest.mark.asyncio
async def test_unreachable_issuer_with_no_cached_key_yields_none():
    fetcher = _Fetcher(OSError("connection refused"))
    cache = _cache(fetcher, _Clock())

    assert await cache.get_key("k1") is None


def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://iam.aslamel.net/auth/v1/")
    monkeypatch.setenv("OIDC_AUDIENCES", "cognee, https://cognee-mcp.int.aslamel.net/mcp")
    monkeypatch.setenv("OIDC_ALLOWED_TENANT_GROUPS", "nova-terra,cookiebot")
    monkeypatch.setenv("OIDC_SUPERUSER_GROUP", "platform")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cognee")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv(
        "OIDC_REDIRECT_URI", "https://cognee.int.aslamel.net/api/v1/auth/oidc/callback"
    )
    monkeypatch.setenv("OIDC_ALLOWED_RETURN_TO", "https://cognee.int.aslamel.net")

    settings = get_oidc_settings()

    assert settings.issuer == "https://iam.aslamel.net/auth/v1/"
    assert settings.jwks_uri == "https://iam.aslamel.net/auth/v1/oidc/certs"
    assert settings.audiences == ("cognee", "https://cognee-mcp.int.aslamel.net/mcp")
    assert settings.allowed_tenant_groups == ("nova-terra", "cookiebot")
    assert settings.superuser_group == "platform"
    assert settings.client_id == "cognee"
    assert settings.client_secret == "s3cret"
    assert settings.redirect_uri == "https://cognee.int.aslamel.net/api/v1/auth/oidc/callback"
    assert settings.allowed_return_to == ("https://cognee.int.aslamel.net",)
