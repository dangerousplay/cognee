"""MCP over HTTP requires a Rauthy access token and acts as its caller.

COG-11: no bearer is a 401 naming the RFC 9728 metadata, which lists the
issuer. COG-12: an expired token, another issuer, another audience or an id
token is a 401 and no tool runs. A valid token is forwarded unchanged with
X-Cognee-Tenant. COG-14: oidc mode refuses static API credentials. Background
errors are kept per caller, so two users of one dataset name never mix.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from src import auth, server
from starlette.testclient import TestClient

ISSUER = "https://iam.aslamel.net/auth/v1/"
RESOURCE = "https://cognee-mcp.int.aslamel.net/mcp"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)


def _token(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "rauthy-user-1",
        "aud": ["cognee-mcp-claude", RESOURCE],
        "typ": "Bearer",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "scope": "openid email groups",
        "groups": ["nova-terra"],
    }
    claims.update(overrides)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def oidc_app(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "oidc")
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MCP_RESOURCE_URL", RESOURCE)
    verifier = auth.RauthyJWTVerifier(
        public_key=PUBLIC_PEM, issuer=ISSUER, audience=[RESOURCE], algorithm="RS256"
    )
    monkeypatch.setattr(server.mcp, "auth", auth.build_auth_provider(verifier))
    client = AsyncMock()
    monkeypatch.setattr(server, "cognee_client", client)
    return server._build_http_app("http", "127.0.0.1", "/mcp"), client


INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "claude-code", "version": "test"},
    },
}


def _post(app, headers=None):
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        return client.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream", **(headers or {})},
            json=INITIALIZE,
        )


def test_missing_bearer_is_401_with_resource_metadata(oidc_app):
    app, _ = oidc_app

    response = _post(app)

    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]


def test_protected_resource_metadata_lists_the_issuer(oidc_app):
    app, _ = oidc_app

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        response = client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    body = response.json()
    assert body["authorization_servers"] == [ISSUER]
    assert body["resource"] == RESOURCE


@pytest.mark.parametrize(
    "case, overrides",
    [
        ("expired", {"exp": int(time.time()) - 300}),
        ("wrong issuer", {"iss": "https://evil.example/auth/v1/"}),
        ("wrong audience", {"aud": "grafana"}),
        ("id token", {"typ": "Id"}),
    ],
)
def test_invalid_tokens_are_401_and_reach_no_tool(oidc_app, case, overrides):
    app, client = oidc_app

    response = _post(app, {"Authorization": f"Bearer {_token(**overrides)}"})

    assert response.status_code == 401, case
    assert client.mock_calls == []


def test_valid_token_is_accepted(oidc_app):
    app, _ = oidc_app

    response = _post(app, {"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200, response.text


def test_valid_request_forwards_the_same_bearer_and_tenant_to_the_api():
    from src.cognee_client import CogneeClient

    seen = {}
    token = _token()

    async def inner(scope, receive, send):
        api = CogneeClient(api_url="http://cognee-api.cognee.svc:8000", api_token=None)
        seen["headers"] = api._get_headers()
        seen["background"] = await asyncio.create_task(_headers_later(api))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def _headers_later(api):
        await asyncio.sleep(0)
        return api._get_headers()

    client = TestClient(auth.IdentityCaptureMiddleware(inner))
    client.get("/", headers={"Authorization": f"Bearer {token}", "X-Cognee-Tenant": "cookiebot"})

    assert seen["headers"]["Authorization"] == f"Bearer {token}"
    assert seen["headers"]["X-Cognee-Tenant"] == "cookiebot"
    assert seen["background"]["Authorization"] == f"Bearer {token}"
    assert "X-Api-Key" not in seen["headers"]


@pytest.mark.parametrize("variable", ["COGNEE_API_KEY", "API_TOKEN"])
def test_oidc_mode_refuses_a_static_credential_from_env(monkeypatch, variable):
    monkeypatch.setenv(variable, "static-key")

    with pytest.raises(SystemExit):
        auth.refuse_static_credentials(None)


def test_oidc_mode_refuses_a_static_credential_flag(monkeypatch):
    monkeypatch.delenv("COGNEE_API_KEY", raising=False)
    monkeypatch.delenv("API_TOKEN", raising=False)

    with pytest.raises(SystemExit):
        auth.refuse_static_credentials("--api-token value")
    auth.refuse_static_credentials(None)


def test_background_errors_are_kept_per_caller(monkeypatch):
    monkeypatch.setattr(server, "_task_errors", {})
    alice = auth.inbound_token_var.set(_token(sub="alice"))
    server._record_task_error("notes", "alice's failure")
    auth.inbound_token_var.reset(alice)
    bob = auth.inbound_token_var.set(_token(sub="bob"))
    try:
        assert server._task_errors_for("notes") == []
        server._record_task_error("notes", "bob's failure")
        assert [error for _, error in server._task_errors_for("notes")] == ["bob's failure"]
    finally:
        auth.inbound_token_var.reset(bob)


@pytest.fixture
def default_provider(monkeypatch):
    """build_auth_provider() exactly as main() calls it: no injected verifier."""
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MCP_RESOURCE_URL", RESOURCE)
    jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    fetched = []

    async def fetch_jwks(self):
        fetched.append(self.jwks_uri)
        return {"keys": [jwk]}

    monkeypatch.setattr(auth.JWTVerifier, "_fetch_jwks", fetch_jwks)
    return auth.build_auth_provider(), fetched


def test_default_verifier_is_bound_to_the_issuer_jwks_and_resource(default_provider):
    provider, _ = default_provider
    verifier = provider.token_verifier

    assert isinstance(verifier, auth.RauthyJWTVerifier)
    assert verifier.issuer == ISSUER
    assert verifier.audience == [RESOURCE]
    assert verifier.jwks_uri == f"{ISSUER}oidc/certs"
    assert verifier.algorithm == "RS256"
    assert [str(server) for server in provider.authorization_servers] == [ISSUER]


@pytest.mark.parametrize(
    "case, overrides, accepted",
    [
        ("valid", {}, True),
        ("another audience", {"aud": "grafana"}, False),
        ("the UI client only", {"aud": "cognee"}, False),
        ("another issuer", {"iss": "https://evil.example/auth/v1/"}, False),
        ("id token", {"typ": "Id"}, False),
    ],
)
def test_default_verifier_decides_like_the_spec(default_provider, case, overrides, accepted):
    provider, fetched = default_provider

    access = asyncio.run(provider.verify_token(_token(**overrides)))

    assert (access is not None) is accepted, case
    assert fetched == [f"{ISSUER}oidc/certs"]
