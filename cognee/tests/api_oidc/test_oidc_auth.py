"""With AUTH_MODE=oidc a Rauthy access token is the only way in.

COG-05: password login, sign-up and API keys are gone (404). COG-06: the
session cookie is Secure, HttpOnly, SameSite=Lax. COG-12: bearer and cookie
both carry the Rauthy token. COG-14 (API side): X-Api-Key is not a credential.
"""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cognee.tests.api_oidc.oidc_helpers import fake_fetch_jwks, mint


@pytest.fixture(scope="module")
def client():
    from cognee.api.client import app
    from cognee.modules.users.authentication.oidc import jwks

    original = jwks._fetch_json
    jwks._fetch_json = fake_fetch_jwks
    try:
        with TestClient(app, base_url="https://cognee.int.aslamel.net") as client:
            yield client
    finally:
        jwks._fetch_json = original


@pytest.mark.parametrize(
    "method, path",
    [
        ("post", "/api/v1/auth/login"),
        ("post", "/api/v1/auth/register"),
        ("post", "/api/v1/auth/forgot-password"),
        ("post", "/api/v1/auth/request-verify-token"),
        ("get", "/api/v1/auth/api-keys"),
        ("post", "/api/v1/auth/api-keys"),
        ("get", "/api/v1/users/me"),
    ],
)
def test_password_and_key_routes_are_not_mounted(client, method, path):
    response = getattr(client, method)(path)

    assert response.status_code == 404, response.text


def test_me_with_a_valid_bearer_returns_the_token_email(client):
    email = f"dev-me-{uuid4().hex[:8]}@aslamel.net"
    token = mint(["nova-terra"], email=email)

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text
    assert response.json()["email"] == email


def test_me_without_a_token_is_401(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_auth_token_cookie_carries_the_rauthy_token(client):
    email = f"dev-cookie-{uuid4().hex[:8]}@aslamel.net"
    token = mint(["cookiebot"], email=email)

    response = client.get("/api/v1/auth/me", cookies={"auth_token": token})

    assert response.status_code == 200, response.text
    assert response.json()["email"] == email


def test_x_api_key_is_not_a_credential(client):
    assert client.get("/api/v1/auth/me", headers={"X-Api-Key": "anything"}).status_code == 401


def test_id_token_is_not_a_credential(client):
    token = mint(["nova-terra"], typ="Id")

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_token_without_an_allowed_group_is_403(client):
    token = mint(["penpot"])

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_logout_clears_a_secure_httponly_lax_cookie(client):
    token = mint(["nova-terra"])

    response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("auth_token=")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_oidc_mode_authenticates_only_through_the_oidc_strategy():
    from cognee.modules.users.authentication.oidc.oidc_strategy import OIDCStrategy
    from cognee.modules.users.get_fastapi_users import get_fastapi_users

    backends = get_fastapi_users().authenticator.backends

    # No api-key backend: a stored key would skip Rauthy and the group sync.
    assert [backend.name for backend in backends] == ["bearer", "cookie"]
    assert all(isinstance(backend.get_strategy(), OIDCStrategy) for backend in backends)
