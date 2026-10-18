"""Browser login through Rauthy (COG-01, COG-02, COG-03, COG-06, edge cases).

/login sends the browser to the issuer with an S256 PKCE challenge and keeps
state + verifier in a signed, short-lived cookie. /callback checks the state,
redeems the code with the verifier, validates the access token like any other
request, and stores that token in the auth_token cookie. No allowed group is
a 403 page (never a redirect, which would loop); an unreachable issuer is 503.
"""

import base64
import hashlib
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from cognee.tests.api_oidc.oidc_helpers import ISSUER, UI_ORIGIN, fake_fetch_jwks, mint

CALLBACK = "/api/v1/auth/oidc/callback"


@pytest.fixture(scope="module")
def client():
    from cognee.api.client import app
    from cognee.modules.users.authentication.oidc import jwks

    original = jwks._fetch_json
    jwks._fetch_json = fake_fetch_jwks
    try:
        with TestClient(app, base_url=UI_ORIGIN, follow_redirects=False) as client:
            yield client
    finally:
        jwks._fetch_json = original


@pytest.fixture
def token_endpoint(monkeypatch):
    from cognee.api.v1.users.routers import get_oidc_router as module

    calls = []
    state = {"response": None}

    async def exchange(settings, code, verifier):
        calls.append({"code": code, "verifier": verifier, "client_id": settings.client_id})
        response = state["response"]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(module, "exchange_code", exchange)
    return calls, state


def _start(client, return_to=None):
    params = {"return_to": return_to} if return_to else {}
    response = client.get("/api/v1/auth/oidc/login", params=params)
    query = parse_qs(urlparse(response.headers["location"]).query)
    return response, query


def test_login_redirects_to_rauthy_with_pkce(client):
    response, query = _start(client)

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == f"{ISSUER}oidc/authorize"
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["client_id"] == ["cognee"]
    assert query["redirect_uri"] == [f"{UI_ORIGIN}{CALLBACK}"]
    assert {"openid", "email", "groups"} <= set(query["scope"][0].split())
    assert query["state"][0]
    tx_cookie = response.headers["set-cookie"]
    assert tx_cookie.startswith("oidc_tx=")
    assert "HttpOnly" in tx_cookie and "Secure" in tx_cookie and "Max-Age=600" in tx_cookie


def test_callback_sets_the_access_token_cookie_and_returns(client, token_endpoint):
    calls, state = token_endpoint
    email = f"dev-login-{uuid4().hex[:8]}@aslamel.net"
    access_token = mint(["nova-terra"], email=email)
    state["response"] = {"access_token": access_token, "token_type": "Bearer", "expires_in": 600}
    _, query = _start(client, return_to=f"{UI_ORIGIN}/dashboard")

    response = client.get(CALLBACK, params={"code": "the-code", "state": query["state"][0]})

    assert response.status_code == 302, response.text
    assert response.headers["location"] == f"{UI_ORIGIN}/dashboard"
    assert client.cookies.get("auth_token") == access_token
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith("auth_token="))
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    challenge = query["code_challenge"][0]
    verifier = calls[0]["verifier"]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()
    assert calls[0]["code"] == "the-code"
    assert client.get("/api/v1/auth/me").json()["email"] == email


def test_callback_with_a_wrong_state_is_400(client, token_endpoint):
    _start(client)

    response = client.get(CALLBACK, params={"code": "c", "state": "forged"})

    assert response.status_code == 400
    assert token_endpoint[0] == []


def test_callback_without_the_tx_cookie_is_400(client, token_endpoint):
    _, query = _start(client)
    client.cookies.delete("oidc_tx")

    response = client.get(CALLBACK, params={"code": "c", "state": query["state"][0]})

    assert response.status_code == 400


@pytest.mark.parametrize(
    "return_to", ["https://evil.example/steal", "//evil.example/x", "javascript:alert(1)"]
)
def test_return_to_outside_the_allow_list_goes_to_root(client, token_endpoint, return_to):
    _, state = token_endpoint
    state["response"] = {"access_token": mint(["cookiebot"]), "token_type": "Bearer"}
    _, query = _start(client, return_to=return_to)

    response = client.get(CALLBACK, params={"code": "c", "state": query["state"][0]})

    assert response.status_code == 302
    assert response.headers["location"] == "/"


def test_no_allowed_group_renders_403_without_cookie_or_user(client, token_endpoint):
    from sqlalchemy import select

    _, state = token_endpoint
    sub = f"sub-{uuid4()}"
    state["response"] = {"access_token": mint(["penpot"], sub=sub), "token_type": "Bearer"}
    client.cookies.delete("auth_token")
    _, query = _start(client)

    response = client.get(CALLBACK, params={"code": "c", "state": query["state"][0]})

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert not any(c.startswith("auth_token=") for c in response.headers.get_list("set-cookie"))

    import asyncio

    from cognee.infrastructure.databases.relational import get_relational_engine
    from cognee.modules.users.authentication.oidc.sync import user_id_for
    from cognee.modules.users.models import User

    async def count():
        async with get_relational_engine().get_async_session() as session:
            rows = await session.execute(select(User).where(User.id == user_id_for(ISSUER, sub)))
            return len(rows.scalars().all())

    assert asyncio.run(count()) == 0


def test_unreachable_token_endpoint_is_503(client, token_endpoint):
    _, state = token_endpoint
    state["response"] = httpx.ConnectError("connection refused")
    _, query = _start(client)

    response = client.get(CALLBACK, params={"code": "c", "state": query["state"][0]})

    assert response.status_code == 503


def test_invalid_access_token_from_the_issuer_is_401(client, token_endpoint):
    _, state = token_endpoint
    state["response"] = {"access_token": mint(["nova-terra"], typ="Id"), "token_type": "Bearer"}
    _, query = _start(client)

    response = client.get(CALLBACK, params={"code": "c", "state": query["state"][0]})

    assert response.status_code == 401
