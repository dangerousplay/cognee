import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from html import escape
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cognee.modules.users.authentication.default.default_transport import default_transport
from cognee.modules.users.authentication.oidc.backends import get_oidc_strategy
from cognee.modules.users.authentication.oidc.config import OIDCSettings, get_oidc_settings
from cognee.shared.logging_utils import get_logger

logger = get_logger("oidc.router")

TX_COOKIE = "oidc_tx"
TX_LIFETIME_SECONDS = 600
SCOPES = "openid profile email groups"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _tx_secret() -> bytes:
    secret = os.getenv("OIDC_TX_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("OIDC_TX_SECRET must be set to at least 32 characters")
    return secret.encode()


def _sign(payload: dict) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    mac = _b64(hmac.new(_tx_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def _unsign(value: str | None) -> dict | None:
    if not value or "." not in value:
        return None
    body, mac = value.rsplit(".", 1)
    expected = _b64(hmac.new(_tx_secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, expected):
        return None
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def _safe_return_to(value: str | None, settings: OIDCSettings) -> str:
    if not value:
        return "/"
    if value.startswith("/") and not value.startswith("//"):
        return value
    parsed = urlparse(value)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.scheme == "https" and origin in settings.allowed_return_to:
        return value
    return "/"


def _page(status: int, title: str, message: str) -> HTMLResponse:
    body = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title></head>"
        f"<body><h1>{escape(title)}</h1><p>{escape(message)}</p></body></html>"
    )
    return HTMLResponse(body, status_code=status)


async def exchange_code(settings: OIDCSettings, code: str, verifier: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            settings.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.redirect_uri,
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "code_verifier": verifier,
            },
        )
        response.raise_for_status()
        return response.json()


def get_oidc_router() -> APIRouter:
    router = APIRouter()

    @router.get("/login")
    async def login(return_to: str | None = None):
        """Start the authorization-code flow (PKCE S256) at the OIDC issuer."""
        settings = get_oidc_settings()
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(32)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": settings.client_id,
                "redirect_uri": settings.redirect_uri,
                "scope": SCOPES,
                "state": state,
                "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
                "code_challenge_method": "S256",
            }
        )
        response = RedirectResponse(f"{settings.authorize_endpoint}?{query}", status_code=302)
        response.set_cookie(
            TX_COOKIE,
            _sign(
                {
                    "state": state,
                    "verifier": verifier,
                    "return_to": _safe_return_to(return_to, settings),
                    "exp": int(time.time()) + TX_LIFETIME_SECONDS,
                }
            ),
            max_age=TX_LIFETIME_SECONDS,
            path="/api/v1/auth/oidc",
            secure=default_transport.cookie_secure,
            httponly=True,
            samesite=default_transport.cookie_samesite,
        )
        return response

    @router.get("/callback")
    async def callback(request: Request, code: str = "", state: str = ""):
        """Redeem the code, validate the access token and open the session."""
        settings = get_oidc_settings()
        tx = _unsign(request.cookies.get(TX_COOKIE))
        if tx is None or not code or not hmac.compare_digest(tx["state"], state):
            return _page(400, "Login failed", "The login request expired or was tampered with.")

        try:
            tokens = await exchange_code(settings, code, tx["verifier"])
        except (httpx.HTTPError, ValueError) as error:
            logger.warning("OIDC token exchange failed: %s", type(error).__name__)
            return _page(503, "Login unavailable", "The identity provider did not answer.")

        access_token = tokens.get("access_token", "")
        try:
            user = await get_oidc_strategy().read_token(access_token, None)
        except HTTPException as error:
            if error.status_code == 403:
                return _page(403, "No access", "Your account has no cognee access.")
            raise
        if user is None:
            return _page(401, "Login failed", "The identity provider returned an invalid token.")

        expires_at = jwt.decode(access_token, options={"verify_signature": False})["exp"]
        response = RedirectResponse(tx["return_to"], status_code=302)
        response.set_cookie(
            default_transport.cookie_name,
            access_token,
            max_age=max(0, int(expires_at - time.time())),
            path=default_transport.cookie_path,
            domain=default_transport.cookie_domain,
            secure=default_transport.cookie_secure,
            httponly=True,
            samesite=default_transport.cookie_samesite,
        )
        response.delete_cookie(TX_COOKIE, path="/api/v1/auth/oidc")
        return response

    return router
