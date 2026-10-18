"""Rauthy (OIDC) authentication for the HTTP transports, MCP_AUTH_MODE=oidc.

The server is a resource server only: FastMCP's RemoteAuthProvider answers 401
with the RFC 9728 metadata URL and validates the bearer against the issuer's
JWKS. Each request's own bearer (and X-Cognee-Tenant) is then forwarded to the
cognee API, so a tool runs as the caller and this process holds no cognee
credential of its own.
"""

from __future__ import annotations

import base64
import json
import os
from contextvars import ContextVar
from urllib.parse import urlparse

from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

ACCESS_TOKEN_TYPES = ("Bearer", "DPoP")

inbound_token_var: ContextVar[str | None] = ContextVar("mcp_inbound_token", default=None)
inbound_tenant_var: ContextVar[str | None] = ContextVar("mcp_inbound_tenant", default=None)


def is_oidc_mode() -> bool:
    return os.getenv("MCP_AUTH_MODE", "").strip().lower() == "oidc"


class RauthyJWTVerifier(JWTVerifier):
    """JWTVerifier that also refuses id tokens (Rauthy typ "Id")."""

    async def load_access_token(self, token: str):
        access = await super().load_access_token(token)
        if access is None or (access.claims or {}).get("typ") not in ACCESS_TOKEN_TYPES:
            return None
        return access


def build_auth_provider(verifier: JWTVerifier | None = None) -> RemoteAuthProvider:
    issuer = os.environ["OIDC_ISSUER"]
    resource_url = os.environ["MCP_RESOURCE_URL"]
    parsed = urlparse(resource_url)
    verifier = verifier or RauthyJWTVerifier(
        jwks_uri=f"{issuer}oidc/certs",
        issuer=issuer,
        audience=[resource_url],
        algorithm="RS256",
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(issuer)],
        base_url=f"{parsed.scheme}://{parsed.netloc}",
        resource_name="cognee",
    )


def refuse_static_credentials(api_token: str | None) -> None:
    """In oidc mode the caller's token is the only credential."""
    static = api_token or os.getenv("COGNEE_API_KEY") or os.getenv("API_TOKEN")
    if static:
        raise SystemExit(
            "MCP_AUTH_MODE=oidc forwards each caller's token; unset --api-token, "
            "COGNEE_API_KEY and API_TOKEN"
        )


def forwarded_headers() -> dict[str, str]:
    """Headers that carry the current caller's identity to the cognee API."""
    token = inbound_token_var.get()
    if not token:
        return {}
    headers = {"Authorization": f"Bearer {token}"}
    tenant = inbound_tenant_var.get()
    if tenant:
        headers["X-Cognee-Tenant"] = tenant
    return headers


def current_subject() -> str:
    """The caller's sub, from the already-verified inbound token ("" if none)."""
    token = inbound_token_var.get()
    if not token or token.count(".") != 2:
        return ""
    payload = token.split(".")[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return ""
    return str(claims.get("sub", ""))


class IdentityCaptureMiddleware:
    """Puts the request's bearer and X-Cognee-Tenant into ContextVars.

    Runs outside FastMCP's auth middleware, which rejects any request whose
    token is invalid before a tool runs; a tool only ever sees a verified token.
    Background tasks created by a tool copy the context, so they keep it too.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else None
        tenant = headers.get(b"x-cognee-tenant", b"").decode("latin-1").strip() or None
        token_reset = inbound_token_var.set(token)
        tenant_reset = inbound_tenant_var.set(tenant)
        try:
            await self.app(scope, receive, send)
        finally:
            inbound_token_var.reset(token_reset)
            inbound_tenant_var.reset(tenant_reset)
