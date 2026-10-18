from functools import lru_cache

from fastapi_users.authentication import AuthenticationBackend

from ..api_bearer import api_bearer_transport
from ..default import default_transport
from .config import get_oidc_settings
from .jwks import JWKSCache
from .oidc_strategy import OIDCStrategy
from .sync import sync_principal


@lru_cache
def get_oidc_strategy() -> OIDCStrategy:
    settings = get_oidc_settings()
    return OIDCStrategy(settings=settings, jwks=JWKSCache(settings.jwks_uri), sync=sync_principal)


@lru_cache
def get_oidc_backends() -> list[AuthenticationBackend]:
    """Bearer header (MCP, CLI) and the auth_token cookie (UI), one strategy."""
    return [
        AuthenticationBackend(
            name=transport.name, transport=transport, get_strategy=get_oidc_strategy
        )
        for transport in (api_bearer_transport, default_transport)
    ]
