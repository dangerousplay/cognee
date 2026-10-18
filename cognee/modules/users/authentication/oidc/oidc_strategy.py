from collections.abc import Awaitable, Callable

import jwt
from fastapi_users.authentication import Strategy

from cognee.shared.logging_utils import get_logger

from .config import OIDCSettings
from .context import requested_tenant_var
from .jwks import JWKSCache

logger = get_logger("oidc.strategy")

# Rauthy marks access tokens "Bearer" (or "DPoP") and id tokens "Id". Both carry
# aud = client_id, so without this check an id token would pass as a credential.
ACCESS_TOKEN_TYPES = ("Bearer", "DPoP")
LEEWAY_SECONDS = 30


class OIDCStrategy(Strategy):
    """Validates access tokens issued by an external OIDC provider."""

    def __init__(
        self,
        settings: OIDCSettings,
        jwks: JWKSCache,
        sync: Callable[[dict, str | None], Awaitable[object]],
    ):
        self.settings = settings
        self.jwks = jwks
        self.sync = sync

    async def _verified_claims(self, token: str) -> dict | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return None
        if header.get("alg") != "RS256" or not header.get("kid"):
            return None

        key = await self.jwks.get_key(header["kid"])
        if key is None:
            return None

        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                audience=list(self.settings.audiences),
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.InvalidTokenError as error:
            logger.info("Rejected OIDC token: %s", type(error).__name__)
            return None

        if claims.get("typ") not in ACCESS_TOKEN_TYPES:
            return None
        return claims

    async def read_token(self, token, user_manager, requested_tenant: str | None = None):
        if token is None:
            return None
        claims = await self._verified_claims(token)
        if claims is None:
            return None
        if requested_tenant is None:
            requested_tenant = requested_tenant_var.get()
        return await self.sync(claims, requested_tenant)

    async def write_token(self, user):
        raise NotImplementedError("OIDC sessions carry the issuer's access token")

    async def destroy_token(self, token, user):
        return None
