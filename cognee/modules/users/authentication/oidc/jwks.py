import time
from collections.abc import Awaitable, Callable

import httpx
from jwt import PyJWK, PyJWKSet, PyJWKSetError

from cognee.shared.logging_utils import get_logger

logger = get_logger("oidc.jwks")

# An unknown kid refetches the key set at most this often, so tokens with
# invented kids cannot make every request call the issuer.
REFETCH_INTERVAL_SECONDS = 30


async def _fetch_json(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


class JWKSCache:
    def __init__(
        self,
        jwks_uri: str,
        fetch: Callable[[str], Awaitable[dict]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.jwks_uri = jwks_uri
        self._fetch = fetch
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._last_fetch: float | None = None

    async def _refresh(self) -> None:
        self._last_fetch = self._clock()
        try:
            fetch = self._fetch or _fetch_json
            key_set = PyJWKSet.from_dict(await fetch(self.jwks_uri))
        except (httpx.HTTPError, OSError, ValueError, PyJWKSetError) as error:
            logger.warning("JWKS fetch from %s failed: %s", self.jwks_uri, error)
            return
        self._keys = {key.key_id: key for key in key_set.keys if key.key_id}

    async def get_key(self, kid: str) -> PyJWK | None:
        if kid in self._keys:
            return self._keys[kid]
        if self._last_fetch is None or self._clock() - self._last_fetch >= REFETCH_INTERVAL_SECONDS:
            await self._refresh()
        return self._keys.get(kid)
