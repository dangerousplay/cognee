from contextvars import ContextVar
from uuid import UUID

TENANT_HEADER = b"x-cognee-tenant"

# The tenant a request asked for (X-Cognee-Tenant), before it is checked.
requested_tenant_var: ContextVar[str | None] = ContextVar("oidc_requested_tenant", default=None)

# (user id, tenant id) chosen for this request. Applied by get_user() to that
# user only, and never written to the database, so two concurrent requests by
# one user in different tenants do not race on users.tenant_id.
active_tenant_var: ContextVar[tuple[UUID, UUID] | None] = ContextVar(
    "oidc_active_tenant", default=None
)


class TenantHeaderMiddleware:
    """Puts the X-Cognee-Tenant header of each HTTP request into a ContextVar."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        value = next(
            (v.decode("latin-1").strip() for k, v in scope["headers"] if k == TENANT_HEADER),
            None,
        )
        token = requested_tenant_var.set(value or None)
        try:
            await self.app(scope, receive, send)
        finally:
            requested_tenant_var.reset(token)
