from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from cognee.infrastructure.databases.exceptions import EntityNotFoundError
from cognee.infrastructure.databases.relational import get_relational_engine

from ..authentication.oidc.context import active_tenant_var
from ..models import User


async def get_user(user_id: UUID):
    db_engine = get_relational_engine()

    async with db_engine.get_async_session() as session:
        user = (
            await session.execute(
                select(User)
                .options(selectinload(User.roles), selectinload(User.tenants))
                .where(User.id == user_id)
            )
        ).scalar()

        if not user:
            raise EntityNotFoundError(message=f"Could not find user: {user_id}")

        # OIDC requests may pick their tenant per request (X-Cognee-Tenant).
        # Applied to the detached object only; the stored tenant is untouched.
        override = active_tenant_var.get()
        if override is not None and override[0] == user.id:
            session.expunge(user)
            user.tenant_id = override[1]

        return user
