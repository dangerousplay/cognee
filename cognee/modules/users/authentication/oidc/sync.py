from uuid import UUID, uuid5

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.users.methods.create_user import NO_PASSWORD_SENTINEL
from cognee.modules.users.methods.get_user import get_user
from cognee.modules.users.models import Tenant, User
from cognee.modules.users.models.UserTenant import UserTenant
from cognee.modules.users.tenants.methods.revoke_tenant_access import revoke_tenant_access
from cognee.shared.logging_utils import get_logger

from .config import OIDC_NAMESPACE, OIDCSettings, get_oidc_settings

logger = get_logger("oidc.sync")

# Owner of every tenant created from a group. No user row has this id, so no
# synced user ever holds the owner's implicit capabilities.
SENTINEL_OWNER = uuid5(OIDC_NAMESPACE, "owner:none")


def user_id_for(issuer: str, sub: str) -> UUID:
    return uuid5(OIDC_NAMESPACE, f"{issuer}|{sub}")


def tenant_id_for(group: str) -> UUID:
    return uuid5(OIDC_NAMESPACE, f"group:{group}")


def tenants_for(claims: dict, settings: OIDCSettings) -> tuple[list[str], bool]:
    groups = {group for group in claims.get("groups") or [] if group}
    is_superuser = bool(settings.superuser_group) and settings.superuser_group in groups
    if is_superuser:
        return sorted(settings.allowed_tenant_groups), True
    return sorted(groups & set(settings.allowed_tenant_groups)), False


async def _insert_once(session, row) -> None:
    """Insert a row keyed by a derived id; a concurrent insert of the same id wins."""
    try:
        async with session.begin_nested():
            session.add(row)
    except IntegrityError:
        pass


async def _ensure_tenants(session, names: list[str]) -> None:
    for name in names:
        if await session.get(Tenant, tenant_id_for(name)) is None:
            await _insert_once(
                session, Tenant(id=tenant_id_for(name), name=name, owner_id=SENTINEL_OWNER)
            )


async def _ensure_user(session, user_id: UUID, email: str, is_superuser: bool) -> User:
    user = await session.get(User, user_id)
    if user is None:
        await _insert_once(
            session,
            User(
                id=user_id,
                email=email,
                hashed_password=NO_PASSWORD_SENTINEL,
                is_active=True,
                is_verified=True,
                is_superuser=is_superuser,
            ),
        )
        user = await session.get(User, user_id)
        if user is None:
            # The email belongs to another account; the id is still ours.
            await _insert_once(
                session,
                User(
                    id=user_id,
                    email=f"{user_id}@oidc.invalid",
                    hashed_password=NO_PASSWORD_SENTINEL,
                    is_active=True,
                    is_verified=True,
                    is_superuser=is_superuser,
                ),
            )
            user = await session.get(User, user_id)

    user.is_superuser = is_superuser
    if email and user.email != email:
        try:
            async with session.begin_nested():
                user.email = email
        except IntegrityError:
            await session.refresh(user)
            logger.warning("OIDC email for user %s is taken by another account; kept", user_id)
    return user


async def _sync_memberships(session, user: User, names: list[str], settings: OIDCSettings) -> None:
    managed = {tenant_id_for(group) for group in settings.allowed_tenant_groups}
    wanted = {tenant_id_for(name) for name in names}
    current = set(
        (await session.execute(select(UserTenant.tenant_id).where(UserTenant.user_id == user.id)))
        .scalars()
        .all()
    )

    for tenant_id in sorted(wanted - current):
        await _insert_once(session, UserTenant(user_id=user.id, tenant_id=tenant_id))
    for tenant_id in sorted((current & managed) - wanted):
        await revoke_tenant_access(session, user.id, tenant_id)

    await session.refresh(user)
    if user.tenant_id not in wanted:
        user.tenant_id = tenant_id_for(names[0])


async def sync_principal(
    claims: dict, requested_tenant: str | None, settings: OIDCSettings | None = None
) -> User:
    settings = settings or get_oidc_settings()
    names, is_superuser = tenants_for(claims, settings)
    if not names:
        raise HTTPException(status_code=403, detail="No cognee access for this account")

    user_id = user_id_for(claims["iss"], claims["sub"])
    async with get_relational_engine().get_async_session() as session:
        await _ensure_tenants(session, names)
        user = await _ensure_user(session, user_id, claims.get("email") or "", is_superuser)
        await _sync_memberships(session, user, names, settings)
        await session.commit()

    return await get_user(user_id)
