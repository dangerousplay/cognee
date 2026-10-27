from uuid import UUID, uuid5

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.users.methods.create_user import NO_PASSWORD_SENTINEL
from cognee.modules.users.methods.get_user import get_user
from cognee.modules.users.models import Tenant, User
from cognee.modules.users.models.UserRole import UserRole
from cognee.modules.users.models.UserTenant import UserTenant
from cognee.modules.users.tenants.methods.revoke_tenant_access import revoke_tenant_access
from cognee.shared.logging_utils import get_logger

from .config import OIDC_NAMESPACE, OIDCSettings, get_oidc_settings
from .context import active_tenant_var
from .roles import EDITOR, READER, editor_role_id, ensure_editor_role

logger = get_logger("oidc.sync")

# Owner of every tenant created from a group. No user row has this id, so no
# synced user ever holds the owner's implicit capabilities.
SENTINEL_OWNER = uuid5(OIDC_NAMESPACE, "owner:none")


def user_id_for(issuer: str, sub: str) -> UUID:
    return uuid5(OIDC_NAMESPACE, f"{issuer}|{sub}")


def tenant_id_for(group: str) -> UUID:
    return uuid5(OIDC_NAMESPACE, f"group:{group}")


def access_for(claims: dict, settings: OIDCSettings) -> tuple[dict[str, str], bool]:
    """Each tenant the token reaches, as editor or reader, and whether it is a superuser.

    Without role groups the tenant's own group makes an editor. With them only
    the editor and reader groups count, and editor wins when a token has both.
    """
    groups = {group for group in claims.get("groups") or [] if group}
    is_superuser = bool(settings.superuser_group) and settings.superuser_group in groups
    if is_superuser:
        return {tenant: EDITOR for tenant in settings.allowed_tenant_groups}, True

    access = {}
    for tenant in settings.allowed_tenant_groups:
        if not settings.uses_role_groups:
            if tenant in groups:
                access[tenant] = EDITOR
        elif settings.editor_group_format.format(tenant=tenant) in groups:
            access[tenant] = EDITOR
        elif settings.reader_group_format.format(tenant=tenant) in groups:
            access[tenant] = READER
    return access, False


def tenants_for(claims: dict, settings: OIDCSettings) -> tuple[list[str], bool]:
    access, is_superuser = access_for(claims, settings)
    return sorted(access), is_superuser


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


async def _sync_editor_roles(session, user: User, access: dict[str, str]) -> None:
    """Editor role membership follows the token; a lost tenant drops it in revoke_tenant_access."""
    for name, level in sorted(access.items()):
        tenant_id = tenant_id_for(name)
        await ensure_editor_role(session, tenant_id)
        membership = await session.get(UserRole, (user.id, editor_role_id(tenant_id)))
        if level == EDITOR and membership is None:
            await _insert_once(
                session, UserRole(user_id=user.id, role_id=editor_role_id(tenant_id))
            )
        elif level == READER and membership is not None:
            await session.delete(membership)


async def sync_principal(
    claims: dict, requested_tenant: str | None, settings: OIDCSettings | None = None
) -> User:
    settings = settings or get_oidc_settings()
    access, is_superuser = access_for(claims, settings)
    names = sorted(access)
    if not names:
        raise HTTPException(status_code=403, detail="No cognee access for this account")
    if requested_tenant is not None and requested_tenant not in names:
        raise HTTPException(status_code=403, detail=f"Not a member of tenant {requested_tenant}")

    user_id = user_id_for(claims["iss"], claims["sub"])
    async with get_relational_engine().get_async_session() as session:
        await _ensure_tenants(session, names)
        user = await _ensure_user(session, user_id, claims.get("email") or "", is_superuser)
        await _sync_memberships(session, user, names, settings)
        if settings.uses_role_groups:
            await _sync_editor_roles(session, user, access)
        await session.commit()

    active_tenant_var.set((user_id, tenant_id_for(requested_tenant)) if requested_tenant else None)
    return await get_user(user_id)
