"""Editor and reader access to a tenant, from the Rauthy groups.

With OIDC_EDITOR_GROUP_FORMAT / OIDC_READER_GROUP_FORMAT set, membership of a
tenant alone gives read: the tenant principal holds only `read` on its
datasets. Write, delete and share belong to one role per tenant, `editor`,
whose members are the people in the editor group. Nobody holds a dataset
permission personally, so losing the editor group takes write away on the
next request.
"""

from uuid import UUID, uuid5

from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.data.models import Dataset
from cognee.modules.users.models import ACL, Permission, Role, User
from cognee.modules.users.models.UserRole import UserRole

from .config import OIDC_NAMESPACE

EDITOR = "editor"
READER = "reader"
TENANT_PERMISSIONS = ("read",)
EDITOR_PERMISSIONS = ("read", "write", "delete", "share")


def editor_role_id(tenant_id: UUID) -> UUID:
    return uuid5(OIDC_NAMESPACE, f"editor:{tenant_id}")


async def is_editor(user) -> bool:
    async with get_relational_engine().get_async_session() as session:
        membership = await session.get(UserRole, (user.id, editor_role_id(user.tenant_id)))
        return membership is not None


async def permission_ids(session, names) -> dict[str, UUID]:
    """Permission rows are created on first use; a concurrent creation wins."""
    found = {}
    for name in names:
        permission = await session.scalar(select(Permission).where(Permission.name == name))
        if permission is None:
            try:
                async with session.begin_nested():
                    permission = Permission(name=name)
                    session.add(permission)
            except IntegrityError:
                permission = await session.scalar(select(Permission).where(Permission.name == name))
        found[name] = permission.id
    return found


async def grant(session, principal_id: UUID, dataset_id: UUID, names) -> None:
    ids = await permission_ids(session, names)
    held = set(
        (
            await session.scalars(
                select(ACL.permission_id).where(
                    ACL.principal_id == principal_id, ACL.dataset_id == dataset_id
                )
            )
        ).all()
    )
    for permission_id in ids.values():
        if permission_id not in held:
            session.add(
                ACL(principal_id=principal_id, dataset_id=dataset_id, permission_id=permission_id)
            )
    await session.flush()


async def hand_writes_to_editors(session, tenant_id: UUID) -> None:
    """Move write, delete and share on the tenant's datasets to its editor role.

    Run once, when the role is created. Datasets made before role groups were
    turned on carry those permissions on the tenant itself, which every reader
    belongs to, and on their creators personally. Grants to anything other than
    the tenant and users (another role, say) are left alone.
    """
    datasets = select(Dataset.id).where(Dataset.tenant_id == tenant_id)
    writes = await permission_ids(session, ("write", "delete", "share"))
    await session.execute(
        delete(ACL).where(
            ACL.dataset_id.in_(datasets),
            ACL.permission_id.in_(list(writes.values())),
            or_(ACL.principal_id == tenant_id, ACL.principal_id.in_(select(User.id))),
        )
    )
    role_id = editor_role_id(tenant_id)
    for dataset_id in (await session.scalars(datasets)).all():
        await grant(session, role_id, dataset_id, EDITOR_PERMISSIONS)
        await grant(session, tenant_id, dataset_id, TENANT_PERMISSIONS)


async def ensure_editor_role(session, tenant_id: UUID) -> None:
    role_id = editor_role_id(tenant_id)
    if await session.get(Role, role_id) is not None:
        return
    try:
        async with session.begin_nested():
            session.add(Role(id=role_id, name=EDITOR, tenant_id=tenant_id))
            await session.flush()
            await hand_writes_to_editors(session, tenant_id)
    except IntegrityError:
        # Another request created the role, and moved the grants with it.
        pass
