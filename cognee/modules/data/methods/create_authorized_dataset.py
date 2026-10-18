import logging

from cognee.infrastructure.databases.exceptions import EntityNotFoundError
from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.data.models import Dataset
from cognee.modules.users.methods import get_user
from cognee.modules.users.models import User
from cognee.modules.users.permissions.methods import give_permission_on_dataset
from cognee.modules.users.permissions.methods.get_tenant import get_tenant

from .create_dataset import create_dataset
from .tenant_scope import is_tenant_scoped

logger = logging.getLogger(__name__)

_DATASET_PERMISSIONS = ("read", "write", "delete", "share")


async def create_authorized_dataset(dataset_name: str, user: User) -> Dataset:
    """
        Create a new dataset and give all permissions on this dataset to the given user.

        If ``user.parent_user_id`` is set (i.e. the user is an agent/service
        identity with a human owner), the parent user also receives full
        permissions so the dataset is visible to them.
    Args:
        dataset_name: Name of the dataset.
        user: The user object.

    Returns:
        Dataset: The new authorized dataset.
    """
    db_engine = get_relational_engine()

    async with db_engine.get_async_session() as session:
        new_dataset = await create_dataset(dataset_name, user, session)

    for permission in _DATASET_PERMISSIONS:
        await give_permission_on_dataset(user, new_dataset.id, permission)

    # Under AUTH_MODE=oidc every member of the active tenant gets the dataset.
    if is_tenant_scoped(user):
        tenant = await get_tenant(user.tenant_id)
        for permission in _DATASET_PERMISSIONS:
            await give_permission_on_dataset(tenant, new_dataset.id, permission)

    parent_user_id = getattr(user, "parent_user_id", None)
    if parent_user_id is not None and parent_user_id != user.id:
        try:
            parent = await get_user(parent_user_id)
        except EntityNotFoundError:
            logger.warning(
                "parent_user_id %s on user %s does not resolve to a user; "
                "skipping auto-share of dataset %s",
                parent_user_id,
                user.id,
                new_dataset.id,
            )
        else:
            for permission in _DATASET_PERMISSIONS:
                await give_permission_on_dataset(parent, new_dataset.id, permission)

    return new_dataset
