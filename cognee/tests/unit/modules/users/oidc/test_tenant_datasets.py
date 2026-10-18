"""Datasets belong to the tenant under AUTH_MODE=oidc (COG-09, COG-10, COG-22).

Members of one tenant reach the same dataset by name, the tenant itself holds
read/write/delete/share on it, and a member of another tenant is refused on
read (search), write (add) and delete. Without AUTH_MODE upstream naming,
scoped to the owner, is unchanged.
"""

from uuid import NAMESPACE_OID, uuid4, uuid5

import pytest
from sqlalchemy import select

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.data.methods.create_authorized_dataset import create_authorized_dataset
from cognee.modules.data.methods.get_authorized_existing_datasets import (
    get_authorized_existing_datasets,
)
from cognee.modules.data.methods.get_unique_dataset_id import get_unique_dataset_id
from cognee.modules.users.authentication.oidc.config import OIDCSettings
from cognee.modules.users.authentication.oidc.context import active_tenant_var
from cognee.modules.users.authentication.oidc.sync import sync_principal, tenant_id_for
from cognee.modules.users.exceptions import PermissionDeniedError
from cognee.modules.users.models.ACL import ACL
from cognee.modules.users.models.Permission import Permission

ISSUER = "https://iam.aslamel.net/auth/v1/"
SETTINGS = OIDCSettings(
    issuer=ISSUER,
    audiences=("cognee",),
    allowed_tenant_groups=("nova-terra", "cookiebot"),
    superuser_group="platform",
    client_id="cognee",
    client_secret="",
    redirect_uri="",
    allowed_return_to=(),
)


async def _member(groups):
    sub = f"sub-{uuid4()}"
    claims = {"iss": ISSUER, "sub": sub, "email": f"{sub}@aslamel.net", "groups": groups}
    user = await sync_principal(claims, None, settings=SETTINGS)
    active_tenant_var.set(None)
    return user


@pytest.fixture
def oidc_mode(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "oidc")


@pytest.mark.asyncio
async def test_tenant_members_share_a_dataset_by_name(oidc_mode):
    name = f"nt-arch-{uuid4().hex[:6]}"
    alice = await _member(["nova-terra"])
    bob = await _member(["nova-terra"])

    created = await create_authorized_dataset(name, alice)
    resolved = await get_authorized_existing_datasets([name], "write", bob)

    assert created.id == uuid5(NAMESPACE_OID, f"{name}{tenant_id_for('nova-terra')}")
    assert await get_unique_dataset_id(name, bob) == created.id
    assert [dataset.id for dataset in resolved] == [created.id]


@pytest.mark.asyncio
async def test_second_member_creating_the_same_name_gets_the_same_dataset(oidc_mode):
    name = f"nt-notes-{uuid4().hex[:6]}"
    alice = await _member(["nova-terra"])
    bob = await _member(["nova-terra"])

    first = await create_authorized_dataset(name, alice)
    second = await create_authorized_dataset(name, bob)

    assert second.id == first.id


@pytest.mark.asyncio
async def test_tenant_holds_all_four_permissions_on_a_new_dataset(oidc_mode):
    alice = await _member(["nova-terra"])
    dataset = await create_authorized_dataset(f"nt-acl-{uuid4().hex[:6]}", alice)

    async with get_relational_engine().get_async_session() as session:
        rows = await session.execute(
            select(Permission.name)
            .join(ACL, ACL.permission_id == Permission.id)
            .where(ACL.principal_id == tenant_id_for("nova-terra"), ACL.dataset_id == dataset.id)
        )
        granted = set(rows.scalars().all())

    assert granted == {"read", "write", "delete", "share"}


@pytest.mark.parametrize("permission", ["read", "write", "delete"])
@pytest.mark.asyncio
async def test_other_tenant_member_is_refused(oidc_mode, permission):
    alice = await _member(["nova-terra"])
    carol = await _member(["cookiebot"])
    dataset = await create_authorized_dataset(f"nt-private-{uuid4().hex[:6]}", alice)

    with pytest.raises(PermissionDeniedError) as error:
        await get_authorized_existing_datasets([dataset.id], permission, carol)

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_other_tenant_member_cannot_resolve_the_name(oidc_mode):
    name = f"nt-hidden-{uuid4().hex[:6]}"
    alice = await _member(["nova-terra"])
    carol = await _member(["cookiebot"])
    await create_authorized_dataset(name, alice)

    assert await get_authorized_existing_datasets([name], "read", carol) == []


@pytest.mark.asyncio
async def test_without_oidc_mode_naming_stays_scoped_to_the_owner(monkeypatch):
    monkeypatch.delenv("AUTH_MODE", raising=False)
    name = f"legacy-{uuid4().hex[:6]}"
    alice = await _member(["nova-terra"])

    dataset_id = await get_unique_dataset_id(name, alice)

    assert dataset_id == uuid5(NAMESPACE_OID, f"{name}{alice.id!s}{alice.tenant_id!s}")
