"""Editor and reader groups per tenant (OIDC_EDITOR/READER_GROUP_FORMAT).

The tenant's own group grants nothing; `<tenant>-cognee-reader` reads and
`<tenant>-cognee-editor` also writes, deletes and shares, through one editor
role per tenant. Nobody holds a dataset permission personally, a reader cannot
create a dataset or reach an existing one through the create path, and
datasets from before role groups have their write grants moved to the role.
"""

from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import select

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.data.methods.create_authorized_dataset import create_authorized_dataset
from cognee.modules.data.methods.get_authorized_existing_datasets import (
    get_authorized_existing_datasets,
)
from cognee.modules.users.authentication.oidc.config import OIDCSettings
from cognee.modules.users.authentication.oidc.context import active_tenant_var
from cognee.modules.users.authentication.oidc.roles import editor_role_id
from cognee.modules.users.authentication.oidc.sync import (
    access_for,
    sync_principal,
    tenant_id_for,
)
from cognee.modules.users.exceptions import PermissionDeniedError
from cognee.modules.users.models.ACL import ACL
from cognee.modules.users.models.Permission import Permission

ISSUER = "https://iam.aslamel.net/auth/v1/"
EDITOR_FORMAT = "{tenant}-cognee-editor"
READER_FORMAT = "{tenant}-cognee-reader"


def _settings(*tenants, role_groups=True):
    return OIDCSettings(
        issuer=ISSUER,
        audiences=("cognee",),
        allowed_tenant_groups=tenants,
        superuser_group="platform",
        client_id="cognee",
        client_secret="",
        redirect_uri="",
        allowed_return_to=(),
        editor_group_format=EDITOR_FORMAT if role_groups else "",
        reader_group_format=READER_FORMAT if role_groups else "",
    )


@pytest.fixture
def tenant(monkeypatch):
    """A tenant of its own per test: the editor role and its grant move happen once per tenant."""
    name = f"t-{uuid4().hex[:8]}"
    monkeypatch.setenv("AUTH_MODE", "oidc")
    monkeypatch.setenv("OIDC_EDITOR_GROUP_FORMAT", EDITOR_FORMAT)
    monkeypatch.setenv("OIDC_READER_GROUP_FORMAT", READER_FORMAT)
    return name


async def _login(groups, settings, sub=None):
    sub = sub or f"sub-{uuid4()}"
    claims = {"iss": ISSUER, "sub": sub, "email": f"{sub}@aslamel.net", "groups": groups}
    user = await sync_principal(claims, None, settings=settings)
    active_tenant_var.set(None)
    return user


async def _granted(principal_id, dataset_id):
    async with get_relational_engine().get_async_session() as session:
        rows = await session.execute(
            select(Permission.name)
            .join(ACL, ACL.permission_id == Permission.id)
            .where(ACL.principal_id == principal_id, ACL.dataset_id == dataset_id)
        )
        return set(rows.scalars().all())


def test_access_levels_come_from_the_editor_and_reader_groups():
    settings = _settings("nova-terra", "cookiebot")
    claims = {
        "groups": [
            "nova-terra-cognee-editor",
            "nova-terra-cognee-reader",
            "cookiebot-cognee-reader",
        ]
    }

    assert access_for(claims, settings) == ({"nova-terra": "editor", "cookiebot": "reader"}, False)


def test_the_tenant_group_alone_grants_nothing_with_role_groups():
    assert access_for({"groups": ["nova-terra"]}, _settings("nova-terra")) == ({}, False)


def test_without_role_groups_the_tenant_group_is_an_editor():
    settings = _settings("nova-terra", role_groups=False)

    assert access_for({"groups": ["nova-terra"]}, settings) == ({"nova-terra": "editor"}, False)


def test_superuser_edits_every_tenant():
    access, is_superuser = access_for({"groups": ["platform"]}, _settings("a", "b"))

    assert access == {"a": "editor", "b": "editor"}
    assert is_superuser


@pytest.mark.parametrize(
    ("editor", "reader"),
    [("{tenant}-cognee-editor", ""), ("x-editor", "x-reader"), ("{tenant}-x", "{tenant}-x")],
)
def test_half_configured_role_groups_refuse_to_start(editor, reader):
    with pytest.raises(ValueError):
        replace(_settings("a"), editor_group_format=editor, reader_group_format=reader)


@pytest.mark.asyncio
async def test_a_group_less_token_is_refused(tenant):
    settings = _settings(tenant)

    with pytest.raises(Exception) as error:
        await _login([tenant], settings)

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_editor_dataset_is_read_by_the_tenant_and_owned_by_the_role(tenant):
    settings = _settings(tenant)
    editor = await _login([f"{tenant}-cognee-editor"], settings)

    dataset = await create_authorized_dataset(f"ds-{uuid4().hex[:6]}", editor)

    assert await _granted(tenant_id_for(tenant), dataset.id) == {"read"}
    assert await _granted(editor_role_id(tenant_id_for(tenant)), dataset.id) == {
        "read",
        "write",
        "delete",
        "share",
    }
    assert await _granted(editor.id, dataset.id) == set()


@pytest.mark.parametrize("permission", ["write", "delete", "share"])
@pytest.mark.asyncio
async def test_reader_reads_but_cannot_change(tenant, permission):
    settings = _settings(tenant)
    editor = await _login([f"{tenant}-cognee-editor"], settings)
    reader = await _login([f"{tenant}-cognee-reader"], settings)
    dataset = await create_authorized_dataset(f"ds-{uuid4().hex[:6]}", editor)

    readable = await get_authorized_existing_datasets([dataset.id], "read", reader)
    assert [d.id for d in readable] == [dataset.id]
    with pytest.raises(PermissionDeniedError):
        await get_authorized_existing_datasets([dataset.id], permission, reader)


@pytest.mark.asyncio
async def test_reader_cannot_create_or_reach_a_dataset_through_create(tenant):
    settings = _settings(tenant)
    editor = await _login([f"{tenant}-cognee-editor"], settings)
    reader = await _login([f"{tenant}-cognee-reader"], settings)
    existing = await create_authorized_dataset(f"ds-{uuid4().hex[:6]}", editor)

    for name in (f"new-{uuid4().hex[:6]}", existing.name):
        with pytest.raises(PermissionDeniedError):
            await create_authorized_dataset(name, reader)
    assert await _granted(reader.id, existing.id) == set()


@pytest.mark.asyncio
async def test_losing_the_editor_group_takes_write_away(tenant):
    settings = _settings(tenant)
    sub = f"sub-{uuid4()}"
    editor = await _login([f"{tenant}-cognee-editor"], settings, sub=sub)
    dataset = await create_authorized_dataset(f"ds-{uuid4().hex[:6]}", editor)

    demoted = await _login([f"{tenant}-cognee-reader"], settings, sub=sub)

    with pytest.raises(PermissionDeniedError):
        await get_authorized_existing_datasets([dataset.id], "write", demoted)
    assert await get_authorized_existing_datasets([dataset.id], "read", demoted)


@pytest.mark.asyncio
async def test_datasets_from_before_role_groups_move_their_writes_to_the_role(tenant, monkeypatch):
    monkeypatch.delenv("OIDC_EDITOR_GROUP_FORMAT")
    monkeypatch.delenv("OIDC_READER_GROUP_FORMAT")
    creator_sub = f"sub-{uuid4()}"
    creator = await _login([tenant], _settings(tenant, role_groups=False), sub=creator_sub)
    old = await create_authorized_dataset(f"old-{uuid4().hex[:6]}", creator)
    assert await _granted(tenant_id_for(tenant), old.id) == {"read", "write", "delete", "share"}

    monkeypatch.setenv("OIDC_EDITOR_GROUP_FORMAT", EDITOR_FORMAT)
    monkeypatch.setenv("OIDC_READER_GROUP_FORMAT", READER_FORMAT)
    settings = _settings(tenant)
    reader = await _login([f"{tenant}-cognee-reader"], settings)
    creator = await _login([f"{tenant}-cognee-reader"], settings, sub=creator_sub)

    assert await _granted(tenant_id_for(tenant), old.id) == {"read"}
    assert await _granted(creator.id, old.id) == {"read"}
    assert await _granted(editor_role_id(tenant_id_for(tenant)), old.id) == {
        "read",
        "write",
        "delete",
        "share",
    }
    for user in (reader, creator):
        with pytest.raises(PermissionDeniedError):
            await get_authorized_existing_datasets([old.id], "write", user)
