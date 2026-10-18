"""Users and tenant membership follow the Rauthy token, on every request.

COG-03: no allowed group -> 403 and no user row. COG-04: the first token makes
exactly one user, keyed by the Rauthy sub. COG-07/08: allowed groups become
tenant memberships and a group that is gone takes the membership with it.
COG-10: the platform group is a member of every tenant and superuser.
"""

import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.users.authentication.oidc.config import OIDCSettings
from cognee.modules.users.authentication.oidc.sync import (
    SENTINEL_OWNER,
    sync_principal,
    tenant_id_for,
    user_id_for,
)
from cognee.modules.users.models import Tenant, User
from cognee.modules.users.models.UserTenant import UserTenant

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


def _claims(groups, sub=None, email=None):
    sub = sub or f"sub-{uuid4()}"
    return {
        "iss": ISSUER,
        "sub": sub,
        "email": email or f"{sub}@aslamel.net",
        "groups": groups,
    }


async def _sync(claims, requested_tenant=None):
    return await sync_principal(claims, requested_tenant, settings=SETTINGS)


async def _users_with_id(user_id):
    async with get_relational_engine().get_async_session() as session:
        return (await session.execute(select(User).where(User.id == user_id))).scalars().all()


async def _memberships(user_id):
    async with get_relational_engine().get_async_session() as session:
        rows = await session.execute(
            select(Tenant.name)
            .join(UserTenant, UserTenant.tenant_id == Tenant.id)
            .where(UserTenant.user_id == user_id)
        )
        return sorted(rows.scalars().all())


@pytest.mark.asyncio
async def test_first_token_creates_one_user_keyed_by_sub():
    claims = _claims(["nova-terra"])

    user = await _sync(claims)

    assert user.id == user_id_for(ISSUER, claims["sub"])
    assert user.email == claims["email"]
    assert user.hashed_password == "!"
    assert len(await _users_with_id(user.id)) == 1


@pytest.mark.asyncio
async def test_repeated_tokens_reuse_the_same_user():
    claims = _claims(["nova-terra"])

    first = await _sync(claims)
    second = await _sync(claims)

    assert first.id == second.id
    assert len(await _users_with_id(first.id)) == 1


@pytest.mark.asyncio
async def test_concurrent_first_requests_create_one_user():
    claims = _claims(["cookiebot"])

    users = await asyncio.gather(_sync(claims), _sync(claims))

    assert users[0].id == users[1].id
    assert len(await _users_with_id(users[0].id)) == 1


@pytest.mark.asyncio
async def test_allowed_group_becomes_tenant_membership_with_sentinel_owner():
    user = await _sync(_claims(["nova-terra"]))

    assert await _memberships(user.id) == ["nova-terra"]
    async with get_relational_engine().get_async_session() as session:
        tenant = await session.get(Tenant, tenant_id_for("nova-terra"))
    assert tenant.name == "nova-terra"
    assert tenant.owner_id == SENTINEL_OWNER
    assert user.tenant_id == tenant_id_for("nova-terra")


@pytest.mark.asyncio
async def test_lost_group_removes_the_membership():
    claims = _claims(["nova-terra", "cookiebot"])
    user = await _sync(claims)
    assert await _memberships(user.id) == ["cookiebot", "nova-terra"]

    claims["groups"] = ["cookiebot"]
    user = await _sync(claims)

    assert await _memberships(user.id) == ["cookiebot"]
    assert user.tenant_id == tenant_id_for("cookiebot")


@pytest.mark.asyncio
async def test_platform_group_is_member_of_every_tenant_and_superuser():
    user = await _sync(_claims(["platform"]))

    assert await _memberships(user.id) == ["cookiebot", "nova-terra"]
    assert user.is_superuser is True


@pytest.mark.asyncio
async def test_losing_platform_drops_superuser():
    claims = _claims(["platform"])
    await _sync(claims)

    claims["groups"] = ["nova-terra"]
    user = await _sync(claims)

    assert user.is_superuser is False
    assert await _memberships(user.id) == ["nova-terra"]


@pytest.mark.parametrize("groups", [[], [""], ["other"], ["penpot", ""]])
@pytest.mark.asyncio
async def test_no_allowed_group_is_403_and_creates_no_user(groups):
    claims = _claims(groups)

    with pytest.raises(HTTPException) as error:
        await _sync(claims)

    assert error.value.status_code == 403
    assert await _users_with_id(user_id_for(ISSUER, claims["sub"])) == []


@pytest.mark.asyncio
async def test_missing_groups_claim_is_403():
    claims = _claims([])
    del claims["groups"]

    with pytest.raises(HTTPException) as error:
        await _sync(claims)

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_unknown_group_next_to_an_allowed_one_is_ignored():
    user = await _sync(_claims(["nova-terra", "penpot"]))

    assert await _memberships(user.id) == ["nova-terra"]


@pytest.mark.asyncio
async def test_email_collision_keeps_the_previous_email():
    taken = _claims(["nova-terra"])
    await _sync(taken)
    claims = _claims(["nova-terra"])
    user = await _sync(claims)

    claims["email"] = taken["email"]
    user_after = await _sync(claims)

    assert user_after.id == user.id
    assert user_after.email == user.email


@pytest.mark.asyncio
async def test_email_change_is_copied():
    claims = _claims(["nova-terra"])
    await _sync(claims)

    claims["email"] = f"renamed-{uuid4()}@aslamel.net"
    user = await _sync(claims)

    assert user.email == claims["email"]
