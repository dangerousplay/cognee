"""The active tenant of a request (spec edge case: a user in both tenants).

X-Cognee-Tenant picks the tenant for one request only; the stored current
tenant does not move. A tenant the user is not a member of is a 403. Without
the header a stale stored tenant is replaced by the first allowed one and
persisted, so background work that re-reads the user sees a valid tenant.
"""

from uuid import uuid4

import pytest
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import update

from cognee.infrastructure.databases.relational import get_relational_engine
from cognee.modules.users.authentication.oidc.config import OIDCSettings
from cognee.modules.users.authentication.oidc.context import (
    TenantHeaderMiddleware,
    active_tenant_var,
    requested_tenant_var,
)
from cognee.modules.users.authentication.oidc.sync import sync_principal, tenant_id_for
from cognee.modules.users.methods.get_user import get_user
from cognee.modules.users.models import User

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


def _claims(groups):
    sub = f"sub-{uuid4()}"
    return {"iss": ISSUER, "sub": sub, "email": f"{sub}@aslamel.net", "groups": groups}


@pytest.fixture(autouse=True)
def _clean_context():
    token = active_tenant_var.set(None)
    yield
    active_tenant_var.reset(token)


@pytest.mark.asyncio
async def test_header_selects_tenant_for_the_request_only():
    claims = _claims(["nova-terra", "cookiebot"])
    stored = (await sync_principal(claims, None, settings=SETTINGS)).tenant_id

    user = await sync_principal(claims, "nova-terra", settings=SETTINGS)
    assert user.tenant_id == tenant_id_for("nova-terra")
    user = await sync_principal(claims, "cookiebot", settings=SETTINGS)
    assert user.tenant_id == tenant_id_for("cookiebot")

    active_tenant_var.set(None)
    assert (await get_user(user.id)).tenant_id == stored


@pytest.mark.asyncio
async def test_header_naming_a_non_member_tenant_is_403():
    claims = _claims(["cookiebot"])

    with pytest.raises(HTTPException) as error:
        await sync_principal(claims, "nova-terra", settings=SETTINGS)

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_without_header_a_stale_stored_tenant_is_replaced_and_persisted():
    claims = _claims(["nova-terra", "cookiebot"])
    user = await sync_principal(claims, None, settings=SETTINGS)
    async with get_relational_engine().get_async_session() as session:
        await session.execute(update(User).where(User.id == user.id).values(tenant_id=None))
        await session.commit()

    user = await sync_principal(claims, None, settings=SETTINGS)

    assert user.tenant_id == tenant_id_for("cookiebot")
    active_tenant_var.set(None)
    assert (await get_user(user.id)).tenant_id == tenant_id_for("cookiebot")


@pytest.mark.asyncio
async def test_override_applies_only_to_the_requesting_user():
    claims = _claims(["nova-terra", "cookiebot"])
    other = await sync_principal(_claims(["cookiebot"]), None, settings=SETTINGS)
    await sync_principal(claims, "nova-terra", settings=SETTINGS)

    assert (await get_user(other.id)).tenant_id == tenant_id_for("cookiebot")


def test_header_reaches_sync_and_background_tasks_see_the_tenant():
    claims = _claims(["nova-terra", "cookiebot"])
    seen = {}
    app = FastAPI()
    app.add_middleware(TenantHeaderMiddleware)

    async def current_user():
        return await sync_principal(claims, requested_tenant_var.get(), settings=SETTINGS)

    async def record(user_id):
        seen["background"] = (await get_user(user_id)).tenant_id

    @app.get("/probe")
    async def probe(background: BackgroundTasks, user=Depends(current_user)):
        seen["header"] = requested_tenant_var.get()
        background.add_task(record, user.id)
        return {"tenant": str(user.tenant_id)}

    with TestClient(app) as client:
        response = client.get("/probe", headers={"X-Cognee-Tenant": "nova-terra"})

    assert response.status_code == 200
    assert response.json()["tenant"] == str(tenant_id_for("nova-terra"))
    assert seen["header"] == "nova-terra"
    assert seen["background"] == tenant_id_for("nova-terra")
