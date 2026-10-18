"""Cross-tenant isolation through the HTTP API (COG-09, COG-10, Independent Test).

User A (nova-terra) creates a dataset; user B (nova-terra) reaches it by name
and by id; user C (cookiebot only) is refused with 403 on read, add, search
and delete of it.
"""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from cognee.tests.api_oidc.oidc_helpers import UI_ORIGIN, fake_fetch_jwks, mint


@pytest.fixture(scope="module")
def client():
    from cognee.api.client import app
    from cognee.modules.users.authentication.oidc import jwks

    original = jwks._fetch_json
    jwks._fetch_json = fake_fetch_jwks
    try:
        with TestClient(app, base_url=UI_ORIGIN) as client:
            yield client
    finally:
        jwks._fetch_json = original


def _as(groups):
    return {"Authorization": f"Bearer {mint(groups)}"}


@pytest.fixture(scope="module")
def dataset(client):
    alice = _as(["nova-terra"])
    name = f"nt-arch-{uuid4().hex[:6]}"
    response = client.post("/api/v1/datasets", json={"name": name}, headers=alice)
    assert response.status_code == 200, response.text
    return {"name": name, "id": response.json()["id"]}


def test_another_member_of_the_tenant_gets_the_same_dataset_by_name(client, dataset):
    bob = _as(["nova-terra"])

    response = client.post("/api/v1/datasets", json={"name": dataset["name"]}, headers=bob)

    assert response.status_code == 200, response.text
    assert response.json()["id"] == dataset["id"]


def test_another_member_of_the_tenant_can_read_it(client, dataset):
    response = client.get(f"/api/v1/datasets/{dataset['id']}/data", headers=_as(["nova-terra"]))

    assert response.status_code == 200, response.text


def test_other_tenant_cannot_read_it(client, dataset):
    response = client.get(f"/api/v1/datasets/{dataset['id']}/data", headers=_as(["cookiebot"]))

    assert response.status_code == 403, response.text


def test_other_tenant_cannot_search_it(client, dataset):
    response = client.post(
        "/api/v1/search",
        json={"query": "architecture", "dataset_ids": [dataset["id"]], "search_type": "CHUNKS"},
        headers=_as(["cookiebot"]),
    )

    assert response.status_code == 403, response.text


def test_other_tenant_cannot_add_to_it(client, dataset):
    response = client.post(
        "/api/v1/add",
        data={"datasetId": dataset["id"], "raw_data": ["a fact"]},
        headers=_as(["cookiebot"]),
    )

    assert response.status_code == 403, response.text


def test_other_tenant_cannot_delete_it(client, dataset):
    response = client.delete(f"/api/v1/datasets/{dataset['id']}", headers=_as(["cookiebot"]))

    assert response.status_code == 403, response.text
