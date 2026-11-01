"""The per-dataset pgvector engine's search_path, as sent to the server."""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("asyncpg")

import cognee.infrastructure.databases.vector.pgvector.PGVectorAdapter as module  # noqa: E402


def test_schema_search_path_has_no_space_after_the_comma():
    captured = {}

    def fake_init(self, connection_string, connect_args=None, pool_args=None):
        captured["connect_args"] = connect_args

    relational = MagicMock(db_uri="postgresql+asyncpg://u:p@h:5432/cognee")
    config = MagicMock(pool_args=None, database_connect_args=None)
    with (
        patch.object(module, "get_relational_engine", return_value=relational),
        patch.object(module, "get_relational_config", return_value=config),
        patch.object(module, "get_vectordb_config", return_value=MagicMock(vector_pool_args=None)),
        patch.object(module, "backend_access_control_enabled", return_value=True),
        patch.object(module.SQLAlchemyAdapter, "__init__", fake_init),
    ):
        module.PGVectorAdapter(
            "postgresql+asyncpg://u:p@h:5432/cognee",
            api_key=None,
            embedding_engine=MagicMock(),
            schema="ds_abc",
        )

    # PgDog splits on "," and quotes each part, leading space included.
    assert captured["connect_args"]["server_settings"]["search_path"] == "ds_abc,public"
