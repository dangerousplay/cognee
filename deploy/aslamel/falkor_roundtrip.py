"""Write a node to FalkorDB and read it back through cognee's graph factory.

Proves the community adapter registers under the provider name "falkor" with
this cognee version and that its query path works against a real server.
Usage: python falkor_roundtrip.py <host> [port] [password]
"""

import asyncio
import sys
from uuid import uuid4

import cognee_community_hybrid_adapter_falkor.register  # noqa: F401
from cognee.infrastructure.databases.graph.get_graph_engine import create_graph_engine


async def main(host: str, port: int, password: str | None) -> None:
    graph = create_graph_engine(
        graph_database_provider="falkor",
        graph_file_path="",
        graph_database_url=host,
        graph_database_port=port,
        graph_database_password=password or "",
        graph_database_name=f"roundtrip_{uuid4().hex[:8]}",
    )
    probe = uuid4().hex
    await graph.query("CREATE (n:Probe {id: $id})", {"id": probe})
    rows = await graph.query("MATCH (n:Probe {id: $id}) RETURN n.id", {"id": probe})
    await graph.delete_graph()
    if not rows or probe not in str(rows):
        raise SystemExit(f"round trip failed: wrote {probe}, read {rows!r}")
    print(f"falkor round trip ok ({probe})")


if __name__ == "__main__":
    args = sys.argv[1:]
    asyncio.run(main(args[0], int(args[1]) if len(args) > 1 else 6379, args[2] if len(args) > 2 else None))
