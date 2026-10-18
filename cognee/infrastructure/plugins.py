import importlib
import os

from cognee.shared.logging_utils import get_logger

logger = get_logger("plugins")


def load_plugins() -> list[str]:
    """Import every module named in COGNEE_PLUGINS (comma-separated).

    Community adapters register their provider names when imported, so this
    must run before any database engine is created.
    """
    names = [name.strip() for name in os.getenv("COGNEE_PLUGINS", "").split(",") if name.strip()]
    for name in names:
        try:
            importlib.import_module(name)
        except ImportError as error:
            raise RuntimeError(f"COGNEE_PLUGINS: cannot import {name}: {error}") from error
        logger.info("Loaded plugin %s", name)
    return names
