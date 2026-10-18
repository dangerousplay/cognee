"""COGNEE_PLUGINS registers adapters before any engine is built (COG-22).

The FalkorDB community adapter only becomes a valid provider after its
``register`` module is imported, so the API imports every module listed in
COGNEE_PLUGINS at startup, before migrations, and refuses to start when one
is missing rather than failing later on the first graph call.
"""

import sys
import types

import pytest

from cognee.infrastructure.plugins import load_plugins


@pytest.fixture
def fake_plugin(monkeypatch):
    monkeypatch.setitem(sys.modules, "aslamel_fake_plugin", types.ModuleType("aslamel_fake_plugin"))


def test_listed_module_is_imported(monkeypatch, fake_plugin):
    monkeypatch.setenv("COGNEE_PLUGINS", " aslamel_fake_plugin , json")

    loaded = load_plugins()

    assert loaded == ["aslamel_fake_plugin", "json"]


def test_module_body_runs_once_across_calls(monkeypatch, tmp_path):
    (tmp_path / "aslamel_counting_plugin.py").write_text(
        "import builtins\nbuiltins.ASLAMEL_PLUGIN_RUNS = getattr(builtins, 'ASLAMEL_PLUGIN_RUNS', 0) + 1\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("COGNEE_PLUGINS", "aslamel_counting_plugin")
    import builtins

    load_plugins()
    load_plugins()

    assert builtins.ASLAMEL_PLUGIN_RUNS == 1
    del builtins.ASLAMEL_PLUGIN_RUNS
    sys.modules.pop("aslamel_counting_plugin", None)


def test_missing_module_fails_naming_it(monkeypatch):
    monkeypatch.setenv("COGNEE_PLUGINS", "aslamel_no_such_plugin")

    with pytest.raises(RuntimeError, match="aslamel_no_such_plugin"):
        load_plugins()


@pytest.mark.parametrize("value", [None, "", " , "])
def test_unset_or_empty_imports_nothing(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("COGNEE_PLUGINS", raising=False)
    else:
        monkeypatch.setenv("COGNEE_PLUGINS", value)

    assert load_plugins() == []


def test_api_lifespan_loads_plugins_before_migrations():
    import inspect

    from cognee.api.client import lifespan

    source = inspect.getsource(lifespan)

    assert "load_plugins()" in source
    assert source.index("load_plugins()") < source.index("await run_migrations()")
