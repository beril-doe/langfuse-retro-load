"""One Langfuse destination for the presence check, the marker and the client.

https://github.com/beril-doe/langfuse-retro-load/issues/31: the loader read LANGFUSE_HOST
first and passed it as `host`, while the SDK ranks the LANGFUSE_BASE_URL variable above an
explicit `host`, so with both set the check and the marker named one project and the traces
went to another. Offline: no network, no real keys.
"""
import contextlib
import json
import sys
import types
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("dotenv")
import retro_load  # noqa: E402


@pytest.mark.parametrize("environ,expected", [
    ({"LANGFUSE_BASE_URL": "https://b.test", "LANGFUSE_HOST": "https://h.test"}, "https://b.test"),
    ({"LANGFUSE_HOST": "https://h.test"}, "https://h.test"),
    ({"LANGFUSE_BASE_URL": "https://b.test/"}, "https://b.test"),
    ({}, retro_load.DEFAULT_DESTINATION),
])
def test_the_destination_follows_the_sdks_order(environ, expected):
    assert retro_load.resolve_destination(environ) == expected


def test_the_real_client_uses_the_resolved_destination_despite_conflicting_variables(monkeypatch):
    pytest.importorskip("langfuse")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://b.test")
    monkeypatch.setenv("LANGFUSE_HOST", "https://h.test")
    destination = retro_load.resolve_destination()
    # The SDK caches its resources per public key, so each client here gets its own key.
    client = retro_load.make_client(f"pk-{uuid.uuid4().hex}", "sk-test", destination,
                                    tracing_enabled=False)
    assert client._resources.base_url == destination == "https://b.test"


def test_an_explicit_destination_outranks_both_variables(monkeypatch):
    pytest.importorskip("langfuse")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://b.test")
    monkeypatch.setenv("LANGFUSE_HOST", "https://h.test")
    client = retro_load.make_client(f"pk-{uuid.uuid4().hex}", "sk-test", "https://chosen.test",
                                    tracing_enabled=False)
    assert client._resources.base_url == "https://chosen.test"


def test_presence_marker_and_client_all_get_the_same_destination(monkeypatch, tmp_path):
    monkeypatch.setattr(retro_load, "MARKER_DIR", tmp_path / "markers")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-test")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://b.test")
    monkeypatch.setenv("LANGFUSE_HOST", "https://h.test")
    seen = {}
    monkeypatch.setattr(retro_load.presence, "session_observation_count",
                        lambda host, *a, **k: seen.setdefault("presence", host) and 0)
    monkeypatch.setattr(retro_load, "make_client", lambda pk, sk, dest, **k: seen.setdefault(
        "client", dest) and types.SimpleNamespace(flush=lambda: None, shutdown=lambda: None))
    monkeypatch.setattr(retro_load, "write_marker",
                        lambda *a, **k: seen.setdefault("marker", k.get("host")))
    monkeypatch.setattr(retro_load, "build_turns", lambda msgs: [object()])
    monkeypatch.setattr(retro_load, "emit_turn", lambda *a, **k: None)
    fake = types.ModuleType("langfuse")
    fake.propagate_attributes = lambda **k: contextlib.nullcontext()
    monkeypatch.setitem(sys.modules, "langfuse", fake)

    path = tmp_path / "s-1.jsonl"
    path.write_text(json.dumps({"type": "user", "uuid": "u-1", "timestamp": "2026-01-01T00:00:00Z",
                                "message": {"role": "user", "content": "hi"}}) + "\n")
    monkeypatch.setattr(sys, "argv", ["retro_load.py", "--without-plan", "--min-idle-days", "0",
                                      str(path)])
    assert retro_load.main() == 0
    assert seen == {"presence": "https://b.test", "client": "https://b.test",
                    "marker": "https://b.test"}
