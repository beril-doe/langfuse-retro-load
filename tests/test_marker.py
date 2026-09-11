"""The idempotency marker, which is where this repo's worst bug lived.

On 2026-08-20 four sessions were loaded into `projtestproj` as a pre-flight sample.
The real run hours later saw their markers, skipped all four, and printed
`106 emitted, 5 already loaded (skipped), 0 not found, 0 failed`. Every word true,
and 198 turns never reached the project they were meant for, including the largest
session in the corpus. Nobody noticed for three weeks.

The cause is visible in `marker_path`: the key is a hash of the source path and
nothing else. A marker records that a file was loaded, never where it went.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import retro_load


@pytest.fixture(autouse=True)
def marker_dir(tmp_path, monkeypatch):
    """Never touch the real ~/.retro_load_markers/ during a test."""
    d = tmp_path / "markers"
    monkeypatch.setattr(retro_load, "MARKER_DIR", d)
    return d


def test_marker_key_is_the_source_path(tmp_path):
    a, b = tmp_path / "one.jsonl", tmp_path / "two.jsonl"
    assert retro_load.marker_path(a) != retro_load.marker_path(b)
    assert retro_load.marker_path(a).name == hashlib.sha256(str(a).encode()).hexdigest() + ".json"


def test_marker_does_not_record_a_destination(tmp_path):
    """The regression test for the August misfiling.

    If a future change adds a project or host to the marker, this fails and should be
    updated deliberately. Until then it documents the gap rather than hiding it.
    """
    path = tmp_path / "s.jsonl"
    retro_load.write_marker(path, "sess-1", 5, ["claude-code", "retro-load"])
    recorded = json.loads(retro_load.marker_path(path).read_text())
    assert set(recorded) == {"session_id", "turns_emitted", "tags", "loaded_at_utc"}
    assert not any("project" in k or "host" in k for k in recorded)


def test_already_loaded_reads_back_what_was_written(tmp_path):
    path = tmp_path / "s.jsonl"
    assert retro_load.already_loaded(path) is None
    retro_load.write_marker(path, "sess-1", 5, ["t"])
    assert retro_load.already_loaded(path)["turns_emitted"] == 5


def test_a_corrupt_marker_reads_as_absent_not_as_an_error(tmp_path):
    """A marker that cannot be parsed must not abort a load, but it also must not
    be treated as proof the file was loaded."""
    path = tmp_path / "s.jsonl"
    retro_load.marker_path(path).parent.mkdir(parents=True, exist_ok=True)
    retro_load.marker_path(path).write_text("{ not json")
    assert retro_load.already_loaded(path) is None
