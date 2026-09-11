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
import inspect
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


def test_the_marker_records_what_it_claims_to(tmp_path):
    """The fields a reader of a marker is entitled to find. A superset check, so adding
    a destination to the marker does not fail this test: that change is the fix, not a
    regression."""
    path = tmp_path / "s.jsonl"
    retro_load.write_marker(path, "sess-1", 5, ["claude-code", "retro-load"])
    recorded = json.loads(retro_load.marker_path(path).read_text())
    assert {"session_id", "turns_emitted", "tags", "loaded_at_utc"} <= set(recorded)
    assert recorded["session_id"] == "sess-1"
    assert recorded["turns_emitted"] == 5


def test_a_marker_cannot_know_where_a_load_went(tmp_path):
    """The August misfiling, stated as what the code can and cannot express.

    An earlier version of this test asserted that no key in the marker mentions a project
    or a host. That locks the defect in as the contract: it passes today and fails on the
    day someone fixes it, which is a regression test for the bug rather than against it.

    The defect is structural, so state it structurally. `marker_path` takes the source
    path and nothing else, so no marker can distinguish a load that went to `beril-usage`
    from one that went to `projtestproj`, and `already_loaded` therefore reports a skip
    for a file that reached the wrong project. When that is fixed, this fails with a
    message saying what to do about it rather than looking like a broken assertion.
    """
    assert list(inspect.signature(retro_load.marker_path).parameters) == ["transcript_path"], (
        "marker_path now takes more than the source path. If the new parameter is the "
        "destination, this is the fix for the August misfiling: delete this test and "
        "assert instead that two destinations produce two markers."
    )
    a = tmp_path / "s.jsonl"
    retro_load.write_marker(a, "sess-1", 5, ["t"])
    assert retro_load.already_loaded(a) is not None, (
        "a second load of this file is skipped no matter which project it would go to")


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
