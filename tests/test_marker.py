"""The idempotency marker, which is where this repo's worst bug lived.

On 2026-08-20 four sessions were loaded into `projtestproj` as a pre-flight sample.
The real run hours later saw their markers, skipped all four, and printed
`106 emitted, 5 already loaded (skipped), 0 not found, 0 failed`. Every word true,
and 198 turns never reached the project they were meant for, including the largest
session in the corpus. Nobody noticed for three weeks.

The cause is visible in `marker_path`: the key is a hash of the source path and
nothing else. A marker records that a file was loaded, never where it went.
"""
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


def test_two_sources_get_two_markers(tmp_path):
    """Different files must not collide. Stated as the property, not as the recipe.

    This used to also assert the filename equals the sha256 of the source path, which is the
    same mistake as the one below it: a destination-aware marker changes that hash, so the
    assertion would have to be deleted before the fix could pass. Two files getting two
    markers stays true either way, and it is the thing that actually matters.
    """
    a, b = tmp_path / "one.jsonl", tmp_path / "two.jsonl"
    assert retro_load.marker_path(a) != retro_load.marker_path(b)
    assert retro_load.marker_path(a).suffix == ".json"
    assert retro_load.marker_path(a).parent == retro_load.marker_path(b).parent


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


@pytest.mark.xfail(strict=True, reason=(
    "Known defect, not yet fixed: a marker records that a file was loaded and never where it "
    "went. On 2026-08-20 four sessions were loaded into projtestproj as a sample; the real run "
    "hours later saw their markers, skipped them, and 198 turns never reached the project they "
    "were meant for. When marker_path learns its destination this starts passing, strict xfail "
    "turns that into a failure, and the fix is to delete this decorator."
))
def test_two_destinations_get_two_markers(tmp_path):
    """The contract this repo should have, asserted now and failing now.

    The previous version asserted the behaviour that exists: that `marker_path` takes the
    source path and nothing else. That is worse than having no test. It makes the unsafe
    contract pass, so continuous integration stays green while a load of the same file into a
    different project is still reported as already done, and it would have to be deleted
    before the real fix could go green. A test that must be deleted to fix a bug is protecting
    the bug.

    Written as a strict expected failure instead. The assertion says what safety looks like,
    it fails today for the reason above, and the day it starts passing the suite says so.

    The signature is checked first, and that matters. Calling `marker_path(path, "a")` on
    today's one-argument function raises `TypeError`, which satisfies an expected failure just
    as well as a failed assertion does, so the test was passing for a reason that had nothing
    to do with destinations. An expected failure has to fail for the stated reason or it is
    only recording that something went wrong.
    """
    path = tmp_path / "s.jsonl"
    accepts_destination = len(inspect.signature(retro_load.marker_path).parameters) > 1
    assert accepts_destination, (
        "marker_path takes only the source path, so no marker can record where its load went")
    assert retro_load.marker_path(path, "project-a") != retro_load.marker_path(path, "project-b")


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
