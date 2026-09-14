"""Tag computation, which decides how a loaded trace can ever be found again."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import run_manifest

BASE = {"session_id": "s", "source": "pod-live", "user_id": "u",
        "consent_bin": None, "event_day": None, "role": None, "group": None}


def test_claude_code_and_retro_load_are_not_duplicated():
    """retro_load.py prepends both itself. Adding them here too put them in twice."""
    tags = run_manifest.compute_tags(BASE, "batch-1")
    assert "claude-code" not in tags and "retro-load" not in tags


def test_batch_tag_is_always_present():
    """The only handle for finding or deleting one run's output afterwards."""
    assert "batch-1" in run_manifest.compute_tags(BASE, "batch-1")


def test_absent_consent_produces_no_consent_tag():
    """An absent consent_bin must not become consent:None, which would read as a
    recorded consent decision that was never made."""
    tags = run_manifest.compute_tags(BASE, "b")
    assert not any(t.startswith("consent:") for t in tags)


def test_recorded_consent_is_tagged():
    entry = {**BASE, "consent_bin": "opt_in"}
    assert "consent:opt_in" in run_manifest.compute_tags(entry, "b")


def test_event_day_uses_the_entry_date_not_a_hardcoded_one():
    """The date here must differ from the fallback in `compute_tags`, or this cannot fail.

    It used 2026-05-07, which is exactly the fallback the function substitutes when an entry
    has no `event_day_date`. An implementation that ignored the field entirely and always
    emitted the fallback passed, which is the opposite of what the name claims.
    """
    fallback = "2026-05-07"
    entry = {**BASE, "event_day": True, "event_day_date": "2024-11-30"}
    tags = run_manifest.compute_tags(entry, "b")
    assert "event_day:2024-11-30" in tags
    assert f"event_day:{fallback}" not in tags


def test_event_day_without_a_date_falls_back():
    """The other half, so the fallback is covered deliberately rather than by accident."""
    entry = {**BASE, "event_day": True}
    assert "event_day:2026-05-07" in run_manifest.compute_tags(entry, "b")
