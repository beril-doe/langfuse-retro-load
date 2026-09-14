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
    entry = {**BASE, "event_day": True, "event_day_date": "2026-05-07"}
    assert "event_day:2026-05-07" in run_manifest.compute_tags(entry, "b")
