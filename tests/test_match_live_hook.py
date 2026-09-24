"""Retro-loaded traces carry what BERIL's live hook would have sent.

Two differences from the live hook were measured on beril-usage on 2026-09-23: user IDs
were pod account names where live traces carry ORCIDs, and at least 5 of 1,210
retro-loaded observations were cut at 20,000 characters, which the live hook stopped
doing on 2026-09-22.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import build_manifest  # noqa: E402
import langfuse_hook_official  # noqa: E402
import retro_load  # noqa: E402


def test_long_text_is_kept_whole_by_default(monkeypatch):
    monkeypatch.delenv("CC_LANGFUSE_MAX_CHARS", raising=False)
    text = "x" * 23_636
    kept, meta = langfuse_hook_official.truncate_text(text)
    assert kept == text
    assert meta == {"truncated": False, "orig_len": 23_636}


def test_zero_means_no_limit_not_empty(monkeypatch):
    """The vendored sample treats 0 as keep nothing; the live hook treats it as no limit."""
    monkeypatch.setenv("CC_LANGFUSE_MAX_CHARS", "0")
    assert langfuse_hook_official.truncate_text("abc")[0] == "abc"


def test_a_positive_limit_still_applies(monkeypatch):
    monkeypatch.setenv("CC_LANGFUSE_MAX_CHARS", "10")
    kept, meta = langfuse_hook_official.truncate_text("x" * 25)
    assert kept == "x" * 10 and meta["truncated"] is True


def test_none_is_still_empty(monkeypatch):
    monkeypatch.delenv("CC_LANGFUSE_MAX_CHARS", raising=False)
    assert langfuse_hook_official.truncate_text(None) == ("", {"truncated": False, "orig_len": 0})


def test_emit_turn_uses_the_replacement():
    """emit_turn looks truncate_text up in its own module, so that is where it must change."""
    assert langfuse_hook_official.truncate_text is retro_load.truncate_text


@pytest.mark.parametrize("given", ["https://orcid.org/0000-0001-9076-6066",
                                   "0000-0001-9076-6066", " http://orcid.org/0000-0001-9076-6066 "])
def test_orcid_becomes_the_bare_id(given):
    person = {"person": "p", "user_id": "p", "orcid": given}
    assert build_manifest.langfuse_user_id(person) == "0000-0001-9076-6066"


def test_without_an_orcid_the_account_name_is_used():
    assert build_manifest.langfuse_user_id({"person": "p", "user_id": "p"}) == "p"


def test_a_malformed_orcid_is_refused_not_ignored():
    with pytest.raises(ValueError):
        build_manifest.langfuse_user_id({"person": "p", "user_id": "p", "orcid": "0000-0001"})


def test_the_committed_manifest_agrees_with_people_json():
    people = {p["person"]: build_manifest.langfuse_user_id(p)
              for p in json.loads((ROOT / "people.json").read_text())}
    manifest = json.loads((ROOT / "manifest.json").read_text())
    assert {(r["person"], r["user_id"]) for r in manifest} <= set(people.items())
