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


def test_a_mistyped_check_digit_is_refused():
    """Well formed but one digit off would otherwise send a different person's identity."""
    with pytest.raises(ValueError):
        build_manifest.langfuse_user_id({"person": "p", "user_id": "p",
                                         "orcid": "0000-0001-9076-6067"})


@pytest.mark.parametrize("orcid", ["0000-0002-1825-0097", "0000-0002-1694-233X",
                                   "0000-0001-9076-6066", "0000-0003-4859-8681"])
def test_valid_check_digits_pass(orcid):
    """0000-0002-1825-0097 and 0000-0002-1694-233X are ORCID's own documented examples."""
    assert build_manifest.orcid_checksum_ok(orcid)


def test_a_bad_orcid_stops_the_build_before_any_scan(monkeypatch, tmp_path, capsys):
    people = tmp_path / "people.json"
    people.write_text(json.dumps([{"person": "p", "user_id": "p", "orcid": "0000-0001-9076-6067",
                                   "sources": [{"type": "t", "find_root": str(tmp_path)}]}]))

    def no_scan(root):
        raise AssertionError("scanned transcripts before validating ORCIDs")

    monkeypatch.setattr(build_manifest, "find_jsonl_files", no_scan)
    monkeypatch.setattr(sys, "argv", ["build_manifest.py", "--people", str(people),
                                      "--out", str(tmp_path / "m.json")])
    assert build_manifest.main() == 2
    assert "not a valid ORCID" in capsys.readouterr().err
    assert not (tmp_path / "m.json").exists()


@pytest.mark.parametrize("bad", ["", "   ", 0, False, []])
def test_a_recorded_but_empty_orcid_is_refused(bad):
    """Only an absent or null orcid means "use the account name"; anything else is a typo."""
    with pytest.raises(ValueError):
        build_manifest.langfuse_user_id({"person": "p", "user_id": "p", "orcid": bad})


def test_null_orcid_means_the_account_name():
    assert build_manifest.langfuse_user_id({"person": "p", "user_id": "p", "orcid": None}) == "p"


def test_the_readme_example_passes_validation():
    import re
    text = (ROOT / "README.md").read_text()
    example = re.search(r'"orcid": "([^"]+)"', text).group(1)
    assert build_manifest.langfuse_user_id({"person": "p", "user_id": "p", "orcid": example})


def test_the_sample_env_does_not_reintroduce_a_limit():
    """retro_load.py loads .env before reading the limit, so a copied sample decides it."""
    for line in (ROOT / ".env.example").read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key == "CC_LANGFUSE_MAX_CHARS":
            assert int(value) <= 0, f".env.example sets a {value}-character limit"


def test_non_ascii_digits_are_refused():
    """Python's \\d matches Arabic-Indic digits, and int() accepts them, so the checksum passes."""
    arabic_indic = "٠٠٠٠-٠٠٠٢-١٨٢٥-٠٠٩7"
    with pytest.raises(ValueError):
        build_manifest.langfuse_user_id({"person": "p", "user_id": "p", "orcid": arabic_indic})
