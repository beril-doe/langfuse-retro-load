"""The removal warning, which has a timezone-sensitive contract nothing exercised.

`warn_deprecated` compares today against the date Langfuse states for removing four routes.
It used `date.today()`, which is local, so on a machine west of Greenwich it kept saying
"before" for hours after the date had passed in UTC. That was fixed by reading UTC, and the
deletion tests monkeypatch the whole function to a no-op, so a regression straight back to
local time would not have failed anything.
"""
import datetime
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import langfuse_admin


class FrozenDatetime(datetime.datetime):
    """A clock stuck at one instant, honouring the tz it is asked for."""

    frozen = datetime.datetime(2026, 11, 16, 3, 30, tzinfo=datetime.timezone.utc)

    @classmethod
    def now(cls, tz=None):
        # tz=None has to behave like the real datetime.now(): local wall time, naive.
        # Returning the UTC instant here made this whole file unable to fail. Reverting the
        # code to date.today() left both tests green, because the fake clock was answering
        # the UTC question no matter which one was asked.
        if tz is None:
            return cls.frozen.astimezone().replace(tzinfo=None)
        return cls.frozen.astimezone(tz)


@pytest.fixture
def at_the_boundary(monkeypatch):
    """03:30 UTC on removal day, which is still the day before in US Pacific.

    This is the exact hour the bug lived in: UTC says the routes are gone, local time west of
    Greenwich still says they are fine.
    """
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    time.tzset()
    monkeypatch.setattr(langfuse_admin.datetime, "datetime", FrozenDatetime)
    # Assert the fixture really is at a boundary. Without this the test passes in any
    # timezone for the wrong reason, which is the failure it exists to catch.
    assert FrozenDatetime.now().date().isoformat() < langfuse_admin.V3_REMOVAL
    assert FrozenDatetime.now(datetime.timezone.utc).date().isoformat() == langfuse_admin.V3_REMOVAL
    yield
    time.tzset()


def test_on_removal_day_it_warns_even_where_it_is_still_yesterday(at_the_boundary, capsys):
    langfuse_admin.warn_deprecated()
    err = capsys.readouterr().err
    assert "warning:" in err, "read local time and concluded the date had not arrived"
    assert "may mean the route is gone" in err


def test_before_removal_it_says_note_not_warning(monkeypatch, capsys):
    class Earlier(FrozenDatetime):
        frozen = datetime.datetime(2026, 9, 14, 12, 0, tzinfo=datetime.timezone.utc)
    monkeypatch.setattr(langfuse_admin.datetime, "datetime", Earlier)
    langfuse_admin.warn_deprecated()
    err = capsys.readouterr().err
    assert err.startswith("note:")
    assert langfuse_admin.V3_REMOVAL in err, "say the date, not just that one exists"
