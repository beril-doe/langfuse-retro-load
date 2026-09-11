"""The refusals in `langfuse_admin.py delete`, which are the only thing between a
typo and a production deletion.

Every case here asserts two things: that the command refuses, and that it refused
*before* touching the network. The second is the one worth testing. An earlier
version required the --name/--all selector at parse time, so `delete --type
observation` died on a missing selector and never printed the reason observations
cannot be deleted. A refusal that happens for the wrong reason, or after the tool
has already authenticated and enumerated a project, is not the same refusal.
"""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import langfuse_admin


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any refusal that reaches the network fails the test rather than passing quietly."""
    def forbidden(*a, **k):
        raise AssertionError("refusal path made a network call")
    monkeypatch.setattr(langfuse_admin, "api", forbidden)
    monkeypatch.setattr(langfuse_admin, "auth_for_project", forbidden)
    monkeypatch.setattr(langfuse_admin, "confirm_project", forbidden)


def args(**kw):
    base = dict(project="p", type="trace", name=None, all=False,
                dry_run=False, yes=False, record=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.mark.parametrize("kind", sorted(langfuse_admin.UNDELETABLE_REASON))
def test_every_undeletable_type_refuses_with_its_reason(kind, capsys):
    """The reason matters as much as the refusal: it is the only place the API's
    limits are written down where someone hits them."""
    assert langfuse_admin.cmd_delete(args(type=kind, all=True)) == 2
    err = capsys.readouterr().err
    assert kind in err
    assert langfuse_admin.UNDELETABLE_REASON[kind].split(".")[0] in err


def test_unknown_type_lists_what_is_deletable(capsys):
    assert langfuse_admin.cmd_delete(args(type="banana", all=True)) == 2
    err = capsys.readouterr().err
    assert "unknown or undeletable type" in err
    assert "trace" in err


@pytest.mark.parametrize("kind", sorted(set(langfuse_admin.DELETABLE) - {"trace"}))
def test_deletable_but_unimplemented_types_say_so(kind, capsys):
    """These are in DELETABLE because the API can remove them, and the tool cannot yet.
    Saying "not implemented" rather than "unknown type" is the difference between a
    missing feature and a wrong claim about Langfuse."""
    assert langfuse_admin.cmd_delete(args(type=kind, all=True)) == 2
    assert "not implemented yet" in capsys.readouterr().err


def test_no_selector_refuses(capsys):
    """Neither --name nor --all. Defaulting either way is how a narrow deletion
    becomes a whole-project one."""
    assert langfuse_admin.cmd_delete(args()) == 2
    assert "--name" in capsys.readouterr().err


def test_name_and_all_together_are_rejected_at_parse_time(monkeypatch):
    monkeypatch.setattr(sys, "argv",
                        ["langfuse_admin.py", "delete", "--project", "p",
                         "--type", "trace", "--name", "x", "--all"])
    with pytest.raises(SystemExit) as e:
        langfuse_admin.main()
    assert e.value.code == 2


def test_undeletable_type_refuses_before_the_missing_selector(capsys):
    """The regression that prompted the parse-time change. With no selector AND an
    undeletable type, the type explanation must win, because it is the one that tells
    the operator something they did not know."""
    assert langfuse_admin.cmd_delete(args(type="observation")) == 2
    assert "no delete exists" in capsys.readouterr().err


def test_deletable_and_undeletable_do_not_overlap():
    """A type in both tables would be refused by the first check while the second
    table claims it can go, and nothing in the code would report the contradiction."""
    assert not (set(langfuse_admin.DELETABLE) & set(langfuse_admin.UNDELETABLE_REASON))


def test_every_countable_type_is_classified():
    """Adding an object type to COUNTABLE without deciding whether it can be deleted
    makes `count` report it and `delete` call it unknown. This is the check that
    catches the next Langfuse object type rather than the ones already here."""
    unclassified = (set(langfuse_admin.COUNTABLE)
                    - set(langfuse_admin.DELETABLE)
                    - set(langfuse_admin.UNDELETABLE_REASON))
    assert not unclassified
