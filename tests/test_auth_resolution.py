"""Which key `langfuse_admin` picks for a project, and what it refuses to do.

This is the guarantee named in `auth_for_project`'s own docstring: "Never falls back
to 'the only key present'." It is the highest-stakes untested behaviour in the file,
because a silent fallback means a delete aimed at one project authenticates against a
different one, and the confirmation step would then report the project the key serves
rather than the project the operator named.

Copilot pointed out that the deletion tests could not cover this: their fixture replaces
`auth_for_project` with a function that raises, so those tests would pass unchanged if
the resolver started falling back. These tests use the real resolver with a synthetic
environment instead. No file is read and no network is touched.
"""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import langfuse_admin

# Synthetic. Nothing here resembles a real key, and nothing reads a real .env.
ENV = {
    "ALPHA_LANGFUSE_PROJECT_ID": "proj-alpha",
    "ALPHA_LANGFUSE_PUBLIC_KEY": "pk-alpha",
    "ALPHA_LANGFUSE_SECRET_KEY": "sk-alpha",
    "ALPHA_LANGFUSE_BASE_URL": "https://alpha.example.test/",
    "BETA_LANGFUSE_PROJECT_ID": "proj-beta",
    "BETA_LANGFUSE_PUBLIC_KEY": "pk-beta",
    "BETA_LANGFUSE_SECRET_KEY": "sk-beta",
}


@pytest.fixture
def env(monkeypatch):
    def fake_load_env():
        return dict(ENV), Path("/synthetic/.env")
    monkeypatch.setattr(langfuse_admin, "load_env", fake_load_env)


def expected_header(public: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{public}:{secret}".encode()).decode()


def test_resolves_the_matching_prefix(env):
    """Asserting the exact header, not that it starts with Basic. Checking the scheme
    only would pass on a resolver that returned the wrong project's credentials, which
    is the failure this file exists to catch."""
    header, host = langfuse_admin.auth_for_project("proj-alpha")
    assert host == "https://alpha.example.test", "the trailing slash has to go, or every path double-slashes"
    assert header == expected_header("pk-alpha", "sk-alpha")


def test_each_project_gets_its_own_key(env):
    """Two projects, two prefixes, each with the credentials that belong to it. Asserting
    only that the headers differ would pass on a resolver that swapped them."""
    alpha, _ = langfuse_admin.auth_for_project("proj-alpha")
    beta, _ = langfuse_admin.auth_for_project("proj-beta")
    assert alpha == expected_header("pk-alpha", "sk-alpha")
    assert beta == expected_header("pk-beta", "sk-beta")


def test_an_unknown_project_refuses_rather_than_falling_back(env):
    """The regression this file exists for. With two complete key sets present, an
    unmatched project id must produce no header at all."""
    with pytest.raises(SystemExit) as excinfo:
        langfuse_admin.auth_for_project("proj-nonexistent")
    message = str(excinfo.value)
    assert "neither a project id nor a prefix" in message
    assert "ALPHA" in message and "BETA" in message, "say which prefixes do name a project"
    assert "pk-alpha" not in message and "sk-alpha" not in message, "never echo key values"


def test_a_prefix_with_a_project_id_but_no_keys_is_not_used(monkeypatch):
    """Half a configuration is not a configuration.

    ALPHA and BETA are present on purpose. Written with GAMMA alone, this test could not
    fail: a resolver that reached for another project's credentials would still raise,
    because there would be no other credentials to reach for. With two complete key sets
    beside the broken one, refusing is a decision rather than the only option.
    """
    env = dict(ENV)
    env["GAMMA_LANGFUSE_PROJECT_ID"] = "proj-gamma"
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: (env, Path("/synthetic/.env")))
    with pytest.raises(SystemExit):
        langfuse_admin.auth_for_project("proj-gamma")


def test_falls_back_to_the_default_host_only_for_the_host(env):
    """A missing BASE_URL is recoverable, because Langfuse US cloud is where these
    projects are. A missing key never is. The two must not share a fallback path."""
    _, host = langfuse_admin.auth_for_project("proj-beta")
    assert host == langfuse_admin.DEFAULT_HOST.rstrip("/")


def test_no_env_at_all_refuses_and_says_so(monkeypatch):
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: ({}, None))
    with pytest.raises(SystemExit) as excinfo:
        langfuse_admin.auth_for_project("proj-alpha")
    assert "(no .env found)" in str(excinfo.value)



# --- https://github.com/beril-doe/langfuse-retro-load/issues/21 -------------------------------

@pytest.mark.parametrize("given", ["ALPHA", "alpha", "Alpha"])
def test_a_prefix_resolves_to_its_project_id(env, given):
    assert langfuse_admin.resolve_project(given) == ("proj-alpha", "ALPHA")
    header, _ = langfuse_admin.auth_for_project(*langfuse_admin.resolve_project(given))
    assert header == expected_header("pk-alpha", "sk-alpha")


def test_a_project_id_passes_through_unchanged(env):
    assert langfuse_admin.resolve_project("proj-beta") == ("proj-beta", None)


def test_an_unknown_value_still_refuses_and_names_both_forms(env):
    with pytest.raises(SystemExit) as excinfo:
        langfuse_admin.auth_for_project(*langfuse_admin.resolve_project("GAMMA"))
    message = str(excinfo.value)
    assert "--project GAMMA is neither a project id nor a prefix" in message
    assert "ALPHA" in message and "BETA" in message


def test_count_accepts_a_prefix_on_the_command_line(env, monkeypatch):
    """The id and the chosen prefix both reach the credential lookup, so the keys used are
    that prefix's own (third Copilot review of
    https://github.com/beril-doe/langfuse-retro-load/pull/53)."""
    seen = []
    monkeypatch.setattr(langfuse_admin, "auth_for_project",
                        lambda project, prefix=None: seen.append((project, prefix)) or ("h", "x"))
    monkeypatch.setattr(langfuse_admin, "confirm_project", lambda *a: "stop here")
    class Stop(Exception):
        pass

    def stop(*a, **k):
        raise Stop

    for name in ("api", "observation_census"):
        monkeypatch.setattr(langfuse_admin, name, stop)
    monkeypatch.setattr(langfuse_admin.sys, "argv", ["langfuse_admin.py", "count", "--project", "beta"])
    with pytest.raises(Stop):
        langfuse_admin.main()
    assert seen == [("proj-beta", "BETA")]



def twin(monkeypatch, host):
    """ALPHA2 names proj-alpha too, with its own key and the given host."""
    env = dict(ENV)
    env.update({"ALPHA2_LANGFUSE_PROJECT_ID": "proj-alpha",
                "ALPHA2_LANGFUSE_PUBLIC_KEY": "pk-alpha2", "ALPHA2_LANGFUSE_SECRET_KEY": "sk-alpha2",
                "ALPHA2_LANGFUSE_BASE_URL": host})
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: (env, Path("/synthetic/.env")))


def test_a_chosen_prefix_uses_its_own_keys_when_two_prefixes_share_an_id(monkeypatch):
    """Copilot review of https://github.com/beril-doe/langfuse-retro-load/pull/53."""
    twin(monkeypatch, "https://elsewhere.example.test")
    header, host = langfuse_admin.auth_for_project(*langfuse_admin.resolve_project("ALPHA2"))
    assert header == expected_header("pk-alpha2", "sk-alpha2")
    assert host == "https://elsewhere.example.test"


def test_an_id_shared_by_prefixes_that_disagree_is_refused(monkeypatch):
    twin(monkeypatch, "https://elsewhere.example.test")
    with pytest.raises(SystemExit) as excinfo:
        langfuse_admin.auth_for_project("proj-alpha")
    message = str(excinfo.value)
    assert "ALPHA, ALPHA2" in message and "Pass the prefix instead" in message
    assert "pk-alpha" not in message and "sk-alpha" not in message


def test_a_prefix_with_an_id_but_no_keys_says_so(monkeypatch):
    env = dict(ENV)
    env["GAMMA_LANGFUSE_PROJECT_ID"] = "proj-gamma"
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: (env, Path("/synthetic/.env")))
    with pytest.raises(SystemExit) as excinfo:
        langfuse_admin.auth_for_project(*langfuse_admin.resolve_project("GAMMA"))
    message = str(excinfo.value)
    assert "GAMMA in /synthetic/.env names project proj-gamma but lacks" in message
    assert "neither" not in message



def test_prefixes_that_differ_only_in_case_can_each_be_named(monkeypatch):
    env = dict(ENV)
    env.update({"alpha_LANGFUSE_PROJECT_ID": "proj-lower",
                "alpha_LANGFUSE_PUBLIC_KEY": "pk-lower", "alpha_LANGFUSE_SECRET_KEY": "sk-lower"})
    monkeypatch.setattr(langfuse_admin, "load_env", lambda: (env, Path("/synthetic/.env")))
    assert langfuse_admin.resolve_project("ALPHA") == ("proj-alpha", "ALPHA")
    assert langfuse_admin.resolve_project("alpha") == ("proj-lower", "alpha")
    # Neither spelling matches exactly, and the case-insensitive match is not unique.
    assert langfuse_admin.resolve_project("Alpha") == ("Alpha", None)
