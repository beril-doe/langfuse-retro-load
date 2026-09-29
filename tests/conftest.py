import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backfill  # noqa: E402
import inventory  # noqa: E402

REAL_GITLEAKS_TOO_OLD = inventory._gitleaks_too_old


def pytest_configure(config):
    config.addinivalue_line("markers", "real_gitleaks_version: run inventory's real gitleaks "
                                       "version check instead of treating the version as current")
    config.addinivalue_line("markers", "real_langfuse_check: run retro_load's real langfuse "
                                       "pin check instead of treating the install as locked")


@pytest.fixture(autouse=True)
def _gitleaks_version_is_current(monkeypatch, request):
    """Most tests fake gitleaks' output, which would also fake its version. The version check
    is cached per run, so clear it around every test, and treat the version as current unless
    a test asks for the real check."""
    REAL_GITLEAKS_TOO_OLD.cache_clear()
    if "real_gitleaks_version" not in request.keywords:
        monkeypatch.setattr(inventory, "_gitleaks_too_old", lambda: None)
    yield
    REAL_GITLEAKS_TOO_OLD.cache_clear()


@pytest.fixture(autouse=True)
def _langfuse_is_locked(monkeypatch, request):
    """Many loader tests replace langfuse with a stub that has no version, so retro_load's
    pin check would refuse them. Treat the install as locked unless a test asks otherwise."""
    if "real_langfuse_check" not in request.keywords:
        monkeypatch.setattr(backfill, "langfuse_problems", lambda: [])


def require_gitleaks():
    """Skip a test that needs the real gitleaks binary where it isn't installed, except in
    CI, which sets REQUIRE_GITLEAKS so a missing binary fails the run instead of quietly
    skipping the only tests of .gitleaks.toml
    (https://github.com/beril-doe/langfuse-retro-load/issues/58)."""
    if shutil.which("gitleaks") is None:
        if os.environ.get("REQUIRE_GITLEAKS"):
            pytest.fail("REQUIRE_GITLEAKS is set but gitleaks is not on PATH")
        pytest.skip("gitleaks not installed")
