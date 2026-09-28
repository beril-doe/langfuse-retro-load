import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import inventory  # noqa: E402

REAL_GITLEAKS_TOO_OLD = inventory._gitleaks_too_old


def pytest_configure(config):
    config.addinivalue_line("markers", "real_gitleaks_version: run inventory's real gitleaks "
                                       "version check instead of treating the version as current")


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
