"""The runtime version must come from installed distribution metadata.

``__version__`` is derived from ``importlib.metadata``, so a wheel can no longer
report a version that disagrees with its own dist-info. These checks catch the two
ways that derivation can silently go wrong: the package is not installed under the
name we look up (yielding the ``0.0.0+unknown`` sentinel), or ``pyproject.toml``
stops being the single source of truth for the version.
"""

import sys
import tomllib
from pathlib import Path

import pytest

import crewai_nti

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="tomllib is only available on Python 3.11+"
)


def test_version_was_resolved_from_metadata():
    assert crewai_nti.__version__ != "0.0.0+unknown", (
        "importlib.metadata could not find the 'crewai-nti' distribution; "
        "check the distribution name passed to importlib.metadata.version()"
    )


def test_runtime_version_matches_pyproject():
    root = Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert crewai_nti.__version__ == declared
