"""Guards against packaging metadata drifting from the runtime version string.

A wheel whose dist-info version disagrees with ``__version__`` misleads users and
dependency resolvers, and it is invisible to normal tests because both values are
read from different places.
"""

import tomllib
from pathlib import Path

import crewai_nti


def test_runtime_version_matches_pyproject():
    root = Path(__file__).resolve().parents[1]
    declared = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert crewai_nti.__version__ == declared
