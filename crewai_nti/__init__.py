"""
crewai-nti: Drop-in NTI (Neutral Trust Infrastructure) security for CrewAI.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from crewai_nti.guardrail import NTIGuardrailMiddleware

try:
    __version__ = _version("crewai-nti")
except PackageNotFoundError:  # imported from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["NTIGuardrailMiddleware"]
