"""
crewai-nti: Drop-in NTI (Neutral Trust Infrastructure) security for CrewAI.
"""

from crewai_nti.guardrail import NTIGuardrailMiddleware

__version__ = "0.1.0"
__all__ = ["NTIGuardrailMiddleware"]
