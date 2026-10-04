"""
NTI Guardrail Middleware for CrewAI.
Intercepts tool calls, evaluates all 5 pillars of NTI policy, and blocks unauthorized actions.
"""

import json
import uuid
from typing import Any


class NTIGuardrailMiddleware:
    """
    NTI Guardrail Middleware for CrewAI.

    Enforces all 5 pillars of NTI (Neutral Trust Infrastructure) on every
    CrewAI tool execution:
      Pillar 1 - Zero-Trust Capability Enforcement
      Pillar 2 - NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
      Pillar 3 - BFT Multi-Agent Consensus
      Pillar 4 - Merkle-Chained Audit Trails
      Pillar 5 - P2P Agent Mesh & State Persistence
    """

    def __init__(self, agent_id: str, strict: bool = True) -> None:
        from ube_foundation import TrustEngine, PqcKeyPair

        self.agent_id = agent_id
        self.strict = strict
        self.engine = TrustEngine()
        self.pqc_key = PqcKeyPair.generate()

    def grant_capability(self, capability: str) -> None:
        self.engine.grant(self.agent_id, capability)

    def revoke_token(self, token_id: str) -> None:
        self.engine.revoke_token(token_id)

    def public_key_hex(self) -> str:
        return self.pqc_key.public_key_hex()

    def kyber_public_key_bytes(self) -> bytes:
        return self.pqc_key.get_kyber_public_key_bytes()

    def sign(self, message: bytes) -> str:
        return self.pqc_key.sign(message)

    def register_voter_key(self, voter_id: str, public_key_bytes: bytes) -> None:
        self.engine.register_voter_key(voter_id, public_key_bytes)

    def verify_tool_execution(self, tool_name: str, tool_input: dict) -> bool:
        req = {
            "id": f"req-{uuid.uuid4()}",
            "actor": self.agent_id,
            "capability": tool_name,
            "action": tool_name,
            "input": tool_input,
            "signature": None,
            "pqc_signature": None,
            "public_key": None,
            "pqc_public_key": None,
            "token": None,
            "identity_claim": None,
        }

        message = json.dumps(req, sort_keys=True).encode("utf-8")
        req["pqc_signature"] = self.pqc_key.sign(message).hex()
        req["pqc_public_key"] = self.pqc_key.public_key_hex()

        decision = json.loads(self.engine.evaluate(json.dumps(req)))

        if decision.get("decision") != "Allow":
            reason = decision.get("reason", "Unknown reason")
            if self.strict:
                raise PermissionError(f"NTI Security Denied Action: {reason}")
            return False
        return True
