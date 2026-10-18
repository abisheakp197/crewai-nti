"""
NTI Guardrail Middleware for CrewAI.
Intercepts tool calls, evaluates all 5 pillars of NTI policy, signs and verifies
multi-agent handoffs/delegations, and blocks unauthorized actions.
"""

import json
import threading
import uuid
from typing import Any, Dict, Optional, Tuple, Union


class NTIGuardrailMiddleware:
    """
    NTI Guardrail Middleware for CrewAI.

    Enforces all 5 pillars of NTI (Neutral Trust Infrastructure) on every
    CrewAI tool execution and multi-agent handoff:
      Pillar 1 - Zero-Trust Capability Enforcement
      Pillar 2 - NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
      Pillar 3 - BFT Multi-Agent Consensus
      Pillar 4 - Merkle-Chained Audit Trails
      Pillar 5 - P2P Agent Mesh & State Persistence
    """

    def __init__(
        self,
        agent_id: str,
        strict: bool = True,
        pqc_key: Optional[Any] = None,
    ) -> None:
        from ube_foundation import PqcKeyPair, TrustEngine

        self.agent_id: str = agent_id
        self.strict: bool = strict
        self._lock: threading.Lock = threading.Lock()
        self.registered_agent_keys: Dict[str, Any] = {}

        with self._lock:
            self.engine: TrustEngine = TrustEngine()
            if pqc_key is not None:
                self.pqc_key = pqc_key
            else:
                self.pqc_key = PqcKeyPair()

    def grant_capability(self, capability: str) -> None:
        """Grants a capability to this agent in the NTI Trust Engine."""
        with self._lock:
            self.engine.grant(self.agent_id, capability)

    def revoke_token(self, token_id: str) -> None:
        """Revokes a capability token in the NTI Trust Engine."""
        with self._lock:
            self.engine.revoke_token(token_id)

    def register_voter_key(self, voter_id: str, public_key_bytes: bytes) -> None:
        """Registers a voter public key for BFT multi-agent consensus."""
        with self._lock:
            self.engine.register_voter_key(voter_id, public_key_bytes)

    def register_agent_key(self, agent_id: str, key_or_middleware: Any) -> None:
        """Registers another agent's PQC key or middleware instance for verification."""
        with self._lock:
            self.registered_agent_keys[agent_id] = key_or_middleware

    def public_key_hex(self) -> str:
        """Returns the hex-encoded PQC public key."""
        return self.pqc_key.public_key_hex()

    def kyber_public_key_bytes(self) -> bytes:
        """Returns the Kyber1024 public key bytes for KEM handshakes."""
        return self.pqc_key.get_kyber_public_key_bytes()

    def sign(self, message: bytes) -> str:
        """Signs message bytes using Dilithium5 PQC key and returns hex signature."""
        return self.pqc_key.sign(message)

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Verifies a Dilithium5 PQC signature against a message."""
        try:
            return bool(self.pqc_key.verify(message, signature_hex))
        except (TypeError, ValueError, AttributeError):
            return False

    def verify_tool_execution(self, tool_name: str, tool_input: Union[dict, Any]) -> bool:
        """
        Verifies tool execution against NTI zero-trust policy.
        Signs the canonical request and evaluates capability in TrustEngine.
        Fails closed on error or denial.
        """
        try:
            if not isinstance(tool_input, dict):
                input_dict = {"data": str(tool_input)}
            else:
                input_dict = tool_input

            req = {
                "id": f"req-{uuid.uuid4()}",
                "actor": self.agent_id,
                "capability": tool_name,
                "action": tool_name,
                "input": input_dict,
                "signature": None,
                "pqc_signature": None,
                "public_key": None,
                "pqc_public_key": None,
                "token": None,
                "identity_claim": None,
            }

            canonical_bytes = json.dumps(req, sort_keys=True, separators=(",", ":")).encode("utf-8")
            sig_hex = self.pqc_key.sign(canonical_bytes)
            local_verified = bool(self.pqc_key.verify(canonical_bytes, sig_hex))

            if not local_verified:
                if self.strict:
                    raise PermissionError("NTI Security Denied Action: PQC local signature verification failed")
                return False

            with self._lock:
                raw_decision = self.engine.evaluate(json.dumps(req))

            decision = json.loads(raw_decision)
            if decision.get("decision") != "Allow":
                reason = decision.get("reason", "Unknown policy denial")
                if self.strict:
                    raise PermissionError(f"NTI Security Denied Action: {reason}")
                return False

            return True

        except PermissionError:
            raise
        except Exception as err:
            if self.strict:
                raise PermissionError(f"NTI Security Denied Action due to error: {err}") from err
            return False

    def sign_handoff(self, target_agent_id: str, payload: dict) -> Dict[str, Any]:
        """
        Signs a multi-agent task handoff/delegation packet to target_agent_id
        using canonical JSON and Dilithium5 PQC signature.
        """
        try:
            packet = {
                "id": f"handoff-{uuid.uuid4()}",
                "sender": self.agent_id,
                "recipient": target_agent_id,
                "payload": payload,
                "pqc_public_key": self.public_key_hex(),
                "pqc_signature": None,
            }

            canonical_bytes = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")
            packet["pqc_signature"] = self.pqc_key.sign(canonical_bytes)
            return packet
        except Exception as err:
            raise PermissionError(f"Failed to sign handoff packet: {err}") from err

    def verify_handoff(
        self,
        handoff_packet: Dict[str, Any],
        expected_sender_public_key_hex: Optional[str] = None,
        sender_key: Optional[Any] = None,
    ) -> bool:
        """
        Verifies a multi-agent task handoff packet.
        Validates sender identity, recipient matching, canonical JSON signature,
        and public key matching.
        """
        try:
            if not isinstance(handoff_packet, dict):
                if self.strict:
                    raise PermissionError("NTI Handoff Verification Failed: Invalid packet type")
                return False

            required_fields = ["sender", "recipient", "payload", "pqc_public_key", "pqc_signature"]
            for field in required_fields:
                if field not in handoff_packet or handoff_packet[field] is None:
                    if self.strict:
                        raise PermissionError(f"NTI Handoff Verification Failed: Missing field '{field}'")
                    return False

            if handoff_packet.get("recipient") != self.agent_id:
                if self.strict:
                    raise PermissionError("NTI Handoff Verification Failed: Recipient mismatch")
                return False

            sender_pub_key = handoff_packet.get("pqc_public_key")
            if expected_sender_public_key_hex and sender_pub_key != expected_sender_public_key_hex:
                if self.strict:
                    raise PermissionError("NTI Handoff Verification Failed: Sender public key mismatch")
                return False

            sig_hex = handoff_packet.get("pqc_signature")
            if not sig_hex or not isinstance(sig_hex, str):
                if self.strict:
                    raise PermissionError("NTI Handoff Verification Failed: Missing or invalid signature string")
                return False

            unsigned_packet = dict(handoff_packet)
            unsigned_packet["pqc_signature"] = None
            canonical_bytes = json.dumps(unsigned_packet, sort_keys=True, separators=(",", ":")).encode("utf-8")

            sender_id = handoff_packet.get("sender")
            verifier_key = None
            if sender_key is not None:
                if hasattr(sender_key, "pqc_key"):
                    verifier_key = sender_key.pqc_key
                else:
                    verifier_key = sender_key
            elif sender_id in self.registered_agent_keys:
                reg_entry = self.registered_agent_keys[sender_id]
                if hasattr(reg_entry, "pqc_key"):
                    verifier_key = reg_entry.pqc_key
                else:
                    verifier_key = reg_entry
            elif sender_pub_key == self.public_key_hex():
                verifier_key = self.pqc_key

            if verifier_key is not None:
                verified = bool(verifier_key.verify(canonical_bytes, sig_hex))
            else:
                # Without a known PQC key object to perform signature verification, fail closed!
                verified = False

            if not verified:
                if self.strict:
                    raise PermissionError("NTI Handoff Verification Failed: Tampered or invalid signature")
                return False

            return True

        except PermissionError:
            raise
        except Exception as err:
            if self.strict:
                raise PermissionError(f"NTI Handoff Verification Failed due to error: {err}") from err
            return False

    def sign_response(self, handoff_id: str, result: Any) -> Dict[str, Any]:
        """
        Signs a delegatee response packet using canonical JSON and Dilithium5 PQC signature.
        """
        try:
            packet = {
                "handoff_id": handoff_id,
                "responder": self.agent_id,
                "result": result,
                "pqc_public_key": self.public_key_hex(),
                "pqc_signature": None,
            }

            canonical_bytes = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")
            packet["pqc_signature"] = self.pqc_key.sign(canonical_bytes)
            return packet
        except Exception as err:
            raise PermissionError(f"Failed to sign response packet: {err}") from err

    def verify_response(
        self,
        response_packet: Dict[str, Any],
        expected_responder_public_key_hex: Optional[str] = None,
        responder_key: Optional[Any] = None,
    ) -> bool:
        """
        Verifies a delegatee response packet signature and responder identity.
        """
        try:
            if not isinstance(response_packet, dict):
                if self.strict:
                    raise PermissionError("NTI Response Verification Failed: Invalid packet type")
                return False

            required_fields = ["handoff_id", "responder", "result", "pqc_public_key", "pqc_signature"]
            for field in required_fields:
                if field not in response_packet or response_packet[field] is None:
                    if self.strict:
                        raise PermissionError(f"NTI Response Verification Failed: Missing field '{field}'")
                    return False

            responder_pub_key = response_packet.get("pqc_public_key")
            if expected_responder_public_key_hex and responder_pub_key != expected_responder_public_key_hex:
                if self.strict:
                    raise PermissionError("NTI Response Verification Failed: Responder public key mismatch")
                return False

            sig_hex = response_packet.get("pqc_signature")
            if not sig_hex or not isinstance(sig_hex, str):
                if self.strict:
                    raise PermissionError("NTI Response Verification Failed: Missing signature")
                return False

            unsigned_packet = dict(response_packet)
            unsigned_packet["pqc_signature"] = None
            canonical_bytes = json.dumps(unsigned_packet, sort_keys=True, separators=(",", ":")).encode("utf-8")

            responder_id = response_packet.get("responder")
            verifier_key = None
            if responder_key is not None:
                if hasattr(responder_key, "pqc_key"):
                    verifier_key = responder_key.pqc_key
                else:
                    verifier_key = responder_key
            elif responder_id in self.registered_agent_keys:
                reg_entry = self.registered_agent_keys[responder_id]
                if hasattr(reg_entry, "pqc_key"):
                    verifier_key = reg_entry.pqc_key
                else:
                    verifier_key = reg_entry
            elif responder_pub_key == self.public_key_hex():
                verifier_key = self.pqc_key

            if verifier_key is not None:
                verified = bool(verifier_key.verify(canonical_bytes, sig_hex))
            else:
                # Without a known PQC key object to perform signature verification, fail closed!
                verified = False

            if not verified:
                if self.strict:
                    raise PermissionError("NTI Response Verification Failed: Tampered or invalid signature")
                return False

            return True

        except PermissionError:
            raise
        except Exception as err:
            if self.strict:
                raise PermissionError(f"NTI Response Verification Failed due to error: {err}") from err
            return False

    def attach_hooks(self) -> None:
        """
        Registers this middleware with CrewAI global tool execution hooks.
        """
        try:
            import crewai.hooks as crewai_hooks

            def _before_tool_call_hook(context: Any) -> None:
                tool_name = getattr(context, "tool_name", "unknown_tool")
                tool_input = getattr(context, "tool_input", {})
                self.verify_tool_execution(tool_name, tool_input)

            crewai_hooks.register_before_tool_call_hook(_before_tool_call_hook)
        except Exception as err:
            if self.strict:
                raise RuntimeError(f"Failed to attach CrewAI hooks: {err}") from err

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """
        Callable interface for CrewAI Agent/Task guardrail parameters or callbacks.
        """
        if len(args) == 2 and isinstance(args[0], str):
            return self.verify_tool_execution(args[0], args[1])

        if "tool_name" in kwargs and "tool_input" in kwargs:
            return self.verify_tool_execution(kwargs["tool_name"], kwargs["tool_input"])

        if len(args) == 1:
            arg = args[0]
            if isinstance(arg, dict):
                tool_name = arg.get("tool_name") or arg.get("action") or arg.get("capability") or "default_action"
                tool_input = arg.get("tool_input") or arg.get("input") or {}
                return self.verify_tool_execution(tool_name, tool_input)

            return (True, arg)

        return True
