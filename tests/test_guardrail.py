"""
Unit tests for NTIGuardrailMiddleware in crewai-nti.
Tests PQC key handling, canonical JSON signing/verification, capability enforcement,
multi-agent handoffs, and fail-closed behavior across strict and non-strict modes.
"""

import threading
import pytest
from ube_foundation import PqcKeyPair
from crewai_nti import NTIGuardrailMiddleware


class FailingVerifyKey:
    def public_key_hex(self):
        return "00" * 32
    def get_kyber_public_key_bytes(self):
        return b"kyber"
    def sign(self, message):
        return "11" * 32
    def verify(self, message, signature_hex):
        return False


class ExceptionKey:
    def public_key_hex(self):
        return "00" * 32
    def get_kyber_public_key_bytes(self):
        return b"kyber"
    def sign(self, message):
        raise RuntimeError("Crypto hardware error")
    def verify(self, message, signature_hex):
        raise RuntimeError("Crypto hardware error")


def test_init_custom_pqc_key():
    custom_key = PqcKeyPair()
    guardrail = NTIGuardrailMiddleware(agent_id="custom_agent", pqc_key=custom_key)
    assert guardrail.pqc_key == custom_key
    assert guardrail.public_key_hex() == custom_key.public_key_hex()


def test_sign_and_verify_bytes_and_error_handling():
    guardrail = NTIGuardrailMiddleware(agent_id="signer")
    msg = b"hello post-quantum world"
    sig_hex = guardrail.sign(msg)
    assert isinstance(sig_hex, str)
    assert len(sig_hex) > 0
    assert guardrail.verify(msg, sig_hex) is True
    assert guardrail.verify(b"tampered message", sig_hex) is False

    # Invalid signature or type errors in verify
    assert guardrail.verify(msg, "invalid_hex") is False
    assert guardrail.verify(msg, 12345) is False


def test_capability_grant_and_verify_tool_execution():
    guardrail = NTIGuardrailMiddleware(agent_id="finance_agent", strict=True)

    # Before grant -> fails closed with PermissionError
    with pytest.raises(PermissionError) as exc_info:
        guardrail.verify_tool_execution("execute_transfer", {"amount": 500})
    assert "NTI Security Denied Action" in str(exc_info.value)

    # Non-dict tool_input
    with pytest.raises(PermissionError):
        guardrail.verify_tool_execution("execute_transfer", "string_input")

    # Grant capability
    guardrail.grant_capability("execute_transfer")
    assert guardrail.verify_tool_execution("execute_transfer", {"amount": 500}) is True
    assert guardrail.verify_tool_execution("execute_transfer", 123) is True


def test_verify_tool_execution_local_verify_fail():
    guardrail = NTIGuardrailMiddleware(agent_id="failing_agent", strict=False, pqc_key=FailingVerifyKey())
    assert guardrail.verify_tool_execution("any_tool", {}) is False

    guardrail.strict = True
    with pytest.raises(PermissionError) as exc:
        guardrail.verify_tool_execution("any_tool", {})
    assert "PQC local signature verification failed" in str(exc.value)


def test_verify_tool_execution_exception_in_non_strict():
    guardrail = NTIGuardrailMiddleware(agent_id="err_agent", strict=False, pqc_key=ExceptionKey())
    assert guardrail.verify_tool_execution("tool", {}) is False

    guardrail.strict = True
    with pytest.raises(PermissionError) as exc:
        guardrail.verify_tool_execution("tool", {})
    assert "NTI Security Denied Action due to error" in str(exc.value)


def test_multi_agent_handoff_success_and_registration():
    alice = NTIGuardrailMiddleware(agent_id="alice")
    bob = NTIGuardrailMiddleware(agent_id="bob")

    alice.grant_capability("delegate_task")
    assert alice.verify_tool_execution("delegate_task", {"target": "bob"}) is True

    handoff_packet = alice.sign_handoff(
        target_agent_id="bob",
        payload={"task_id": "task-101", "action": "analyze_market"},
    )

    assert handoff_packet["sender"] == "alice"
    assert handoff_packet["recipient"] == "bob"
    assert handoff_packet["pqc_signature"] is not None

    # Bob verifies handoff with sender_key
    verified = bob.verify_handoff(
        handoff_packet,
        expected_sender_public_key_hex=alice.public_key_hex(),
        sender_key=alice,
    )
    assert verified is True

    # Register Alice's key on Bob
    bob.register_agent_key("alice", alice)
    reg_verified = bob.verify_handoff(
        handoff_packet,
        expected_sender_public_key_hex=alice.public_key_hex(),
    )
    assert reg_verified is True

    # Bob responds
    response_packet = bob.sign_response(handoff_id=handoff_packet["id"], result={"status": "complete"})

    # Alice verifies response with registered key
    alice.register_agent_key("bob", bob)
    verified_resp = alice.verify_response(
        response_packet,
        expected_responder_public_key_hex=bob.public_key_hex(),
    )
    assert verified_resp is True


def test_unregistered_key_fails_closed():
    alice = NTIGuardrailMiddleware(agent_id="alice")
    bob = NTIGuardrailMiddleware(agent_id="bob")

    packet = alice.sign_handoff("bob", {"amount": 100})

    # Without passing sender_key or registering alice's key, verification fails closed!
    with pytest.raises(PermissionError) as exc:
        bob.verify_handoff(packet)
    assert "NTI Handoff Verification Failed" in str(exc.value)


def test_sign_handoff_exception():
    guardrail = NTIGuardrailMiddleware(agent_id="faulty", pqc_key=ExceptionKey())
    with pytest.raises(PermissionError) as exc:
        guardrail.sign_handoff("bob", {})
    assert "Failed to sign handoff packet" in str(exc.value)


def test_handoff_negative_paths_strict_and_non_strict():
    alice = NTIGuardrailMiddleware(agent_id="alice")
    bob = NTIGuardrailMiddleware(agent_id="bob")
    non_strict_bob = NTIGuardrailMiddleware(agent_id="bob", strict=False)

    # 1. Invalid packet type
    with pytest.raises(PermissionError):
        bob.verify_handoff("invalid_packet_type")
    assert non_strict_bob.verify_handoff("invalid_packet_type") is False

    # 2. Missing field
    packet = alice.sign_handoff("bob", {"data": 1})
    del packet["sender"]
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet)
    assert non_strict_bob.verify_handoff(packet) is False

    # 3. Recipient mismatch
    packet2 = alice.sign_handoff("eve", {"data": 1})
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet2)
    assert non_strict_bob.verify_handoff(packet2) is False

    # 4. Sender pubkey mismatch
    packet3 = alice.sign_handoff("bob", {"data": 1})
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet3, expected_sender_public_key_hex="wrong_pubkey_hex")
    assert non_strict_bob.verify_handoff(packet3, expected_sender_public_key_hex="wrong_pubkey_hex") is False

    # 5. Missing or non-string signature
    packet4 = alice.sign_handoff("bob", {"data": 1})
    packet4["pqc_signature"] = None
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet4)
    packet4["pqc_signature"] = 12345
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet4)
    assert non_strict_bob.verify_handoff(packet4) is False

    # 6. Tampered signature
    packet5 = alice.sign_handoff("bob", {"data": 1})
    packet5["payload"]["data"] = 999
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet5, sender_key=alice)
    assert non_strict_bob.verify_handoff(packet5, sender_key=alice) is False

    # 7. Unverified signature with verifier key returning False
    packet6 = alice.sign_handoff("bob", {"data": 1})
    with pytest.raises(PermissionError):
        bob.verify_handoff(packet6, sender_key=bob)  # Verifying with Bob's key instead of Alice's key

    # 8. Exception during verify_handoff
    packet7 = alice.sign_handoff("bob", {"data": 1})
    with pytest.raises(PermissionError) as exc:
        bob.verify_handoff(packet7, sender_key=ExceptionKey())
    assert "NTI Handoff Verification Failed due to error" in str(exc.value)
    assert non_strict_bob.verify_handoff(packet7, sender_key=ExceptionKey()) is False


def test_sign_response_and_verify_response_full_coverage():
    alice = NTIGuardrailMiddleware(agent_id="alice")
    bob = NTIGuardrailMiddleware(agent_id="bob")
    non_strict_alice = NTIGuardrailMiddleware(agent_id="alice", strict=False)

    resp = bob.sign_response("handoff-101", {"result": "success"})
    assert resp["responder"] == "bob"

    # Successful verify
    assert alice.verify_response(resp, expected_responder_public_key_hex=bob.public_key_hex(), responder_key=bob) is True

    # 1. Invalid packet type
    with pytest.raises(PermissionError):
        alice.verify_response("invalid")
    assert non_strict_alice.verify_response("invalid") is False

    # 2. Missing field
    resp_bad = dict(resp)
    del resp_bad["result"]
    with pytest.raises(PermissionError):
        alice.verify_response(resp_bad)
    assert non_strict_alice.verify_response(resp_bad) is False

    # 3. Responder pubkey mismatch
    with pytest.raises(PermissionError):
        alice.verify_response(resp, expected_responder_public_key_hex="wrong_key")
    assert non_strict_alice.verify_response(resp, expected_responder_public_key_hex="wrong_key") is False

    # 4. Missing or invalid signature string
    resp_bad_sig = dict(resp)
    resp_bad_sig["pqc_signature"] = None
    with pytest.raises(PermissionError):
        alice.verify_response(resp_bad_sig)
    resp_bad_sig["pqc_signature"] = 999
    with pytest.raises(PermissionError):
        alice.verify_response(resp_bad_sig)
    assert non_strict_alice.verify_response(resp_bad_sig) is False

    # 5. Tampered result
    resp_tampered = dict(resp)
    resp_tampered["result"] = {"result": "hacked"}
    with pytest.raises(PermissionError):
        alice.verify_response(resp_tampered, responder_key=bob)
    assert non_strict_alice.verify_response(resp_tampered, responder_key=bob) is False

    # 6. Sign response exception
    faulty = NTIGuardrailMiddleware(agent_id="faulty", pqc_key=ExceptionKey())
    with pytest.raises(PermissionError) as exc:
        faulty.sign_response("id", "res")
    assert "Failed to sign response packet" in str(exc.value)

    # 7. Exception in verify_response
    with pytest.raises(PermissionError) as exc:
        alice.verify_response(resp, responder_key=ExceptionKey())
    assert "NTI Response Verification Failed due to error" in str(exc.value)
    assert non_strict_alice.verify_response(resp, responder_key=ExceptionKey()) is False


def test_revoked_token_and_register_voter():
    guardrail = NTIGuardrailMiddleware(agent_id="admin")
    guardrail.revoke_token("token-99")
    guardrail.register_voter_key("voter-1", b"bytes")


def test_thread_safety():
    guardrail = NTIGuardrailMiddleware(agent_id="concurrent_agent")
    guardrail.grant_capability("concurrent_task")

    errors = []

    def worker():
        try:
            for _ in range(20):
                res = guardrail.verify_tool_execution("concurrent_task", {"iter": 1})
                if not res:
                    errors.append("Execution returned False")
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0


def test_callable_interface_all_branches():
    guardrail = NTIGuardrailMiddleware(agent_id="callable_agent")
    guardrail.grant_capability("callable_tool")
    guardrail.grant_capability("action_cap")
    guardrail.grant_capability("default_action")

    # 2 positional args
    assert guardrail("callable_tool", {"param": 1}) is True

    # kwargs
    assert guardrail(tool_name="callable_tool", tool_input={"param": 1}) is True

    # 1 dict arg with tool_name
    assert guardrail({"tool_name": "callable_tool", "tool_input": {"param": 1}}) is True

    # 1 dict arg with action / input
    assert guardrail({"action": "action_cap", "input": {"x": 2}}) is True

    # 1 dict arg without action or tool_name
    assert guardrail({"other": "field"}) is True

    # Output guardrail 1 non-dict arg
    ok, output = guardrail("agent result output")
    assert ok is True
    assert output == "agent result output"

    # No args / default branch
    assert guardrail() is True


def test_attach_hooks():
    guardrail = NTIGuardrailMiddleware(agent_id="hook_agent")
    guardrail.grant_capability("hooked_tool")
    guardrail.attach_hooks()

    import crewai.hooks as crewai_hooks

    # Simulate triggering hook with context
    class DummyContext:
        tool_name = "hooked_tool"
        tool_input = {"arg": "val"}

    hooks = crewai_hooks.get_before_tool_call_hooks()
    assert len(hooks) > 0
    # Execute the last attached hook
    hooks[-1](DummyContext())

    # Attach hooks error branch
    guardrail_err = NTIGuardrailMiddleware(agent_id="hook_err", strict=True)
    import sys
    # Temporarily corrupt crewai.hooks to trigger exception in attach_hooks
    orig_hooks = sys.modules.get("crewai.hooks")
    sys.modules["crewai.hooks"] = None
    try:
        with pytest.raises(RuntimeError) as exc:
            guardrail_err.attach_hooks()
        assert "Failed to attach CrewAI hooks" in str(exc.value)

        guardrail_non_strict = NTIGuardrailMiddleware(agent_id="hook_err_non_strict", strict=False)
        guardrail_non_strict.attach_hooks()  # Should not raise
    finally:
        if orig_hooks:
            sys.modules["crewai.hooks"] = orig_hooks
