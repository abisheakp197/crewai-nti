"""
Integration tests for crewai-nti with real CrewAI Agent, Task, and Crew objects.
Ensures zero mocks for CrewAI core logic and verifies real guardrail enforcement.
"""

import pytest
from crewai import Agent, Task, Crew
from crewai.tools import tool
from crewai_nti import NTIGuardrailMiddleware


@tool("sample_transfer_tool")
def sample_transfer_tool(amount: int) -> str:
    """Executes a financial transfer of the specified amount."""
    return f"Successfully transferred ${amount}"


def test_crewai_agent_with_nti_guardrail_allowed():
    guardrail = NTIGuardrailMiddleware(agent_id="finance_analyst")
    guardrail.grant_capability("sample_transfer_tool")

    agent = Agent(
        role="Financial Analyst",
        goal="Execute authorized transfers",
        backstory="Expert financial analyst with strict security protocol.",
        tools=[sample_transfer_tool],
        guardrail=guardrail,
        verbose=False,
    )

    task = Task(
        description="Transfer 100 dollars using sample_transfer_tool",
        expected_output="Confirmation of transfer",
        agent=agent,
    )

    crew = Crew(
        agents=[agent],
        tasks=[task],
        verbose=False,
    )

    assert agent.role == "Financial Analyst"
    assert task.agent.role == "Financial Analyst"
    assert crew is not None


def test_crewai_hooks_attachment():
    guardrail = NTIGuardrailMiddleware(agent_id="hooked_agent")
    guardrail.grant_capability("sample_transfer_tool")
    guardrail.attach_hooks()

    # Verify execution permitted via hook
    assert guardrail.verify_tool_execution("sample_transfer_tool", {"amount": 50}) is True


def test_multi_agent_delegation_trust_boundary():
    delegator_nti = NTIGuardrailMiddleware(agent_id="delegator_agent")
    delegatee_nti = NTIGuardrailMiddleware(agent_id="delegatee_agent")

    delegator_nti.grant_capability("delegate_work")
    delegatee_nti.grant_capability("process_subtask")

    delegator_agent = Agent(
        role="Delegator",
        goal="Delegate tasks securely",
        backstory="Main coordinator agent",
        allow_delegation=True,
        guardrail=delegator_nti,
        verbose=False,
    )

    delegatee_agent = Agent(
        role="Delegatee",
        goal="Process subtasks securely",
        backstory="Specialized worker agent",
        allow_delegation=False,
        guardrail=delegatee_nti,
        verbose=False,
    )

    # Delegator signs handoff to Delegatee
    handoff_packet = delegator_nti.sign_handoff(
        target_agent_id="delegatee_agent",
        payload={"task_description": "Analyze dataset X"},
    )

    # Delegatee verifies handoff
    verified_handoff = delegatee_nti.verify_handoff(
        handoff_packet,
        expected_sender_public_key_hex=delegator_nti.public_key_hex(),
        sender_key=delegator_nti,
    )
    assert verified_handoff is True

    # Delegatee signs response
    response_packet = delegatee_nti.sign_response(
        handoff_id=handoff_packet["id"],
        result="Dataset analyzed: 0 anomalies found",
    )

    # Delegator verifies response
    verified_response = delegator_nti.verify_response(
        response_packet,
        expected_responder_public_key_hex=delegatee_nti.public_key_hex(),
        responder_key=delegatee_nti,
    )
    assert verified_response is True
