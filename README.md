# crewai-nti

Drop-in post-quantum security for CrewAI agents, powered by NTI (Neutral Trust Infrastructure).

## Install

pip install crewai-nti

## Usage

from crewai import Agent
from crewai_nti import NTIGuardrailMiddleware

guardrail = NTIGuardrailMiddleware(agent_id="finance_agent")
guardrail.grant_capability("execute_transfer")

agent = Agent(
    role="Financial Analyst",
    goal="Execute transfers",
    backstory="...",
    guardrail=guardrail,
)

## What it enforces (all 5 pillars)

1. Zero-Trust Capability Enforcement
2. NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
3. BFT Multi-Agent Consensus
4. Merkle-Chained Audit Trails
5. P2P Agent Mesh & State Persistence

## License

PolyForm Shield License 1.0.0. Source-available.

## Links

- Core SDK: https://pypi.org/project/ube-foundation/
- Homepage: https://abisheakp197.github.io/Neutral-Trust-Infrastructure/
