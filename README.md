# crewai-nti

[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)

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

## Architecture

```mermaid
graph TD
    subgraph CrewAI["CrewAI Framework"]
        AgentA["Agent A (Delegator)"]
        Delegation["Task Delegation / Handoff"]
        AgentB["Agent B (Delegatee)"]
        TaskExec["Execute Task / Tool"]
    end

    subgraph NTISecurity["NTI Security Layer"]
        MW_A["NTIGuardrailMiddleware (Agent A)"]
        MW_B["NTIGuardrailMiddleware (Agent B)"]
        HandoffVerify{"Verify Handoff Packet"}
        TrustEngine["NTI Trust Engine / Policy"]
        BlockAction["Block Action (PermissionError)"]
    end

    subgraph CryptoEngine["Crypto Engine (ube-foundation)"]
        PqcKeyA["PqcKeyPair (Agent A)"]
        PqcKeyB["PqcKeyPair (Agent B)"]
        Dilithium["Dilithium5 (PQC Signature)"]
        Kyber["Kyber1024 (KEM Handshake)"]
    end

    %% Flow: Agent A Initiates Task Delegation
    AgentA -->|"1. Initiates Handoff"| MW_A
    MW_A -->|"2. Requests PQC Signing"| PqcKeyA
    PqcKeyA -->|"3. Dilithium5 Sign Canonical JSON"| Dilithium
    Dilithium -->|"4. Returns Signed Packet"| MW_A
    MW_A -->|"5. Emits Handoff Packet"| Delegation

    %% Flow: Agent B Receives Task Handoff
    Delegation -->|"6. Delivers Packet"| MW_B
    MW_B -->|"7. Intercepts Handoff"| HandoffVerify
    HandoffVerify -->|"8. Check Recipient & PQC Signature"| PqcKeyB
    PqcKeyB -->|"9. Verify Dilithium5 Signature"| Dilithium

    %% Verification Decisions
    HandoffVerify -->|"Signature Valid & Authorized"| TrustEngine
    TrustEngine -->|"Policy: Allow"| AgentB
    AgentB -->|"Run Tool / Action"| TaskExec

    HandoffVerify -.->"Tampered / Invalid Signature"| BlockAction
    TrustEngine -.->"Policy Denial / Unauthorized"| BlockAction
```

## License

Apache License 2.0. See LICENSE.

## Links

- Core SDK: https://pypi.org/project/ube-foundation/
- Homepage: https://abisheakp197.github.io/Neutral-Trust-Infrastructure/
