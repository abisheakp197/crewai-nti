# NTI — Neutral Trust Infrastructure
## Whitepaper v0.1.0

### Abstract

Neutral Trust Infrastructure (NTI) is a deterministic, zero-trust cryptographic governance runtime engineered for autonomous AI agent ecosystems. NTI sits as a security boundary between AI agents and external side-effects — executing financial transactions, modifying cloud infrastructure, reading sensitive data, or orchestrating multi-agent workflows.

NTI is distributed as `ube-foundation` on PyPI and crates.io. This document describes the architecture, the 5 pillars, and the threat model.

### The Problem

Autonomous LLM agents are vulnerable to:
- Prompt injection attacks
- Hallucinated function calls
- Unconstrained action execution
- Multi-agent collusion and rogue behavior

Existing frameworks (LangChain, CrewAI, AutoGen, MAF) provide orchestration but not cryptographic governance. Enterprises deploying AI agents to execute real-world actions need a verifiable security boundary.

### The 5 Pillars

#### Pillar 1: Zero-Trust Capability Enforcement
Agents possess zero inherent permissions. Every action requires an explicit capability token backed by real-time caveat evaluation:
- Expires
- MaxExecutions
- ValueLimit
- PathRestricted

#### Pillar 2: NIST Post-Quantum Cryptography
- CRYSTALS-Dilithium5 — NIST Level 5 post-quantum signatures
- CRYSTALS-Kyber1024 — NIST Level 4 KEM
- ChaCha20Poly1305 — symmetric AEAD with SHA-256 KDF from Kyber shared secret

#### Pillar 3: BFT Multi-Agent Consensus
- Threshold signature collection (ConsensusVote)
- Voter key identity verification
- Outcome hash agreement
- Prevents single-agent prompt injection and rogue behavior

#### Pillar 4: Merkle-Chained Audit Trails
- SHA-256 Merkle audit chain (AuditEvent, AuditBatch)
- Serializes to disk
- verify_history() verifies integrity on reload

#### Pillar 5: P2P Agent Mesh & State Persistence
- Cryptographic agent identity
- Key rotation (rotate_key)
- X25519 DH handshakes
- Persistent state with self-verifying integrity

### Architecture

Rust core (crates.io: `ube-foundation`)
Python bindings via PyO3 / Maturin (PyPI: `ube-foundation`)

The Python layer is a thin wrapper. All cryptographic math runs in Rust.

### Integration

- `langchain-nti` — LangChain callback handler
- `crewai-nti` — CrewAI guardrail middleware (in progress)
- `autogen-nti` — Microsoft Agent Framework security wrapper (in progress)

### License

Apache License 2.0. The core remains a neutral standard that cannot be hijacked by a competitor.
