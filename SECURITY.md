# Security Policy

## Supported Versions

We actively maintain and patch the latest release of the NTI integration for CrewAI.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

This repository provides the trust layer for CrewAI multi-agent delegations and handoffs. We take the integrity of inter-agent task execution, spoofing prevention, and cryptographic signature verification extremely seriously. If the NTI middleware fails, a compromised agent could execute unauthorized tasks.

Please report vulnerabilities directly to **abisheakp197@gmail.com**.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:
*   Type of issue (e.g., handoff signature bypass, spoofed agent identity, fail-open vulnerability, mutable default arguments in middleware)
*   Full paths of source file(s) related to the manifestation of the issue
*   The location of the affected source code (tag/branch/commit or direct URL)
*   Any special configuration required to reproduce the issue

We will investigate all legitimate reports and do our best to quickly fix the problem.
