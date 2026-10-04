# NTI Discovery Playbook

This document records the standard integration pattern for wrapping any agent framework with NTI.

## The Pattern

1. **Subclass the framework's hook interface.**
   - LangChain → BaseCallbackHandler.on_tool_start
   - CrewAI → GuardrailMiddleware.verify_tool_execution
   - AutoGen/MAF → NTISecurityWrapper.verify_message

2. **On every tool call, build a signed ActionRequest:**

   req = {
       "id": f"req-{uuid.uuid4()}",
       "actor": agent_id,
       "capability": tool_name,
       "action": tool_name,
       "input": tool_input,
       "pqc_signature": pqc_key.sign(message).hex(),
       "pqc_public_key": pqc_key.public_key_hex(),
       ...
   }

3. **Evaluate against TrustEngine:**

   decision = json.loads(engine.evaluate(json.dumps(req)))

4. **Block if Deny:**

   if decision["decision"] != "Allow":
       raise PermissionError(f"NTI Security Denied Action: {decision['reason']}")

## Non-Negotiable Rules

- Never hard-import `ube_foundation` at module top level. Use lazy imports inside __init__.
- Always use `uuid.uuid4()` for request IDs, never Python's hash().
- Always `.hex()` the PQC signature before JSON serialization.
- Always declare `ube-foundation` as an optional dependency in pyproject.toml.
- Always include the PolyForm Shield License.

## Distribution Strategy

- Publish each wrapper as its own PyPI package.
- Never fork the framework. Always build on top of it.
- Link back to the core SDK and homepage in the README.
- Add the NTI badge once the spec is public.
