---
name: safeguard
description: Use when guarded Codex CLI file edits should go through the Safeguard plugin wrapper.
---

# Safeguard

Safeguard is an external Codex CLI plugin package. It must stay outside the Codex CLI source tree.

Use its MCP tools for deterministic guarded text replacements and audit summaries.

Expected MCP tools:

- `sg_ping`
- `sg_plan`
- `sg_dry`
- `sg_apply`
- `sg_audit`

Internal integrity metadata is wrapper state. Do not ask the model to reason over hashes or include digests in normal prompts.
