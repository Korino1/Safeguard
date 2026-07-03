---
name: safeguard
description: Use when Safeguard is installed and normal Codex file edits are protected by the plugin hook wrapper.
---

# Safeguard

Safeguard is an external Codex CLI plugin package. It must stay outside the Codex CLI source tree.

Use normal Codex edit flows. Safeguard lifecycle hooks protect native `apply_patch` and shell write paths transparently.

Use MCP tools only for explicit fallback/API operations.

Expected MCP tools:

- `sg_ping`
- `sg_plan`
- `sg_dry`
- `sg_apply`
- `sg_audit`

Internal integrity metadata is wrapper state. Do not ask the model to reason over hashes or include digests in normal prompts.

Do not switch every edit to MCP. Ordinary edits should remain native Codex edits.
