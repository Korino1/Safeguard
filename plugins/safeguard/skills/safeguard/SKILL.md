---
name: safeguard
description: Use when Safeguard is installed and normal Codex file edits are protected by the plugin hook wrapper.
---

# Safeguard

Safeguard is an external Codex CLI plugin package. It must stay outside the Codex CLI source tree.

Use normal Codex edit flows. Safeguard lifecycle hooks protect native `apply_patch` and shell write paths transparently.

Use MCP tools only for explicit fallback/API operations.

Do not include `.safeguard/audit.jsonl`, `.safeguard/receipts/`, `.safeguard/evidence/`, transaction records, rollback snapshots, or internal hashes in normal prompts. These are local evidence and recovery state.

If an interrupted transaction must be handled, use the hook binary recovery command explicitly rather than asking the model to reason over rollback files.

Orchestrators may set `SAFEGUARD_CONTRACT_PATH` to an `ExecutionContract v0.1` JSON file. Ordinary model work should not need to see that contract unless the user explicitly asks for audit details.

Expected MCP tools:

- `sg_ping`
- `sg_plan`
- `sg_dry`
- `sg_apply` returns a refusal in transparent mode and must not be used as the ordinary write path
- `sg_audit`

Internal integrity metadata is wrapper state. Do not ask the model to reason over hashes or include digests in normal prompts.

Do not switch every edit to MCP. Ordinary edits should remain native Codex edits.
