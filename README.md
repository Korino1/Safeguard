# Safeguard

Safeguard is a native external Codex CLI plugin package with bundled Rust lifecycle hooks and a Rust STDIO MCP server. It is not compiled into Codex CLI and does not patch Codex internals.

Current plugin id: `safeguard@safeguard-local`.

## What It Does

- Installs through the official Codex plugin marketplace flow.
- Installs plugin-bundled lifecycle hooks for transparent native edit protection.
- Audits ordinary Codex `apply_patch` edits without requiring the model to call a special tool.
- Wraps native patch edits in a local transaction record with target locks and rollback snapshots.
- Blocks obvious direct shell write commands in default protect mode.
- Exposes guarded text-replacement MCP tools as an explicit fallback/API.
- Requires the old text fragment to appear exactly once before planning or applying an edit.
- Enforces workspace-root containment for file edits.
- Writes internal hook and MCP audit metadata to external Safeguard state.
- Writes native edit execution receipts to external Safeguard state.
- Writes compact MemoryX-shaped evidence summaries to external Safeguard state.
- Keeps hash/integrity metadata inside the plugin wrapper; normal model-facing responses do not expose digests.

## Repository Layout

- `plugins/safeguard/` - final Codex plugin package.
- `crates/safeguard-core/` - core hashing, text planning, file replacement logic.
- `crates/safeguard-hook/` - Rust lifecycle hook guard.
- `crates/safeguard-mcp/` - Rust STDIO MCP server fallback/API.
- `.agents/plugins/marketplace.json` - repo-local Codex marketplace.
- `scripts/build-plugin-binaries.ps1` - Windows packaging/install helper.
- `scripts/build-plugin-binaries.sh` - Linux packaging helper.

Local orchestration state such as Codex hook data, MemoryX bases, task plans, and work logs is intentionally ignored by git.

## Requirements

- Codex CLI with plugin support.
- Rust nightly, edition 2024.
- Windows 11 for the included `bin/windows/` package.
- Linux support through the packaged musl binaries at `plugins/safeguard/bin/linux/`.

## Connect To Codex CLI

From the repository root:

```powershell
codex plugin marketplace add . --json
.\scripts\build-plugin-binaries.ps1 -Target windows -Plugin safeguard
codex plugin list
codex mcp list
```

Expected final state:

- `codex plugin list` shows `safeguard@safeguard-local` as `installed, enabled`.
- `codex mcp list` shows `safeguard` with command `./bin/windows/safeguard-mcp.exe` on Windows.
- Codex hook review may require trusting the plugin hook before it runs. After trust, Safeguard protects normal Codex edit paths without extra model-visible tool calls.

## Transparent Edit Protection

Normal Codex editing should stay normal. The model can use native `apply_patch`; Safeguard hooks run before and after the edit.

- `PreToolUse` records target files and before-digests for native `apply_patch`.
- `PreToolUse` creates a guarded transaction record and target lock set.
- `PostToolUse` records after-digests and changed-file evidence.
- `PostToolUse` makes a final decision durable, writes the final receipt, then releases target locks and snapshots.
- `PostToolUse` writes an `ExecutionReceipt v0.1` for the guarded edit.
- Receipt acceptance requires both tool success and expected add/modify/delete result verification.
- Receipts include a local hash-chain link through `previous_receipt_hash` when a prior receipt exists.
- `PermissionRequest` denies risky direct shell writes in protect mode.
- Internal digests are written to the external Safeguard state root, not to model context.

Policy mode:

- default `SAFEGUARD_MODE=protect`: allow guarded native patches, block obvious shell writes.
- `SAFEGUARD_MODE=monitor`: audit shell writes without blocking.

Optional execution contract:

- Set `SAFEGUARD_CONTRACT_PATH` to a signed `ExecutionContract v0.1` envelope when an orchestrator wants explicit capability enforcement. Safeguard verifies Ed25519 signatures with public keys from its external authority store, binds the envelope to the workspace and issuer run id, and consumes its nonce once.
- If no contract path is set, Safeguard creates an implicit local contract for native patch edits.
- Contract parsing, capability checks, expected-file checks, and denied-resource checks happen inside the hook layer.

## MCP Tools

- `sg_ping` - connectivity check.
- `sg_plan` - plans a unique in-memory text replacement.
- `sg_dry` - plans a guarded file replacement without writing.
- `sg_apply` - disabled in transparent mode; native Codex edits are the write path.
- `sg_audit` - returns recent audit records without internal digest fields.

## Human Usage Pattern

Use Codex normally. Safeguard protects native edit paths through plugin hooks.

Use `sg_dry` only for explicit planning/debugging of deterministic text replacements. `sg_apply` remains listed for protocol compatibility, but returns a short refusal in transparent mode so models cannot bypass lifecycle hooks through MCP.

Audit records, receipts, rollback snapshots, and MemoryX-shaped evidence summaries are stored outside the workspace: `%LOCALAPPDATA%\\Safeguard\\workspaces\\<workspace-blake3>` on Windows and `${XDG_STATE_HOME:-$HOME/.local/state}/Safeguard/workspaces/<workspace-blake3>` on Linux. They are not model context and are not written into the repository.

## Recovery

If a hook transaction is interrupted before `PostToolUse`, recovery is explicit:

```powershell
.\plugins\safeguard\bin\windows\safeguard-hook-1.4.0.exe recover --cwd <workspace> --list
.\plugins\safeguard\bin\windows\safeguard-hook-1.4.0.exe recover --cwd <workspace> --rollback <transaction_id>
.\plugins\safeguard\bin\windows\safeguard-hook-1.4.0.exe recover --cwd <workspace> --finalize <transaction_id>
```

Rollback restores guarded targets from local snapshots, durably records rollback finality, writes a rollback receipt, then cleans local state. Interrupted finalization is resumed automatically on the next native hook invocation; `recover --finalize <transaction_id>` is available for explicit recovery.

## AI Agent Instructions

When Safeguard is available, use normal Codex edit flows. Do not switch to MCP tools for every edit.

Agent rules:

- Do not ask the model to reason over BLAKE3 or other internal digests.
- Do not include internal hash metadata in prompts or normal summaries.
- Treat hash/integrity checks as wrapper state owned by Safeguard hooks and MCP server.
- Use native `apply_patch` for ordinary file edits.
- Use `sg_dry` only when explicit MCP planning/debugging is needed.
- If a replacement is rejected as ambiguous, narrow the old fragment with more surrounding context.
- If a path is rejected as outside workspace root, do not bypass Safeguard with arbitrary shell writes unless the user explicitly asks for that path and understands the policy boundary.
- Use `sg_audit` for operation visibility; it intentionally omits digest fields.

## Development Checks

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --target x86_64-unknown-linux-gnu
cargo build -p safeguard-mcp --release --target x86_64-unknown-linux-musl
cargo build -p safeguard-hook --release --target x86_64-unknown-linux-musl
```

If you have Codex's plugin validator locally, set `VALIDATE_PLUGIN` to its script path before running packaging scripts.

## Platform Packaging

Windows package:

```powershell
.\scripts\build-plugin-binaries.ps1 -Target windows -Plugin safeguard
```

Linux checks/artifacts from Windows:

```powershell
.\scripts\build-plugin-binaries.ps1 -Target linux-check -Plugin safeguard
.\scripts\build-plugin-binaries.ps1 -Target linux-musl -Plugin safeguard
```

Linux host build:

```bash
scripts/build-plugin-binaries.sh
```
