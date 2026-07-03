# Safeguard

Safeguard is a native external Codex CLI plugin package with a bundled Rust STDIO MCP server. It is not compiled into Codex CLI and does not patch Codex internals.

Current plugin id: `safeguard@safeguard-local`.

## What It Does

- Installs through the official Codex plugin marketplace flow.
- Exposes guarded text-replacement MCP tools.
- Requires the old text fragment to appear exactly once before planning or applying an edit.
- Enforces workspace-root containment for file edits.
- Writes internal audit metadata to `.safeguard/audit.jsonl`.
- Keeps hash/integrity metadata inside the plugin wrapper; normal model-facing responses do not expose digests.

## Repository Layout

- `plugins/safeguard/` - final Codex plugin package.
- `crates/safeguard-core/` - core hashing, text planning, file replacement logic.
- `crates/safeguard-mcp/` - Rust STDIO MCP server.
- `.agents/plugins/marketplace.json` - repo-local Codex marketplace.
- `scripts/build-plugin-binaries.ps1` - Windows packaging/install helper.
- `scripts/build-plugin-binaries.sh` - Linux packaging helper.

Local orchestration state such as Codex hook data, MemoryX bases, task plans, and work logs is intentionally ignored by git.

## Requirements

- Codex CLI with plugin support.
- Rust nightly, edition 2024.
- Windows 11 for the included `bin/windows/safeguard-mcp.exe` package.
- Linux support through the packaged musl binary at `plugins/safeguard/bin/linux/safeguard-mcp`.

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

## MCP Tools

- `sg_ping` - connectivity check.
- `sg_plan` - plans a unique in-memory text replacement.
- `sg_dry` - plans a guarded file replacement without writing.
- `sg_apply` - applies a guarded file replacement.
- `sg_audit` - returns recent audit records without internal digest fields.

## Human Usage Pattern

Use `sg_dry` before applying a risky edit. The tool rejects missing, empty, or ambiguous fragments. Use `sg_apply` only when the dry-run coordinates match the intended edit.

Audit records are stored locally in `.safeguard/audit.jsonl`. This file is ignored by git.

## AI Agent Instructions

When Safeguard is available, prefer its file-edit tools for narrow text replacements where the expected old fragment is known exactly.

Agent rules:

- Do not ask the model to reason over BLAKE3 or other internal digests.
- Do not include internal hash metadata in prompts or normal summaries.
- Treat hash/integrity checks as wrapper state owned by the MCP server.
- Use `sg_dry` before `sg_apply` when edit risk is non-trivial.
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
