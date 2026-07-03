# Safeguard Codex Plugin

This directory is the final external Codex plugin package.

Plugin id: `safeguard@safeguard-local`.

## Files

- `.codex-plugin/plugin.json` - Codex plugin manifest.
- `.mcp.json` - active MCP config for the current platform.
- `.mcp.windows.json` - Windows MCP config template.
- `.mcp.linux.json` - Linux MCP config template.
- `hooks/hooks.json` - active lifecycle hook config for the current platform.
- `hooks/hooks.windows.json` - Windows hook config template.
- `hooks/hooks.linux.json` - Linux hook config template.
- `bin/windows/safeguard-hook.exe` - Windows Rust lifecycle hook guard.
- `bin/windows/safeguard-mcp.exe` - Windows Rust MCP server.
- `bin/linux/safeguard-hook` - expected Linux Rust lifecycle hook guard path.
- `bin/linux/safeguard-mcp` - expected Linux Rust MCP server path.
- `skills/safeguard/SKILL.md` - agent-facing plugin skill guidance.

## Install From Repo Marketplace

From repository root:

```powershell
codex plugin marketplace add . --json
.\scripts\build-plugin-binaries.ps1 -Target windows -Plugin safeguard
codex mcp list
```

Expected MCP server name: `safeguard`.

The plugin also installs lifecycle hooks for native `apply_patch` and shell write policy. Codex may ask you to trust the hook before it runs.

Linux host build:

```bash
scripts/build-plugin-binaries.sh
```

## Agent Boundary

Internal integrity metadata is not model context. Safeguard hooks and MCP tools may use BLAKE3 internally for audit/integrity state, but model-facing responses should remain limited to normal tool status and concise policy failures.
