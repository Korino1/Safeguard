# Safeguard Codex Plugin

This directory is the final external Codex plugin package.

Plugin id: `safeguard@safeguard-local`.

## Files

- `.codex-plugin/plugin.json` - Codex plugin manifest.
- `.mcp.json` - active MCP config for the current platform.
- `.mcp.windows.json` - Windows MCP config template.
- `.mcp.linux.json` - Linux MCP config template.
- `bin/windows/safeguard-mcp.exe` - Windows Rust MCP server.
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

Linux host build:

```bash
scripts/build-plugin-binaries.sh
```

## Agent Boundary

Internal integrity metadata is not model context. The MCP server may use BLAKE3 internally for audit/integrity state, but model-facing responses should remain limited to status, path, coordinates, and byte counts.
