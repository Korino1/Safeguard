#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="${PLUGIN:-safeguard}"
PLUGIN_PATH="$ROOT/plugins/$PLUGIN"
VALIDATOR="${VALIDATE_PLUGIN:-}"

cd "$ROOT"

cargo build -p safeguard-mcp --release
mkdir -p "$PLUGIN_PATH/bin/linux"
cp "$ROOT/target/release/safeguard-mcp" "$PLUGIN_PATH/bin/linux/safeguard-mcp"
chmod +x "$PLUGIN_PATH/bin/linux/safeguard-mcp"
cp "$PLUGIN_PATH/.mcp.linux.json" "$PLUGIN_PATH/.mcp.json"

if [[ -n "$VALIDATOR" ]]; then
  python "$VALIDATOR" "$PLUGIN_PATH"
else
  echo "VALIDATE_PLUGIN is not set; skipped plugin manifest validator."
fi

echo "Linux plugin binary ready at $PLUGIN_PATH/bin/linux/safeguard-mcp"
