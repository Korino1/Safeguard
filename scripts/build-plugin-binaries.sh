#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="${PLUGIN:-safeguard}"
PLUGIN_PATH="$ROOT/plugins/$PLUGIN"
VALIDATOR="${VALIDATE_PLUGIN:-}"

cd "$ROOT"

cargo build -p safeguard-mcp --release
cargo build -p safeguard-hook --release
mkdir -p "$PLUGIN_PATH/bin/linux"
cp "$ROOT/target/release/safeguard-mcp" "$PLUGIN_PATH/bin/linux/safeguard-mcp"
cp "$ROOT/target/release/safeguard-hook" "$PLUGIN_PATH/bin/linux/safeguard-hook-1.4.0"
chmod +x "$PLUGIN_PATH/bin/linux/safeguard-mcp"
chmod +x "$PLUGIN_PATH/bin/linux/safeguard-hook-1.4.0"
cp "$PLUGIN_PATH/.mcp.linux.json" "$PLUGIN_PATH/.mcp.json"
cp "$PLUGIN_PATH/hooks/hooks.linux.json" "$PLUGIN_PATH/hooks/hooks.json"

if [[ -n "$VALIDATOR" ]]; then
  python "$VALIDATOR" "$PLUGIN_PATH"
else
  echo "VALIDATE_PLUGIN is not set; skipped plugin manifest validator."
fi

echo "Linux plugin binaries ready at $PLUGIN_PATH/bin/linux"
