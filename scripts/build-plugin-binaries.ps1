param(
    [ValidateSet("windows", "linux-check", "linux-musl")]
    [string] $Target = "windows",

    [ValidateSet("safeguard")]
    [string] $Plugin = "safeguard"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $Root
try {
    $PluginPath = ".\plugins\$Plugin"
    $PluginId = "$Plugin@safeguard-local"

    function Invoke-OptionalValidator {
        if ($env:VALIDATE_PLUGIN) {
            python $env:VALIDATE_PLUGIN $PluginPath
        }
        else {
            Write-Host "VALIDATE_PLUGIN is not set; skipped plugin manifest validator."
        }
    }

    if ($Target -eq "windows") {
        cargo build -p safeguard-mcp --release
        cargo build -p safeguard-hook --release
        Copy-Item ".\target\release\safeguard-mcp.exe" "$PluginPath\bin\windows\safeguard-mcp.exe" -Force
        Copy-Item ".\target\release\safeguard-hook.exe" "$PluginPath\bin\windows\safeguard-hook.exe" -Force
        Copy-Item "$PluginPath\.mcp.windows.json" "$PluginPath\.mcp.json" -Force
        Copy-Item "$PluginPath\hooks\hooks.windows.json" "$PluginPath\hooks\hooks.json" -Force
        Invoke-OptionalValidator
        codex plugin add $PluginId --json
        exit 0
    }

    if ($Target -eq "linux-musl") {
        rustup target add x86_64-unknown-linux-musl
        cargo build -p safeguard-mcp --release --target x86_64-unknown-linux-musl
        cargo build -p safeguard-hook --release --target x86_64-unknown-linux-musl
        New-Item -ItemType Directory -Force -Path "$PluginPath\bin\linux" | Out-Null
        Copy-Item ".\target\x86_64-unknown-linux-musl\release\safeguard-mcp" "$PluginPath\bin\linux\safeguard-mcp" -Force
        Copy-Item ".\target\x86_64-unknown-linux-musl\release\safeguard-hook" "$PluginPath\bin\linux\safeguard-hook" -Force
        Copy-Item "$PluginPath\.mcp.linux.json" "$PluginPath\.mcp.json" -Force
        Copy-Item "$PluginPath\hooks\hooks.linux.json" "$PluginPath\hooks\hooks.json" -Force
        Invoke-OptionalValidator
        exit 0
    }

    rustup target add x86_64-unknown-linux-gnu
    cargo check --workspace --target x86_64-unknown-linux-gnu
    Copy-Item "$PluginPath\.mcp.linux.json" "$PluginPath\.mcp.json" -Force
    Copy-Item "$PluginPath\hooks\hooks.linux.json" "$PluginPath\hooks\hooks.json" -Force
    Invoke-OptionalValidator
}
finally {
    Pop-Location
}
