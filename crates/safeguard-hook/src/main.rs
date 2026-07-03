//! Codex lifecycle hook guard for transparent Safeguard protection.

use std::collections::BTreeSet;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read hook stdin")?;

    let request: HookRequest = serde_json::from_str(&input).context("failed to parse hook JSON")?;
    let output = handle_hook(&request);
    println!("{output}");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct HookRequest {
    cwd: String,
    #[serde(rename = "hook_event_name")]
    hook_event_name: String,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    tool_response: Value,
    #[serde(default)]
    tool_use_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingEdit {
    tool_use_id: String,
    tool_name: String,
    cwd: String,
    command_kind: String,
    files: Vec<PendingFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingFile {
    path: String,
    operation: String,
    existed_before: bool,
    before_blake3: Option<String>,
}

fn handle_hook(request: &HookRequest) -> Value {
    match request.hook_event_name.as_str() {
        "PreToolUse" => pre_tool_use(request),
        "PermissionRequest" => permission_request(request),
        "PostToolUse" => post_tool_use(request),
        _ => continue_output(),
    }
}

fn pre_tool_use(request: &HookRequest) -> Value {
    let tool_name = request.tool_name.as_deref().unwrap_or_default();
    if tool_name.starts_with("mcp__safeguard__") {
        return continue_output();
    }

    if tool_name == "apply_patch" {
        return match command_text(&request.tool_input)
            .and_then(|command| plan_patch_files(&request.cwd, command).ok())
        {
            Some(files) => {
                let pending = PendingEdit {
                    tool_use_id: request
                        .tool_use_id
                        .clone()
                        .unwrap_or_else(|| "unknown-tool-use".to_string()),
                    tool_name: tool_name.to_string(),
                    cwd: request.cwd.clone(),
                    command_kind: "apply_patch".to_string(),
                    files,
                };
                match write_pending(&pending) {
                    Ok(()) => continue_output(),
                    Err(err) => {
                        deny_pre_tool_use(format!("Safeguard could not record patch intent: {err}"))
                    }
                }
            }
            None => deny_pre_tool_use(
                "Safeguard rejected apply_patch because patch targets could not be determined"
                    .to_string(),
            ),
        };
    }

    if tool_name == "Bash" {
        let command = command_text(&request.tool_input).unwrap_or_default();
        if command.contains("apply_patch") {
            return match plan_patch_files(&request.cwd, command) {
                Ok(files) => {
                    let pending = PendingEdit {
                        tool_use_id: request
                            .tool_use_id
                            .clone()
                            .unwrap_or_else(|| stable_id_for_command(command)),
                        tool_name: tool_name.to_string(),
                        cwd: request.cwd.clone(),
                        command_kind: "bash_apply_patch".to_string(),
                        files,
                    };
                    match write_pending(&pending) {
                        Ok(()) => continue_output(),
                        Err(err) => deny_pre_tool_use(format!(
                            "Safeguard could not record shell patch intent: {err}"
                        )),
                    }
                }
                Err(err) => deny_pre_tool_use(format!(
                    "Safeguard rejected shell apply_patch command: {err}"
                )),
            };
        }

        if is_risky_shell_write(command) {
            let _ = append_policy_audit(
                &request.cwd,
                json!({
                    "operation": "blocked_shell_write",
                    "tool": tool_name,
                    "reason": "direct shell writes are blocked in protect mode",
                    "command_preview": preview(command)
                }),
            );
            if safeguard_mode() == "monitor" {
                return continue_output();
            }
            return deny_pre_tool_use(
                "Safeguard protect mode blocks direct shell writes; use native apply_patch"
                    .to_string(),
            );
        }
    }

    continue_output()
}

fn permission_request(request: &HookRequest) -> Value {
    let tool_name = request.tool_name.as_deref().unwrap_or_default();
    if tool_name == "apply_patch" {
        return continue_output();
    }

    let command = command_text(&request.tool_input).unwrap_or_default();
    if tool_name == "Bash" && is_risky_shell_write(command) && safeguard_mode() != "monitor" {
        return json!({
            "continue": true,
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": "Safeguard protect mode denies approval for direct shell writes"
                }
            }
        });
    }

    continue_output()
}

fn post_tool_use(request: &HookRequest) -> Value {
    let Some(tool_use_id) = request.tool_use_id.as_deref() else {
        return continue_output();
    };
    let Ok(Some(pending)) = read_pending(&request.cwd, tool_use_id) else {
        return continue_output();
    };

    let success = !request
        .tool_response
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut files = Vec::new();
    for file in &pending.files {
        let path = PathBuf::from(&file.path);
        let after_blake3 = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => Some(safeguard_core::blake3_hex(&bytes).as_hex().to_string()),
                Err(_) => None,
            }
        } else {
            None
        };
        files.push(json!({
            "path": file.path,
            "operation": file.operation,
            "existed_before": file.existed_before,
            "exists_after": path.exists(),
            "before_blake3": file.before_blake3,
            "after_blake3": after_blake3
        }));
    }

    let _ = append_policy_audit(
        &pending.cwd,
        json!({
            "operation": "native_edit_audit",
            "tool": pending.tool_name,
            "command_kind": pending.command_kind,
            "tool_use_id": pending.tool_use_id,
            "success": success,
            "files": files
        }),
    );
    let _ = remove_pending(&request.cwd, tool_use_id);
    continue_output()
}

fn continue_output() -> Value {
    json!({ "continue": true })
}

fn deny_pre_tool_use(reason: String) -> Value {
    json!({
        "continue": true,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    })
}

fn command_text(tool_input: &Value) -> Option<&str> {
    tool_input
        .get("command")
        .and_then(Value::as_str)
        .or_else(|| tool_input.get("cmd").and_then(Value::as_str))
}

fn safeguard_mode() -> String {
    std::env::var("SAFEGUARD_MODE")
        .unwrap_or_else(|_| "protect".to_string())
        .to_ascii_lowercase()
}

fn plan_patch_files(cwd: &str, command: &str) -> anyhow::Result<Vec<PendingFile>> {
    let patch = extract_patch(command).context("missing apply_patch payload")?;
    let cwd = PathBuf::from(cwd)
        .canonicalize()
        .with_context(|| format!("failed to canonicalize cwd {cwd}"))?;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();

    for (operation, path) in patch_targets(patch) {
        if !seen.insert(path.clone()) {
            continue;
        }
        let resolved = resolve_patch_path(&cwd, &path)?;
        let existed_before = resolved.exists();
        let before_blake3 = if existed_before {
            Some(
                safeguard_core::blake3_hex(&std::fs::read(&resolved)?)
                    .as_hex()
                    .to_string(),
            )
        } else {
            None
        };
        files.push(PendingFile {
            path: resolved.display().to_string(),
            operation,
            existed_before,
            before_blake3,
        });
    }

    if files.is_empty() {
        anyhow::bail!("patch contains no file target headers");
    }
    Ok(files)
}

fn extract_patch(command: &str) -> Option<&str> {
    let start = command.find("*** Begin Patch")?;
    let end = command.find("*** End Patch")?;
    command.get(start..end + "*** End Patch".len())
}

fn patch_targets(patch: &str) -> Vec<(String, String)> {
    let mut targets = Vec::new();
    for line in patch.lines() {
        for (prefix, operation) in [
            ("*** Add File: ", "add"),
            ("*** Update File: ", "update"),
            ("*** Delete File: ", "delete"),
        ] {
            if let Some(path) = line.strip_prefix(prefix) {
                targets.push((operation.to_string(), path.trim().to_string()));
            }
        }
    }
    targets
}

fn resolve_patch_path(cwd: &Path, patch_path: &str) -> anyhow::Result<PathBuf> {
    let candidate = cwd.join(patch_path);
    if candidate.exists() {
        let canonical = candidate.canonicalize()?;
        if !canonical.starts_with(cwd) {
            anyhow::bail!("patch target escapes workspace: {patch_path}");
        }
        return Ok(canonical);
    }

    let parent = candidate
        .parent()
        .with_context(|| format!("patch target has no parent: {patch_path}"))?;
    let parent = parent.canonicalize()?;
    if !parent.starts_with(cwd) {
        anyhow::bail!("patch target escapes workspace: {patch_path}");
    }
    Ok(candidate)
}

fn is_risky_shell_write(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let write_words = [
        "set-content",
        "add-content",
        "out-file",
        "remove-item",
        "move-item",
        "copy-item",
        "new-item",
        "del ",
        "rm ",
        "mv ",
        "cp ",
        "tee ",
        "cat >",
    ];
    write_words.iter().any(|word| lower.contains(word))
        || lower.contains(" > ")
        || lower.contains(">>")
}

fn pending_dir(cwd: &str) -> PathBuf {
    PathBuf::from(cwd).join(".safeguard").join("pending")
}

fn audit_path(cwd: &str) -> PathBuf {
    PathBuf::from(cwd).join(".safeguard").join("audit.jsonl")
}

fn write_pending(pending: &PendingEdit) -> anyhow::Result<()> {
    let dir = pending_dir(&pending.cwd);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_file_id(&pending.tool_use_id)));
    std::fs::write(path, serde_json::to_vec(pending)?)?;
    Ok(())
}

fn read_pending(cwd: &str, tool_use_id: &str) -> anyhow::Result<Option<PendingEdit>> {
    let path = pending_dir(cwd).join(format!("{}.json", safe_file_id(tool_use_id)));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&std::fs::read(path)?)?))
}

fn remove_pending(cwd: &str, tool_use_id: &str) -> anyhow::Result<()> {
    let path = pending_dir(cwd).join(format!("{}.json", safe_file_id(tool_use_id)));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn append_policy_audit(cwd: &str, mut record: Value) -> anyhow::Result<()> {
    let path = audit_path(cwd);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    record["ts_unix"] = json!(ts);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{record}")?;
    Ok(())
}

fn safe_file_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn stable_id_for_command(command: &str) -> String {
    safeguard_core::blake3_hex(command.as_bytes()).as_hex()[..16].to_string()
}

fn preview(command: &str) -> String {
    const MAX: usize = 160;
    if command.len() <= MAX {
        command.to_string()
    } else {
        format!("{}...", &command[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::extract_patch;
    use super::is_risky_shell_write;
    use super::patch_targets;

    #[test]
    fn extracts_patch_targets() {
        let patch = extract_patch(
            r#"apply_patch <<'PATCH'
*** Begin Patch
*** Update File: README.md
@@
-old
+new
*** End Patch
PATCH"#,
        )
        .unwrap_or_default();
        assert_eq!(
            patch_targets(patch),
            vec![("update".to_string(), "README.md".to_string())]
        );
    }

    #[test]
    fn detects_shell_writes() {
        assert!(is_risky_shell_write("Set-Content file.txt value"));
        assert!(is_risky_shell_write("cat > file.txt"));
        assert!(!is_risky_shell_write("cargo test --workspace"));
    }
}
