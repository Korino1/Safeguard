//! STDIO MCP server for the Safeguard plugin.

use std::io::BufRead;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use serde_json::Value;
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line.context("failed to read MCP stdin")?;
        if line.trim().is_empty() {
            continue;
        }

        let response = handle_line(&line);
        if let Some(response) = response {
            writeln!(stdout, "{response}").context("failed to write MCP stdout")?;
            stdout.flush().context("failed to flush MCP stdout")?;
        }
    }

    Ok(())
}

fn handle_line(line: &str) -> Option<String> {
    let request = match serde_json::from_str::<Value>(line) {
        Ok(value) => value,
        Err(error) => {
            return Some(
                json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": error.to_string()
                    }
                })
                .to_string(),
            );
        }
    };

    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    match method {
        "initialize" => Some(initialize_response(id).to_string()),
        "notifications/initialized" => None,
        "tools/list" => Some(tools_list_response(id).to_string()),
        "tools/call" => Some(tools_call_response(id, &request).to_string()),
        _ if id.is_null() => None,
        _ => Some(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Unsupported method: {method}")
                }
            })
            .to_string(),
        ),
    }
}

fn initialize_response(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "safeguard",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Safeguard MCP server. Use safe tools for guarded file editing; internal hashes are not model-facing by default."
        }
    })
}

fn tools_list_response(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [
                {
                    "name": "sg_ping",
                    "description": "Ping Safeguard.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Echo text."
                            }
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "sg_plan",
                    "description": "Plan one exact text replacement.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "input": {
                                "type": "string",
                                "description": "Full text."
                            },
                            "old": {
                                "type": "string",
                                "description": "Old fragment."
                            },
                            "new": {
                                "type": "string",
                                "description": "New fragment."
                            }
                        },
                        "required": ["input", "old", "new"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "sg_dry",
                    "description": "Plan one file replacement.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path."
                            },
                            "old": {
                                "type": "string",
                                "description": "Old fragment."
                            },
                            "new": {
                                "type": "string",
                                "description": "New fragment."
                            }
                        },
                        "required": ["path", "old", "new"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "sg_apply",
                    "description": "Apply one file replacement.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path."
                            },
                            "old": {
                                "type": "string",
                                "description": "Old fragment."
                            },
                            "new": {
                                "type": "string",
                                "description": "New fragment."
                            }
                        },
                        "required": ["path", "old", "new"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "sg_audit",
                    "description": "Show recent audit records.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Record limit."
                            }
                        },
                        "additionalProperties": false
                    }
                }
            ]
        }
    })
}

fn tools_call_response(id: Value, request: &Value) -> Value {
    let Some(params) = request.get("params") else {
        return invalid_params(id, "missing params");
    };
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params.get("arguments").unwrap_or(&Value::Null);

    match tool_name {
        "sg_ping" => {
            let message = arguments
                .get("message")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("pong");
            tool_text(id, format!("safeguard: {message}"))
        }
        "sg_plan" => {
            let Some(input) = arguments.get("input").and_then(Value::as_str) else {
                return invalid_params(id, "sg_plan requires string argument 'input'");
            };
            let Some(old_fragment) = arguments.get("old").and_then(Value::as_str) else {
                return invalid_params(id, "sg_plan requires string argument 'old'");
            };
            let Some(new_fragment) = arguments.get("new").and_then(Value::as_str) else {
                return invalid_params(id, "sg_plan requires string argument 'new'");
            };

            match safeguard_core::plan_unique_replacement(input, old_fragment, new_fragment) {
                Ok(plan) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json!({
                                    "status": "planned",
                                    "start": plan.start,
                                    "end": plan.end,
                                    "removed_bytes": plan.removed_bytes,
                                    "inserted_bytes": plan.inserted_bytes
                                }).to_string()
                            }
                        ],
                        "isError": false
                    }
                }),
                Err(err) => tool_error_text(id, format!("rejected: {err:?}")),
            }
        }
        "sg_dry" => {
            let Some(args) = file_replace_args(id.clone(), arguments) else {
                return invalid_params(
                    id,
                    "file replacement requires string arguments 'path', 'old', and 'new'",
                );
            };

            let path = match resolve_allowed_path(&args.path) {
                Ok(path) => path,
                Err(err) => return tool_error_text(id, format!("rejected: {err}")),
            };

            match safeguard_core::plan_text_file_replacement(&path, &args.old, &args.new) {
                Ok(plan) => replacement_plan_result(id, "planned", &plan),
                Err(err) => tool_error_text(id, format!("rejected: {err}")),
            }
        }
        "sg_apply" => tool_error_text(
            id,
            "rejected: sg_apply is disabled in transparent mode; use native Codex edits"
                .to_string(),
        ),
        "sg_audit" => {
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value > 0)
                .unwrap_or(10);
            match read_audit_summary(limit) {
                Ok(summary) => tool_json_text(id, summary),
                Err(err) => tool_error_text(id, format!("rejected: {err}")),
            }
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Unknown tool: {tool_name}")
            }
        }),
    }
}

fn tool_text(id: Value, text: String) -> Value {
    tool_json_text_with_error(id, Value::String(text), false)
}

fn tool_error_text(id: Value, text: String) -> Value {
    tool_json_text_with_error(id, Value::String(text), true)
}

fn tool_json_text(id: Value, text: Value) -> Value {
    tool_json_text_with_error(id, text, false)
}

fn tool_json_text_with_error(id: Value, text: Value, is_error: bool) -> Value {
    let text = match text {
        Value::String(text) => text,
        value => value.to_string(),
    };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": text
                }
            ],
            "isError": is_error
        }
    })
}

fn invalid_params(id: Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32602,
            "message": message
        }
    })
}

struct FileReplaceArgs {
    path: PathBuf,
    old: String,
    new: String,
}

fn file_replace_args(_id: Value, arguments: &Value) -> Option<FileReplaceArgs> {
    let path = arguments.get("path").and_then(Value::as_str)?;
    let old = arguments.get("old").and_then(Value::as_str)?;
    let new = arguments.get("new").and_then(Value::as_str)?;

    Some(FileReplaceArgs {
        path: PathBuf::from(path),
        old: old.to_string(),
        new: new.to_string(),
    })
}

fn resolve_allowed_path(path: &Path) -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to resolve current directory")?;
    let root = workspace_root()?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("failed to canonicalize target {}", candidate.display()))?;

    if !canonical.starts_with(&root) {
        anyhow::bail!(
            "target {} is outside workspace root {}",
            canonical.display(),
            root.display()
        );
    }
    reject_internal_state_target(&root, &canonical)?;

    Ok(canonical)
}

fn reject_internal_state_target(root: &Path, target: &Path) -> anyhow::Result<()> {
    let state_root = safeguard_core::legacy_workspace_state_root(root);
    let state_root = if state_root.exists() {
        state_root.canonicalize()?
    } else {
        state_root
    };
    if target.starts_with(state_root) {
        anyhow::bail!("target is inside Safeguard internal state");
    }
    Ok(())
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to resolve current directory")?;
    let root = match std::env::var_os("SAFEGUARD_WORKSPACE_ROOT") {
        Some(root) => PathBuf::from(root),
        None => cwd,
    };
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize workspace root {}", root.display()))
}

fn replacement_plan_result(
    id: Value,
    status: &str,
    plan: &safeguard_core::FileReplacementPlan,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json!({
                        "status": status,
                        "path": plan.path.display().to_string(),
                        "start": plan.replacement.start,
                        "end": plan.replacement.end,
                        "removed_bytes": plan.replacement.removed_bytes,
                        "inserted_bytes": plan.replacement.inserted_bytes
                    }).to_string()
                }
            ],
            "isError": false
        }
    })
}

fn read_audit_summary(limit: usize) -> anyhow::Result<Value> {
    let audit_path = safeguard_core::workspace_state_root(workspace_root()?).join("audit.jsonl");
    if !audit_path.exists() {
        return Ok(json!({
            "status": "empty",
            "total_records": 0,
            "records": []
        }));
    }

    let content = std::fs::read_to_string(&audit_path).context("failed to read audit jsonl")?;
    let mut records = Vec::new();
    let mut total_records = 0usize;

    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        total_records += 1;
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        records.push(json!({
            "ts_unix": value.get("ts_unix").cloned().unwrap_or(Value::Null),
            "operation": value.get("operation").cloned().unwrap_or(Value::Null),
            "path": value.get("path").cloned().unwrap_or(Value::Null),
            "start": value.get("start").cloned().unwrap_or(Value::Null),
            "end": value.get("end").cloned().unwrap_or(Value::Null),
            "removed_bytes": value.get("removed_bytes").cloned().unwrap_or(Value::Null),
            "inserted_bytes": value.get("inserted_bytes").cloned().unwrap_or(Value::Null)
        }));
    }

    let keep_from = records.len().saturating_sub(limit);
    let records = records.split_off(keep_from);

    Ok(json!({
        "status": "ok",
        "total_records": total_records,
        "records": records
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::handle_line;

    #[test]
    fn ping_returns_json_rpc_response() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sg_ping","arguments":{"message":"ok"}}}"#,
        )
        .unwrap_or_default();

        assert!(response.contains("safeguard: ok"));
    }

    #[test]
    fn plan_replace_rejects_ambiguous_input() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sg_plan","arguments":{"input":"x x","old":"x","new":"y"}}}"#,
        )
        .unwrap_or_default();

        assert!(response.contains("Ambiguous"));
        assert_tool_result_is_error(&response, "rejected:");
    }

    #[test]
    fn apply_file_replacement_rejects_in_transparent_mode() {
        let path = test_path("apply_file_replacement_rejects_in_transparent_mode.txt");
        let write_result = std::fs::write(&path, "alpha beta gamma");
        assert!(write_result.is_ok());

        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"sg_apply","arguments":{{"path":{},"old":"beta","new":"BETA"}}}}}}"#,
            serde_json::json!(path.display().to_string())
        );
        let response = handle_line(&request).unwrap_or_default();

        assert_tool_result_is_error(&response, "sg_apply is disabled in transparent mode");
        assert!(!response.to_lowercase().contains("blake3"));
        assert!(std::fs::read_to_string(&path).is_ok_and(|value| value == "alpha beta gamma"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audit_summary_omits_internal_digest_fields() {
        let summary_response = handle_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sg_audit","arguments":{"limit":1}}}"#,
        )
        .unwrap_or_default();

        assert!(summary_response.contains(r#"\"total_records\":"#));
        assert!(!summary_response.to_lowercase().contains("blake3"));
    }

    #[test]
    fn apply_rejects_internal_state_target() {
        let internal_dir = PathBuf::from(".safeguard");
        assert!(std::fs::create_dir_all(&internal_dir).is_ok());
        let path = internal_dir.join(format!("blocked-test-{}-audit.jsonl", std::process::id()));
        assert!(std::fs::write(&path, "alpha").is_ok());

        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"sg_apply","arguments":{{"path":{},"old":"alpha","new":"beta"}}}}}}"#,
            serde_json::json!(path.display().to_string())
        );
        let response = handle_line(&request).unwrap_or_default();

        assert!(response.contains("rejected"));
        assert_tool_result_is_error(&response, "sg_apply is disabled in transparent mode");
        assert!(std::fs::read_to_string(&path).is_ok_and(|value| value == "alpha"));
        let _ = std::fs::remove_file(&path);
    }

    fn assert_tool_result_is_error(response: &str, expected_text: &str) {
        let value: serde_json::Value = match serde_json::from_str(response) {
            Ok(value) => value,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert_eq!(
            value
                .get("result")
                .and_then(|result| result.get("isError"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            value
                .get("result")
                .and_then(|result| result.get("content"))
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("text"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| text.contains(expected_text))
        );
    }

    fn test_path(name: &str) -> PathBuf {
        PathBuf::from(format!(".safeguard-test-{}-{name}", std::process::id()))
    }
}
