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
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "recover") {
        let output = handle_recover_cli(&args[1..]);
        println!("{output}");
        return Ok(());
    }

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
    contract_id: String,
    transaction_id: String,
    transaction_record_path: String,
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

fn handle_recover_cli(args: &[String]) -> Value {
    let mut cwd = None;
    let mut list = false;
    let mut rollback = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--cwd" => {
                let Some(value) = args.get(index + 1) else {
                    return recover_error("missing value for --cwd");
                };
                cwd = Some(value.clone());
                index += 2;
            }
            "--list" => {
                list = true;
                index += 1;
            }
            "--rollback" => {
                let Some(value) = args.get(index + 1) else {
                    return recover_error("missing value for --rollback");
                };
                rollback = Some(value.clone());
                index += 2;
            }
            _ => return recover_error("unknown recover argument"),
        }
    }

    let cwd = cwd.unwrap_or_else(|| {
        std::env::current_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| ".".to_string())
    });
    if list || rollback.is_none() {
        return match safeguard_transaction::recovery_candidates(state_root(&cwd)) {
            Ok(candidates) => json!({
                "ok": true,
                "operation": "list",
                "count": candidates.len(),
                "records": candidates
                    .into_iter()
                    .map(|candidate| candidate.record_path.display().to_string())
                    .collect::<Vec<_>>()
            }),
            Err(err) => recover_error(&model_safe_transaction_error(err).to_string()),
        };
    }

    let transaction_id = match rollback {
        Some(value) => value,
        None => return recover_error("missing transaction id"),
    };
    let id = match safeguard_transaction::TransactionId::new(transaction_id.clone()) {
        Ok(id) => id,
        Err(err) => return recover_error(&model_safe_transaction_error(err).to_string()),
    };
    match safeguard_transaction::rollback_transaction(state_root(&cwd), &id) {
        Ok(Some(record)) => {
            let receipt_path = write_recovery_receipt(&cwd, &transaction_id, &record).ok();
            json!({
                "ok": true,
                "operation": "rollback",
                "transaction_id": transaction_id,
                "targets": record.targets.len(),
                "receipt_path": receipt_path.map(|path| path.display().to_string())
            })
        }
        Ok(None) => recover_error("transaction record not found"),
        Err(err) => recover_error(&model_safe_transaction_error(err).to_string()),
    }
}

fn recover_error(reason: &str) -> Value {
    json!({
        "ok": false,
        "error": reason
    })
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
                let tool_use_id = request
                    .tool_use_id
                    .clone()
                    .unwrap_or_else(|| "unknown-tool-use".to_string());
                match prepare_and_write_guarded_pending(
                    &request.cwd,
                    &tool_use_id,
                    tool_name,
                    "apply_patch",
                    files,
                ) {
                    Ok(()) => continue_output(),
                    Err(err) => deny_pre_tool_use(format!(
                        "Safeguard could not prepare guarded patch: {err}"
                    )),
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
                    let tool_use_id = request
                        .tool_use_id
                        .clone()
                        .unwrap_or_else(|| stable_id_for_command(command));
                    match prepare_and_write_guarded_pending(
                        &request.cwd,
                        &tool_use_id,
                        tool_name,
                        "bash_apply_patch",
                        files,
                    ) {
                        Ok(()) => continue_output(),
                        Err(err) => deny_pre_tool_use(format!(
                            "Safeguard could not prepare guarded shell patch: {err}"
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
    let mut changed_files = Vec::new();
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
        changed_files.push(safeguard_protocol::ChangedFile {
            path: file.path.clone(),
            operation: protocol_file_operation(&file.operation),
            before_digest: file.before_blake3.clone(),
            after_digest: after_blake3,
            diff_digest: None,
        });
    }
    let started_at = transaction_started_at(&pending).unwrap_or_else(current_unix_timestamp);
    let _ = write_execution_receipt(&pending, success, started_at, changed_files);

    let _ = append_policy_audit(
        &pending.cwd,
        json!({
            "operation": "native_edit_audit",
            "tool": pending.tool_name,
            "command_kind": pending.command_kind,
            "tool_use_id": pending.tool_use_id,
            "contract_id": pending.contract_id,
            "transaction_id": pending.transaction_id,
            "success": success,
            "files": files
        }),
    );
    if let Ok(id) = safeguard_transaction::TransactionId::new(pending.transaction_id.clone()) {
        let _ = safeguard_transaction::complete_transaction(state_root(&pending.cwd), &id);
    }
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

fn prepare_and_write_guarded_pending(
    cwd: &str,
    tool_use_id: &str,
    tool_name: &str,
    command_kind: &str,
    files: Vec<PendingFile>,
) -> anyhow::Result<()> {
    let pending = prepare_guarded_pending(cwd, tool_use_id, tool_name, command_kind, files)?;
    if let Err(err) = write_pending(&pending) {
        if let Ok(id) = safeguard_transaction::TransactionId::new(pending.transaction_id.clone()) {
            let _ = safeguard_transaction::complete_transaction(state_root(&pending.cwd), &id);
        }
        return Err(err);
    }
    Ok(())
}

fn prepare_guarded_pending(
    cwd: &str,
    tool_use_id: &str,
    tool_name: &str,
    command_kind: &str,
    files: Vec<PendingFile>,
) -> anyhow::Result<PendingEdit> {
    let contract = load_explicit_contract(cwd)?
        .map(|contract| enforce_explicit_contract(cwd, tool_name, command_kind, &files, contract))
        .unwrap_or_else(|| {
            Ok(implicit_contract(
                cwd,
                tool_use_id,
                tool_name,
                command_kind,
                &files,
            ))
        })?;
    let contract_id = contract.contract_id.clone();

    let transaction_id = safeguard_transaction::transaction_id_from_contract(&contract)
        .map_err(model_safe_transaction_error)?;
    let targets = safeguard_transaction::targets_from_contract(&contract);
    let guard = safeguard_transaction::begin_transaction(
        cwd,
        state_root(cwd),
        transaction_id.clone(),
        &targets,
    )
    .map_err(model_safe_transaction_error)?;
    let record_path = guard
        .persist_record_keep_locks()
        .map_err(model_safe_transaction_error)?;

    Ok(PendingEdit {
        tool_use_id: tool_use_id.to_string(),
        tool_name: tool_name.to_string(),
        cwd: cwd.to_string(),
        command_kind: command_kind.to_string(),
        contract_id,
        transaction_id: transaction_id.as_str().to_string(),
        transaction_record_path: record_path.display().to_string(),
        files,
    })
}

fn implicit_contract(
    cwd: &str,
    tool_use_id: &str,
    tool_name: &str,
    command_kind: &str,
    files: &[PendingFile],
) -> safeguard_protocol::ExecutionContract {
    let contract_id = format!("hook-{}", safe_file_id(tool_use_id));
    let mut contract = safeguard_protocol::ExecutionContract::v0_1(contract_id);
    contract.workspace.root = cwd.to_string();
    contract.workspace.allowed_roots = vec![cwd.to_string()];
    contract.capabilities.push(safeguard_protocol::Capability {
        tool: tool_name.to_string(),
        operation: command_kind.to_string(),
        resources: files.iter().map(|file| file.path.clone()).collect(),
        constraints: Default::default(),
    });
    contract.expected_changes.files = files
        .iter()
        .map(|file| safeguard_protocol::ExpectedFileChange {
            path: file.path.clone(),
            operation: protocol_file_operation(&file.operation),
            before_digest: file.before_blake3.clone(),
            expected_diff_digest: None,
        })
        .collect();
    contract
}

fn load_explicit_contract(
    cwd: &str,
) -> anyhow::Result<Option<safeguard_protocol::ExecutionContract>> {
    let Ok(value) = std::env::var("SAFEGUARD_CONTRACT_PATH") else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    let path = resolve_contract_path(cwd, &value)?;
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read Safeguard contract {}", path.display()))?;
    let contract = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse Safeguard contract {}", path.display()))?;
    Ok(Some(contract))
}

fn enforce_explicit_contract(
    cwd: &str,
    tool_name: &str,
    command_kind: &str,
    files: &[PendingFile],
    mut contract: safeguard_protocol::ExecutionContract,
) -> anyhow::Result<safeguard_protocol::ExecutionContract> {
    for file in files {
        if contract
            .denied_resources
            .iter()
            .any(|resource| resource_matches(cwd, resource, &file.path))
        {
            anyhow::bail!("explicit contract denies a patch target");
        }
        if !expected_change_matches(cwd, &contract, file) {
            anyhow::bail!("patch target is not declared in explicit contract");
        }
        if !capability_matches(cwd, &contract, tool_name, command_kind, file) {
            anyhow::bail!("explicit contract does not grant this patch capability");
        }
    }

    for expected in &mut contract.expected_changes.files {
        if expected.before_digest.is_none()
            && let Some(file) = files
                .iter()
                .find(|file| resource_matches(cwd, &expected.path, &file.path))
        {
            expected.before_digest = file.before_blake3.clone();
        }
    }
    Ok(contract)
}

fn expected_change_matches(
    cwd: &str,
    contract: &safeguard_protocol::ExecutionContract,
    file: &PendingFile,
) -> bool {
    contract.expected_changes.files.iter().any(|expected| {
        expected.operation == protocol_file_operation(&file.operation)
            && resource_matches(cwd, &expected.path, &file.path)
    })
}

fn capability_matches(
    cwd: &str,
    contract: &safeguard_protocol::ExecutionContract,
    tool_name: &str,
    command_kind: &str,
    file: &PendingFile,
) -> bool {
    contract.capabilities.iter().any(|capability| {
        (capability.tool == "*" || capability.tool == tool_name)
            && (capability.operation == "*" || capability.operation == command_kind)
            && capability
                .resources
                .iter()
                .any(|resource| resource_matches(cwd, resource, &file.path))
    })
}

fn resource_matches(cwd: &str, resource: &str, target: &str) -> bool {
    if resource == "*" {
        return true;
    }
    if let Some(prefix) = resource
        .strip_suffix("/**")
        .or_else(|| resource.strip_suffix("\\**"))
    {
        return resolve_resource_path(cwd, prefix).is_some_and(|path| {
            PathBuf::from(target)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(target))
                .starts_with(path)
        });
    }
    resolve_resource_path(cwd, resource).is_some_and(|path| {
        PathBuf::from(target)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(target))
            == path
    })
}

fn resolve_resource_path(cwd: &str, resource: &str) -> Option<PathBuf> {
    let cwd = PathBuf::from(cwd).canonicalize().ok()?;
    let candidate = if Path::new(resource).is_absolute() {
        PathBuf::from(resource)
    } else {
        cwd.join(resource)
    };
    if candidate.exists() {
        candidate.canonicalize().ok()
    } else {
        let parent = candidate.parent()?.canonicalize().ok()?;
        let file_name = candidate.file_name()?;
        Some(parent.join(file_name))
    }
}

fn resolve_contract_path(cwd: &str, value: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(PathBuf::from(cwd).join(path))
}

fn protocol_file_operation(operation: &str) -> safeguard_protocol::FileOperation {
    match operation {
        "add" => safeguard_protocol::FileOperation::Add,
        "delete" => safeguard_protocol::FileOperation::Delete,
        _ => safeguard_protocol::FileOperation::Modify,
    }
}

fn transaction_started_at(pending: &PendingEdit) -> Option<u64> {
    let id = safeguard_transaction::TransactionId::new(pending.transaction_id.clone()).ok()?;
    safeguard_transaction::load_transaction_record(state_root(&pending.cwd), &id)
        .ok()
        .flatten()
        .map(|record| record.started_at)
}

fn write_execution_receipt(
    pending: &PendingEdit,
    success: bool,
    started_at: u64,
    changed_files: Vec<safeguard_protocol::ChangedFile>,
) -> anyhow::Result<PathBuf> {
    let receipt_id = format!("receipt-{}", safe_file_id(&pending.tool_use_id));
    let mut receipt = safeguard_protocol::ExecutionReceipt {
        schema_version: safeguard_protocol::SCHEMA_VERSION_0_1.to_string(),
        contract_id: pending.contract_id.clone(),
        receipt_id,
        status: if success {
            safeguard_protocol::ReceiptStatus::Accepted
        } else {
            safeguard_protocol::ReceiptStatus::Rejected
        },
        started_at: format!("unix:{started_at}"),
        completed_at: format!("unix:{}", current_unix_timestamp()),
        executor: safeguard_protocol::ReceiptExecutor {
            system: "safeguard-hook".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        observed_operations: changed_files
            .iter()
            .map(|file| safeguard_protocol::ObservedOperation {
                tool: pending.tool_name.clone(),
                operation: pending.command_kind.clone(),
                path: Some(file.path.clone()),
                command: None,
            })
            .collect(),
        changed_files,
        validations: Vec::new(),
        policy_violations: Vec::new(),
        invariants: vec![safeguard_protocol::InvariantResult {
            name: "transaction_completed".to_string(),
            status: if success {
                safeguard_protocol::InvariantStatus::Passed
            } else {
                safeguard_protocol::InvariantStatus::Failed
            },
        }],
        receipt_hash: None,
        previous_receipt_hash: None,
        signature: None,
        extensions: Default::default(),
    };
    let unsigned = serde_json::to_vec(&receipt)?;
    receipt.receipt_hash = Some(safeguard_core::blake3_hex(&unsigned).as_hex().to_string());

    let dir = state_root(&pending.cwd).join("receipts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_file_id(&receipt.receipt_id)));
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(path)
}

fn write_recovery_receipt(
    cwd: &str,
    transaction_id: &str,
    record: &safeguard_transaction::TransactionRecord,
) -> anyhow::Result<PathBuf> {
    let receipt_id = format!("recovery-{}", safe_file_id(transaction_id));
    let mut receipt = safeguard_protocol::ExecutionReceipt {
        schema_version: safeguard_protocol::SCHEMA_VERSION_0_1.to_string(),
        contract_id: transaction_id.to_string(),
        receipt_id,
        status: safeguard_protocol::ReceiptStatus::RolledBack,
        started_at: format!("unix:{}", record.started_at),
        completed_at: format!("unix:{}", current_unix_timestamp()),
        executor: safeguard_protocol::ReceiptExecutor {
            system: "safeguard-hook".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        observed_operations: record
            .targets
            .iter()
            .map(|target| safeguard_protocol::ObservedOperation {
                tool: "safeguard-hook".to_string(),
                operation: "recover.rollback".to_string(),
                path: Some(target.path.display().to_string()),
                command: None,
            })
            .collect(),
        changed_files: record
            .targets
            .iter()
            .map(|target| safeguard_protocol::ChangedFile {
                path: target.path.display().to_string(),
                operation: if target.existed_before {
                    safeguard_protocol::FileOperation::Modify
                } else {
                    safeguard_protocol::FileOperation::Delete
                },
                before_digest: target.before_blake3.clone(),
                after_digest: digest_path_if_exists(&target.path),
                diff_digest: None,
            })
            .collect(),
        validations: Vec::new(),
        policy_violations: Vec::new(),
        invariants: vec![safeguard_protocol::InvariantResult {
            name: "rollback_completed".to_string(),
            status: safeguard_protocol::InvariantStatus::Passed,
        }],
        receipt_hash: None,
        previous_receipt_hash: None,
        signature: None,
        extensions: Default::default(),
    };
    let unsigned = serde_json::to_vec(&receipt)?;
    receipt.receipt_hash = Some(safeguard_core::blake3_hex(&unsigned).as_hex().to_string());

    let dir = state_root(cwd).join("receipts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_file_id(&receipt.receipt_id)));
    std::fs::write(&path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(path)
}

fn digest_path_if_exists(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    std::fs::read(path)
        .ok()
        .map(|bytes| safeguard_core::blake3_hex(&bytes).as_hex().to_string())
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn model_safe_transaction_error(err: safeguard_transaction::TransactionError) -> anyhow::Error {
    let message = match err {
        safeguard_transaction::TransactionError::InvalidTransactionId => {
            "invalid guarded edit id".to_string()
        }
        safeguard_transaction::TransactionError::PathOutsideWorkspace { .. } => {
            "patch target is outside the workspace".to_string()
        }
        safeguard_transaction::TransactionError::SymlinkTarget { .. } => {
            "patch target is a symlink".to_string()
        }
        safeguard_transaction::TransactionError::StaleDigest { .. } => {
            "target changed after the edit was planned; retry with fresh file contents".to_string()
        }
        safeguard_transaction::TransactionError::LockHeld { .. } => {
            "target is already locked by another guarded edit".to_string()
        }
        safeguard_transaction::TransactionError::MissingRollbackSnapshot { .. } => {
            "rollback snapshot is missing for a guarded edit".to_string()
        }
        safeguard_transaction::TransactionError::Io { operation, .. } => {
            format!("guarded edit storage failed during {operation}")
        }
        safeguard_transaction::TransactionError::SerializeRecord(_) => {
            "guarded edit record could not be written".to_string()
        }
        safeguard_transaction::TransactionError::DeserializeRecord(_) => {
            "guarded edit record could not be read".to_string()
        }
        safeguard_transaction::TransactionError::Time(_) => {
            "system clock prevented guarded edit setup".to_string()
        }
    };
    anyhow::anyhow!(message)
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
    state_root(cwd).join("pending")
}

fn audit_path(cwd: &str) -> PathBuf {
    state_root(cwd).join("audit.jsonl")
}

fn state_root(cwd: &str) -> PathBuf {
    PathBuf::from(cwd).join(".safeguard")
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
    use std::path::PathBuf;

    use super::enforce_explicit_contract;
    use super::extract_patch;
    use super::handle_recover_cli;
    use super::implicit_contract;
    use super::is_risky_shell_write;
    use super::patch_targets;
    use super::plan_patch_files;
    use super::prepare_guarded_pending;
    use super::read_pending;
    use super::state_root;
    use super::write_execution_receipt;
    use super::write_pending;

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

    #[test]
    fn guarded_pending_keeps_transaction_until_completed() {
        let fixture = Fixture::new("guarded_pending_keeps_transaction_until_completed");
        let file = fixture.root.join("a.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let command = r#"apply_patch <<'PATCH'
*** Begin Patch
*** Update File: a.txt
@@
-alpha
+beta
*** End Patch
PATCH"#;
        let files = match plan_patch_files(root, command) {
            Ok(files) => files,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        let pending =
            match prepare_guarded_pending(root, "unit-1", "Bash", "bash_apply_patch", files) {
                Ok(pending) => pending,
                Err(err) => {
                    assert_eq!(err.to_string(), "");
                    return;
                }
            };

        assert!(PathBuf::from(&pending.transaction_record_path).exists());
        assert_eq!(count_files(state_root(root).join("locks"), "lock"), 1);
        let receipt_path = write_execution_receipt(&pending, true, 1, Vec::new());
        assert!(receipt_path.as_ref().is_ok_and(|path| path.exists()));
        assert!(write_pending(&pending).is_ok());
        assert!(read_pending(root, "unit-1").is_ok_and(|pending| pending.is_some()));

        let id = match safeguard_transaction::TransactionId::new(pending.transaction_id) {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert!(safeguard_transaction::complete_transaction(state_root(root), &id).is_ok());
        assert_eq!(count_files(state_root(root).join("locks"), "lock"), 0);
    }

    #[test]
    fn recover_cli_lists_and_rolls_back_transaction() {
        let fixture = Fixture::new("recover_cli_lists_and_rolls_back_transaction");
        let file = fixture.root.join("a.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let command = r#"apply_patch <<'PATCH'
*** Begin Patch
*** Update File: a.txt
@@
-alpha
+beta
*** End Patch
PATCH"#;
        let files = match plan_patch_files(root, command) {
            Ok(files) => files,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        let pending =
            match prepare_guarded_pending(root, "unit-rollback", "Bash", "bash_apply_patch", files)
            {
                Ok(pending) => pending,
                Err(err) => {
                    assert_eq!(err.to_string(), "");
                    return;
                }
            };
        assert!(std::fs::write(&file, "beta").is_ok());

        let list_args = vec!["--cwd".to_string(), root.to_string(), "--list".to_string()];
        let listed = handle_recover_cli(&list_args);
        assert_eq!(
            listed.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            listed.get("count").and_then(serde_json::Value::as_u64),
            Some(1)
        );

        let rollback_args = vec![
            "--cwd".to_string(),
            root.to_string(),
            "--rollback".to_string(),
            pending.transaction_id,
        ];
        let rolled_back = handle_recover_cli(&rollback_args);
        assert_eq!(
            rolled_back.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(std::fs::read_to_string(&file).is_ok_and(|value| value == "alpha"));
        assert_eq!(count_files(state_root(root).join("locks"), "lock"), 0);
        assert_eq!(count_files(state_root(root).join("receipts"), "json"), 1);
    }

    #[test]
    fn explicit_contract_allows_declared_patch() {
        let fixture = Fixture::new("explicit_contract_allows_declared_patch");
        let file = fixture.root.join("a.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let files = vec![super::PendingFile {
            path: file.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
        }];
        let contract = implicit_contract(root, "contract-ok", "Bash", "bash_apply_patch", &files);
        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_ok());
    }

    #[test]
    fn explicit_contract_rejects_undeclared_patch() {
        let fixture = Fixture::new("explicit_contract_rejects_undeclared_patch");
        let file = fixture.root.join("a.txt");
        let other = fixture.root.join("b.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        assert!(std::fs::write(&other, "beta").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let declared = vec![super::PendingFile {
            path: file.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
        }];
        let attempted = vec![super::PendingFile {
            path: other.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
        }];
        let contract =
            implicit_contract(root, "contract-deny", "Bash", "bash_apply_patch", &declared);
        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &attempted, contract);
        assert!(enforced.is_err());
    }

    fn count_files(dir: PathBuf, extension: &str) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some(extension)
            })
            .count()
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("safeguard-hook-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            assert!(std::fs::create_dir_all(&root).is_ok());
            Self { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
