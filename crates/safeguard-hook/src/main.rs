//! Codex lifecycle hook guard for transparent Safeguard protection.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
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
    #[serde(default)]
    contract_hash: Option<String>,
    #[serde(default)]
    required_validations: Vec<String>,
    files: Vec<PendingFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingFile {
    path: String,
    operation: String,
    existed_before: bool,
    before_blake3: Option<String>,
    #[serde(default)]
    expected_after_blake3: Option<String>,
    #[serde(default)]
    patch_blake3: Option<String>,
}

#[derive(Debug, Clone)]
struct ReceiptOutcome {
    status: safeguard_protocol::ReceiptStatus,
    expected_result_verified: bool,
    validations_passed: bool,
    rollback_completed: Option<bool>,
    completion_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReceiptChainHead {
    sequence: u64,
    receipt_hash: String,
    receipt_path: String,
}

#[derive(Debug)]
struct ReceiptChainLock {
    path: PathBuf,
}

impl Drop for ReceiptChainLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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
                let Some(tool_use_id) = request.tool_use_id.as_deref() else {
                    return deny_pre_tool_use(
                        "Safeguard could not identify this edit; retry the edit".to_string(),
                    );
                };
                match prepare_and_write_guarded_pending(
                    &request.cwd,
                    tool_use_id,
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
                    let Some(tool_use_id) = request.tool_use_id.as_deref() else {
                        return deny_pre_tool_use(
                            "Safeguard could not identify this edit; retry the edit".to_string(),
                        );
                    };
                    match prepare_and_write_guarded_pending(
                        &request.cwd,
                        tool_use_id,
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
        let _ = append_policy_audit(
            &request.cwd,
            json!({
                "operation": "missing_tool_use_id",
                "hook": "PostToolUse",
                "reason": "guarded edit could not be correlated"
            }),
        );
        return json!({
            "continue": true,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "message": "Safeguard could not identify this edit; retry the edit"
            }
        });
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
    let mut expected_result_verified = true;
    for file in &pending.files {
        let path = PathBuf::from(&file.path);
        let exists_after = path.exists();
        let after_blake3 = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => Some(safeguard_core::blake3_hex(&bytes).as_hex().to_string()),
                Err(_) => None,
            }
        } else {
            None
        };
        let file_verified = expected_result_matches(file, exists_after, after_blake3.as_deref());
        expected_result_verified &= file_verified;
        files.push(json!({
            "path": file.path,
            "operation": file.operation,
            "existed_before": file.existed_before,
            "exists_after": exists_after,
            "verified": file_verified,
            "before_blake3": file.before_blake3,
            "after_blake3": after_blake3
        }));
        changed_files.push(safeguard_protocol::ChangedFile {
            path: file.path.clone(),
            operation: protocol_file_operation(&file.operation),
            before_digest: file.before_blake3.clone(),
            after_digest: after_blake3,
            diff_digest: file.patch_blake3.clone(),
        });
    }
    let started_at = transaction_started_at(&pending).unwrap_or_else(current_unix_timestamp);
    let (validations, validations_passed, validation_side_effects) =
        run_required_validations(&pending, success && expected_result_verified);
    let accepted = success && expected_result_verified && validations_passed;
    let mut receipt_status = if accepted {
        safeguard_protocol::ReceiptStatus::Accepted
    } else {
        safeguard_protocol::ReceiptStatus::RolledBack
    };
    let mut rollback_completed = None;
    let mut completion_error = None;
    let mut receipt_written = false;
    let mut transaction_cleaned = false;

    match safeguard_transaction::TransactionId::new(pending.transaction_id.clone()) {
        Ok(id) if accepted => {
            let prepared = write_execution_receipt(
                &pending,
                ReceiptOutcome {
                    status: safeguard_protocol::ReceiptStatus::Prepared,
                    expected_result_verified,
                    validations_passed,
                    rollback_completed,
                    completion_error: completion_error.clone(),
                },
                started_at,
                changed_files.clone(),
                validations.clone(),
            );
            match prepared {
                Ok(_) => {
                    match safeguard_transaction::complete_transaction(state_root(&pending.cwd), &id)
                    {
                        Ok(()) => {
                            transaction_cleaned = true;
                            match write_execution_receipt(
                                &pending,
                                ReceiptOutcome {
                                    status: receipt_status.clone(),
                                    expected_result_verified,
                                    validations_passed,
                                    rollback_completed,
                                    completion_error: completion_error.clone(),
                                },
                                started_at,
                                changed_files.clone(),
                                validations.clone(),
                            ) {
                                Ok(_) => {
                                    receipt_written = true;
                                }
                                Err(err) => {
                                    receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                                    completion_error = Some(format!("receipt write failed: {err}"));
                                    let _ =
                                        write_quarantine_marker(&pending, "receipt_write_failed");
                                    let _ = write_execution_receipt(
                                        &pending,
                                        ReceiptOutcome {
                                            status: receipt_status.clone(),
                                            expected_result_verified,
                                            validations_passed,
                                            rollback_completed,
                                            completion_error: completion_error.clone(),
                                        },
                                        started_at,
                                        changed_files.clone(),
                                        validations.clone(),
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                            completion_error = Some(model_safe_transaction_error(err).to_string());
                            let _ = write_quarantine_marker(&pending, "commit_failed");
                            let _ = write_execution_receipt(
                                &pending,
                                ReceiptOutcome {
                                    status: receipt_status.clone(),
                                    expected_result_verified,
                                    validations_passed,
                                    rollback_completed,
                                    completion_error: completion_error.clone(),
                                },
                                started_at,
                                changed_files.clone(),
                                validations.clone(),
                            );
                        }
                    }
                }
                Err(err) => {
                    receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                    completion_error = Some(format!("receipt write failed: {err}"));
                    let _ = write_quarantine_marker(&pending, "receipt_write_failed");
                }
            }
        }
        Ok(id) => match safeguard_transaction::restore_transaction(state_root(&pending.cwd), &id) {
            Ok(Some(_record)) => {
                rollback_completed = Some(true);
                if validation_side_effects {
                    receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                    completion_error =
                        Some("validation modified undeclared workspace files".to_string());
                    let _ = write_quarantine_marker(&pending, "validation_side_effects");
                }
                match write_execution_receipt(
                    &pending,
                    ReceiptOutcome {
                        status: receipt_status.clone(),
                        expected_result_verified,
                        validations_passed,
                        rollback_completed,
                        completion_error: completion_error.clone(),
                    },
                    started_at,
                    changed_files.clone(),
                    validations.clone(),
                ) {
                    Ok(_) => {
                        receipt_written = true;
                        if !validation_side_effects {
                            match safeguard_transaction::complete_transaction(
                                state_root(&pending.cwd),
                                &id,
                            ) {
                                Ok(()) => {
                                    transaction_cleaned = true;
                                }
                                Err(err) => {
                                    receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                                    completion_error =
                                        Some(model_safe_transaction_error(err).to_string());
                                    let _ = write_quarantine_marker(
                                        &pending,
                                        "rollback_cleanup_failed",
                                    );
                                    let _ = write_execution_receipt(
                                        &pending,
                                        ReceiptOutcome {
                                            status: receipt_status.clone(),
                                            expected_result_verified,
                                            validations_passed,
                                            rollback_completed,
                                            completion_error: completion_error.clone(),
                                        },
                                        started_at,
                                        changed_files.clone(),
                                        validations.clone(),
                                    );
                                }
                            }
                        }
                    }
                    Err(err) => {
                        receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                        completion_error = Some(format!("receipt write failed: {err}"));
                        let _ = write_quarantine_marker(&pending, "receipt_write_failed");
                    }
                }
            }
            Ok(None) => {
                receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                rollback_completed = Some(false);
                completion_error = Some("transaction record not found".to_string());
                let _ = write_quarantine_marker(&pending, "rollback_record_missing");
                if write_execution_receipt(
                    &pending,
                    ReceiptOutcome {
                        status: receipt_status.clone(),
                        expected_result_verified,
                        validations_passed,
                        rollback_completed,
                        completion_error: completion_error.clone(),
                    },
                    started_at,
                    changed_files.clone(),
                    validations.clone(),
                )
                .is_ok()
                {
                    receipt_written = true;
                }
            }
            Err(err) => {
                receipt_status = safeguard_protocol::ReceiptStatus::Partial;
                rollback_completed = Some(false);
                completion_error = Some(model_safe_transaction_error(err).to_string());
                let _ = write_quarantine_marker(&pending, "rollback_failed");
                if write_execution_receipt(
                    &pending,
                    ReceiptOutcome {
                        status: receipt_status.clone(),
                        expected_result_verified,
                        validations_passed,
                        rollback_completed,
                        completion_error: completion_error.clone(),
                    },
                    started_at,
                    changed_files.clone(),
                    validations.clone(),
                )
                .is_ok()
                {
                    receipt_written = true;
                }
            }
        },
        Err(err) => {
            receipt_status = safeguard_protocol::ReceiptStatus::Partial;
            completion_error = Some(model_safe_transaction_error(err).to_string());
            let _ = write_quarantine_marker(&pending, "invalid_transaction_id");
            if write_execution_receipt(
                &pending,
                ReceiptOutcome {
                    status: receipt_status.clone(),
                    expected_result_verified,
                    validations_passed,
                    rollback_completed,
                    completion_error: completion_error.clone(),
                },
                started_at,
                changed_files.clone(),
                validations.clone(),
            )
            .is_ok()
            {
                receipt_written = true;
            }
        }
    }

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
            "verified": expected_result_verified,
            "validations_passed": validations_passed,
            "validation_side_effects": validation_side_effects,
            "receipt_status": format!("{:?}", receipt_status),
            "receipt_written": receipt_written,
            "transaction_cleaned": transaction_cleaned,
            "completion_error": completion_error,
            "files": files
        }),
    );
    if receipt_status != safeguard_protocol::ReceiptStatus::Partial
        && receipt_written
        && transaction_cleaned
    {
        let _ = remove_pending(&request.cwd, tool_use_id);
    }
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
        contract_hash: contract_hash(&contract),
        required_validations: contract
            .required_validations
            .iter()
            .map(|validation| validation.command.clone())
            .collect(),
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
            expected_diff_digest: file.patch_blake3.clone(),
            requirement: safeguard_protocol::ExpectedChangeRequirement::Required,
        })
        .collect();
    contract
}

fn contract_hash(contract: &safeguard_protocol::ExecutionContract) -> Option<String> {
    serde_json::to_vec(contract)
        .ok()
        .map(|bytes| safeguard_core::blake3_hex(&bytes).as_hex().to_string())
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
    contract = safeguard_protocol::VerifiedContract::verify(contract, cwd)?.into_inner();
    enforce_capability_constraints(&contract, files)?;
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
    enforce_required_expected_changes(cwd, &contract, files)?;

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

fn enforce_capability_constraints(
    contract: &safeguard_protocol::ExecutionContract,
    files: &[PendingFile],
) -> anyhow::Result<()> {
    for capability in &contract.capabilities {
        for (key, value) in &capability.constraints {
            match key.as_str() {
                "max_files_changed" => {
                    let Some(max) = value.as_u64() else {
                        anyhow::bail!("invalid max_files_changed constraint");
                    };
                    if files.len() as u64 > max {
                        anyhow::bail!("explicit contract max_files_changed exceeded");
                    }
                }
                "network" => {
                    if value.as_bool().is_none() {
                        anyhow::bail!("invalid network constraint");
                    }
                }
                "allowed_write_roots" => {
                    if !value
                        .as_array()
                        .is_some_and(|items| items.iter().all(|item| item.as_str().is_some()))
                    {
                        anyhow::bail!("invalid allowed_write_roots constraint");
                    }
                }
                "validation_timeout_seconds" => {
                    if value.as_u64().is_none() {
                        anyhow::bail!("invalid validation_timeout_seconds constraint");
                    }
                }
                _ => anyhow::bail!("unknown mandatory contract constraint"),
            }
        }
    }
    Ok(())
}

fn enforce_required_expected_changes(
    cwd: &str,
    contract: &safeguard_protocol::ExecutionContract,
    files: &[PendingFile],
) -> anyhow::Result<()> {
    for expected in contract.expected_changes.files.iter().filter(|expected| {
        expected.requirement == safeguard_protocol::ExpectedChangeRequirement::Required
    }) {
        let observed = files.iter().any(|file| {
            expected.operation == protocol_file_operation(&file.operation)
                && resource_matches(cwd, &expected.path, &file.path)
                && expected_diff_matches(expected, file)
        });
        if !observed {
            anyhow::bail!("required expected change was not observed");
        }
    }
    Ok(())
}

fn expected_change_matches(
    cwd: &str,
    contract: &safeguard_protocol::ExecutionContract,
    file: &PendingFile,
) -> bool {
    contract.expected_changes.files.iter().any(|expected| {
        expected.operation == protocol_file_operation(&file.operation)
            && resource_matches(cwd, &expected.path, &file.path)
            && expected_diff_matches(expected, file)
    })
}

fn expected_diff_matches(
    expected: &safeguard_protocol::ExpectedFileChange,
    file: &PendingFile,
) -> bool {
    expected
        .expected_diff_digest
        .as_deref()
        .is_none_or(|digest| file.patch_blake3.as_deref() == Some(digest))
}

fn capability_matches(
    cwd: &str,
    contract: &safeguard_protocol::ExecutionContract,
    tool_name: &str,
    command_kind: &str,
    file: &PendingFile,
) -> bool {
    contract.capabilities.iter().any(|capability| {
        capability_tool_matches(&capability.tool, tool_name, command_kind)
            && capability_operation_matches(&capability.operation, command_kind, file)
            && capability
                .resources
                .iter()
                .any(|resource| resource_matches(cwd, resource, &file.path))
            && capability_constraints_match(cwd, capability, file)
    })
}

fn capability_constraints_match(
    cwd: &str,
    capability: &safeguard_protocol::Capability,
    file: &PendingFile,
) -> bool {
    let Some(roots) = capability
        .constraints
        .get("allowed_write_roots")
        .and_then(serde_json::Value::as_array)
    else {
        return true;
    };
    roots
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|root| {
            if root.ends_with("/**") || root.ends_with("\\**") {
                resource_matches(cwd, root, &file.path)
            } else {
                resolve_resource_path(cwd, root).is_some_and(|root| {
                    PathBuf::from(&file.path)
                        .canonicalize()
                        .unwrap_or_else(|_| PathBuf::from(&file.path))
                        .starts_with(root)
                })
            }
        })
}

fn capability_tool_matches(capability_tool: &str, tool_name: &str, command_kind: &str) -> bool {
    capability_tool == "*"
        || capability_tool == tool_name
        || (capability_tool == "apply_patch" && command_kind.contains("apply_patch"))
}

fn capability_operation_matches(
    capability_operation: &str,
    command_kind: &str,
    file: &PendingFile,
) -> bool {
    capability_operation == "*"
        || capability_operation == command_kind
        || capability_operation == "invoke"
        || capability_operation == file_resource_operation(file)
}

fn file_resource_operation(file: &PendingFile) -> &'static str {
    match file.operation.as_str() {
        "add" => "add",
        "delete" => "delete",
        _ => "modify",
    }
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

fn run_required_validations(
    pending: &PendingEdit,
    should_run: bool,
) -> (Vec<safeguard_protocol::ValidationResult>, bool, bool) {
    let mut all_passed = true;
    let mut changed_workspace = false;
    let results = pending
        .required_validations
        .iter()
        .map(|command| {
            let status = if should_run {
                match run_validation_command_guarded(&pending.cwd, command) {
                    Ok(ValidationCommandOutcome::Passed) => {
                        safeguard_protocol::ValidationStatus::Passed
                    }
                    Ok(ValidationCommandOutcome::ChangedWorkspace) => {
                        changed_workspace = true;
                        all_passed = false;
                        safeguard_protocol::ValidationStatus::Failed
                    }
                    Ok(ValidationCommandOutcome::Failed) | Err(_) => {
                        all_passed = false;
                        safeguard_protocol::ValidationStatus::Failed
                    }
                }
            } else {
                all_passed = false;
                safeguard_protocol::ValidationStatus::NotRun
            };
            safeguard_protocol::ValidationResult {
                command: command.clone(),
                status,
            }
        })
        .collect::<Vec<_>>();
    (results, all_passed, changed_workspace)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationCommandOutcome {
    Passed,
    Failed,
    ChangedWorkspace,
}

fn run_validation_command_guarded(
    cwd: &str,
    command: &str,
) -> anyhow::Result<ValidationCommandOutcome> {
    let before = workspace_manifest(cwd)?;
    let status = validation_shell_command(command)
        .current_dir(cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("failed to run validation command: {command}"))?;
    if !status.success() {
        return Ok(ValidationCommandOutcome::Failed);
    }
    let after = workspace_manifest(cwd)?;
    if workspace_manifest_changed(&before, &after) {
        return Ok(ValidationCommandOutcome::ChangedWorkspace);
    }
    Ok(ValidationCommandOutcome::Passed)
}

fn workspace_manifest(cwd: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let root = PathBuf::from(cwd)
        .canonicalize()
        .with_context(|| format!("failed to canonicalize cwd {cwd}"))?;
    let mut manifest = BTreeMap::new();
    collect_workspace_manifest(&root, &root, &mut manifest)?;
    Ok(manifest)
}

fn collect_workspace_manifest(
    root: &Path,
    dir: &Path,
    manifest: &mut BTreeMap<String, String>,
) -> anyhow::Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_manifest_entry(&file_name.to_string_lossy()) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_workspace_manifest(root, &path, manifest)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let digest = std::fs::read(&path)
                .map(|bytes| safeguard_core::blake3_hex(&bytes).as_hex().to_string())
                .with_context(|| format!("failed to hash {}", path.display()))?;
            manifest.insert(relative, digest);
        }
    }
    Ok(())
}

fn should_skip_manifest_entry(name: &str) -> bool {
    matches!(name, ".git" | ".safeguard" | "target")
}

fn workspace_manifest_changed(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> bool {
    before != after
}

#[cfg(windows)]
fn validation_shell_command(command: &str) -> std::process::Command {
    let mut process = std::process::Command::new("powershell");
    process.args(["-NoProfile", "-Command", command]);
    process
}

#[cfg(not(windows))]
fn validation_shell_command(command: &str) -> std::process::Command {
    let mut process = std::process::Command::new("sh");
    process.args(["-c", command]);
    process
}

fn write_execution_receipt(
    pending: &PendingEdit,
    outcome: ReceiptOutcome,
    started_at: u64,
    changed_files: Vec<safeguard_protocol::ChangedFile>,
    validations: Vec<safeguard_protocol::ValidationResult>,
) -> anyhow::Result<PathBuf> {
    let receipt_id = format!("receipt-{}", safe_file_id(&pending.tool_use_id));
    let transaction_completed = match &outcome.status {
        safeguard_protocol::ReceiptStatus::Accepted => true,
        safeguard_protocol::ReceiptStatus::RolledBack => outcome.rollback_completed != Some(false),
        _ => false,
    };
    let mut invariants = vec![
        safeguard_protocol::InvariantResult {
            name: "transaction_completed".to_string(),
            status: if transaction_completed {
                safeguard_protocol::InvariantStatus::Passed
            } else {
                safeguard_protocol::InvariantStatus::Failed
            },
        },
        safeguard_protocol::InvariantResult {
            name: "expected_result".to_string(),
            status: if outcome.expected_result_verified {
                safeguard_protocol::InvariantStatus::Passed
            } else {
                safeguard_protocol::InvariantStatus::Failed
            },
        },
        safeguard_protocol::InvariantResult {
            name: "required_validations".to_string(),
            status: if outcome.validations_passed {
                safeguard_protocol::InvariantStatus::Passed
            } else {
                safeguard_protocol::InvariantStatus::Failed
            },
        },
    ];
    if let Some(completed) = outcome.rollback_completed {
        invariants.push(safeguard_protocol::InvariantResult {
            name: "rollback_completed".to_string(),
            status: if completed {
                safeguard_protocol::InvariantStatus::Passed
            } else {
                safeguard_protocol::InvariantStatus::Failed
            },
        });
    }
    let policy_violations = outcome
        .completion_error
        .map(|reason| {
            vec![safeguard_protocol::PolicyViolation {
                code: "transaction_completion_failed".to_string(),
                reason,
            }]
        })
        .unwrap_or_default();
    let mut receipt = safeguard_protocol::ExecutionReceipt {
        schema_version: safeguard_protocol::SCHEMA_VERSION_0_1.to_string(),
        contract_id: pending.contract_id.clone(),
        receipt_id,
        status: outcome.status,
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
        validations,
        policy_violations,
        invariants,
        receipt_hash: None,
        previous_receipt_hash: None,
        signature: None,
        extensions: Default::default(),
    };
    let path = commit_receipt(&pending.cwd, &mut receipt)?;
    if receipt.status != safeguard_protocol::ReceiptStatus::Prepared {
        let _ = write_memoryx_evidence(pending, &receipt, &path);
    }
    Ok(path)
}

fn write_memoryx_evidence(
    pending: &PendingEdit,
    receipt: &safeguard_protocol::ExecutionReceipt,
    receipt_path: &Path,
) -> anyhow::Result<PathBuf> {
    let receipt_hash = receipt.receipt_hash.clone().unwrap_or_else(|| {
        safeguard_core::blake3_hex(receipt.receipt_id.as_bytes())
            .as_hex()
            .to_string()
    });
    let contract_hash = pending.contract_hash.clone().unwrap_or_else(|| {
        safeguard_core::blake3_hex(pending.contract_id.as_bytes())
            .as_hex()
            .to_string()
    });
    let evidence = safeguard_protocol::MemoryxEvidence {
        schema_version: safeguard_protocol::SCHEMA_VERSION_0_1.to_string(),
        contract_id: pending.contract_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        claim: format!(
            "Safeguard receipt {} ended with status {:?}",
            receipt.receipt_id, receipt.status
        ),
        basis: safeguard_protocol::EvidenceBasis {
            contract_hash,
            receipt_hash,
            source_paths: vec![receipt_path.display().to_string()],
        },
        summary: safeguard_protocol::EvidenceSummary {
            changed_files_count: receipt.changed_files.len(),
            validations_passed: receipt
                .validations
                .iter()
                .filter(|validation| {
                    validation.status == safeguard_protocol::ValidationStatus::Passed
                })
                .count(),
            policy_violations_count: receipt.policy_violations.len(),
        },
    };

    let dir = state_root(&pending.cwd).join("evidence");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_file_id(&receipt.receipt_id)));
    std::fs::write(&path, serde_json::to_vec_pretty(&evidence)?)?;
    Ok(path)
}

fn write_quarantine_marker(pending: &PendingEdit, reason: &str) -> anyhow::Result<PathBuf> {
    let dir = state_root(&pending.cwd).join("quarantine");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_file_id(&pending.transaction_id)));
    let record = json!({
        "transaction_id": pending.transaction_id,
        "contract_id": pending.contract_id,
        "tool_use_id": pending.tool_use_id,
        "reason": reason,
        "ts_unix": current_unix_timestamp()
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&record)?)?;
    Ok(path)
}

fn expected_result_matches(
    file: &PendingFile,
    exists_after: bool,
    after_blake3: Option<&str>,
) -> bool {
    if file.operation == "delete" {
        return file.existed_before && !exists_after && file.expected_after_blake3.is_none();
    }
    if let Some(expected_after) = file.expected_after_blake3.as_deref() {
        return exists_after && after_blake3 == Some(expected_after);
    }
    match file.operation.as_str() {
        "add" => !file.existed_before && exists_after && after_blake3.is_some(),
        "delete" => file.existed_before && !exists_after,
        _ => file.existed_before && exists_after && file.before_blake3.as_deref() != after_blake3,
    }
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
    commit_receipt(cwd, &mut receipt)
}

fn commit_receipt(
    cwd: &str,
    receipt: &mut safeguard_protocol::ExecutionReceipt,
) -> anyhow::Result<PathBuf> {
    let state_root = state_root(cwd);
    let receipts_dir = state_root.join("receipts");
    std::fs::create_dir_all(&receipts_dir)?;
    let _lock = acquire_receipt_chain_lock(&state_root)?;
    let previous = load_receipt_chain_head(&state_root);
    let sequence = previous.as_ref().map(|head| head.sequence + 1).unwrap_or(1);
    let base_receipt_id = receipt.receipt_id.clone();
    receipt.receipt_id = format!("{sequence:020}-{}", safe_file_id(&base_receipt_id));
    receipt.previous_receipt_hash = previous.map(|head| head.receipt_hash);
    receipt.receipt_hash = None;
    let unsigned = serde_json::to_vec(&receipt)?;
    let receipt_hash = safeguard_core::blake3_hex(&unsigned).as_hex().to_string();
    receipt.receipt_hash = Some(receipt_hash.clone());

    let path = receipts_dir.join(format!("{}.json", safe_file_id(&receipt.receipt_id)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    file.sync_all()?;
    drop(file);

    if let Err(err) = write_receipt_chain_head(
        &state_root,
        &ReceiptChainHead {
            sequence,
            receipt_hash,
            receipt_path: path.display().to_string(),
        },
    ) {
        let _ = std::fs::remove_file(&path);
        return Err(err);
    }
    Ok(path)
}

fn acquire_receipt_chain_lock(state_root: &Path) -> anyhow::Result<ReceiptChainLock> {
    let dir = state_root.join("receipt-chain");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("head.lock");
    for _ in 0..50 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                writeln!(file, "pid={}", std::process::id())?;
                return Ok(ReceiptChainLock { path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = remove_stale_receipt_chain_lock(&path);
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
    anyhow::bail!("receipt chain lock is held")
}

fn remove_stale_receipt_chain_lock(path: &Path) -> anyhow::Result<()> {
    const STALE_AFTER: Duration = Duration::from_secs(300);
    let metadata = std::fs::metadata(path)?;
    let modified = metadata.modified()?;
    if modified
        .elapsed()
        .map(|elapsed| elapsed >= STALE_AFTER)
        .unwrap_or(false)
    {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn load_receipt_chain_head(state_root: &Path) -> Option<ReceiptChainHead> {
    let path = state_root.join("receipt-chain").join("head.json");
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_receipt_chain_head(state_root: &Path, head: &ReceiptChainHead) -> anyhow::Result<()> {
    let dir = state_root.join("receipt-chain");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("head.json");
    let temp_path = dir.join(format!("head.{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(&serde_json::to_vec_pretty(head)?)?;
    file.sync_all()?;
    drop(file);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    std::fs::rename(&temp_path, path)?;
    Ok(())
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
        reject_internal_state_target(&cwd, &resolved)?;
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
        let expected_after_blake3 =
            expected_after_digest_for_patch(&resolved, patch, &path, &operation)?;
        let patch_blake3 = file_patch_digest(patch, &path);
        files.push(PendingFile {
            path: resolved.display().to_string(),
            operation,
            existed_before,
            before_blake3,
            expected_after_blake3,
            patch_blake3,
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

fn expected_after_digest_for_patch(
    resolved: &Path,
    patch: &str,
    patch_path: &str,
    operation: &str,
) -> anyhow::Result<Option<String>> {
    if operation == "delete" {
        return Ok(None);
    }
    let section = file_patch_section(patch, patch_path)
        .with_context(|| format!("missing patch body for {patch_path}"))?;
    let expected = match operation {
        "add" => added_file_content(&section)?,
        _ => {
            let original = std::fs::read_to_string(resolved)
                .with_context(|| format!("failed to read patch target {}", resolved.display()))?;
            updated_file_content(&original, &section)?
        }
    };
    Ok(Some(
        safeguard_core::blake3_hex(expected.as_bytes())
            .as_hex()
            .to_string(),
    ))
}

fn file_patch_digest(patch: &str, patch_path: &str) -> Option<String> {
    file_patch_section(patch, patch_path).map(|section| {
        safeguard_core::blake3_hex(section.join("\n").as_bytes())
            .as_hex()
            .to_string()
    })
}

fn file_patch_section(patch: &str, patch_path: &str) -> Option<Vec<String>> {
    let mut collecting = false;
    let mut lines = Vec::new();
    for line in patch.lines() {
        let starts_file = line.starts_with("*** Add File: ")
            || line.starts_with("*** Update File: ")
            || line.starts_with("*** Delete File: ");
        if starts_file {
            if collecting {
                break;
            }
            let matched = line
                .strip_prefix("*** Add File: ")
                .or_else(|| line.strip_prefix("*** Update File: "))
                .or_else(|| line.strip_prefix("*** Delete File: "))
                .is_some_and(|path| path.trim() == patch_path);
            collecting = matched;
            continue;
        }
        if collecting && line.starts_with("*** End Patch") {
            break;
        }
        if collecting {
            lines.push(line.to_string());
        }
    }
    collecting.then_some(lines)
}

fn added_file_content(section: &[String]) -> anyhow::Result<String> {
    let mut lines = Vec::new();
    for line in section {
        if line.starts_with("@@") {
            continue;
        }
        let Some(content) = line.strip_prefix('+') else {
            anyhow::bail!("add file patch contains a non-added line");
        };
        lines.push(content.to_string());
    }
    Ok(join_patch_lines(lines, true))
}

fn updated_file_content(original: &str, section: &[String]) -> anyhow::Result<String> {
    let (original_lines, trailing_newline) = split_patch_text(original);
    let mut output = Vec::new();
    let mut index = 0usize;
    for hunk in update_hunks(section) {
        let anchor = find_hunk_anchor(&original_lines, index, hunk)?;
        output.extend(original_lines.iter().take(anchor).skip(index).cloned());
        index = anchor;
        for line in hunk {
            if line.starts_with("@@") {
                continue;
            }
            if let Some(expected) = line.strip_prefix(' ') {
                let Some(actual) = original_lines.get(index) else {
                    anyhow::bail!("patch context exceeds original file");
                };
                if actual != expected {
                    anyhow::bail!("patch context does not match original file");
                }
                output.push(actual.clone());
                index += 1;
            } else if let Some(expected) = line.strip_prefix('-') {
                let Some(actual) = original_lines.get(index) else {
                    anyhow::bail!("patch removal exceeds original file");
                };
                if actual != expected {
                    anyhow::bail!("patch removal does not match original file");
                }
                index += 1;
            } else if let Some(added) = line.strip_prefix('+') {
                output.push(added.to_string());
            }
        }
    }
    output.extend(original_lines.into_iter().skip(index));
    Ok(join_patch_lines(output, trailing_newline))
}

fn update_hunks(section: &[String]) -> Vec<&[String]> {
    let mut hunks = Vec::new();
    let mut start = 0usize;
    let mut saw_header = false;
    for (index, line) in section.iter().enumerate() {
        if line.starts_with("@@") {
            if saw_header && start < index {
                hunks.push(&section[start..index]);
            }
            saw_header = true;
            start = index + 1;
        }
    }
    if start < section.len() {
        hunks.push(&section[start..]);
    }
    if hunks.is_empty() && !section.is_empty() {
        hunks.push(section);
    }
    hunks
}

fn find_hunk_anchor(
    original_lines: &[String],
    start_index: usize,
    hunk: &[String],
) -> anyhow::Result<usize> {
    let expected = hunk
        .iter()
        .filter_map(|line| {
            line.strip_prefix(' ')
                .or_else(|| line.strip_prefix('-'))
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    if expected.is_empty() {
        return Ok(start_index);
    }
    for candidate in start_index..=original_lines.len() {
        if hunk_matches_at(original_lines, candidate, &expected) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("patch hunk does not match original file")
}

fn hunk_matches_at(original_lines: &[String], start_index: usize, expected: &[String]) -> bool {
    if start_index + expected.len() > original_lines.len() {
        return false;
    }
    original_lines[start_index..start_index + expected.len()] == *expected
}

fn split_patch_text(value: &str) -> (Vec<String>, bool) {
    let trailing_newline = value.ends_with('\n');
    let lines = if value.is_empty() {
        Vec::new()
    } else {
        value
            .trim_end_matches('\n')
            .split('\n')
            .map(|line| line.trim_end_matches('\r').to_string())
            .collect()
    };
    (lines, trailing_newline)
}

fn join_patch_lines(lines: Vec<String>, trailing_newline: bool) -> String {
    let mut value = lines.join("\n");
    if trailing_newline && !value.is_empty() {
        value.push('\n');
    }
    value
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

fn reject_internal_state_target(cwd: &Path, target: &Path) -> anyhow::Result<()> {
    let state_root = cwd.join(".safeguard");
    let state_root = if state_root.exists() {
        state_root.canonicalize()?
    } else {
        state_root
    };
    let target = if target.exists() {
        target.canonicalize()?
    } else {
        target.to_path_buf()
    };
    if target.starts_with(&state_root) {
        anyhow::bail!("patch target is inside Safeguard internal state");
    }
    Ok(())
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

fn preview(command: &str) -> String {
    const MAX: usize = 160;
    if command.chars().count() <= MAX {
        command.to_string()
    } else {
        format!("{}...", command.chars().take(MAX).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::enforce_explicit_contract;
    use super::expected_result_matches;
    use super::extract_patch;
    use super::handle_recover_cli;
    use super::implicit_contract;
    use super::is_risky_shell_write;
    use super::patch_targets;
    use super::plan_patch_files;
    use super::prepare_guarded_pending;
    use super::read_pending;
    use super::run_required_validations;
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
    fn preview_is_utf8_safe() {
        let command = "Ж".repeat(200);
        let value = super::preview(&command);
        assert!(value.ends_with("..."));
        assert_eq!(value.trim_end_matches("...").chars().count(), 160);
    }

    #[test]
    fn pre_tool_use_apply_patch_missing_tool_use_id_is_denied() {
        let fixture = Fixture::new("pre_tool_use_apply_patch_missing_tool_use_id_is_denied");
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
        let request = super::HookRequest {
            cwd: root.to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: Some("apply_patch".to_string()),
            tool_input: serde_json::json!({ "cmd": command }),
            tool_response: serde_json::Value::Null,
            tool_use_id: None,
        };

        let output = super::pre_tool_use(&request);

        assert!(pre_tool_use_denied(&output));
        assert!(read_pending(root, "unknown-tool-use").is_ok_and(|pending| pending.is_none()));
    }

    #[test]
    fn post_tool_use_missing_tool_use_id_is_not_bare_continue() {
        let fixture = Fixture::new("post_tool_use_missing_tool_use_id_is_not_bare_continue");
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let request = super::HookRequest {
            cwd: root.to_string(),
            hook_event_name: "PostToolUse".to_string(),
            tool_name: Some("apply_patch".to_string()),
            tool_input: serde_json::Value::Null,
            tool_response: serde_json::json!({ "isError": false }),
            tool_use_id: None,
        };

        let output = super::post_tool_use(&request);

        assert_ne!(output, serde_json::json!({ "continue": true }));
        assert_eq!(
            output
                .get("hookSpecificOutput")
                .and_then(|value| value.get("hookEventName"))
                .and_then(serde_json::Value::as_str),
            Some("PostToolUse")
        );
        assert_eq!(count_files(state_root(root).join("receipts"), "json"), 0);
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
        let receipt_path = write_execution_receipt(
            &pending,
            super::ReceiptOutcome {
                status: safeguard_protocol::ReceiptStatus::Accepted,
                expected_result_verified: true,
                validations_passed: true,
                rollback_completed: None,
                completion_error: None,
            },
            1,
            Vec::new(),
            Vec::new(),
        );
        assert!(receipt_path.as_ref().is_ok_and(|path| path.exists()));
        let first_hash = receipt_path
            .as_ref()
            .ok()
            .and_then(|path| receipt_field(path, "receipt_hash"));
        let second_receipt_path = write_execution_receipt(
            &pending,
            super::ReceiptOutcome {
                status: safeguard_protocol::ReceiptStatus::Accepted,
                expected_result_verified: true,
                validations_passed: true,
                rollback_completed: None,
                completion_error: None,
            },
            1,
            Vec::new(),
            Vec::new(),
        );
        let previous_hash = second_receipt_path
            .as_ref()
            .ok()
            .and_then(|path| receipt_field(path, "previous_receipt_hash"));
        assert!(first_hash.is_some());
        assert_eq!(previous_hash, first_hash);
        assert_ne!(receipt_path.ok(), second_receipt_path.ok());
        assert_eq!(count_files(state_root(root).join("receipts"), "json"), 2);
        assert_eq!(count_files(state_root(root).join("evidence"), "json"), 2);
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
    fn post_tool_failure_rolls_back_transaction() {
        let fixture = Fixture::new("post_tool_failure_rolls_back_transaction");
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
        let pending = match prepare_guarded_pending(
            root,
            "unit-failed-post",
            "Bash",
            "bash_apply_patch",
            files,
        ) {
            Ok(pending) => pending,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert!(write_pending(&pending).is_ok());
        assert!(std::fs::write(&file, "beta").is_ok());

        let request = super::HookRequest {
            cwd: root.to_string(),
            hook_event_name: "PostToolUse".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: serde_json::json!({ "command": command }),
            tool_response: serde_json::json!({ "isError": true }),
            tool_use_id: Some("unit-failed-post".to_string()),
        };
        let output = super::post_tool_use(&request);

        assert_eq!(
            output.get("continue").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(std::fs::read_to_string(&file).is_ok_and(|value| value == "alpha"));
        assert_eq!(count_files(state_root(root).join("locks"), "lock"), 0);
        assert_eq!(
            count_files(state_root(root).join("transactions"), "json"),
            0
        );
        let receipt = first_receipt(root);
        assert_eq!(
            receipt
                .as_ref()
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("rolled_back")
        );
    }

    #[test]
    fn accepted_post_tool_use_writes_prepared_then_accepted_receipts() {
        let fixture = Fixture::new("accepted_post_tool_use_writes_prepared_then_accepted_receipts");
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
        let pending = match prepare_guarded_pending(
            root,
            "unit-accepted-post",
            "Bash",
            "bash_apply_patch",
            files,
        ) {
            Ok(pending) => pending,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert!(write_pending(&pending).is_ok());
        assert!(std::fs::write(&file, "beta").is_ok());

        let request = super::HookRequest {
            cwd: root.to_string(),
            hook_event_name: "PostToolUse".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: serde_json::json!({ "command": command }),
            tool_response: serde_json::json!({ "isError": false }),
            tool_use_id: Some("unit-accepted-post".to_string()),
        };
        let output = super::post_tool_use(&request);

        assert_eq!(
            output.get("continue").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            receipt_statuses(root),
            vec!["prepared".to_string(), "accepted".to_string()]
        );
        assert_eq!(count_files(state_root(root).join("evidence"), "json"), 1);
        assert_eq!(
            count_files(state_root(root).join("transactions"), "json"),
            0
        );
        assert!(read_pending(root, "unit-accepted-post").is_ok_and(|pending| pending.is_none()));
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
            expected_after_blake3: None,
            patch_blake3: None,
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
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let attempted = vec![super::PendingFile {
            path: other.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let contract =
            implicit_contract(root, "contract-deny", "Bash", "bash_apply_patch", &declared);
        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &attempted, contract);
        assert!(enforced.is_err());
    }

    #[test]
    fn plans_expected_after_digest_for_update_patch() {
        let fixture = Fixture::new("plans_expected_after_digest_for_update_patch");
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
        let files = plan_patch_files(root, command);
        assert!(files.as_ref().is_ok_and(|files| files.len() == 1));
        let expected = safeguard_core::blake3_hex(b"beta").as_hex().to_string();
        assert_eq!(
            files
                .ok()
                .and_then(|mut files| files.pop())
                .and_then(|file| file.expected_after_blake3),
            Some(expected)
        );
    }

    #[test]
    fn plans_expected_after_digest_for_middle_hunk() {
        let fixture = Fixture::new("plans_expected_after_digest_for_middle_hunk");
        let file = fixture.root.join("a.txt");
        assert!(std::fs::write(&file, "one\ntwo\nthree\n").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let command = r#"apply_patch <<'PATCH'
*** Begin Patch
*** Update File: a.txt
@@
 two
-three
+THREE
*** End Patch
PATCH"#;
        let files = plan_patch_files(root, command);
        assert!(files.as_ref().is_ok_and(|files| files.len() == 1));
        let expected = safeguard_core::blake3_hex(b"one\ntwo\nTHREE\n")
            .as_hex()
            .to_string();
        assert_eq!(
            files
                .ok()
                .and_then(|mut files| files.pop())
                .and_then(|file| file.expected_after_blake3),
            Some(expected)
        );
    }

    #[test]
    fn rejects_patch_target_inside_internal_state() {
        let fixture = Fixture::new("rejects_patch_target_inside_internal_state");
        let internal_dir = fixture.root.join(".safeguard");
        assert!(std::fs::create_dir_all(&internal_dir).is_ok());
        assert!(std::fs::write(internal_dir.join("audit.jsonl"), "alpha").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let command = r#"apply_patch <<'PATCH'
*** Begin Patch
*** Update File: .safeguard/audit.jsonl
@@
-alpha
+beta
*** End Patch
PATCH"#;
        let planned = plan_patch_files(root, command);
        assert!(planned.is_err());
    }

    #[test]
    fn failed_required_validation_is_not_accepted() {
        let fixture = Fixture::new("failed_required_validation_is_not_accepted");
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let pending = super::PendingEdit {
            tool_use_id: "validation-fail".to_string(),
            tool_name: "Bash".to_string(),
            cwd: root.to_string(),
            command_kind: "bash_apply_patch".to_string(),
            contract_id: "validation-fail".to_string(),
            transaction_id: "validation-fail".to_string(),
            transaction_record_path: String::new(),
            contract_hash: None,
            required_validations: vec!["this-command-should-not-exist-safeguard".to_string()],
            files: Vec::new(),
        };

        let (validations, passed, changed_workspace) = run_required_validations(&pending, true);

        assert!(!passed);
        assert!(!changed_workspace);
        assert_eq!(validations.len(), 1);
        assert_eq!(
            validations[0].status,
            safeguard_protocol::ValidationStatus::Failed
        );
    }

    #[test]
    fn validation_side_effect_is_not_accepted() {
        let fixture = Fixture::new("validation_side_effect_is_not_accepted");
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        #[cfg(windows)]
        let command = "Set-Content -NoNewline side-effect.txt beta";
        #[cfg(not(windows))]
        let command = "printf beta > side-effect.txt";
        let pending = super::PendingEdit {
            tool_use_id: "validation-side-effect".to_string(),
            tool_name: "Bash".to_string(),
            cwd: root.to_string(),
            command_kind: "bash_apply_patch".to_string(),
            contract_id: "validation-side-effect".to_string(),
            transaction_id: "validation-side-effect".to_string(),
            transaction_record_path: String::new(),
            contract_hash: None,
            required_validations: vec![command.to_string()],
            files: Vec::new(),
        };

        let (validations, passed, changed_workspace) = run_required_validations(&pending, true);

        assert!(!passed);
        assert!(changed_workspace);
        assert_eq!(validations.len(), 1);
        assert_eq!(
            validations[0].status,
            safeguard_protocol::ValidationStatus::Failed
        );
    }

    #[test]
    fn validation_side_effect_keeps_transaction_partial() {
        let fixture = Fixture::new("validation_side_effect_keeps_transaction_partial");
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
        let mut pending = match prepare_guarded_pending(
            root,
            "validation-side-effect-post",
            "Bash",
            "bash_apply_patch",
            files,
        ) {
            Ok(pending) => pending,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        let side_effect_path = fixture.root.join("side-effect.txt");
        #[cfg(windows)]
        let validation = format!(
            "Set-Content -NoNewline -LiteralPath '{}' -Value beta",
            side_effect_path.display()
        );
        #[cfg(not(windows))]
        let validation = format!("printf beta > '{}'", side_effect_path.display());
        pending.required_validations = vec![validation];
        assert!(write_pending(&pending).is_ok());
        assert!(std::fs::write(&file, "beta").is_ok());

        let request = super::HookRequest {
            cwd: root.to_string(),
            hook_event_name: "PostToolUse".to_string(),
            tool_name: Some("Bash".to_string()),
            tool_input: serde_json::json!({ "command": command }),
            tool_response: serde_json::json!({ "isError": false }),
            tool_use_id: Some("validation-side-effect-post".to_string()),
        };
        let output = super::post_tool_use(&request);

        assert_eq!(
            output.get("continue").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(std::fs::read_to_string(&file).is_ok_and(|value| value == "alpha"));
        assert!(side_effect_path.exists());
        assert!(
            read_pending(root, "validation-side-effect-post")
                .is_ok_and(|pending| pending.is_some())
        );
        assert_eq!(
            count_files(state_root(root).join("transactions"), "json"),
            1
        );
        let receipt = first_receipt(root);
        assert_eq!(
            receipt
                .as_ref()
                .and_then(|value| value.get("status"))
                .and_then(serde_json::Value::as_str),
            Some("partial")
        );
    }

    #[test]
    fn docs_style_contract_allows_patch_modify_operation() {
        let fixture = Fixture::new("docs_style_contract_allows_patch_modify_operation");
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
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let mut contract = safeguard_protocol::ExecutionContract::v0_1("docs-style");
        contract.capabilities.push(safeguard_protocol::Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec![file.display().to_string()],
            constraints: Default::default(),
        });
        contract
            .expected_changes
            .files
            .push(safeguard_protocol::ExpectedFileChange {
                path: file.display().to_string(),
                operation: safeguard_protocol::FileOperation::Modify,
                before_digest: None,
                expected_diff_digest: None,
                requirement: Default::default(),
            });

        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_ok());
    }

    #[test]
    fn explicit_contract_rejects_missing_required_expected_change() {
        let fixture = Fixture::new("explicit_contract_rejects_missing_required_expected_change");
        let file = fixture.root.join("a.txt");
        let other = fixture.root.join("b.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        assert!(std::fs::write(&other, "bravo").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let files = vec![super::PendingFile {
            path: file.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let mut contract = safeguard_protocol::ExecutionContract::v0_1("missing-required");
        contract.capabilities.push(safeguard_protocol::Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec![file.display().to_string(), other.display().to_string()],
            constraints: Default::default(),
        });
        for path in [file.display().to_string(), other.display().to_string()] {
            contract
                .expected_changes
                .files
                .push(safeguard_protocol::ExpectedFileChange {
                    path,
                    operation: safeguard_protocol::FileOperation::Modify,
                    before_digest: None,
                    expected_diff_digest: None,
                    requirement: safeguard_protocol::ExpectedChangeRequirement::Required,
                });
        }

        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_err());
    }

    #[test]
    fn explicit_contract_allows_missing_optional_expected_change() {
        let fixture = Fixture::new("explicit_contract_allows_missing_optional_expected_change");
        let file = fixture.root.join("a.txt");
        let other = fixture.root.join("b.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        assert!(std::fs::write(&other, "bravo").is_ok());
        let Some(root) = fixture.root.to_str() else {
            assert_eq!(fixture.root.display().to_string(), "");
            return;
        };
        let files = vec![super::PendingFile {
            path: file.display().to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: None,
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let mut contract = safeguard_protocol::ExecutionContract::v0_1("missing-optional");
        contract.capabilities.push(safeguard_protocol::Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec![file.display().to_string(), other.display().to_string()],
            constraints: Default::default(),
        });
        contract
            .expected_changes
            .files
            .push(safeguard_protocol::ExpectedFileChange {
                path: file.display().to_string(),
                operation: safeguard_protocol::FileOperation::Modify,
                before_digest: None,
                expected_diff_digest: None,
                requirement: safeguard_protocol::ExpectedChangeRequirement::Required,
            });
        contract
            .expected_changes
            .files
            .push(safeguard_protocol::ExpectedFileChange {
                path: other.display().to_string(),
                operation: safeguard_protocol::FileOperation::Modify,
                before_digest: None,
                expected_diff_digest: None,
                requirement: safeguard_protocol::ExpectedChangeRequirement::Optional,
            });

        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_ok());
    }

    #[test]
    fn explicit_contract_enforces_allowed_write_roots() {
        let fixture = Fixture::new("explicit_contract_enforces_allowed_write_roots");
        let allowed_dir = fixture.root.join("allowed");
        let denied_dir = fixture.root.join("denied");
        assert!(std::fs::create_dir_all(&allowed_dir).is_ok());
        assert!(std::fs::create_dir_all(&denied_dir).is_ok());
        let file = denied_dir.join("a.txt");
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
            expected_after_blake3: None,
            patch_blake3: None,
        }];
        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert(
            "allowed_write_roots".to_string(),
            serde_json::json!(["allowed/**"]),
        );
        let mut contract = safeguard_protocol::ExecutionContract::v0_1("allowed-roots");
        contract.capabilities.push(safeguard_protocol::Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec![file.display().to_string()],
            constraints,
        });
        contract
            .expected_changes
            .files
            .push(safeguard_protocol::ExpectedFileChange {
                path: file.display().to_string(),
                operation: safeguard_protocol::FileOperation::Modify,
                before_digest: None,
                expected_diff_digest: None,
                requirement: safeguard_protocol::ExpectedChangeRequirement::Required,
            });

        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_err());
    }

    #[test]
    fn explicit_contract_rejects_wrong_expected_diff_digest() {
        let fixture = Fixture::new("explicit_contract_rejects_wrong_expected_diff_digest");
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
            expected_after_blake3: Some(safeguard_core::blake3_hex(b"beta").as_hex().to_string()),
            patch_blake3: Some("actual-patch-digest".to_string()),
        }];
        let mut contract = safeguard_protocol::ExecutionContract::v0_1("wrong-diff");
        contract.capabilities.push(safeguard_protocol::Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec![file.display().to_string()],
            constraints: Default::default(),
        });
        contract
            .expected_changes
            .files
            .push(safeguard_protocol::ExpectedFileChange {
                path: file.display().to_string(),
                operation: safeguard_protocol::FileOperation::Modify,
                before_digest: None,
                expected_diff_digest: Some("expected-different-digest".to_string()),
                requirement: Default::default(),
            });

        let enforced =
            enforce_explicit_contract(root, "Bash", "bash_apply_patch", &files, contract);
        assert!(enforced.is_err());
    }

    #[test]
    fn verifies_expected_file_results() {
        let modified = super::PendingFile {
            path: "a.txt".to_string(),
            operation: "update".to_string(),
            existed_before: true,
            before_blake3: Some("old".to_string()),
            expected_after_blake3: Some("new".to_string()),
            patch_blake3: None,
        };
        assert!(expected_result_matches(&modified, true, Some("new")));
        assert!(!expected_result_matches(&modified, true, Some("old")));

        let added = super::PendingFile {
            path: "b.txt".to_string(),
            operation: "add".to_string(),
            existed_before: false,
            before_blake3: None,
            expected_after_blake3: None,
            patch_blake3: None,
        };
        assert!(expected_result_matches(&added, true, Some("new")));
        assert!(!expected_result_matches(&added, false, None));

        let deleted = super::PendingFile {
            path: "c.txt".to_string(),
            operation: "delete".to_string(),
            existed_before: true,
            before_blake3: Some("old".to_string()),
            expected_after_blake3: None,
            patch_blake3: None,
        };
        assert!(expected_result_matches(&deleted, false, None));
        assert!(!expected_result_matches(&deleted, true, Some("old")));
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

    fn pre_tool_use_denied(output: &serde_json::Value) -> bool {
        output
            .get("hookSpecificOutput")
            .and_then(|value| value.get("permissionDecision"))
            .and_then(serde_json::Value::as_str)
            == Some("deny")
    }

    fn receipt_field(path: &PathBuf, field: &str) -> Option<String> {
        let bytes = std::fs::read(path).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    }

    fn first_receipt(root: &str) -> Option<serde_json::Value> {
        let path = std::fs::read_dir(state_root(root).join("receipts"))
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))?;
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn receipt_statuses(root: &str) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(state_root(root).join("receipts")) else {
            return Vec::new();
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .filter_map(|path| {
                let bytes = std::fs::read(path).ok()?;
                let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .collect()
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
