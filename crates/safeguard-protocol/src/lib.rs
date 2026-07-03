//! Shared Safeguard execution protocol schemas.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

/// Current protocol schema version.
pub const SCHEMA_VERSION_0_1: &str = "0.1";

/// Authority object that defines what execution is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContract {
    /// Schema version for compatibility checks.
    pub schema_version: String,
    /// Stable correlation key across planning, execution, and evidence.
    pub contract_id: String,
    /// Optional parent contract id.
    pub parent_contract_id: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
    /// Optional expiry timestamp.
    pub expires_at: Option<String>,
    /// Contract issuer.
    pub issuer: ContractIssuer,
    /// Contract subject.
    pub subject: ContractSubject,
    /// Workspace scope.
    pub workspace: WorkspaceScope,
    /// Allowed capabilities.
    pub capabilities: Vec<Capability>,
    /// Denied resource globs or exact paths.
    pub denied_resources: Vec<String>,
    /// Expected changes.
    pub expected_changes: ExpectedChanges,
    /// Required validations.
    pub required_validations: Vec<RequiredValidation>,
    /// Required invariant names.
    pub invariants: Vec<String>,
    /// Extension fields for future compatible readers.
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl ExecutionContract {
    /// Construct a minimal v0.1 contract.
    pub fn v0_1(contract_id: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_0_1.to_string(),
            contract_id: contract_id.into(),
            parent_contract_id: None,
            created_at: String::new(),
            expires_at: None,
            issuer: ContractIssuer {
                system: "safeguard".to_string(),
                run_id: None,
            },
            subject: ContractSubject {
                agent_id: None,
                model: None,
            },
            workspace: WorkspaceScope {
                root: ".".to_string(),
                allowed_roots: vec![".".to_string()],
            },
            capabilities: Vec::new(),
            denied_resources: Vec::new(),
            expected_changes: ExpectedChanges { files: Vec::new() },
            required_validations: Vec::new(),
            invariants: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }
}

/// Contract issuer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractIssuer {
    /// Issuing system, such as safeguard or cabal.
    pub system: String,
    /// Optional run id.
    pub run_id: Option<String>,
}

/// Contract subject metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSubject {
    /// Optional agent id.
    pub agent_id: Option<String>,
    /// Optional model id.
    pub model: Option<String>,
}

/// Workspace scope for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceScope {
    /// Primary workspace root.
    pub root: String,
    /// Allowed roots.
    pub allowed_roots: Vec<String>,
}

/// Capability granted by an execution contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Tool name, such as apply_patch or Bash.
    pub tool: String,
    /// Operation name, such as modify or execute.
    pub operation: String,
    /// Resource identifiers.
    pub resources: Vec<String>,
    /// Capability constraints.
    #[serde(default)]
    pub constraints: BTreeMap<String, serde_json::Value>,
}

/// Expected changes section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedChanges {
    /// Expected file changes.
    pub files: Vec<ExpectedFileChange>,
}

/// Expected file change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedFileChange {
    /// File path.
    pub path: String,
    /// Operation name.
    pub operation: FileOperation,
    /// Optional before digest.
    pub before_digest: Option<String>,
    /// Optional expected diff digest.
    pub expected_diff_digest: Option<String>,
}

/// File operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    /// File is added.
    Add,
    /// File is modified.
    Modify,
    /// File is deleted.
    Delete,
}

/// Required validation command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredValidation {
    /// Command to run.
    pub command: String,
}

/// Safeguard evidence object for one contract execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Schema version for compatibility checks.
    pub schema_version: String,
    /// Contract id.
    pub contract_id: String,
    /// Receipt id.
    pub receipt_id: String,
    /// Receipt status.
    pub status: ReceiptStatus,
    /// Start timestamp.
    pub started_at: String,
    /// Completion timestamp.
    pub completed_at: String,
    /// Executor metadata.
    pub executor: ReceiptExecutor,
    /// Observed operations.
    pub observed_operations: Vec<ObservedOperation>,
    /// Changed files.
    pub changed_files: Vec<ChangedFile>,
    /// Validation results.
    pub validations: Vec<ValidationResult>,
    /// Policy violations.
    pub policy_violations: Vec<PolicyViolation>,
    /// Invariant results.
    pub invariants: Vec<InvariantResult>,
    /// Receipt hash.
    pub receipt_hash: Option<String>,
    /// Previous receipt hash.
    pub previous_receipt_hash: Option<String>,
    /// Optional signature.
    pub signature: Option<String>,
    /// Extension fields for future compatible readers.
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// Receipt status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    /// Contract execution was accepted.
    Accepted,
    /// Contract execution was rejected.
    Rejected,
    /// Contract execution partially completed.
    Partial,
    /// Contract execution was rolled back.
    RolledBack,
}

/// Receipt executor metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptExecutor {
    /// Executor system.
    pub system: String,
    /// Executor version.
    pub version: String,
}

/// Operation observed during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedOperation {
    /// Tool name.
    pub tool: String,
    /// Operation.
    pub operation: String,
    /// Optional path.
    pub path: Option<String>,
    /// Optional command.
    pub command: Option<String>,
}

/// Changed file evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFile {
    /// File path.
    pub path: String,
    /// Operation.
    pub operation: FileOperation,
    /// Optional before digest.
    pub before_digest: Option<String>,
    /// Optional after digest.
    pub after_digest: Option<String>,
    /// Optional diff digest.
    pub diff_digest: Option<String>,
}

/// Validation command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Command that was run.
    pub command: String,
    /// Status such as passed, failed, or not_run.
    pub status: ValidationStatus,
}

/// Validation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Validation passed.
    Passed,
    /// Validation failed.
    Failed,
    /// Validation was not run.
    NotRun,
}

/// Policy violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Violation code.
    pub code: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Invariant check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantResult {
    /// Invariant name.
    pub name: String,
    /// Invariant status.
    pub status: InvariantStatus,
}

/// Invariant status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    /// Invariant passed.
    Passed,
    /// Invariant failed.
    Failed,
}

/// Compact MemoryX evidence anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryxEvidence {
    /// Schema version.
    pub schema_version: String,
    /// Contract id.
    pub contract_id: String,
    /// Receipt id.
    pub receipt_id: String,
    /// Claim summarized for memory.
    pub claim: String,
    /// Evidence basis.
    pub basis: EvidenceBasis,
    /// Evidence summary.
    pub summary: EvidenceSummary,
}

/// Evidence basis hashes and paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBasis {
    /// Contract hash.
    pub contract_hash: String,
    /// Receipt hash.
    pub receipt_hash: String,
    /// Source paths.
    pub source_paths: Vec<String>,
}

/// Compact evidence summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Number of changed files.
    pub changed_files_count: usize,
    /// Number of passed validations.
    pub validations_passed: usize,
    /// Number of policy violations.
    pub policy_violations_count: usize,
}

#[cfg(test)]
mod tests {
    use super::Capability;
    use super::ExecutionContract;
    use super::FileOperation;
    use super::ReceiptExecutor;
    use super::ReceiptStatus;

    #[test]
    fn contract_serializes_version_and_contract_id() {
        let mut contract = ExecutionContract::v0_1("task-1");
        contract.capabilities.push(Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec!["README.md".to_string()],
            constraints: Default::default(),
        });
        let json = serde_json::to_string(&contract);
        assert!(json.is_ok());
        let json = match json {
            Ok(json) => json,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert!(json.contains(r#""schema_version":"0.1""#));
        assert!(json.contains(r#""contract_id":"task-1""#));
    }

    #[test]
    fn receipt_status_uses_snake_case() {
        let receipt = super::ExecutionReceipt {
            schema_version: "0.1".to_string(),
            contract_id: "task-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            status: ReceiptStatus::RolledBack,
            started_at: String::new(),
            completed_at: String::new(),
            executor: ReceiptExecutor {
                system: "safeguard".to_string(),
                version: "0.1.0".to_string(),
            },
            observed_operations: Vec::new(),
            changed_files: vec![super::ChangedFile {
                path: "README.md".to_string(),
                operation: FileOperation::Modify,
                before_digest: None,
                after_digest: None,
                diff_digest: None,
            }],
            validations: Vec::new(),
            policy_violations: Vec::new(),
            invariants: Vec::new(),
            receipt_hash: None,
            previous_receipt_hash: None,
            signature: None,
            extensions: Default::default(),
        };

        let json = serde_json::to_string(&receipt);
        assert!(json.is_ok());
        let json = match json {
            Ok(json) => json,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        assert!(json.contains(r#""status":"rolled_back""#));
    }
}
