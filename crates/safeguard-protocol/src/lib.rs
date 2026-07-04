//! Shared Safeguard execution protocol schemas.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
    /// Whether this expected change is mandatory for this contract.
    #[serde(default)]
    pub requirement: ExpectedChangeRequirement,
}

/// Requirement level for an expected file change.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedChangeRequirement {
    /// The change must be observed for the contract to be accepted.
    #[default]
    Required,
    /// The change is allowed but not required.
    Optional,
}

/// Contract that passed local validation and can be used for authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContract {
    contract: ExecutionContract,
}

impl VerifiedContract {
    /// Validate a parsed contract for a workspace root.
    pub fn verify(
        contract: ExecutionContract,
        workspace_root: impl AsRef<Path>,
    ) -> Result<Self, ContractValidationError> {
        validate_contract_schema(&contract)?;
        validate_contract_expiry(&contract)?;
        validate_contract_issuer(&contract)?;
        validate_contract_subject(&contract)?;
        validate_contract_workspace(&contract, workspace_root.as_ref())?;
        validate_capability_constraints(&contract)?;
        validate_contract_invariants(&contract)?;
        Ok(Self { contract })
    }

    /// Return the validated contract.
    pub fn into_inner(self) -> ExecutionContract {
        self.contract
    }

    /// Borrow the validated contract.
    pub fn contract(&self) -> &ExecutionContract {
        &self.contract
    }
}

/// Why a contract failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractValidationError {
    /// Unsupported schema version.
    UnsupportedSchemaVersion(String),
    /// Contract has expired.
    Expired,
    /// Expiry timestamp is not parseable by this implementation.
    UnsupportedExpiryFormat(String),
    /// Issuer is not trusted by the local policy.
    UntrustedIssuer(String),
    /// Workspace root is not this workspace.
    WorkspaceRootMismatch {
        /// Expected canonical workspace root.
        expected: PathBuf,
        /// Contract-declared canonical workspace root.
        actual: PathBuf,
    },
    /// Allowed root is outside this workspace.
    AllowedRootOutsideWorkspace {
        /// Contract-declared allowed root.
        root: PathBuf,
        /// Canonical workspace root.
        workspace: PathBuf,
    },
    /// Constraint key is unknown and therefore denied.
    UnknownConstraint(String),
    /// Constraint value has an unsupported type.
    InvalidConstraint {
        /// Constraint key.
        key: String,
        /// Validation failure reason.
        reason: String,
    },
    /// Constraint is known but not enforceable by this implementation.
    UnsupportedExecutableConstraint(String),
    /// Invariant is known only as a declaration and has no evaluator.
    UnsupportedInvariant(String),
    /// Subject binding is declared but not verified by trusted runtime context.
    UnsupportedSubjectBinding(String),
}

impl fmt::Display for ContractValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported contract schema version {version}")
            }
            Self::Expired => write!(f, "contract has expired"),
            Self::UnsupportedExpiryFormat(value) => {
                write!(f, "unsupported contract expiry format {value}")
            }
            Self::UntrustedIssuer(issuer) => write!(f, "untrusted contract issuer {issuer}"),
            Self::WorkspaceRootMismatch { expected, actual } => write!(
                f,
                "contract workspace root {} does not match {}",
                actual.display(),
                expected.display()
            ),
            Self::AllowedRootOutsideWorkspace { root, workspace } => write!(
                f,
                "contract allowed root {} is outside workspace {}",
                root.display(),
                workspace.display()
            ),
            Self::UnknownConstraint(key) => write!(f, "unknown mandatory constraint {key}"),
            Self::InvalidConstraint { key, reason } => {
                write!(f, "invalid constraint {key}: {reason}")
            }
            Self::UnsupportedExecutableConstraint(key) => {
                write!(f, "unsupported executable constraint {key}")
            }
            Self::UnsupportedInvariant(name) => {
                write!(f, "unsupported contract invariant {name}")
            }
            Self::UnsupportedSubjectBinding(name) => {
                write!(f, "unsupported contract subject binding {name}")
            }
        }
    }
}

impl std::error::Error for ContractValidationError {}

fn validate_contract_schema(contract: &ExecutionContract) -> Result<(), ContractValidationError> {
    if contract.schema_version == SCHEMA_VERSION_0_1 {
        Ok(())
    } else {
        Err(ContractValidationError::UnsupportedSchemaVersion(
            contract.schema_version.clone(),
        ))
    }
}

fn validate_contract_expiry(contract: &ExecutionContract) -> Result<(), ContractValidationError> {
    let Some(expires_at) = contract.expires_at.as_deref() else {
        return Ok(());
    };
    let expires = parse_contract_timestamp(expires_at)
        .ok_or_else(|| ContractValidationError::UnsupportedExpiryFormat(expires_at.to_string()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    if expires <= now {
        Err(ContractValidationError::Expired)
    } else {
        Ok(())
    }
}

fn validate_contract_issuer(contract: &ExecutionContract) -> Result<(), ContractValidationError> {
    match contract.issuer.system.as_str() {
        "safeguard" | "cabal" => Ok(()),
        value => Err(ContractValidationError::UntrustedIssuer(value.to_string())),
    }
}

fn validate_contract_subject(contract: &ExecutionContract) -> Result<(), ContractValidationError> {
    if contract.subject.agent_id.is_some() {
        return Err(ContractValidationError::UnsupportedSubjectBinding(
            "agent_id".to_string(),
        ));
    }
    if contract.subject.model.is_some() {
        return Err(ContractValidationError::UnsupportedSubjectBinding(
            "model".to_string(),
        ));
    }
    Ok(())
}

fn validate_contract_workspace(
    contract: &ExecutionContract,
    workspace_root: &Path,
) -> Result<(), ContractValidationError> {
    let workspace_root =
        canonicalize_or_join(workspace_root, ".").unwrap_or_else(|| workspace_root.to_path_buf());
    let contract_root = canonicalize_or_join(&workspace_root, &contract.workspace.root)
        .ok_or_else(|| ContractValidationError::WorkspaceRootMismatch {
            expected: workspace_root.clone(),
            actual: PathBuf::from(&contract.workspace.root),
        })?;
    if contract_root != workspace_root {
        return Err(ContractValidationError::WorkspaceRootMismatch {
            expected: workspace_root.clone(),
            actual: contract_root,
        });
    }
    for allowed in &contract.workspace.allowed_roots {
        let allowed_root = canonicalize_or_join(&workspace_root, allowed).ok_or_else(|| {
            ContractValidationError::AllowedRootOutsideWorkspace {
                root: PathBuf::from(allowed),
                workspace: workspace_root.clone(),
            }
        })?;
        if !allowed_root.starts_with(&workspace_root) {
            return Err(ContractValidationError::AllowedRootOutsideWorkspace {
                root: allowed_root,
                workspace: workspace_root.clone(),
            });
        }
    }
    Ok(())
}

fn validate_capability_constraints(
    contract: &ExecutionContract,
) -> Result<(), ContractValidationError> {
    for capability in &contract.capabilities {
        for (key, value) in &capability.constraints {
            validate_constraint(key, value)?;
        }
    }
    Ok(())
}

fn validate_constraint(
    key: &str,
    value: &serde_json::Value,
) -> Result<(), ContractValidationError> {
    match key {
        "max_files_changed" => {
            if value.as_u64().is_some() {
                Ok(())
            } else {
                Err(ContractValidationError::InvalidConstraint {
                    key: key.to_string(),
                    reason: "expected unsigned integer".to_string(),
                })
            }
        }
        "network" | "validation_timeout_seconds" => Err(
            ContractValidationError::UnsupportedExecutableConstraint(key.to_string()),
        ),
        "allowed_write_roots" => {
            if value
                .as_array()
                .is_some_and(|items| items.iter().all(|item| item.as_str().is_some()))
            {
                Ok(())
            } else {
                Err(ContractValidationError::InvalidConstraint {
                    key: key.to_string(),
                    reason: "expected string array".to_string(),
                })
            }
        }
        _ => Err(ContractValidationError::UnknownConstraint(key.to_string())),
    }
}

fn validate_contract_invariants(
    contract: &ExecutionContract,
) -> Result<(), ContractValidationError> {
    if let Some(name) = contract.invariants.first() {
        Err(ContractValidationError::UnsupportedInvariant(name.clone()))
    } else {
        Ok(())
    }
}

fn canonicalize_or_join(root: &Path, value: &str) -> Option<PathBuf> {
    let candidate = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        root.join(value)
    };
    if candidate.exists() {
        candidate.canonicalize().ok()
    } else {
        let parent = candidate.parent()?.canonicalize().ok()?;
        let file_name = candidate.file_name()?;
        Some(parent.join(file_name))
    }
}

fn parse_contract_timestamp(value: &str) -> Option<u64> {
    if let Some(raw) = value.strip_prefix("unix:") {
        return raw.parse().ok();
    }
    parse_rfc3339_utc_seconds(value)
}

fn parse_rfc3339_utc_seconds(value: &str) -> Option<u64> {
    let date_time = value.strip_suffix('Z')?;
    let (date, time) = date_time.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let second = time_parts.next()?.parse::<u32>().ok()?;
    if time_parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days as u64 * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
    /// Contract execution is durably prepared but not finally accepted.
    Prepared,
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
    use std::collections::BTreeMap;

    use super::Capability;
    use super::ContractValidationError;
    use super::ExecutionContract;
    use super::FileOperation;
    use super::ReceiptExecutor;
    use super::ReceiptStatus;
    use super::VerifiedContract;

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
    fn verified_contract_rejects_unsupported_schema() {
        let mut contract = ExecutionContract::v0_1("bad-schema");
        contract.schema_version = "9.9".to_string();
        let verified = VerifiedContract::verify(contract, ".");
        assert!(verified.is_err());
    }

    #[test]
    fn verified_contract_rejects_expired_contract() {
        let mut contract = ExecutionContract::v0_1("expired");
        contract.expires_at = Some("unix:1".to_string());
        let verified = VerifiedContract::verify(contract, ".");
        assert!(verified.is_err());
    }

    #[test]
    fn verified_contract_rejects_unknown_constraint() {
        let mut contract = ExecutionContract::v0_1("unknown-constraint");
        let mut constraints = BTreeMap::new();
        constraints.insert("unknown".to_string(), serde_json::json!(true));
        contract.capabilities.push(Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec!["README.md".to_string()],
            constraints,
        });
        let verified = VerifiedContract::verify(contract, ".");
        assert!(verified.is_err());
    }

    #[test]
    fn verified_contract_accepts_enforced_constraints() {
        let mut contract = ExecutionContract::v0_1("known-constraints");
        contract.expires_at = Some("2099-01-01T00:00:00Z".to_string());
        let mut constraints = BTreeMap::new();
        constraints.insert("max_files_changed".to_string(), serde_json::json!(1));
        constraints.insert("allowed_write_roots".to_string(), serde_json::json!(["."]));
        contract.capabilities.push(Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec!["README.md".to_string()],
            constraints,
        });
        let verified = VerifiedContract::verify(contract, ".");
        assert!(verified.is_ok());
    }

    #[test]
    fn verified_contract_rejects_declarative_network_constraint() {
        let mut contract = ExecutionContract::v0_1("network-constraint");
        let mut constraints = BTreeMap::new();
        constraints.insert("network".to_string(), serde_json::json!(false));
        contract.capabilities.push(Capability {
            tool: "Bash".to_string(),
            operation: "execute".to_string(),
            resources: vec!["*".to_string()],
            constraints,
        });
        let verified = VerifiedContract::verify(contract, ".");
        assert_eq!(
            verified,
            Err(ContractValidationError::UnsupportedExecutableConstraint(
                "network".to_string()
            ))
        );
    }

    #[test]
    fn verified_contract_rejects_declarative_validation_timeout_constraint() {
        let mut contract = ExecutionContract::v0_1("validation-timeout");
        let mut constraints = BTreeMap::new();
        constraints.insert(
            "validation_timeout_seconds".to_string(),
            serde_json::json!(30),
        );
        contract.capabilities.push(Capability {
            tool: "apply_patch".to_string(),
            operation: "modify".to_string(),
            resources: vec!["README.md".to_string()],
            constraints,
        });
        let verified = VerifiedContract::verify(contract, ".");
        assert_eq!(
            verified,
            Err(ContractValidationError::UnsupportedExecutableConstraint(
                "validation_timeout_seconds".to_string()
            ))
        );
    }

    #[test]
    fn verified_contract_rejects_unsupported_invariants() {
        let mut contract = ExecutionContract::v0_1("unsupported-invariant");
        contract.invariants.push("no_new_unsafe".to_string());
        let verified = VerifiedContract::verify(contract, ".");
        assert_eq!(
            verified,
            Err(ContractValidationError::UnsupportedInvariant(
                "no_new_unsafe".to_string()
            ))
        );
    }

    #[test]
    fn verified_contract_rejects_unverified_agent_subject() {
        let mut contract = ExecutionContract::v0_1("agent-subject");
        contract.subject.agent_id = Some("agent-1".to_string());
        let verified = VerifiedContract::verify(contract, ".");
        assert_eq!(
            verified,
            Err(ContractValidationError::UnsupportedSubjectBinding(
                "agent_id".to_string()
            ))
        );
    }

    #[test]
    fn verified_contract_rejects_unverified_model_subject() {
        let mut contract = ExecutionContract::v0_1("model-subject");
        contract.subject.model = Some("gpt-5.4-mini".to_string());
        let verified = VerifiedContract::verify(contract, ".");
        assert_eq!(
            verified,
            Err(ContractValidationError::UnsupportedSubjectBinding(
                "model".to_string()
            ))
        );
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
