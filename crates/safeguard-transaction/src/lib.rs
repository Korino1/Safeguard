//! Internal transaction primitives for Safeguard guarded edits.

use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;

use safeguard_protocol::ExecutionContract;

/// Transaction identifier supplied by the caller or orchestrator layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(String);

impl TransactionId {
    /// Creates a filesystem-safe transaction id.
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TransactionError::InvalidTransactionId);
        }
        if !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(TransactionError::InvalidTransactionId);
        }
        Ok(Self(value))
    }

    /// Returns the raw transaction id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A file target guarded by compare-and-swap semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionTarget {
    /// Target path, absolute or workspace-relative.
    pub path: PathBuf,
    /// Expected BLAKE3 digest for existing files.
    pub expected_blake3: Option<String>,
}

/// A file accepted into an active transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedTarget {
    /// Canonical or planned absolute target path.
    pub path: PathBuf,
    /// Stable lock key derived from the target path.
    pub lock_key: String,
    /// Whether the file existed when the transaction started.
    pub existed_before: bool,
    /// Observed BLAKE3 digest when the transaction started.
    pub before_blake3: Option<String>,
    /// Rollback snapshot path for existing files.
    pub rollback_path: Option<PathBuf>,
}

/// Active transaction guard. Dropping it releases lock files.
#[derive(Debug)]
pub struct TransactionGuard {
    id: TransactionId,
    state_root: PathBuf,
    targets: Vec<LockedTarget>,
    lock_paths: Vec<PathBuf>,
}

impl TransactionGuard {
    /// Transaction id.
    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    /// Locked targets accepted by this transaction.
    pub fn targets(&self) -> &[LockedTarget] {
        &self.targets
    }

    /// Persist a transaction record for recovery/audit layers.
    pub fn persist_record(&self) -> Result<PathBuf, TransactionError> {
        let transactions_dir = self.state_root.join("transactions");
        std::fs::create_dir_all(&transactions_dir).map_err(|source| TransactionError::Io {
            operation: "create transactions directory",
            path: transactions_dir.clone(),
            source,
        })?;

        let record_path = transactions_dir.join(format!("{}.json", self.id.as_str()));
        let started_at = unix_timestamp()?;
        let record = TransactionRecord {
            transaction_id: self.id.as_str().to_string(),
            started_at,
            targets: self.targets.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&record).map_err(TransactionError::SerializeRecord)?;
        std::fs::write(&record_path, bytes).map_err(|source| TransactionError::Io {
            operation: "write transaction record",
            path: record_path.clone(),
            source,
        })?;
        Ok(record_path)
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        for path in &self.lock_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionRecord {
    transaction_id: String,
    started_at: u64,
    targets: Vec<LockedTarget>,
}

/// Summary of transaction records left after an interrupted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    /// Path to the transaction record.
    pub record_path: PathBuf,
}

/// Transaction layer errors.
#[derive(Debug)]
pub enum TransactionError {
    /// Transaction id is empty or not filesystem-safe.
    InvalidTransactionId,
    /// Target path escaped the configured workspace root.
    PathOutsideWorkspace {
        /// Target path.
        path: PathBuf,
        /// Workspace root.
        workspace_root: PathBuf,
    },
    /// Existing target is a symlink.
    SymlinkTarget {
        /// Target path.
        path: PathBuf,
    },
    /// Existing file digest does not match the expected digest.
    StaleDigest {
        /// Target path.
        path: PathBuf,
        /// Expected BLAKE3 digest.
        expected: String,
        /// Actual BLAKE3 digest.
        actual: String,
    },
    /// Another active transaction holds the target lock.
    LockHeld {
        /// Target path.
        path: PathBuf,
        /// Lock file path.
        lock_path: PathBuf,
    },
    /// I/O failure.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Related path.
        path: PathBuf,
        /// Source error.
        source: std::io::Error,
    },
    /// JSON serialization failed.
    SerializeRecord(serde_json::Error),
    /// System time is earlier than Unix epoch.
    Time(std::time::SystemTimeError),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransactionId => write!(f, "invalid transaction id"),
            Self::PathOutsideWorkspace {
                path,
                workspace_root,
            } => write!(
                f,
                "target {} is outside workspace root {}",
                path.display(),
                workspace_root.display()
            ),
            Self::SymlinkTarget { path } => {
                write!(f, "target {} is a symlink", path.display())
            }
            Self::StaleDigest {
                path,
                expected,
                actual,
            } => write!(
                f,
                "target {} digest changed before commit: expected {expected}, actual {actual}",
                path.display()
            ),
            Self::LockHeld { path, lock_path } => write!(
                f,
                "target {} is already locked by {}",
                path.display(),
                lock_path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "{operation} failed for {}: {source}", path.display()),
            Self::SerializeRecord(source) => write!(f, "failed to serialize transaction: {source}"),
            Self::Time(source) => write!(f, "system time is before unix epoch: {source}"),
        }
    }
}

impl std::error::Error for TransactionError {}

/// Begin a guarded transaction by locking targets and validating before-digests.
pub fn begin_transaction(
    workspace_root: impl AsRef<Path>,
    state_root: impl AsRef<Path>,
    id: TransactionId,
    targets: &[TransactionTarget],
) -> Result<TransactionGuard, TransactionError> {
    let workspace_root = canonicalize_existing(workspace_root.as_ref(), "canonicalize workspace")?;
    let state_root = state_root.as_ref().to_path_buf();
    let locks_dir = state_root.join("locks");
    let rollback_dir = state_root.join("rollback").join(id.as_str());

    std::fs::create_dir_all(&locks_dir).map_err(|source| TransactionError::Io {
        operation: "create locks directory",
        path: locks_dir.clone(),
        source,
    })?;
    std::fs::create_dir_all(&rollback_dir).map_err(|source| TransactionError::Io {
        operation: "create rollback directory",
        path: rollback_dir.clone(),
        source,
    })?;

    let mut accepted_targets = Vec::with_capacity(targets.len());
    let mut lock_paths = Vec::with_capacity(targets.len());

    for target in targets {
        let resolved = resolve_target(&workspace_root, &target.path)?;

        let lock_key = lock_key_for_path(&resolved);
        let lock_path = locks_dir.join(format!("{lock_key}.lock"));
        create_lock(&lock_path, &id, &resolved)?;
        lock_paths.push(lock_path.clone());

        let existed_before = resolved.exists();
        let before_blake3 = if existed_before {
            let digest = digest_file(&resolved)?;
            if let Some(expected) = &target.expected_blake3
                && &digest != expected
            {
                return Err(TransactionError::StaleDigest {
                    path: resolved,
                    expected: expected.clone(),
                    actual: digest,
                });
            }
            Some(digest)
        } else {
            None
        };

        let rollback_path = if existed_before {
            let rollback_path = rollback_dir.join(format!("{lock_key}.rollback"));
            std::fs::copy(&resolved, &rollback_path).map_err(|source| TransactionError::Io {
                operation: "write rollback snapshot",
                path: rollback_path.clone(),
                source,
            })?;
            Some(rollback_path)
        } else {
            None
        };

        accepted_targets.push(LockedTarget {
            path: resolved,
            lock_key,
            existed_before,
            before_blake3,
            rollback_path,
        });
    }

    Ok(TransactionGuard {
        id,
        state_root,
        targets: accepted_targets,
        lock_paths,
    })
}

/// Build a transaction id from a shared execution contract.
pub fn transaction_id_from_contract(
    contract: &ExecutionContract,
) -> Result<TransactionId, TransactionError> {
    TransactionId::new(contract.contract_id.clone())
}

/// Convert shared execution contract expected files into transaction targets.
pub fn targets_from_contract(contract: &ExecutionContract) -> Vec<TransactionTarget> {
    contract
        .expected_changes
        .files
        .iter()
        .map(|file| TransactionTarget {
            path: PathBuf::from(&file.path),
            expected_blake3: file.before_digest.clone(),
        })
        .collect()
}

/// List transaction records that may need recovery handling after a crash.
pub fn recovery_candidates(
    state_root: impl AsRef<Path>,
) -> Result<Vec<RecoveryCandidate>, TransactionError> {
    let dir = state_root.as_ref().join("transactions");
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|source| TransactionError::Io {
        operation: "read transactions directory",
        path: dir.clone(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| TransactionError::Io {
            operation: "read transaction directory entry",
            path: dir.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            candidates.push(RecoveryCandidate { record_path: path });
        }
    }
    candidates.sort_by(|left, right| left.record_path.cmp(&right.record_path));
    Ok(candidates)
}

fn canonicalize_existing(
    path: &Path,
    operation: &'static str,
) -> Result<PathBuf, TransactionError> {
    path.canonicalize().map_err(|source| TransactionError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn resolve_target(workspace_root: &Path, target_path: &Path) -> Result<PathBuf, TransactionError> {
    let candidate = if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        workspace_root.join(target_path)
    };

    let resolved = if candidate.exists() {
        reject_symlink_if_present(&candidate)?;
        canonicalize_existing(&candidate, "canonicalize target")?
    } else {
        let Some(parent) = candidate.parent() else {
            return Err(TransactionError::PathOutsideWorkspace {
                path: candidate,
                workspace_root: workspace_root.to_path_buf(),
            });
        };
        let parent = canonicalize_existing(parent, "canonicalize target parent")?;
        let Some(file_name) = candidate.file_name() else {
            return Err(TransactionError::PathOutsideWorkspace {
                path: candidate,
                workspace_root: workspace_root.to_path_buf(),
            });
        };
        parent.join(file_name)
    };

    if !resolved.starts_with(workspace_root) {
        return Err(TransactionError::PathOutsideWorkspace {
            path: resolved,
            workspace_root: workspace_root.to_path_buf(),
        });
    }

    Ok(resolved)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), TransactionError> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|source| TransactionError::Io {
        operation: "read symlink metadata",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TransactionError::SymlinkTarget {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn create_lock(
    lock_path: &Path,
    id: &TransactionId,
    target_path: &Path,
) -> Result<(), TransactionError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(TransactionError::LockHeld {
                path: target_path.to_path_buf(),
                lock_path: lock_path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(TransactionError::Io {
                operation: "create target lock",
                path: lock_path.to_path_buf(),
                source,
            });
        }
    };
    writeln!(file, "transaction_id={}", id.as_str()).map_err(|source| TransactionError::Io {
        operation: "write target lock",
        path: lock_path.to_path_buf(),
        source,
    })
}

fn digest_file(path: &Path) -> Result<String, TransactionError> {
    let bytes = std::fs::read(path).map_err(|source| TransactionError::Io {
        operation: "read target for digest",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(safeguard_core::blake3_hex(&bytes).as_hex().to_string())
}

fn lock_key_for_path(path: &Path) -> String {
    safeguard_core::blake3_hex(path.display().to_string().as_bytes()).as_hex()[..24].to_string()
}

fn unix_timestamp() -> Result<u64, TransactionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(TransactionError::Time)
}

#[allow(dead_code)]
fn create_empty_file(path: &Path) -> Result<File, TransactionError> {
    File::create(path).map_err(|source| TransactionError::Io {
        operation: "create file",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use safeguard_core::blake3_hex;
    use safeguard_protocol::ExecutionContract;
    use safeguard_protocol::ExpectedFileChange;
    use safeguard_protocol::FileOperation;

    use super::TransactionError;
    use super::TransactionId;
    use super::TransactionTarget;
    use super::begin_transaction;
    use super::recovery_candidates;
    use super::targets_from_contract;
    use super::transaction_id_from_contract;

    #[test]
    fn begins_transaction_and_writes_rollback_snapshot() {
        let fixture = Fixture::new("begins_transaction_and_writes_rollback_snapshot");
        let file = fixture.workspace.join("a.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());
        let expected = blake3_hex(b"alpha").as_hex().to_string();

        let id = match TransactionId::new("tx-1") {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };
        let guard = match begin_transaction(
            &fixture.workspace,
            &fixture.state,
            id,
            &[TransactionTarget {
                path: PathBuf::from("a.txt"),
                expected_blake3: Some(expected),
            }],
        ) {
            Ok(guard) => guard,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };

        assert_eq!(guard.targets().len(), 1);
        let rollback_path = guard.targets()[0].rollback_path.clone();
        assert!(rollback_path.as_ref().is_some_and(|path| path.exists()));
        let record = guard.persist_record();
        assert!(record.is_ok());
        let candidates = recovery_candidates(&fixture.state);
        assert!(candidates.is_ok_and(|items| items.len() == 1));
    }

    #[test]
    fn rejects_stale_digest() {
        let fixture = Fixture::new("rejects_stale_digest");
        let file = fixture.workspace.join("a.txt");
        assert!(std::fs::write(&file, "changed").is_ok());
        let id = match TransactionId::new("tx-2") {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                return;
            }
        };

        let err = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            id,
            &[TransactionTarget {
                path: PathBuf::from("a.txt"),
                expected_blake3: Some(blake3_hex(b"old").as_hex().to_string()),
            }],
        );

        assert!(matches!(err, Err(TransactionError::StaleDigest { .. })));
    }

    #[test]
    fn rejects_concurrent_lock() {
        let fixture = Fixture::new("rejects_concurrent_lock");
        let file = fixture.workspace.join("a.txt");
        assert!(std::fs::write(&file, "alpha").is_ok());

        let first = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            valid_id("tx-3a"),
            &[TransactionTarget {
                path: PathBuf::from("a.txt"),
                expected_blake3: None,
            }],
        );
        assert!(first.is_ok());

        let second = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            valid_id("tx-3b"),
            &[TransactionTarget {
                path: PathBuf::from("a.txt"),
                expected_blake3: None,
            }],
        );

        assert!(matches!(second, Err(TransactionError::LockHeld { .. })));
    }

    #[test]
    fn rejects_path_outside_workspace() {
        let fixture = Fixture::new("rejects_path_outside_workspace");
        let outside = fixture.root.join("outside.txt");
        assert!(std::fs::write(&outside, "alpha").is_ok());

        let err = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            valid_id("tx-4"),
            &[TransactionTarget {
                path: outside,
                expected_blake3: None,
            }],
        );

        assert!(matches!(
            err,
            Err(TransactionError::PathOutsideWorkspace { .. })
        ));
    }

    #[test]
    fn converts_execution_contract_to_transaction_inputs() {
        let mut contract = ExecutionContract::v0_1("task-1842");
        contract.expected_changes.files.push(ExpectedFileChange {
            path: "src/lib.rs".to_string(),
            operation: FileOperation::Modify,
            before_digest: Some("digest-before".to_string()),
            expected_diff_digest: None,
        });

        let id = transaction_id_from_contract(&contract);
        assert!(id.is_ok());
        let targets = targets_from_contract(&contract);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, PathBuf::from("src/lib.rs"));
        assert_eq!(
            targets[0].expected_blake3,
            Some("digest-before".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() {
        let fixture = Fixture::new("rejects_symlink_target");
        let real = fixture.workspace.join("real.txt");
        let link = fixture.workspace.join("link.txt");
        assert!(std::fs::write(&real, "alpha").is_ok());
        assert!(std::os::unix::fs::symlink(&real, &link).is_ok());

        let err = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            valid_id("tx-5"),
            &[TransactionTarget {
                path: PathBuf::from("link.txt"),
                expected_blake3: None,
            }],
        );

        assert!(matches!(err, Err(TransactionError::SymlinkTarget { .. })));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_symlink_target() {
        let fixture = Fixture::new("rejects_symlink_target");
        let real = fixture.workspace.join("real.txt");
        let link = fixture.workspace.join("link.txt");
        assert!(std::fs::write(&real, "alpha").is_ok());
        let symlink_result = std::os::windows::fs::symlink_file(&real, &link);
        if symlink_result.is_err() {
            return;
        }

        let err = begin_transaction(
            &fixture.workspace,
            &fixture.state,
            valid_id("tx-5"),
            &[TransactionTarget {
                path: PathBuf::from("link.txt"),
                expected_blake3: None,
            }],
        );

        assert!(matches!(err, Err(TransactionError::SymlinkTarget { .. })));
    }

    fn valid_id(value: &str) -> TransactionId {
        match TransactionId::new(value) {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                fallback_id()
            }
        }
    }

    fn fallback_id() -> TransactionId {
        match TransactionId::new("safe") {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                loop {
                    std::thread::park();
                }
            }
        }
    }

    struct Fixture {
        root: PathBuf,
        workspace: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "safeguard-transaction-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let workspace = root.join("workspace");
            let state = root.join("state");
            assert!(std::fs::create_dir_all(&workspace).is_ok());
            assert!(std::fs::create_dir_all(&state).is_ok());
            Self {
                root,
                workspace,
                state,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
