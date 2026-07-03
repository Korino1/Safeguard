//! Guarded text-file replacement planning and application.

use std::fmt;
use std::path::Path;
use std::path::PathBuf;

use crate::Blake3Digest;
use crate::PlannedReplacement;
use crate::TextMatchError;
use crate::blake3_hex;
use crate::plan_unique_replacement;

/// Full internal plan for a text-file replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReplacementPlan {
    /// Target path exactly as resolved by the caller.
    pub path: PathBuf,
    /// Deterministic replacement plan.
    pub replacement: PlannedReplacement,
    /// Internal digest of the file before replacement.
    pub before_blake3: Blake3Digest,
    /// Internal digest of the file after replacement.
    pub after_blake3: Blake3Digest,
}

/// Errors that prevent a guarded file edit.
#[derive(Debug)]
pub enum FileEditError {
    /// File could not be read as UTF-8 text.
    Read {
        /// Target path.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// The requested text replacement is not deterministic.
    Match(TextMatchError),
    /// Target path has no parent directory.
    MissingParent {
        /// Target path.
        path: PathBuf,
    },
    /// Temporary file write failed.
    WriteTemp {
        /// Temporary path.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// Existing target could not be moved aside.
    MoveOriginal {
        /// Target path.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// Replacement file could not be moved into place.
    MoveReplacement {
        /// Target path.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
    /// Backup cleanup failed after a successful replacement.
    CleanupBackup {
        /// Backup path.
        path: PathBuf,
        /// Source I/O error.
        source: std::io::Error,
    },
}

impl fmt::Display for FileEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Match(err) => write!(f, "replacement rejected: {err:?}"),
            Self::MissingParent { path } => {
                write!(f, "target path has no parent: {}", path.display())
            }
            Self::WriteTemp { path, source } => {
                write!(f, "failed to write temp file {}: {source}", path.display())
            }
            Self::MoveOriginal { path, source } => {
                write!(f, "failed to move original {}: {source}", path.display())
            }
            Self::MoveReplacement { path, source } => {
                write!(
                    f,
                    "failed to move replacement into {}: {source}",
                    path.display()
                )
            }
            Self::CleanupBackup { path, source } => {
                write!(f, "failed to clean backup {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for FileEditError {}

/// Plan a text-file replacement, including internal before/after digests.
pub fn plan_text_file_replacement(
    path: impl AsRef<Path>,
    old_fragment: &str,
    new_fragment: &str,
) -> Result<FileReplacementPlan, FileEditError> {
    let path = path.as_ref().to_path_buf();
    let input = std::fs::read_to_string(&path).map_err(|source| FileEditError::Read {
        path: path.clone(),
        source,
    })?;
    let replacement = plan_unique_replacement(&input, old_fragment, new_fragment)
        .map_err(FileEditError::Match)?;
    let before_blake3 = blake3_hex(input.as_bytes());
    let after_blake3 = blake3_hex(replacement.output.as_bytes());

    Ok(FileReplacementPlan {
        path,
        replacement,
        before_blake3,
        after_blake3,
    })
}

/// Apply a previously planned replacement to disk.
pub fn apply_text_file_replacement(plan: &FileReplacementPlan) -> Result<(), FileEditError> {
    let Some(parent) = plan.path.parent() else {
        return Err(FileEditError::MissingParent {
            path: plan.path.clone(),
        });
    };

    let temp_path = unique_sidecar_path(&plan.path, "safeguard-tmp");
    let backup_path = unique_sidecar_path(&plan.path, "safeguard-backup");

    std::fs::write(&temp_path, plan.replacement.output.as_bytes()).map_err(|source| {
        FileEditError::WriteTemp {
            path: temp_path.clone(),
            source,
        }
    })?;

    std::fs::rename(&plan.path, &backup_path).map_err(|source| FileEditError::MoveOriginal {
        path: plan.path.clone(),
        source,
    })?;

    if let Err(source) = std::fs::rename(&temp_path, &plan.path) {
        let _ = std::fs::rename(&backup_path, &plan.path);
        return Err(FileEditError::MoveReplacement {
            path: plan.path.clone(),
            source,
        });
    }

    std::fs::remove_file(&backup_path).map_err(|source| FileEditError::CleanupBackup {
        path: backup_path,
        source,
    })?;

    let _ = parent;
    Ok(())
}

fn unique_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| "file".into());
    file_name.push(format!(".{suffix}.{}", std::process::id()));
    path.with_file_name(file_name)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::apply_text_file_replacement;
    use super::plan_text_file_replacement;

    #[test]
    fn plans_and_applies_file_replacement() {
        let path = test_path("plans_and_applies_file_replacement.txt");
        let write_result = std::fs::write(&path, "alpha beta gamma");
        assert!(write_result.is_ok());

        let plan = match plan_text_file_replacement(&path, "beta", "BETA") {
            Ok(plan) => plan,
            Err(err) => {
                assert_eq!(format!("{err}"), "");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };

        assert_ne!(plan.before_blake3, plan.after_blake3);
        assert_eq!(plan.replacement.start, 6);

        let apply_result = apply_text_file_replacement(&plan);
        assert!(apply_result.is_ok());

        let output = match std::fs::read_to_string(&path) {
            Ok(output) => output,
            Err(err) => {
                assert_eq!(err.to_string(), "");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };

        assert_eq!(output, "alpha BETA gamma");
        let _ = std::fs::remove_file(&path);
    }

    fn test_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("safeguard-core-{}-{name}", std::process::id()));
        path
    }
}
