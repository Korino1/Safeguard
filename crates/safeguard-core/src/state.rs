//! External state-root selection for Safeguard runtime evidence.

use std::path::Path;
use std::path::PathBuf;

use crate::blake3_hex;

/// Return the external state directory dedicated to one canonical workspace.
///
/// `SAFEGUARD_STATE_DIR` may select a managed base directory, but a relative
/// value or a base inside the workspace is ignored so guarded state never
/// falls back into agent-editable project files.
pub fn workspace_state_root(workspace: impl AsRef<Path>) -> PathBuf {
    let workspace = canonical_workspace(workspace.as_ref());
    let base = configured_state_base(&workspace).unwrap_or_else(default_state_base);
    let workspace_id = workspace_id(&workspace);
    base.join("Safeguard").join("workspaces").join(workspace_id)
}

/// Stable opaque identity for a canonical workspace path.
pub fn workspace_id(workspace: impl AsRef<Path>) -> String {
    let workspace = canonical_workspace(workspace.as_ref());
    blake3_hex(workspace.to_string_lossy().as_bytes())
        .as_hex()
        .to_string()
}

/// Root containing locally trusted authority public keys.
pub fn authority_state_root() -> PathBuf {
    default_state_base().join("Safeguard").join("authorities")
}

/// Legacy in-workspace state location retained only for denial/migration checks.
pub fn legacy_workspace_state_root(workspace: impl AsRef<Path>) -> PathBuf {
    canonical_workspace(workspace.as_ref()).join(".safeguard")
}

fn canonical_workspace(workspace: &Path) -> PathBuf {
    workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf())
}

fn configured_state_base(workspace: &Path) -> Option<PathBuf> {
    let value = std::env::var_os("SAFEGUARD_STATE_DIR")?;
    let candidate = PathBuf::from(value);
    if !candidate.is_absolute() || candidate.starts_with(workspace) {
        return None;
    }
    Some(candidate)
}

#[cfg(windows)]
fn default_state_base() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .map(|home| home.join("AppData").join("Local"))
        })
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(not(windows))]
fn default_state_base() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local").join("state"))
        })
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(test)]
mod tests {
    use super::legacy_workspace_state_root;
    use super::workspace_state_root;

    #[test]
    fn state_root_is_outside_workspace_and_stable() {
        let workspace = std::env::temp_dir().join("safeguard-state-root-test");
        let _ = std::fs::create_dir_all(&workspace);
        let first = workspace_state_root(&workspace);
        let second = workspace_state_root(&workspace);

        assert_eq!(first, second);
        assert!(!first.starts_with(&workspace));
        assert_ne!(first, legacy_workspace_state_root(&workspace));

        let _ = std::fs::remove_dir_all(workspace);
    }
}
