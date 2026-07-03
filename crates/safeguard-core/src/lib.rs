//! Core primitives for Safeguard guarded editing.

pub mod file;
pub mod hash;
pub mod text;

pub use file::FileEditError;
pub use file::FileReplacementPlan;
pub use file::apply_text_file_replacement;
pub use file::plan_text_file_replacement;
pub use hash::Blake3Digest;
pub use hash::blake3_hex;
pub use text::PlannedReplacement;
pub use text::TextMatchError;
pub use text::plan_unique_replacement;
