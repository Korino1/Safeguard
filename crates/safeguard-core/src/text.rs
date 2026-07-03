//! Text matching and replacement planning.

/// Replacement plan produced after locating exactly one target fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedReplacement {
    /// Byte offset where the old fragment starts.
    pub start: usize,
    /// Byte offset where the old fragment ends.
    pub end: usize,
    /// Number of removed bytes.
    pub removed_bytes: usize,
    /// Number of inserted bytes.
    pub inserted_bytes: usize,
    /// Full planned output text.
    pub output: String,
}

/// Errors that prevent a deterministic text edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextMatchError {
    /// Empty target fragments are ambiguous by definition.
    EmptyNeedle,
    /// The expected old fragment was not found.
    Missing,
    /// The expected old fragment appears more than once.
    Ambiguous {
        /// Number of matching fragments found in the input.
        matches: usize,
    },
}

/// Plan a replacement only if `old_fragment` appears exactly once in `input`.
pub fn plan_unique_replacement(
    input: &str,
    old_fragment: &str,
    new_fragment: &str,
) -> Result<PlannedReplacement, TextMatchError> {
    if old_fragment.is_empty() {
        return Err(TextMatchError::EmptyNeedle);
    }

    let mut matches = input.match_indices(old_fragment);
    let Some((start, _)) = matches.next() else {
        return Err(TextMatchError::Missing);
    };
    if matches.next().is_some() {
        let count = input.match_indices(old_fragment).count();
        return Err(TextMatchError::Ambiguous { matches: count });
    }

    let end = start + old_fragment.len();
    let mut output = String::with_capacity(input.len() - old_fragment.len() + new_fragment.len());
    output.push_str(&input[..start]);
    output.push_str(new_fragment);
    output.push_str(&input[end..]);

    Ok(PlannedReplacement {
        start,
        end,
        removed_bytes: old_fragment.len(),
        inserted_bytes: new_fragment.len(),
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::TextMatchError;
    use super::plan_unique_replacement;

    #[test]
    fn plans_unique_replacement() {
        let plan = match plan_unique_replacement("alpha beta gamma", "beta", "BETA") {
            Ok(plan) => plan,
            Err(err) => {
                assert_eq!(format!("{err:?}"), "");
                return;
            }
        };

        assert_eq!(plan.start, 6);
        assert_eq!(plan.end, 10);
        assert_eq!(plan.output, "alpha BETA gamma");
    }

    #[test]
    fn rejects_missing_fragment() {
        let err = match plan_unique_replacement("alpha beta", "gamma", "G") {
            Ok(_) => {
                assert_eq!("unexpected success", "");
                return;
            }
            Err(err) => err,
        };

        assert_eq!(err, TextMatchError::Missing);
    }

    #[test]
    fn rejects_ambiguous_fragment() {
        let err = match plan_unique_replacement("alpha beta beta", "beta", "B") {
            Ok(_) => {
                assert_eq!("unexpected success", "");
                return;
            }
            Err(err) => err,
        };

        assert_eq!(err, TextMatchError::Ambiguous { matches: 2 });
    }

    #[test]
    fn rejects_empty_fragment() {
        let err = match plan_unique_replacement("alpha", "", "x") {
            Ok(_) => {
                assert_eq!("unexpected success", "");
                return;
            }
            Err(err) => err,
        };

        assert_eq!(err, TextMatchError::EmptyNeedle);
    }
}
