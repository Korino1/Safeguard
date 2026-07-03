//! Fast hashing helpers used by guarded edit verification.

/// BLAKE3 digest rendered as lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Blake3Digest(String);

impl Blake3Digest {
    /// Returns the lowercase hexadecimal digest string.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Compute BLAKE3 over raw bytes and return lowercase hexadecimal.
pub fn blake3_hex(bytes: &[u8]) -> Blake3Digest {
    Blake3Digest(blake3::hash(bytes).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::blake3_hex;

    #[test]
    fn blake3_empty_matches_known_value() {
        let digest = blake3_hex(b"");
        assert_eq!(
            digest.as_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn blake3_text_matches_known_value() {
        let digest = blake3_hex(b"safeguard");
        assert_eq!(
            digest.as_hex(),
            "4078ab255d53fee42959677bf682e5a70f5cc2ab38f48f41e67be1b64ee9dde5"
        );
    }
}
