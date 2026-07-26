use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `data`.
pub fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// True if `haystack` contains the UTF-16LE encoding of `needle`.
pub fn utf16le_contains(haystack: &[u8], needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let encoded: Vec<u8> = needle
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    haystack
        .windows(encoded.len())
        .any(|w| w == encoded.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_is_known() {
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn utf16le_finds_ascii() {
        let mut buf = Vec::new();
        for c in "Hello Northwind Softworks".encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        assert!(utf16le_contains(&buf, "Northwind Softworks"));
        assert!(!utf16le_contains(&buf, "missing"));
    }
}
