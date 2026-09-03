//! Bearer-token check. Same model as `dag node serve`: compare SHA-256
//! digests with no early exit, so timing does not leak the token.

use sha2::{Digest, Sha256};

/// `true` when `offered` is exactly `expected`.
pub fn token_matches(expected: &str, offered: &str) -> bool {
    digests_match(&digest(expected.as_bytes()), &digest(offered.as_bytes()))
}

/// Pull a bearer token out of an `Authorization` header value.
pub fn bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn digests_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_tokens_match_and_unequal_do_not() {
        assert!(token_matches("secret", "secret"));
        assert!(!token_matches("secret", "Secret"));
        assert!(!token_matches("secret", "secre"));
    }

    #[test]
    fn bearer_strips_the_scheme() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("abc"), None);
    }
}
