//! Bearer-secret helpers over aws-lc-rs: random tokens and their stored hashes.
//! Used for client secrets now, and for session tokens and authorization codes.
//! Secrets are 256-bit random values, so a plain SHA-256 is an adequate stored form
//! (no password-hashing KDF needed: there is nothing low-entropy to brute-force).

use aws_lc_rs::{constant_time, digest, error::Unspecified, rand};

/// 32 bytes from the system CSPRNG, hex encoded.
pub fn random_token() -> Result<String, Unspecified> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes)?;
    Ok(hex(&bytes))
}

pub fn sha256_hex(value: &str) -> String {
    hex(digest::digest(&digest::SHA256, value.as_bytes()).as_ref())
}

/// Constant-time comparison of `candidate`'s hash with a stored hash.
pub fn hash_matches(candidate: &str, stored_hash: &str) -> bool {
    constant_time::verify_slices_are_equal(sha256_hex(candidate).as_bytes(), stored_hash.as_bytes())
        .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_tokens_are_256_bit_and_unique() {
        let (a, b) = (random_token().unwrap(), random_token().unwrap());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_matches_only_the_original() {
        let stored = sha256_hex("secret");
        assert!(hash_matches("secret", &stored));
        assert!(!hash_matches("secreT", &stored));
        assert!(!hash_matches("", &stored));
    }
}
