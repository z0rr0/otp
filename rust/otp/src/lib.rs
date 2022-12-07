//! # OTP crate
//!
//! `otp` is a crate for generating one-time passwords
//! ans secret keys for that purpose.
use data_encoding::BASE32;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate a random base32 string of the given length.
///
/// Parameters:
/// - `size`: a number of bytes to generate
///
/// # Examples
///
/// ```
/// use otp::secret;
///
/// let s: String = secret(16);
/// assert!(s.len() > 0);
/// ```
pub fn secret(size: usize) -> String {
    let size = if size == 0 { 64 } else { size };

    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);

    BASE32.encode(&key).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret() {
        let first = secret(20);
        println!("first value = {}", first);
        assert!(first.len() > 0);
        assert!(first.chars().all(|c| c.is_uppercase() || c.is_digit(10)));

        let second = secret(20);
        println!("second value = {}", second);
        assert!(second.len() > 0);
        assert!(second.chars().all(|c| c.is_uppercase() || c.is_digit(10)));

        assert!(first.ne(&second));
    }
}
