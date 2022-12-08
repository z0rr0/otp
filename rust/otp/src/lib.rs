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
/// let s: String = secret(20);
/// assert!(s.len() > 0);
/// ```
pub fn secret(size: usize) -> String {
    let size = if size == 0 { 64 } else { size };

    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);

    BASE32.encode(&key)
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;

    #[test]
    fn test_secret() {
        // base32 pattern https://en.wikipedia.org/wiki/Base32
        let rg = Regex::new(r"^[A-Z2-7=]+$");
        assert!(rg.is_ok());

        let rg = rg.unwrap();
        let value = secret(20);

        println!("first value = {}", value);
        assert!(rg.is_match(&value));
    }
}
