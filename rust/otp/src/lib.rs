//! # OTP crate
//!
//! `otp` is a crate for generating one-time passwords
//! ans secret keys for that purpose.
use std::error::Error;
use std::io;
use std::io::Cursor;
use std::time::SystemTime;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

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
/// assert!(!s.is_empty());
/// ```
pub fn secret(size: usize) -> String {
    let size = if size == 0 { 64 } else { size };

    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);

    BASE32.encode(&key)
}

// Add counter_bytes to hash mac and return prepared result.
fn hash_result(mut mac: HmacSha1, counter_bytes: &[u8]) -> io::Result<u32> {
    mac.update(counter_bytes);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let offset = code_bytes[code_bytes.len() - 1] & 0xF;
    let offset = offset as usize;

    Cursor::new(&code_bytes[offset..offset + 4]).read_u32::<BigEndian>()
}

/// Generate a one-time password.
///
/// Parameters:
/// - `secret`: a secret key
/// - `seed`: a seed timestamp or None to use current time
///
/// # Examples
///
/// ```
/// use std::error::Error;
/// use otp::code;
///
/// let code: Result<String, Box<dyn Error>> = code("PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH", Some(0));
/// assert!(code.is_ok());
/// assert_eq!(code.unwrap(), "038572");
/// ```
pub fn code(secret: &str, seed: Option<u64>) -> Result<String, Box<dyn Error>> {
    let counter = match seed {
        Some(n) => n,
        None => match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs() / 30,
            Err(err) => return Err(Box::new(err)),
        },
    };

    let secret = secret.to_uppercase();
    let secret = match BASE32.decode(secret.as_bytes()) {
        Ok(key) => key,
        Err(err) => return Err(Box::new(err)),
    };

    let mut counter_bytes: Vec<u8> = Vec::with_capacity(8);
    if let Err(err) = counter_bytes.write_u64::<BigEndian>(counter) {
        return Err(Box::new(err));
    }

    let hash_code = match HmacSha1::new_from_slice(&secret) {
        Ok(mac) => hash_result(mac, &counter_bytes),
        Err(err) => return Err(Box::new(err)),
    };

    let code = match hash_code {
        Ok(n) => format!("{:06}", n & 0x7FFFFFFF),
        Err(err) => return Err(Box::new(err)),
    };

    let code = code[code.len() - 6..].to_string();
    Ok(code)
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use std::time::Instant;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use regex::Regex;

    use super::*;

    struct CodeTest {
        secret: String,
        expected: String,
        seed: u64,
    }

    fn datetime_to_u64(dt: DateTime<Utc>) -> u64 {
        (dt.timestamp() as u64) / 30
    }

    #[test]
    fn test_secret() {
        // base32 pattern https://en.wikipedia.org/wiki/Base32
        let rg = Regex::new(r"^[A-Z2-7=]+$");
        assert!(rg.is_ok());

        let rg = rg.unwrap();
        let value = secret(20);

        println!("secret value = {}", value);
        assert!(rg.is_match(&value));
    }

    #[test]
    fn failed_code() {
        let code = code("AB8*#", Some(0));
        assert!(code.is_err());
        println!("failed code error = {}", code.unwrap_err());
    }

    #[test]
    fn test_code() {
        let start = Utc.with_ymd_and_hms(2020, 1, 2, 3, 0, 0).unwrap();

        let cases = vec![
            CodeTest {
                secret: String::from("PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH"),
                expected: String::from("038572"),
                seed: 0,
            },
            CodeTest {
                secret: String::from("PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH"),
                expected: String::from("300755"),
                seed: datetime_to_u64(start),
            },
            CodeTest {
                secret: String::from("PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH"),
                expected: String::from("300755"),
                seed: datetime_to_u64(start.add(Duration::seconds(10))),
            },
            CodeTest {
                secret: String::from("PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH"),
                expected: String::from("602895"),
                seed: datetime_to_u64(start.add(Duration::seconds(40))),
            },
            CodeTest {
                secret: String::from("AJIS553K23JWRJ4J3GDL7B6PBRWKL4AP"),
                expected: String::from("239244"),
                seed: datetime_to_u64(start),
            },
        ];
        for case in cases {
            let result = code(&case.secret, Some(case.seed));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), case.expected);
        }
    }

    #[test]
    fn benchmark_code() {
        // benchmark tests are still unstable, so use simple time measurement
        let values = vec![
            "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
            "NL5VXOSCGA4FKG7FXWJLKQ3OUH6XLQI6",
            "QT4LBO53X3Y3U5QWDJBSUD6TZIIYUQ3V",
        ];
        let expected = vec!["038572", "501675", "213936"];

        let n = values.len() as u64;
        let mut j;

        let mut min_time: u128 = u128::MAX;
        let mut start;
        let mut duration;

        for i in 0..100_000 {
            j = i % n;
            let ju = j as usize;

            start = Instant::now();
            let r = code(values[ju], Some(j));
            duration = start.elapsed().as_nanos();

            assert!(r.is_ok());
            assert_eq!(r.unwrap(), expected[ju]);

            if duration < min_time {
                min_time = duration;
            }
        }

        println!("benchmark: min {min_time} ns/call");
    }
}
