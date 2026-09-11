//! One-time 6-digit claim confirmation code.
//!
//! Attempt counting is process-wide and lives in [`crate::claim::service`], not here.

use std::fmt;

use crate::claim::memory::secure_zero;
use crate::search::rng::get_secure_uniform_u128;

/// Six ASCII digits drawn from kernel entropy. Not `Clone`. `Debug` is always redacted.
pub struct ClaimCode {
    digits: [u8; 6],
}

/// Reasons [`ClaimCode::matches`] (and generation) can refuse an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// The input was not exactly six ASCII digits after trimming.
    Malformed,
    /// Kernel entropy was unavailable.
    Unavailable,
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::Malformed => f.write_str("malformed claim code"),
            CodeError::Unavailable => f.write_str("claim code unavailable"),
        }
    }
}

impl std::error::Error for CodeError {}

impl ClaimCode {
    /// Uniform 6-digit code in `000000..=999999`, leading zeros preserved.
    pub fn generate() -> Result<ClaimCode, CodeError> {
        let n = get_secure_uniform_u128(999_999).map_err(|_| CodeError::Unavailable)?;
        let mut rendered = format!("{n:06}");
        let mut digits = [0u8; 6];
        digits.copy_from_slice(rendered.as_bytes());
        let mut rendered_bytes = std::mem::take(&mut rendered).into_bytes();
        secure_zero(&mut rendered_bytes);
        Ok(ClaimCode { digits })
    }

    /// Decimal digits, only for the notifier that delivers the alert.
    pub(in crate::claim) fn digits_for_alert(&self) -> String {
        String::from_utf8_lossy(&self.digits).into_owned()
    }

    /// Constant-time equality against a trimmed 6-digit input. Does not count attempts.
    pub fn matches(&self, input: &str) -> Result<bool, CodeError> {
        let trimmed = input.trim();
        if trimmed.len() != 6 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CodeError::Malformed);
        }
        let given = trimmed.as_bytes();
        let mut diff = 0u8;
        for i in 0..6 {
            diff |= given[i] ^ self.digits[i];
        }
        Ok(diff == 0)
    }
}

impl fmt::Debug for ClaimCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimCode(<redacted>)")
    }
}

impl Drop for ClaimCode {
    fn drop(&mut self) {
        secure_zero(&mut self.digits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thousand_codes_are_six_digits() {
        for _ in 0..1000 {
            let code = ClaimCode::generate().expect("entropy");
            let digits = code.digits_for_alert();
            assert_eq!(digits.len(), 6);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{digits}");
        }
    }

    #[test]
    fn matches_accepts_the_true_code_and_rejects_a_wrong_one() {
        let code = ClaimCode::generate().expect("entropy");
        let digits = code.digits_for_alert();
        assert_eq!(code.matches(&digits), Ok(true));
        assert_eq!(code.matches(&format!("  {digits}  ")), Ok(true));
        let wrong = if digits == "000000" {
            "000001"
        } else {
            "000000"
        };
        assert_eq!(code.matches(wrong), Ok(false));
    }

    #[test]
    fn matches_rejects_a_difference_in_each_of_the_six_positions() {
        let code = ClaimCode::generate().expect("entropy");
        let digits = code.digits_for_alert();
        for i in 0..6 {
            let mut candidate = digits.as_bytes().to_vec();
            let d = candidate[i] - b'0';
            candidate[i] = b'0' + (d + 1) % 10;
            let wrong = String::from_utf8(candidate).expect("digit");
            assert_eq!(code.matches(&wrong), Ok(false), "position {i}");
        }
    }

    #[test]
    fn matches_reports_malformed_for_non_six_digit_input() {
        let code = ClaimCode::generate().expect("entropy");
        assert_eq!(code.matches("12345"), Err(CodeError::Malformed));
        assert_eq!(code.matches("1234567"), Err(CodeError::Malformed));
        assert_eq!(code.matches("12 456"), Err(CodeError::Malformed));
        assert_eq!(code.matches("abcdef"), Err(CodeError::Malformed));
        assert_eq!(code.matches(""), Err(CodeError::Malformed));
    }

    #[test]
    fn debug_is_redacted() {
        let code = ClaimCode::generate().expect("entropy");
        let digits = code.digits_for_alert();
        let shown = format!("{code:?}");
        assert_eq!(shown, "ClaimCode(<redacted>)");
        assert!(!shown.contains(&digits), "{shown}");
    }
}
