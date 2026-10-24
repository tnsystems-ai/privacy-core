pub mod iban {
    pub const MIN_LEN: usize = 15;
    pub const MAX_LEN: usize = 34;

    /// Expected IBAN length per ISO 13616 registry for European countries
    /// (EU/EEA, SEPA members and other European registry participants).
    pub const fn country_length(cc: [u8; 2]) -> Option<usize> {
        let len = match &cc {
            b"AD" => 24,
            b"AL" => 28,
            b"AT" => 20,
            b"BA" => 20,
            b"BE" => 16,
            b"BG" => 22,
            b"BY" => 28,
            b"CH" => 21,
            b"CY" => 28,
            b"CZ" => 24,
            b"DE" => 22,
            b"DK" => 18,
            b"EE" => 20,
            b"ES" => 24,
            b"FI" => 18,
            b"FO" => 18,
            b"FR" => 27,
            b"GB" => 22,
            b"GE" => 22,
            b"GI" => 23,
            b"GL" => 18,
            b"GR" => 27,
            b"HR" => 21,
            b"HU" => 28,
            b"IE" => 22,
            b"IS" => 26,
            b"IT" => 27,
            b"LI" => 21,
            b"LT" => 20,
            b"LU" => 20,
            b"LV" => 21,
            b"MC" => 27,
            b"MD" => 24,
            b"ME" => 22,
            b"MK" => 19,
            b"MT" => 31,
            b"NL" => 18,
            b"NO" => 15,
            b"PL" => 28,
            b"PT" => 25,
            b"RO" => 24,
            b"RS" => 22,
            b"SE" => 24,
            b"SI" => 19,
            b"SK" => 24,
            b"SM" => 27,
            b"TR" => 26,
            b"UA" => 29,
            b"VA" => 22,
            b"XK" => 20,
            _ => return None,
        };
        Some(len)
    }

    /// Validates a compact, uppercase IBAN (no separators).
    pub fn validate(iban: &[u8]) -> bool {
        if iban.len() < MIN_LEN || iban.len() > MAX_LEN {
            return false;
        }
        match country_length([iban[0], iban[1]]) {
            Some(expected) if expected == iban.len() => {}
            _ => return false,
        }
        if !iban[2].is_ascii_digit() || !iban[3].is_ascii_digit() {
            return false;
        }
        let check = (iban[2] - b'0') * 10 + (iban[3] - b'0');
        if !(2..=98).contains(&check) {
            return false;
        }

        let mut rem: u32 = 0;
        for &b in iban[4..].iter().chain(&iban[..4]) {
            rem = match b {
                b'0'..=b'9' => (rem * 10 + u32::from(b - b'0')) % 97,
                b'A'..=b'Z' => (rem * 100 + u32::from(b - b'A' + 10)) % 97,
                _ => return false,
            };
        }
        rem == 1
    }

    /// Validates a human-entered IBAN, ignoring spaces and letter case.
    pub fn is_valid(input: &str) -> bool {
        let mut buf = [0u8; MAX_LEN];
        let mut len = 0;
        for b in input.bytes() {
            if b == b' ' {
                continue;
            }
            if len == MAX_LEN || !b.is_ascii_alphanumeric() {
                return false;
            }
            buf[len] = b.to_ascii_uppercase();
            len += 1;
        }
        validate(&buf[..len])
    }
}

pub mod luhn {
    pub const MIN_LEN: usize = 13;
    pub const MAX_LEN: usize = 19;

    const DOUBLED: [u8; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

    /// Validates a PAN given as ASCII digits only.
    pub fn validate(digits: &[u8]) -> bool {
        if digits.len() < MIN_LEN || digits.len() > MAX_LEN {
            return false;
        }
        let first = digits[0];
        let mut all_same = true;
        let mut sum: u32 = 0;
        for (i, &b) in digits.iter().rev().enumerate() {
            if !b.is_ascii_digit() {
                return false;
            }
            all_same &= b == first;
            let d = b - b'0';
            sum += u32::from([d, DOUBLED[d as usize]][i & 1]);
        }
        !all_same && sum % 10 == 0
    }

    /// Validates a human-entered PAN, ignoring spaces and hyphens.
    pub fn is_valid(input: &str) -> bool {
        let mut buf = [0u8; MAX_LEN];
        let mut len = 0;
        for b in input.bytes() {
            if b == b' ' || b == b'-' {
                continue;
            }
            if len == MAX_LEN || !b.is_ascii_digit() {
                return false;
            }
            buf[len] = b;
            len += 1;
        }
        validate(&buf[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::{iban, luhn};

    const VALID_IBANS: &[&str] = &[
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
        "NL91ABNA0417164300",
        "CH9300762011623852957",
        "FR7630006000011234567890189",
        "NO9386011117947",
        "MT84MALT011000012345MTLCAST001S",
    ];

    #[test]
    fn iban_valid_samples() {
        for s in VALID_IBANS {
            assert!(iban::validate(s.as_bytes()), "{s}");
            assert!(iban::is_valid(s), "{s}");
        }
    }

    #[test]
    fn iban_wrong_check_digits() {
        assert!(!iban::validate(b"DE88370400440532013000"));
        assert!(!iban::validate(b"GB82WEST12345698765433"));
    }

    #[test]
    fn iban_wrong_length() {
        assert!(!iban::validate(b"DE8937040044053201300"));
        assert!(!iban::validate(b"DE893704004405320130000"));
    }

    #[test]
    fn iban_unknown_country() {
        assert!(!iban::validate(b"ZZ89370400440532013000"));
    }

    #[test]
    fn iban_lowercase_requires_normalization() {
        assert!(!iban::validate(b"gb82west12345698765432"));
        assert!(iban::is_valid("gb82west12345698765432"));
    }

    #[test]
    fn iban_grouped_form() {
        assert!(iban::is_valid("DE89 3704 0044 0532 0130 00"));
        assert!(iban::is_valid("FR14 2004 1010 0505 0001 3M02 606"));
        assert!(!iban::is_valid("DE89-3704-0044-0532-0130-00"));
    }

    #[test]
    fn iban_rejects_bad_check_digit_range() {
        assert!(!iban::validate(b"DE00370400440532013000"));
        assert!(!iban::validate(b"DE99370400440532013000"));
    }

    #[test]
    fn luhn_valid_samples() {
        for s in [
            "4111111111111111",
            "5500005555555559",
            "378282246310005",
            "6011111111111117",
        ] {
            assert!(luhn::validate(s.as_bytes()), "{s}");
        }
        assert!(luhn::is_valid("4111 1111 1111 1111"));
        assert!(luhn::is_valid("4111-1111-1111-1111"));
    }

    #[test]
    fn luhn_single_digit_change() {
        assert!(!luhn::validate(b"4111111111111112"));
        assert!(!luhn::validate(b"5500005555555558"));
    }

    #[test]
    fn luhn_length_bounds() {
        assert!(!luhn::validate(b"424242424242"));
        assert!(!luhn::validate(b"41111111111111111111"));
    }

    #[test]
    fn luhn_rejects_repeated_digit() {
        assert!(!luhn::validate(b"0000000000000000"));
    }

    #[test]
    fn luhn_rejects_non_digits() {
        assert!(!luhn::validate(b"411111111111111a"));
        assert!(!luhn::is_valid("4111x1111 1111 1111"));
    }
}
