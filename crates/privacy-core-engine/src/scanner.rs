use crate::types::{Detection, PiiType};
use crate::validators::{iban, luhn};

pub(crate) struct ScanOutput {
    pub detections: Vec<Detection>,
    pub chars: usize,
}

/// Single forward pass over `text`. Candidates are only attempted at word
/// boundaries; every candidate probe reads a bounded number of bytes, so the
/// scan is O(n). All matched spans are pure ASCII.
pub(crate) fn scan(text: &str, enabled: &[bool; PiiType::COUNT]) -> ScanOutput {
    let bytes = text.as_bytes();
    let scan_iban = enabled[PiiType::Iban.index()];
    let scan_pan = enabled[PiiType::CreditCard.index()];

    let mut detections = Vec::new();
    let mut chars = 0usize;
    let mut prev_alnum = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if !prev_alnum {
            let hit = if scan_iban && b.is_ascii_uppercase() {
                match_iban(bytes, i).map(|end| (PiiType::Iban, end))
            } else if scan_pan && b.is_ascii_digit() {
                match_pan(bytes, i).map(|end| (PiiType::CreditCard, end))
            } else {
                None
            };
            if let Some((pii_type, end)) = hit {
                detections.push(Detection {
                    pii_type,
                    start: i,
                    end,
                });
                chars += end - i;
                i = end;
                prev_alnum = true;
                continue;
            }
        }
        chars += usize::from(b & 0xC0 != 0x80);
        prev_alnum = b.is_ascii_alphanumeric();
        i += 1;
    }

    ScanOutput { detections, chars }
}

#[inline]
fn is_boundary_at(bytes: &[u8], pos: usize) -> bool {
    bytes.get(pos).is_none_or(|b| !b.is_ascii_alphanumeric())
}

#[inline]
fn is_iban_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

/// Matches an IBAN starting at `start`, allowing single spaces between
/// groups. Returns the exclusive end offset in `bytes`.
fn match_iban(bytes: &[u8], start: usize) -> Option<usize> {
    let head = bytes.get(start..start + 4)?;
    if !head[0].is_ascii_uppercase()
        || !head[1].is_ascii_uppercase()
        || !head[2].is_ascii_digit()
        || !head[3].is_ascii_digit()
    {
        return None;
    }
    let expected = iban::country_length([head[0], head[1]])?;

    let mut buf = [0u8; iban::MAX_LEN];
    let mut len = 0usize;
    let mut pos = start;
    while len < expected {
        let b = *bytes.get(pos)?;
        if is_iban_char(b) {
            buf[len] = b;
            len += 1;
            pos += 1;
        } else if b == b' ' && len > 0 && bytes.get(pos + 1).is_some_and(|&n| is_iban_char(n)) {
            pos += 1;
        } else {
            return None;
        }
    }

    (is_boundary_at(bytes, pos) && iban::validate(&buf[..len])).then_some(pos)
}

/// Matches a PAN starting at `start`, allowing a single consistent separator
/// (space or hyphen) between digit groups. Group-aligned prefixes are tried
/// longest first so trailing digit groups do not mask a valid PAN.
fn match_pan(bytes: &[u8], start: usize) -> Option<usize> {
    let mut buf = [0u8; luhn::MAX_LEN];
    let mut len = 0usize;
    let mut pos = start;
    let mut sep: Option<u8> = None;
    let mut ends = [(0usize, 0usize); luhn::MAX_LEN - luhn::MIN_LEN + 1];
    let mut n_ends = 0usize;
    let mut tail_ok = true;

    loop {
        match bytes.get(pos).copied() {
            Some(b) if b.is_ascii_digit() => {
                if len == luhn::MAX_LEN {
                    tail_ok = false;
                    break;
                }
                buf[len] = b;
                len += 1;
                pos += 1;
            }
            Some(b @ (b' ' | b'-'))
                if len > 0
                    && sep.is_none_or(|s| s == b)
                    && bytes.get(pos + 1).is_some_and(u8::is_ascii_digit) =>
            {
                if len >= luhn::MIN_LEN {
                    ends[n_ends] = (len, pos);
                    n_ends += 1;
                }
                sep = Some(b);
                pos += 1;
            }
            _ => break,
        }
    }

    if tail_ok && len >= luhn::MIN_LEN && is_boundary_at(bytes, pos) {
        ends[n_ends] = (len, pos);
        n_ends += 1;
    }

    ends[..n_ends]
        .iter()
        .rev()
        .find(|&&(n, _)| luhn::validate(&buf[..n]))
        .map(|&(_, end)| end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [bool; PiiType::COUNT] = [true; PiiType::COUNT];

    fn spans(text: &str) -> Vec<(PiiType, &str)> {
        scan(text, &ALL)
            .detections
            .iter()
            .map(|d| (d.pii_type, &text[d.start..d.end]))
            .collect()
    }

    #[test]
    fn finds_embedded_compact_iban() {
        assert_eq!(
            spans("Pay to DE89370400440532013000 today."),
            vec![(PiiType::Iban, "DE89370400440532013000")]
        );
    }

    #[test]
    fn finds_grouped_iban() {
        let t = "IBAN: FR14 2004 1010 0505 0001 3M02 606, thanks";
        assert_eq!(
            spans(t),
            vec![(PiiType::Iban, "FR14 2004 1010 0505 0001 3M02 606")]
        );
    }

    #[test]
    fn iban_requires_boundaries() {
        assert!(spans("XDE89370400440532013000").is_empty());
        assert!(spans("DE89370400440532013000X").is_empty());
        assert!(spans("DE893704004405320130001").is_empty());
    }

    #[test]
    fn finds_pan_forms() {
        assert_eq!(
            spans("card 4111111111111111."),
            vec![(PiiType::CreditCard, "4111111111111111")]
        );
        assert_eq!(
            spans("card 4111 1111 1111 1111 exp"),
            vec![(PiiType::CreditCard, "4111 1111 1111 1111")]
        );
        assert_eq!(
            spans("card 4111-1111-1111-1111"),
            vec![(PiiType::CreditCard, "4111-1111-1111-1111")]
        );
    }

    #[test]
    fn pan_trailing_group_does_not_mask_match() {
        assert_eq!(
            spans("4111 1111 1111 1111 2024"),
            vec![(PiiType::CreditCard, "4111 1111 1111 1111")]
        );
    }

    #[test]
    fn pan_rejects_mixed_separators_and_boundaries() {
        assert!(spans("4111-1111 1111-1111").is_empty());
        assert!(spans("X4111111111111111").is_empty());
        assert!(spans("4111111111111111X").is_empty());
        assert!(spans("41111111111111110000").is_empty());
        assert!(spans("4111111111111112").is_empty());
    }

    #[test]
    fn multibyte_context() {
        let t = "Überweisung → DE89370400440532013000 für Ünal, Karte: 4111111111111111 ✓";
        let out = scan(t, &ALL);
        assert_eq!(out.chars, t.chars().count());
        assert_eq!(
            spans(t),
            vec![
                (PiiType::Iban, "DE89370400440532013000"),
                (PiiType::CreditCard, "4111111111111111")
            ]
        );
    }

    #[test]
    fn adjacent_matches() {
        assert_eq!(
            spans("DE89370400440532013000 4111111111111111,GB82WEST12345698765432"),
            vec![
                (PiiType::Iban, "DE89370400440532013000"),
                (PiiType::CreditCard, "4111111111111111"),
                (PiiType::Iban, "GB82WEST12345698765432"),
            ]
        );
    }

    #[test]
    fn respects_disabled_types() {
        let t = "DE89370400440532013000 4111111111111111";
        let only_pan = scan(t, &[false, true]);
        assert_eq!(only_pan.detections.len(), 1);
        assert_eq!(only_pan.detections[0].pii_type, PiiType::CreditCard);
        assert!(scan(t, &[false, false]).detections.is_empty());
    }

    #[test]
    fn empty_and_short_inputs() {
        assert!(spans("").is_empty());
        assert!(spans("DE").is_empty());
        assert!(spans("4").is_empty());
    }
}
