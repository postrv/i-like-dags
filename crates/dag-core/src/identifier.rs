//! Shared terminal-safe text rules for operator-visible control identifiers.

/// Validate text used as a pointer, pin, or job identifier.
///
/// Normal Unicode remains valid. C0/C1 controls and Unicode bidirectional
/// formatting controls are refused because logs, terminals, JSON, and CLI
/// tables render them as structure or visually reordered text rather than as
/// the identifier that is actually stored.
pub fn validate_identifier_text(value: &str) -> Result<(), &'static str> {
    if value.chars().any(char::is_control) {
        return Err("identifier cannot contain control characters");
    }
    if value
        .chars()
        .any(|character| is_bidi_format(character) || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(
            "identifier cannot contain line, paragraph, or bidirectional formatting characters",
        );
    }
    Ok(())
}

fn is_bidi_format(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_terminal_and_bidi_controls_but_preserves_normal_unicode() {
        assert!(validate_identifier_text("release\nforged").is_err());
        assert!(validate_identifier_text("release\u{001b}[31m").is_err());
        assert!(validate_identifier_text("release\u{202e}txt").is_err());
        assert!(validate_identifier_text("release\u{2028}forged").is_err());
        assert!(validate_identifier_text("release\u{2029}forged").is_err());
        assert!(validate_identifier_text("release\u{2067}مرحبا\u{2069}").is_err());
        assert!(validate_identifier_text("模型/é/مرحبا").is_ok());
        // Join controls shape legitimate scripts but do not reorder terminal
        // text, so do not over-broaden the bidi-format denylist to every Cf.
        assert!(validate_identifier_text("क्\u{200d}ष").is_ok());
        assert!(validate_identifier_text("می\u{200c}خواهم").is_ok());
    }
}
