//! Output helpers.
//!
//! Every command renders through [`Format::emit`]: a human-readable line by default,
//! or the serialised value when `--json` is passed. Keeping both renderings in
//! one call site is what stops the two drifting apart.

use anyhow::Result;
use serde::Serialize;
use std::borrow::Cow;
use std::fmt;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{DefaultFields, FormatFields, Writer};

/// Maximum bytes emitted for one stored, remote, or otherwise untrusted
/// human-readable field. Structured JSON is deliberately not truncated.
const MAX_TERMINAL_TEXT_BYTES: usize = 4 * 1024;
const TERMINAL_TEXT_TRUNCATED: &str = "…[truncated]";

/// Field formatter for human-readable tracing output.
///
/// `DefaultFields` retains tracing's ordinary layout, then the same bounded
/// terminal escaping used by command output is applied to the complete field
/// set. The JSON subscriber deliberately does not use this formatter, so log
/// shippers retain the original structured values.
#[derive(Debug, Default, Clone, Copy)]
pub struct SafeTextFields;

impl<'writer> FormatFields<'writer> for SafeTextFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut rendered = String::new();
        DefaultFields::new().format_fields(Writer::new(&mut rendered), fields)?;
        writer.write_str(&terminal_text(&rendered))
    }
}

/// How the process should render command results.
#[derive(Debug, Clone, Copy)]
pub struct Format {
    /// Emit JSON instead of human-readable text.
    pub json: bool,
    /// Pretty-print JSON (ignored unless `json` is set).
    pub pretty: bool,
}

impl Format {
    /// Print `value` as JSON, or `to_text(&value)` as a plain line.
    pub fn emit<T, F>(&self, value: T, to_text: F) -> Result<()>
    where
        T: Serialize,
        F: FnOnce(&T) -> String,
    {
        if self.json {
            self.emit_json(&value)
        } else {
            println!("{}", to_text(&value));
            Ok(())
        }
    }

    /// Print `value` as JSON regardless of format, for data that has no
    /// meaningful flat text rendering.
    pub fn emit_json<T: Serialize>(&self, value: &T) -> Result<()> {
        if self.pretty {
            println!("{}", serde_json::to_string_pretty(value)?);
        } else {
            println!("{}", serde_json::to_string(value)?);
        }
        Ok(())
    }

    /// Print a status line to stderr, suppressed in JSON mode so stdout stays
    /// machine-parseable.
    pub fn note(&self, msg: impl AsRef<str>) {
        if !self.json {
            eprintln!("{}", msg.as_ref());
        }
    }
}

/// Truncate a CID for display: first 8 and last 4 hex characters.
pub fn short_cid(cid: &str) -> String {
    if cid.len() <= 16 {
        return cid.to_string();
    }
    format!("{}…{}", &cid[..8], &cid[cid.len() - 4..])
}

/// Format a POSIX timestamp as an RFC 3339 string.
pub fn ts(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("@{}", unix))
}

/// Format a byte count with a binary unit suffix.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", n, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Escape terminal-active and direction-changing characters in stored or
/// remote text while preserving ordinary Unicode.
///
/// Callers use this for individual untrusted fields before combining them
/// with trusted layout newlines. JSON output deliberately bypasses it and is
/// protected by the JSON encoder's own escaping rules.
pub fn terminal_text(value: &str) -> Cow<'_, str> {
    if value.len() <= MAX_TERMINAL_TEXT_BYTES && !value.chars().any(terminal_unsafe) {
        return Cow::Borrowed(value);
    }

    // Reserve room for the marker while walking. This makes the expansion
    // bound independent of how many control characters the input contains.
    let content_limit = MAX_TERMINAL_TEXT_BYTES - TERMINAL_TEXT_TRUNCATED.len();
    let mut escaped = String::with_capacity(value.len().min(MAX_TERMINAL_TEXT_BYTES));
    let mut truncated = false;
    for ch in value.chars() {
        if terminal_unsafe(ch) {
            let encoded = ch.escape_default().to_string();
            if escaped.len() + encoded.len() > content_limit {
                truncated = true;
                break;
            }
            escaped.push_str(&encoded);
        } else {
            if escaped.len() + ch.len_utf8() > content_limit {
                truncated = true;
                break;
            }
            escaped.push(ch);
        }
    }
    if truncated {
        escaped.push_str(TERMINAL_TEXT_TRUNCATED);
    }
    Cow::Owned(escaped)
}

/// Unicode `Cc`, line/paragraph separators, and bidi format controls that can
/// hide, reorder, or activate displayed control-plane text. ZWNJ and ZWJ are
/// intentionally ordinary text here.
pub(crate) fn terminal_unsafe(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CaptureWriter(Arc::clone(&self.0))
        }
    }

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8(
                self.0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone(),
            )
            .unwrap()
        }
    }

    #[test]
    fn short_cid_truncates_only_long_input() {
        assert_eq!(short_cid("abcd"), "abcd");
        let long = "0123456789abcdef0123456789abcdef";
        assert_eq!(short_cid(long), "01234567…cdef");
    }

    #[test]
    fn bytes_uses_binary_units() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn terminal_text_escapes_controls_and_bidi_without_ascii_folding_unicode() {
        assert_eq!(terminal_text("ordinary αβγ"), "ordinary αβγ");
        assert_eq!(
            terminal_text("join\u{200c}and\u{200d}shape"),
            "join\u{200c}and\u{200d}shape"
        );
        assert_eq!(terminal_text("line\nbreak"), r"line\nbreak");
        assert_eq!(terminal_text("red\u{1b}[31m"), r"red\u{1b}[31m");
        assert_eq!(terminal_text("next\u{85}line"), r"next\u{85}line");
        assert_eq!(terminal_text("line\u{2028}break"), r"line\u{2028}break");
        assert_eq!(terminal_text("left\u{202e}right"), r"left\u{202e}right");
        assert_eq!(terminal_text("isolate\u{2066}text"), r"isolate\u{2066}text");
    }

    #[test]
    fn terminal_text_has_a_bounded_expansion() {
        let hostile = "\u{1b}".repeat(MAX_TERMINAL_TEXT_BYTES);
        let rendered = terminal_text(&hostile);
        assert!(rendered.len() <= MAX_TERMINAL_TEXT_BYTES);
        assert!(rendered.ends_with(TERMINAL_TEXT_TRUNCATED));
    }

    #[test]
    fn text_log_fields_are_terminal_safe_but_json_values_remain_exact() {
        let hostile = "path\nred\u{1b}[31m\u{202e}txt";

        let text_capture = Capture::default();
        let text_subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_level(false)
            .fmt_fields(SafeTextFields)
            .with_writer(text_capture.clone())
            .finish();
        tracing::subscriber::with_default(text_subscriber, || {
            tracing::warn!(path = %hostile, "failed to read hostile path");
        });
        let text = text_capture.text();
        assert_eq!(
            text.chars().filter(|character| *character == '\n').count(),
            1
        );
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains(r"path\nred\u{1b}[31m\u{202e}txt"));

        let json_capture = Capture::default();
        let json_subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(json_capture.clone())
            .finish();
        tracing::subscriber::with_default(json_subscriber, || {
            tracing::warn!(path = %hostile, "failed to read hostile path");
        });
        let line: serde_json::Value = serde_json::from_str(json_capture.text().trim()).unwrap();
        assert_eq!(line["fields"]["path"], hostile);
        assert_eq!(line["fields"]["message"], "failed to read hostile path");
    }
}
