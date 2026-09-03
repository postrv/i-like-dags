//! Command implementations. Each module takes an already-open [`dag_control::Control`]
//! so every subcommand operates on the same data directory.

/// Complete, offline-restorable snapshots. Unlike `sync`, backups include the
/// control database (run history, keyring, subscriptions and event journal).
pub mod backup;
pub mod content;
pub mod events;
pub mod gc;
pub mod job;
pub mod key;
/// The exception to the rule above: `migrate` runs *before* a `Control` can
/// exist, because `Control::open` refuses the layout it converts.
pub mod migrate;
/// Partly a second exception: `node info` and other remote-only forms talk to
/// *another* node and never open the local directory.
pub mod node;
pub mod pin;
pub mod pointer;
pub mod serve;
pub mod sign;
pub mod sync;
pub mod usecase;

use dag_core::{Cid, CoreError};
use std::io::Read;

/// Parse a hex CID from the command line.
///
/// Every command that takes a `--cid` goes through here so a mistyped one is
/// reported the same way and exits `EX_DATAERR`. Wrapping the raw hex error in
/// `anyhow` instead — which each call site used to do — produced `EX_SOFTWARE`,
/// telling a script the tool had failed rather than that its input was wrong.
pub fn parse_cid(hex: impl AsRef<str>) -> Result<Cid, CoreError> {
    let hex = hex.as_ref();
    Cid::from_hex(hex).map_err(|e| CoreError::InvalidCid(format!("{:?}: {}", hex, e)))
}

/// Read a local command input without allocating according to its file size.
///
/// CLI inputs are operator-selected, but they still cross a process boundary:
/// a mistaken multi-gigabyte file, a growing pseudo-file, or piped data must
/// fail at the command's semantic ceiling rather than exhausting memory before
/// the domain validator gets a chance to reject it.
pub(crate) fn read_bounded(
    reader: impl Read,
    max_bytes: usize,
    description: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("reading {description}: {error}"))?;
    if bytes.len() > max_bytes {
        anyhow::bail!("{description} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::read_bounded;

    #[test]
    fn bounded_input_stops_after_the_limit_plus_one() {
        let input = std::io::Cursor::new(vec![b'x'; 18]);
        let error = read_bounded(input, 16, "test input").unwrap_err();
        assert!(error.to_string().contains("16-byte limit"));
    }
}
