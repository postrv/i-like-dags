//! One process owns a data directory at a time. That is the design; the
//! question is whether a caller can tell, and whether it can wait.
//!
//! Before this, redb's `DatabaseAlreadyOpen` was flattened into a string, so
//! the everyday collision — `dag serve` running while a command fires, or two
//! CI steps sharing a directory — reported as an internal error and gave a
//! wrapper nothing to branch on.

use std::time::{Duration, Instant};

use anyhow::Result;
use dag_control::{Control, ControlError};
use tempfile::TempDir;

#[test]
fn a_second_open_is_reported_as_locked_not_as_a_bug() -> Result<()> {
    let dir = TempDir::new()?;
    let _first = Control::open(dir.path())?;

    let err = match Control::open(dir.path()) {
        Ok(_) => panic!("the directory is already held; a second open must fail"),
        Err(e) => e,
    };

    match err {
        ControlError::DatabaseLocked { ref path } => {
            assert!(
                path.contains(dir.path().to_str().unwrap()),
                "the message must name the directory the caller passed, got {path}"
            );
        }
        other => panic!("expected DatabaseLocked, got {other:?}"),
    }
    Ok(())
}

#[test]
fn open_waiting_returns_immediately_with_a_zero_timeout() -> Result<()> {
    let dir = TempDir::new()?;
    let _first = Control::open(dir.path())?;

    let started = Instant::now();
    let err = Control::open_waiting(dir.path(), Duration::ZERO);

    // The contract is the *error*, not the clock: a zero timeout refuses
    // with the transient, retryable condition rather than waiting or
    // reporting a bug. Asserting the variant tests that directly, where the
    // original 500 ms wall-clock budget was really measuring how loaded the
    // machine was — it failed once under a parallel build while passing in
    // isolation, which is a test nobody can trust.
    assert!(
        matches!(err, Err(ControlError::DatabaseLocked { .. })),
        "expected DatabaseLocked, got {:?}",
        err.map(|_| ())
    );
    // A loose smoke bound: still enough to catch an implementation that
    // waited out a timeout it was told was zero.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a zero timeout waited {:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn open_waiting_acquires_the_directory_once_it_is_released() -> Result<()> {
    let dir = TempDir::new()?;
    let path = dir.path().to_path_buf();

    let first = Control::open(&path)?;
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        drop(first);
    });

    // Waiting turns the collision into a queue rather than a failure the
    // caller can only sleep on itself.
    let second = Control::open_waiting(&path, Duration::from_secs(10));
    releaser.join().expect("releaser thread panicked");

    assert!(
        second.is_ok(),
        "waiting past the holder's lifetime must succeed"
    );
    Ok(())
}
