//! Test utilities for dag-control integration tests
//!
//! This module provides `TestControl`, an in-process test harness that eliminates
//! subprocess overhead for integration tests. It creates isolated temp directories
//! and provides convenient event waiting with timeouts.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "test-utils")] {
//! use dag_control::test_utils::TestControl;
//! use dag_core::ContentStore;
//! use std::time::Duration;
//!
//! let mut tc = TestControl::new().unwrap();
//!
//! // Drive the Control API directly — no subprocess, no fixed paths.
//! let cid = tc.control.store.put_chunk(b"test", None).unwrap();
//! tc.control.pointer_log.create("demo", cid).unwrap();
//!
//! // And wait for what it emitted, with a timeout rather than a sleep.
//! let envelope = tc.wait_for_event(Duration::from_secs(1)).unwrap();
//! # }
//! ```

use crate::events::EventEnvelope;
use crate::Control;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::broadcast;

/// Test harness that provides isolated Control instances with event subscription
///
/// TestControl manages a temp directory that is automatically cleaned up when dropped.
/// It provides direct access to the Control API and convenient methods for waiting
/// on events during tests.
pub struct TestControl {
    /// The Control instance for API access
    pub control: Control,
    /// Receiver for events emitted by the control plane
    receiver: broadcast::Receiver<EventEnvelope>,
    /// Temp directory (kept alive to prevent cleanup during test)
    _temp_dir: TempDir,
    /// Path to the data directory
    data_dir: PathBuf,
}

impl TestControl {
    /// Create a new TestControl with an isolated temp directory
    ///
    /// # Returns
    ///
    /// A new TestControl instance with a fresh Control and event subscription.
    ///
    /// # Errors
    ///
    /// Returns an error if the temp directory or Control cannot be created.
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let data_dir = temp_dir.path().to_path_buf();
        let control = Control::open(&data_dir)?;
        let receiver = control.subscribe_events();

        Ok(Self {
            control,
            receiver,
            _temp_dir: temp_dir,
            data_dir,
        })
    }

    /// Get the path to the data directory
    pub fn path(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Wait for an event with timeout
    ///
    /// Polls the event receiver until an event is received or the timeout expires.
    /// Uses a small sleep between polls to avoid busy-waiting.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for an event
    ///
    /// # Returns
    ///
    /// The received EventEnvelope, or an error if the timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an error if no event is received within the timeout period.
    pub fn wait_for_event(&mut self, timeout: Duration) -> Result<EventEnvelope> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(5);

        loop {
            match self.receiver.try_recv() {
                Ok(envelope) => return Ok(envelope),
                Err(broadcast::error::TryRecvError::Empty) => {
                    if start.elapsed() >= timeout {
                        return Err(anyhow!("timeout waiting for event after {:?}", timeout));
                    }
                    std::thread::sleep(poll_interval);
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    // Skip lagged events and continue - this can happen if many
                    // events are emitted rapidly
                    tracing::warn!("event receiver lagged by {} events", n);
                    continue;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    return Err(anyhow!("event bus closed"));
                }
            }
        }
    }

    /// Try to receive an event without waiting
    ///
    /// Returns immediately with an event if one is available, or None if no
    /// event is pending.
    pub fn try_recv_event(&mut self) -> Option<EventEnvelope> {
        self.receiver.try_recv().ok()
    }

    /// Drain all pending events from the receiver
    ///
    /// Useful for clearing events before setting up expectations in a test.
    pub fn drain_events(&mut self) -> Vec<EventEnvelope> {
        let mut events = Vec::new();
        while let Some(event) = self.try_recv_event() {
            events.push(event);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::ContentStore;
    use std::time::Duration;

    #[test]
    fn test_test_control_creates_isolated_environment() -> Result<()> {
        // Create two TestControl instances
        let tc1 = TestControl::new()?;
        let tc2 = TestControl::new()?;

        // They should have different data directories
        assert_ne!(tc1.path(), tc2.path());

        // Each should be able to store data independently
        let chunk1 = b"data for tc1";
        let chunk2 = b"data for tc2";

        let cid1 = tc1.control.store.put_chunk(chunk1, None)?;
        let cid2 = tc2.control.store.put_chunk(chunk2, None)?;

        // CIDs should be different (different data)
        assert_ne!(cid1, cid2);

        // Each store should only have its own data
        assert!(tc1.control.store.get_chunk(&cid1).is_ok());
        assert!(tc1.control.store.get_chunk(&cid2).is_err()); // Not in tc1

        assert!(tc2.control.store.get_chunk(&cid2).is_ok());
        assert!(tc2.control.store.get_chunk(&cid1).is_err()); // Not in tc2

        Ok(())
    }

    #[test]
    fn test_wait_for_event_receives_pointer_event() -> Result<()> {
        let mut tc = TestControl::new()?;

        // Create a pointer (should emit an event)
        let chunk = b"test data";
        let cid = tc.control.store.put_chunk(chunk, None)?;
        tc.control.pointer_log.create("test-ptr", cid.clone())?;

        // Wait for the event
        let event = tc.wait_for_event(Duration::from_secs(1))?;

        // Verify it's a pointer update event
        match event.event {
            crate::Event::PointerUpdate { id, new, .. } => {
                assert_eq!(id, "test-ptr");
                assert_eq!(new, cid);
            }
            _ => panic!("Expected PointerUpdate event, got {:?}", event.event),
        }

        Ok(())
    }

    #[test]
    fn test_wait_for_event_times_out_when_no_event() -> Result<()> {
        let mut tc = TestControl::new()?;

        // Drain any existing events
        tc.drain_events();

        // Wait for an event that won't come
        let result = tc.wait_for_event(Duration::from_millis(50));

        // Should timeout
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timeout"));

        Ok(())
    }

    #[test]
    fn test_path_returns_data_directory() -> Result<()> {
        let tc = TestControl::new()?;

        let path = tc.path();

        // Path should exist and be a directory
        assert!(path.exists());
        assert!(path.is_dir());

        // Should contain expected subdirectories after Control::open
        assert!(path.join("data").exists() || path.join("index").exists());

        Ok(())
    }

    #[test]
    fn test_drain_events_clears_pending_events() -> Result<()> {
        let mut tc = TestControl::new()?;

        // Create multiple pointers to emit multiple events
        let chunk = b"test data";
        let cid = tc.control.store.put_chunk(chunk, None)?;
        tc.control.pointer_log.create("ptr1", cid.clone())?;
        tc.control.pointer_log.create("ptr2", cid.clone())?;
        tc.control.pointer_log.create("ptr3", cid)?;

        // Drain all events
        let events = tc.drain_events();

        // Should have received 3 events
        assert_eq!(events.len(), 3);

        // No more events should be pending
        assert!(tc.try_recv_event().is_none());

        Ok(())
    }
}
