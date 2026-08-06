//! Replay-window and message-id validation without heap storage.

use crate::error::{Error, ErrorKind, Result};

/// Expected direction of an MTProto message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDirection {
    /// Client to Telegram.
    ClientToServer,
    /// Telegram to client.
    ServerToClient,
}

/// Checks parity and the documented time window for a message identifier.
pub fn validate_message_id(
    message_id: u64,
    direction: MessageDirection,
    unix_seconds: u64,
) -> Result<()> {
    let residue = (message_id & 3) as u32;
    let parity_ok = match direction {
        MessageDirection::ClientToServer => residue == 0,
        MessageDirection::ServerToClient => residue == 1 || residue == 3,
    };
    if !parity_ok {
        return Err(Error::new(ErrorKind::InvalidPacket, 0, residue));
    }
    let message_seconds = message_id >> 32;
    if message_seconds.saturating_add(300) < unix_seconds
        || message_seconds > unix_seconds.saturating_add(30)
    {
        return Err(Error::new(
            ErrorKind::InvalidPacket,
            0,
            message_seconds.min(u64::from(u32::MAX)) as u32,
        ));
    }
    Ok(())
}

/// Fixed 32-entry replay window (264 bytes, no allocation).
#[derive(Clone, Debug)]
#[repr(C)]
pub struct MessageIdWindow {
    ids: [u64; 32],
    used: u8,
}

impl MessageIdWindow {
    /// Creates an empty window.
    pub const fn new() -> Self {
        Self {
            ids: [0; 32],
            used: 0,
        }
    }

    /// Records a new identifier, rejecting duplicates and values below the window.
    pub fn insert(&mut self, message_id: u64) -> Result<()> {
        let used = usize::from(self.used);
        if self.ids[..used].contains(&message_id) {
            return Err(Error::new(ErrorKind::Authentication, 0, 1));
        }
        if used == self.ids.len() && message_id < self.ids[0] {
            return Err(Error::new(ErrorKind::Authentication, 0, 2));
        }
        if used < self.ids.len() {
            self.ids[used] = message_id;
            self.used += 1;
        } else {
            self.ids[0] = message_id;
        }
        self.ids[..usize::from(self.used)].sort_unstable();
        Ok(())
    }

    /// Number of tracked identifiers.
    #[inline]
    pub const fn len(&self) -> u8 {
        self.used
    }

    /// Returns true when no identifier is tracked.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }
}

impl Default for MessageIdWindow {
    fn default() -> Self {
        Self::new()
    }
}
