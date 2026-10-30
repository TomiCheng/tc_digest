//! The error of Skein's `init`.

use core::fmt;

/// Why Skein parameters were rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError {
    /// The key is shorter than 16 bytes, the minimum Bouncy Castle accepts.
    KeyTooShort,
}

impl fmt::Display for InitError {
    /// Writes the error message. Constant time; output timing depends on the
    /// formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::KeyTooShort => f.write_str("Skein key must be at least 128 bits"),
        }
    }
}

impl core::error::Error for InitError {}
