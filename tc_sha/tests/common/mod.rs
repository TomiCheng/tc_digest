//! Helpers shared by the integration tests.

// Each test file uses a different subset.
#![allow(dead_code)]

use tc_digest::Digest;

/// Absorbs `message`, finalizes, and returns the digest as lowercase hex.
pub fn hex_digest(digest: &mut dyn Digest, message: &[u8]) -> String {
    digest.update(message);
    let mut output = [0u8; 64];
    let written = digest.do_final(&mut output);
    output[..written]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The message `0, 1, 2, ...` of `len` bytes, wrapping at 256.
pub fn counting_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}
