//! Various utilities for IKEv2

/// Create a `Vec<u8>` filled with random bytes
///
/// These bytes are not guaranteed to be cryptographically safe.
pub fn get_random_vec(len: usize) -> Vec<u8> {
    rand::random_iter().take(len).collect()
}
