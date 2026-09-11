//! Best-effort secure erasure of sensitive byte buffers held by `src/claim/`.

use std::sync::atomic::{Ordering, compiler_fence};

/// Overwrites every byte of `buf` with zero using a volatile write per byte, followed by a
/// compiler fence, so the compiler is not free to treat the writes as a dead store it can elide
/// (which a plain `for byte in buf.iter_mut() { *byte = 0; }` loop executed immediately before
/// the buffer's backing memory is freed is otherwise allowed to do).
///
/// Modeled directly on `secp256k1_sys::non_secure_erase_impl`, reached from
/// `SecretKey::non_secure_erase` via the `impl_non_secure_erase!` macro
/// (secp256k1-0.29.1/src/macros.rs:56-70): the actual erase primitive — one `ptr::write_volatile`
/// followed by `compiler_fence(Ordering::SeqCst)` — lives at
/// secp256k1-sys-0.10.1/src/lib.rs:482-489. This is the same technique, applied per-byte instead
/// of to a single `T`, since the buffers here (transaction bytes, a compressed pubkey, key-file
/// contents) are slices, not fixed-size secp256k1 types with their own `non_secure_erase`.
///
/// This is a best-effort measure, not a guarantee: as `SecretKey::non_secure_erase`'s own doc
/// comment notes, the compiler remains free to have copied or moved `buf`'s contents to other
/// memory locations before this function ever runs. See the `zeroize` crate's documentation for
/// further discussion of that limitation.
pub(in crate::claim) fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, correctly aligned, exclusively borrowed `&mut u8` for the
        // duration of this write, obtained from `buf.iter_mut()` on the caller's own live
        // `&mut [u8]`. A volatile write to a valid, exclusively owned location of its own type is
        // always sound; `write_volatile` (rather than a plain assignment) is used only so the
        // compiler cannot prove the write is dead and remove it, not because the write would
        // otherwise be unsafe.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    // Prevent the compiler from reordering any later access to `buf`'s memory to before the
    // writes above, and from merging/eliding them despite the per-byte `write_volatile` calls.
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroes_every_byte_of_a_nonzero_buffer() {
        let mut buf = [0xAAu8; 32];
        secure_zero(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn is_a_no_op_on_an_empty_buffer() {
        let mut buf: [u8; 0] = [];
        secure_zero(&mut buf);
        assert_eq!(buf, [0u8; 0]);
    }
}
