#[repr(C)]
pub struct iovec {
    pub iov_base: *const u8,
    pub iov_len: usize,
}
