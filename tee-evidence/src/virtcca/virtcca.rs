
#[allow(non_camel_case_types)]
pub type wchar_t = ::std::os::raw::c_int;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tsi_ctx {
    pub fd: wchar_t,
}

#[link(name = "vccaattestation")]
unsafe extern "C" {
    pub fn tsi_new_ctx() -> *mut tsi_ctx;
}
unsafe extern "C" {
    pub fn tsi_free_ctx(ctx: *mut tsi_ctx);
}
unsafe extern "C" {
    pub fn get_attestation_token(
        ctx: *mut tsi_ctx,
        challenge: *mut ::std::os::raw::c_uchar,
        challenge_len: usize,
        token: *mut ::std::os::raw::c_uchar,
        token_len: *mut usize,
    ) -> wchar_t;
}
unsafe extern "C" {
    pub fn get_dev_cert(
        ctx: *mut tsi_ctx,
        dev_cert: *mut ::std::os::raw::c_uchar,
        dev_cert_len: *mut usize,
    ) -> wchar_t;
}
