

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ra_buffer_data {
    pub size: ::std::os::raw::c_uint,
    pub buf: *mut ::std::os::raw::c_uchar,
}

#[link(name = "qca")]
unsafe extern "C" {
    pub fn RemoteAttest(
        in_: *mut ra_buffer_data,
        out: *mut ra_buffer_data,
    ) -> ::std::os::raw::c_uint;
}
