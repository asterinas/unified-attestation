use anyhow::{Result, bail};

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};

    const RTLD_NOW: c_int = 2;

    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
        fn dlerror() -> *const c_char;
    }

    pub(crate) struct DynamicLibrary {
        handle: *mut c_void,
    }

    impl DynamicLibrary {
        pub(crate) fn open(names: &[&str]) -> Result<Self> {
            let mut errors = Vec::new();
            for name in names {
                let c_name = CString::new(*name)?;
                let handle = unsafe { dlopen(c_name.as_ptr(), RTLD_NOW) };
                if !handle.is_null() {
                    return Ok(Self { handle });
                }
                errors.push(format!("{name}: {}", last_dl_error()));
            }

            bail!("failed to load dynamic library: {}", errors.join("; "))
        }

        pub(crate) unsafe fn symbol<T>(&self, name: &str) -> Result<T>
        where
            T: Copy,
        {
            let c_name = CString::new(name)?;
            let symbol = unsafe { dlsym(self.handle, c_name.as_ptr()) };
            if symbol.is_null() {
                bail!("failed to load symbol `{name}`: {}", last_dl_error());
            }

            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&symbol) })
        }
    }

    impl Drop for DynamicLibrary {
        fn drop(&mut self) {
            unsafe {
                let _ = dlclose(self.handle);
            }
        }
    }

    fn last_dl_error() -> String {
        let err = unsafe { dlerror() };
        if err.is_null() {
            "no dlerror detail".to_string()
        } else {
            unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub(crate) struct DynamicLibrary;

    impl DynamicLibrary {
        pub(crate) fn open(names: &[&str]) -> Result<Self> {
            bail!(
                "dynamic loading is only supported on Unix; requested one of: {}",
                names.join(", ")
            )
        }

        pub(crate) unsafe fn symbol<T>(&self, name: &str) -> Result<T>
        where
            T: Copy,
        {
            bail!("dynamic symbol loading is only supported on Unix; requested `{name}`")
        }
    }
}

pub(crate) use imp::DynamicLibrary;
