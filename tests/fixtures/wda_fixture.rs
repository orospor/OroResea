#![allow(non_snake_case)]

#[link(name = "user32")]
unsafe extern "system" {
    fn SetWindowDisplayAffinity(hwnd: *mut core::ffi::c_void, affinity: u32) -> i32;
}

fn main() {
    // This fixture imports the API but clears affinity on a null handle. It is
    // never executed by the OroResea test process. It exists to verify that an
    // import is reported as capability, not falsely called active blocking.
    unsafe {
        let _ = SetWindowDisplayAffinity(core::ptr::null_mut(), 0);
    }
}

