mod decrypt;
mod elf;
mod jni;
mod signer;
mod stubs;
mod syscalls;

use signer::{Emulator, SignRequest, SignResponse};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};

pub use signer::{Emulator as PublicEmulator, SignRequest as PublicSignRequest, SignResponse as PublicSignResponse};

#[no_mangle]
pub unsafe extern "C" fn hongguo_decrypt_file(
    spade_a_b64: *const c_char,
    input_path: *const c_char,
    output_path: *const c_char,
    flag: i32,
) -> i32 {
    if spade_a_b64.is_null() || input_path.is_null() || output_path.is_null() {
        return -1;
    }
    let spade = match unsafe { CStr::from_ptr(spade_a_b64) }.to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let input = match unsafe { CStr::from_ptr(input_path) }.to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let output = match unsafe { CStr::from_ptr(output_path) }.to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };
    match decrypt::decrypt_file(spade, input, output, flag) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

thread_local! {
    static SIGNER: RefCell<Option<Emulator>> = RefCell::new(None);
}

#[no_mangle]
pub unsafe extern "C" fn hongguo_sign(request_json: *const c_char) -> *mut c_char {
    let request = match unsafe { CStr::from_ptr(request_json) }.to_str() {
        Ok(text) => text,
        Err(error) => {
            return into_c_string(
                serde_json::to_string(&SignResponse {
                    ok: false,
                    headers: Default::default(),
                    error: Some(format!("invalid UTF-8 request: {error}")),
                    diagnostics: None,
                })
                .unwrap_or_else(|_| "{\"ok\":false}".to_string()),
            );
        }
    };

    let parsed: SignRequest = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(error) => {
            return into_c_string(
                serde_json::to_string(&SignResponse {
                    ok: false,
                    headers: Default::default(),
                    error: Some(format!("invalid request JSON: {error}")),
                    diagnostics: None,
                })
                .unwrap_or_else(|_| "{\"ok\":false}".to_string()),
            );
        }
    };

    SIGNER.with(|cell| {
        let mut guard = cell.borrow_mut();
        if guard.is_none() {
            match Emulator::open(
                &parsed.so_path,
                parsed.cpp_path.as_deref(),
                parsed.cert_path.as_deref(),
            ) {
                Ok(emulator) => *guard = Some(emulator),
                Err(error) => {
                    return into_c_string(
                        serde_json::to_string(&SignResponse {
                            ok: false,
                            headers: Default::default(),
                            error: Some(error),
                            diagnostics: None,
                        })
                        .unwrap_or_else(|_| "{\"ok\":false}".to_string()),
                    );
                }
            }
        }

        let response = guard
            .as_mut()
            .map(|emulator| emulator.sign(&parsed))
            .unwrap_or_else(|| SignResponse {
                ok: false,
                headers: Default::default(),
                error: Some("signer unavailable".to_string()),
                diagnostics: None,
            });

        into_c_string(
            serde_json::to_string(&response).unwrap_or_else(|_| "{\"ok\":false}".to_string()),
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn hongguo_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(value) });
}

fn into_c_string(value: String) -> *mut c_char {
    CString::new(value)
        .unwrap_or_else(|_| CString::new("{\"ok\":false}").unwrap())
        .into_raw()
}
