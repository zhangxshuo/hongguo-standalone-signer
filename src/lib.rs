mod elf;
mod jni;
mod signer;
mod stubs;
mod syscalls;

use signer::{Emulator, SignRequest, SignResponse};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};

pub use signer::{Emulator as PublicEmulator, SignRequest as PublicSignRequest, SignResponse as PublicSignResponse};

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
