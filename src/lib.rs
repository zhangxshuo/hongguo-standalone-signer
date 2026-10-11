mod elf;
mod jni;
mod signer;
mod syscalls;

use signer::{Emulator, SignRequest, SignResponse};
use std::ffi::{c_char, CStr, CString};
use std::sync::Mutex;

static SIGNER: Mutex<Option<Emulator>> = Mutex::new(None);

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

    let mut guard = match SIGNER.lock() {
        Ok(value) => value,
        Err(_) => {
            return into_c_string(
                "{\"ok\":false,\"error\":\"signer lock poisoned\"}".to_string(),
            );
        }
    };

    if guard.is_none() {
        match Emulator::open(&parsed.so_path) {
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
