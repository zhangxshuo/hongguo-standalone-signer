use crate::elf::ElfImage;
use crate::jni;
use crate::syscalls::{nr, SyscallTrace};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uc::unicorn_const::{Arch, Mode, Prot};
use uc::{RegisterARM64, Unicorn};

pub const SIGN_FUNCTION_OFFSET: u64 = 0x168c80;
pub const JNI_ON_LOAD_OFFSET: u64 = 0x58b80;
const LOAD_BASE: u64 = 0x4000_0000;
const STACK_BASE: u64 = 0x7000_0000;
const STACK_SIZE: u64 = 8 * 1024 * 1024;
const HEAP_BASE: u64 = 0x8000_0000;
const HEAP_SIZE: u64 = 32 * 1024 * 1024;
const JNIENV_BASE: u64 = 0x9000_0000;
const JNIENV_SIZE: u64 = 0x10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub so_path: String,
    pub cert_path: Option<String>,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub timestamp: u64,
    pub aid: u32,
    pub device_id: String,
    pub version_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub ok: bool,
    pub headers: BTreeMap<String, String>,
    pub error: Option<String>,
    pub diagnostics: Option<BTreeMap<String, String>>,
}

pub struct Emulator {
    unicorn: Unicorn<'static, ()>,
    image: ElfImage,
    trace: SyscallTrace,
}

impl Emulator {
    pub fn open(so_path: &str) -> Result<Self, String> {
        let bytes = std::fs::read(so_path).map_err(|error| format!("read SO failed: {error}"))?;
        let image = ElfImage::parse(bytes)?;
        let mut unicorn = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
            .map_err(|error| format!("Unicorn init failed: {error}"))?;

        for segment in &image.segments {
            let start = LOAD_BASE + segment.virtual_address;
            let size = align_up(segment.memory_size.max(1), 0x1000);
            unicorn
                .mem_map(start, size, Prot::ALL)
                .map_err(|error| format!("map segment 0x{start:x} failed: {error}"))?;
            if segment.file_size > 0 {
                let begin = segment.file_offset as usize;
                let end = begin + segment.file_size as usize;
                if end > image.bytes.len() {
                    return Err("ELF segment exceeds file size".to_string());
                }
                unicorn
                    .mem_write(start, &image.bytes[begin..end])
                    .map_err(|error| format!("write segment 0x{start:x} failed: {error}"))?;
            }
        }

        unicorn
            .mem_map(STACK_BASE, STACK_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map stack failed: {error}"))?;
        unicorn
            .mem_map(HEAP_BASE, HEAP_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map heap failed: {error}"))?;
        unicorn
            .mem_map(JNIENV_BASE, JNIENV_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map JNIEnv failed: {error}"))?;

        unicorn
            .reg_write(RegisterARM64::SP, STACK_BASE + STACK_SIZE - 0x1000)
            .map_err(|error| format!("set SP failed: {error}"))?;

        let trace = SyscallTrace::default();
        Ok(Self {
            unicorn,
            image,
            trace,
        })
    }

    pub fn image(&self) -> &ElfImage {
        &self.image
    }

    pub fn trace(&self) -> &SyscallTrace {
        &self.trace
    }

    pub fn install_syscall_hook(&mut self) -> Result<(), String> {
        self.unicorn
            .add_code_hook(0, u64::MAX, |uc, address, _size, _user| {
                let instruction = match uc.mem_read_as_vec(address, 4) {
                    Ok(bytes) => u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])),
                    Err(_) => 0,
                };
                if instruction & 0xFFE0_001F == 0xD400_0001 {
                    let number = uc.reg_read(RegisterARM64::X8).unwrap_or(u64::MAX);
                    let _ = number;
                }
            })
            .map_err(|error| format!("install syscall hook failed: {error}"))
    }

    /// Emulate the metasec sign entry.
    ///
    /// The scaffold currently proves ELF loading and Unicorn memory setup.
    /// The remaining work is the AArch64 syscall layer and the JNIEnv table:
    /// JNI_OnLoad must run first, then the native sign entry at +0x168c80.
    pub fn sign(&mut self, request: &SignRequest) -> SignResponse {
        let cert = request
            .cert_path
            .as_ref()
            .and_then(|path| std::fs::read(path).ok());
        let _op_probe = jni::ms_b(16777233, cert.as_deref(), now_ms());
        SignResponse {
            ok: false,
            headers: BTreeMap::new(),
            error: Some(
                "standalone emulator scaffold: syscall/JNIEnv layer not implemented yet".to_string(),
            ),
            diagnostics: Some(BTreeMap::from([
                ("image_base".to_string(), format!("0x{:x}", self.image.image_base)),
                (
                    "entry".to_string(),
                    format!("0x{:x}", self.image.entry),
                ),
                (
                    "sign_entry".to_string(),
                    format!("0x{:x}", LOAD_BASE + SIGN_FUNCTION_OFFSET),
                ),
                (
                    "jni_on_load".to_string(),
                    format!("0x{:x}", LOAD_BASE + JNI_ON_LOAD_OFFSET),
                ),
                ("syscalls".to_string(), self.trace.summary()),
                ("known_syscall_openat".to_string(), nr::OPENAT.to_string()),
            ])),
        }
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
