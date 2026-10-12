use crate::elf::ElfImage;
use crate::jni::{ms_b, MsValue};
use crate::stubs::{
    JniObject, JniState, StubKind, StubTable, JNI_CALL_BOOLEAN_METHOD_V,
    JNI_CALL_INT_METHOD_V, JNI_CALL_LONG_METHOD_V, JNI_CALL_OBJECT_METHOD_V,
    JNI_CALL_STATIC_INT_METHOD_V, JNI_CALL_STATIC_OBJECT_METHOD_V, JNI_CALL_VOID_METHOD_V,
    JNI_DELETE_GLOBAL_REF, JNI_DELETE_LOCAL_REF,
    JNI_FIND_CLASS, JNI_GET_ARRAY_LENGTH, JNI_GET_BYTE_ARRAY_ELEMENTS, JNI_GET_METHOD_ID,
    JNI_GET_OBJECT_CLASS,
    JNI_GET_BYTE_ARRAY_REGION, JNI_GET_OBJECT_REF_TYPE, JNI_GET_STATIC_INT_FIELD,
    JNI_GET_STATIC_METHOD_ID,
    JNI_GET_PRIMITIVE_ARRAY_CRITICAL, JNI_GET_STRING_UTF_CHARS, JNI_GET_SUPERCLASS,
    JNI_IS_ASSIGNABLE_FROM, JNI_NEW_GLOBAL_REF, JNI_NEW_STRING_UTF,
    JNI_RELEASE_BYTE_ARRAY_ELEMENTS, JNI_RELEASE_STRING_UTF_CHARS, JVM_GET_ENV,
    JNI_RELEASE_PRIMITIVE_ARRAY_CRITICAL,
};
use crate::syscalls::{nr, SyscallTrace};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use uc::unicorn_const::{Arch, Mode, Prot};
use uc::{RegisterARM64, Unicorn};

const MAIN_BASE: u64 = 0x4000_0000;
const LIBCXX_BASE: u64 = 0x5000_0000;
const STACK_BASE: u64 = 0x7000_0000;
const STACK_SIZE: u64 = 8 * 1024 * 1024;
const HEAP_BASE: u64 = 0x8000_0000;
const HEAP_SIZE: u64 = 64 * 1024 * 1024;
const STUB_BASE: u64 = 0xA000_0000;
const STUB_SIZE: u64 = 0x20_000;
const JNIENV_BASE: u64 = 0xB000_0000;
const JNIENV_SIZE: u64 = 0x20_000;
const HALT_BASE: u64 = 0xC000_0000;
const HALT_SIZE: u64 = 0x1000;
const TLS_BASE: u64 = 0xD000_0000;
const TLS_SIZE: u64 = 0x1000;

const SIGN_OFFSET: u64 = 0x168c80;
const JNI_ON_LOAD_OFFSET: u64 = 0x58b80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub so_path: String,
    pub cpp_path: Option<String>,
    pub cert_path: Option<String>,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub header_order: Option<Vec<String>>,
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

pub struct EmulatorState {
    pub main_base: u64,
    pub libcxx_base: u64,
    pub heap_top: u64,
    pub stack_top: u64,
    pub stubs: StubTable,
    pub jni: JniState,
    pub cert: Option<Vec<u8>>,
    pub trace: SyscallTrace,
    pub jni_env: u64,
    pub java_vm: u64,
    pub main_symbols: HashMap<String, u64>,
    pub libcxx_symbols: HashMap<String, u64>,
    pub next_fd: i32,
    pub files: HashMap<i32, Vec<u8>>,
    pub recent_imports: Vec<String>,
    pub pthread_keys: HashMap<u64, u64>,
    pub next_pthread_key: u32,
    pub pthread_once_done: HashMap<u64, bool>,
    pub jump_pc: Option<u64>,
    pub recent_pcs: Vec<u64>,
    pub recent_jni: Vec<String>,
    pub ms_ops: Vec<i32>,
    pub allocations: HashMap<u64, usize>,
}

pub struct Emulator {
    unicorn: Unicorn<'static, ()>,
    state: Rc<RefCell<EmulatorState>>,
    main: ElfImage,
    libcxx: Option<ElfImage>,
}

impl Emulator {
    pub fn open(so_path: &str, cpp_path: Option<&str>, cert_path: Option<&str>) -> Result<Self, String> {
        let main = ElfImage::parse(
            std::fs::read(so_path).map_err(|error| format!("read SO failed: {error}"))?,
        )?;
        let libcxx = match cpp_path {
            Some(path) if std::path::Path::new(path).exists() => Some(ElfImage::parse(
                std::fs::read(path).map_err(|error| format!("read libc++ failed: {error}"))?,
            )?),
            _ => None,
        };
        let cert = cert_path.and_then(|path| std::fs::read(path).ok());

        let mut unicorn = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
            .map_err(|error| format!("Unicorn init failed: {error}"))?;

        map_image(&mut unicorn, &main, MAIN_BASE)?;
        if let Some(libcxx) = &libcxx {
            map_image(&mut unicorn, libcxx, LIBCXX_BASE)?;
        }
        unicorn
            .mem_map(STACK_BASE, STACK_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map stack failed: {error}"))?;
        unicorn
            .mem_map(HEAP_BASE, HEAP_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map heap failed: {error}"))?;
        unicorn
            .mem_map(STUB_BASE, STUB_SIZE, Prot::READ | Prot::EXEC)
            .map_err(|error| format!("map stubs failed: {error}"))?;
        unicorn
            .mem_map(JNIENV_BASE, JNIENV_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map JNIEnv failed: {error}"))?;
        unicorn
            .mem_map(HALT_BASE, HALT_SIZE, Prot::READ | Prot::EXEC)
            .map_err(|error| format!("map halt page failed: {error}"))?;
        unicorn
            .mem_map(TLS_BASE, TLS_SIZE, Prot::READ | Prot::WRITE)
            .map_err(|error| format!("map TLS failed: {error}"))?;
        unicorn
            .mem_write(TLS_BASE + 0x28, &0x1234_5678_9abc_def0u64.to_le_bytes())
            .map_err(|error| format!("initialize TLS canary failed: {error}"))?;
        unicorn
            .reg_write(RegisterARM64::TPIDR_EL0, TLS_BASE)
            .map_err(|error| format!("set TPIDR_EL0 failed: {error}"))?;

        let mut main_symbols = HashMap::new();
        for (name, symbol) in &main.symbols {
            if !symbol.is_import {
                main_symbols.insert(name.clone(), MAIN_BASE + symbol.value);
            }
        }
        let mut libcxx_symbols = HashMap::new();
        if let Some(libcxx) = &libcxx {
            for (name, symbol) in &libcxx.symbols {
                if !symbol.is_import {
                    libcxx_symbols.insert(name.clone(), LIBCXX_BASE + symbol.value);
                }
            }
        }

        let state = Rc::new(RefCell::new(EmulatorState {
            main_base: MAIN_BASE,
            libcxx_base: LIBCXX_BASE,
            heap_top: HEAP_BASE + 0x1000,
            stack_top: STACK_BASE + STACK_SIZE - 0x1000,
            stubs: StubTable::new(STUB_BASE, STUB_SIZE),
            jni: JniState::new(),
            cert,
            trace: SyscallTrace::default(),
            jni_env: JNIENV_BASE + 0x2000,
            java_vm: JNIENV_BASE + 0x4000,
            main_symbols,
            libcxx_symbols,
            next_fd: 3,
            files: HashMap::new(),
            recent_imports: Vec::new(),
            pthread_keys: HashMap::new(),
            next_pthread_key: 1,
            pthread_once_done: HashMap::new(),
            jump_pc: None,
            recent_pcs: Vec::new(),
            recent_jni: Vec::new(),
            ms_ops: Vec::new(),
            allocations: HashMap::new(),
        }));

        apply_relocations(&mut unicorn, &main, MAIN_BASE, &state, true)?;
        if let Some(libcxx) = &libcxx {
            apply_relocations(&mut unicorn, libcxx, LIBCXX_BASE, &state, false)?;
        }
        setup_jni_tables(&mut unicorn, &state)?;

        let code_state = state.clone();
        unicorn
            .add_code_hook(STUB_BASE, STUB_BASE + STUB_SIZE, move |uc, address, _size| {
                let mut state = code_state.borrow_mut();
                if let Some(kind) = state.stubs.get(address).cloned() {
                    handle_stub(uc, &mut state, kind);
                }
            })
            .map_err(|error| format!("install code hook failed: {error}"))?;

        let syscall_state = state.clone();
        unicorn
            .add_intr_hook(move |uc, _intno| {
                let mut state = syscall_state.borrow_mut();
                handle_syscall(uc, &mut state);
            })
            .map_err(|error| format!("install interrupt hook failed: {error}"))?;

        let pc_state = state.clone();
        unicorn
            .add_code_hook(MAIN_BASE, MAIN_BASE + 0x40_0000, move |uc, address, _size| {
                if address == MAIN_BASE + 0x4e648 {
                    let x0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
                    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
                    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
                    let x3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
                    let x4 = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
                    let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(0);
                    let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
                    let word = |address: u64| {
                        uc.mem_read_as_vec(address, 8)
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                            .map(u64::from_le_bytes)
                            .unwrap_or(0)
                    };
                    eprintln!(
                        "[enter 4e648] x0={x0:x}[{:#x}] x1={x1:x} x2={x2:x}[{:#x}] x3={x3:x}[{:#x}] x4={x4:x}[{:#x},{:#x},{:#x}] lr={lr:x} sp={sp:x}",
                        word(x0),
                        word(x2),
                        word(x3),
                        word(x4),
                        word(x4 + 8),
                        word(x4 + 16)
                    );
                }
                if let Ok(mut state) = pc_state.try_borrow_mut() {
                    state.recent_pcs.push(address);
                    if state.recent_pcs.len() > 96 {
                        state.recent_pcs.remove(0);
                    }
                }
            })
            .map_err(|error| format!("install main trace hook failed: {error}"))?;
        if libcxx.is_some() {
            let pc_state = state.clone();
            unicorn
                .add_code_hook(
                    LIBCXX_BASE,
                    LIBCXX_BASE + 0x20_0000,
                    move |_uc, address, _size| {
                        if let Ok(mut state) = pc_state.try_borrow_mut() {
                            state.recent_pcs.push(address);
                            if state.recent_pcs.len() > 96 {
                                state.recent_pcs.remove(0);
                            }
                        }
                    },
                )
                .map_err(|error| format!("install libcxx trace hook failed: {error}"))?;
        }

        unicorn
            .reg_write(RegisterARM64::SP, STACK_BASE + STACK_SIZE - 0x1000)
            .map_err(|error| format!("set SP failed: {error}"))?;

        let mut emulator = Self {
            unicorn,
            state,
            main,
            libcxx,
        };
        emulator.run_initializers()?;
        Ok(emulator)
    }

    fn run_initializers(&mut self) -> Result<(), String> {
        let libcxx = self.libcxx.clone();
        if let Some(libcxx) = libcxx {
            self.run_image_initializers(&libcxx, LIBCXX_BASE)?;
        }
        let main = self.main.clone();
        self.run_image_initializers(&main, MAIN_BASE)
    }

    fn run_image_initializers(&mut self, image: &ElfImage, base: u64) -> Result<(), String> {
        let Some((address, size)) = image.init_array else {
            return Ok(());
        };
        let mut offset = 0u64;
        while offset + 8 <= size {
            let pointer = read_u64(&self.unicorn, base + address + offset)?;
            if pointer != 0 {
                self.call_function(pointer, &[])?;
            }
            offset += 8;
        }
        Ok(())
    }

    pub fn sign(&mut self, request: &SignRequest) -> SignResponse {
        let result = self.sign_inner(request);
        match result {
            Ok(headers) => SignResponse {
                ok: true,
                headers,
                error: None,
                diagnostics: Some(self.diagnostics()),
            },
            Err(error) => SignResponse {
                ok: false,
                headers: BTreeMap::new(),
                error: Some(error),
                diagnostics: Some(self.diagnostics()),
            },
        }
    }

    fn diagnostics(&self) -> BTreeMap<String, String> {
        let state = self.state.borrow();
        BTreeMap::from([
            ("main_base".to_string(), format!("0x{:x}", state.main_base)),
            (
                "libcxx_base".to_string(),
                format!("0x{:x}", state.libcxx_base),
            ),
            (
                "host_libraries".to_string(),
                self.main.needed.join(","),
            ),
            ("syscalls".to_string(), state.trace.summary()),
            ("jni_objects".to_string(), state.jni.objects.len().to_string()),
            ("stubs".to_string(), state.stubs.kinds.len().to_string()),
            ("recent_imports".to_string(), state.recent_imports.join(",")),
            (
                "recent_pcs".to_string(),
                state
                    .recent_pcs
                    .iter()
                    .map(|address| format!("{address:x}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("recent_jni".to_string(), state.recent_jni.join(",")),
            (
                "ms_ops".to_string(),
                state
                    .ms_ops
                    .iter()
                    .map(i32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ])
    }

    fn sign_inner(&mut self, request: &SignRequest) -> Result<BTreeMap<String, String>, String> {
        let url_addr = self.write_heap_cstring(&request.url)?;
        let mut header_text = String::new();
        if let Some(order) = &request.header_order {
            for key in order {
                if let Some(value) = request.headers.get(key) {
                    header_text.push_str(key);
                    header_text.push_str("\r\n");
                    header_text.push_str(value);
                    header_text.push_str("\r\n");
                }
            }
        } else {
            for (key, value) in &request.headers {
                header_text.push_str(key);
                header_text.push_str("\r\n");
                header_text.push_str(value);
                header_text.push_str("\r\n");
            }
        }
        let header_addr = self.write_heap_cstring(&header_text)?;

        let vm = self.state.borrow().java_vm;
        self.state.borrow_mut().recent_jni.clear();
        let _jni_version = self.call_function(MAIN_BASE + JNI_ON_LOAD_OFFSET, &[vm, 0])?;
        eprintln!(
            "[jni_onload] ret={:#x} calls={:?}",
            _jni_version,
            self.state.borrow().recent_jni
        );
        self.state.borrow_mut().recent_jni.clear();
        let result = self.call_function(MAIN_BASE + SIGN_OFFSET, &[url_addr, header_addr])?;
        if result == 0 {
            return Err("native sign function returned null".to_string());
        }
        let text = self.read_cstring(result)?;
        let raw = self
            .unicorn
            .mem_read_as_vec(result, 128)
            .unwrap_or_default();
        eprintln!(
            "[sign-result] ptr=0x{result:x} len={} text={:?} raw={}",
            text.len(),
            text,
            raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        );
        let scan_start = HEAP_BASE;
        let scan_len = (self.state.borrow().heap_top.saturating_sub(scan_start)).min(0x100000);
        if let Ok(heap) = self.unicorn.mem_read_as_vec(scan_start, scan_len as usize) {
            if let Some(offset) = heap.windows(8).position(|window| window == b"X-Gorgon") {
                eprintln!("[sign-result] X-Gorgon found at heap+0x{offset:x}");
            }
        }
        Ok(parse_signature_text(&text))
    }

    fn call_function(&mut self, address: u64, args: &[u64]) -> Result<u64, String> {
        for register in [
            RegisterARM64::X0,
            RegisterARM64::X1,
            RegisterARM64::X2,
            RegisterARM64::X3,
            RegisterARM64::X4,
            RegisterARM64::X5,
            RegisterARM64::X6,
            RegisterARM64::X7,
            RegisterARM64::X8,
            RegisterARM64::X9,
            RegisterARM64::X10,
            RegisterARM64::X11,
            RegisterARM64::X12,
            RegisterARM64::X13,
            RegisterARM64::X14,
            RegisterARM64::X15,
            RegisterARM64::X16,
            RegisterARM64::X17,
            RegisterARM64::X18,
            RegisterARM64::X19,
            RegisterARM64::X20,
            RegisterARM64::X21,
            RegisterARM64::X22,
            RegisterARM64::X23,
            RegisterARM64::X24,
            RegisterARM64::X25,
            RegisterARM64::X26,
            RegisterARM64::X27,
            RegisterARM64::X28,
            RegisterARM64::X29,
        ] {
            self.unicorn
                .reg_write(register, 0)
                .map_err(|error| format!("clear register failed: {error}"))?;
        }

        for (index, value) in args.iter().enumerate() {
            let register = match index {
                0 => RegisterARM64::X0,
                1 => RegisterARM64::X1,
                2 => RegisterARM64::X2,
                3 => RegisterARM64::X3,
                4 => RegisterARM64::X4,
                5 => RegisterARM64::X5,
                _ => return Err("too many arguments".to_string()),
            };
            self.unicorn
                .reg_write(register, *value)
                .map_err(|error| format!("set arg failed: {error}"))?;
        }
        self.unicorn
            .reg_write(RegisterARM64::LR, HALT_BASE)
            .map_err(|error| format!("set LR failed: {error}"))?;
        self.unicorn
            .emu_start(address, HALT_BASE, 0, 0)
            .map_err(|error| {
                let pc = self
                    .unicorn
                    .reg_read(RegisterARM64::PC)
                    .map(|value| format!("0x{value:x}"))
                    .unwrap_or_else(|_| "?".to_string());
                let lr = self
                    .unicorn
                    .reg_read(RegisterARM64::LR)
                    .map(|value| format!("0x{value:x}"))
                    .unwrap_or_else(|_| "?".to_string());
                let sp = self
                    .unicorn
                    .reg_read(RegisterARM64::SP)
                    .map(|value| format!("0x{value:x}"))
                    .unwrap_or_else(|_| "?".to_string());
                let x0 = self
                    .unicorn
                    .reg_read(RegisterARM64::X0)
                    .map(|value| format!("0x{value:x}"))
                    .unwrap_or_else(|_| "?".to_string());
                let x8 = self
                    .unicorn
                    .reg_read(RegisterARM64::X8)
                    .map(|value| format!("0x{value:x}"))
                    .unwrap_or_else(|_| "?".to_string());
                format!(
                    "emulation failed at 0x{address:x} (pc={pc}, lr={lr}, sp={sp}, x0={x0}, x8={x8}): {error}"
                )
            })?;
        self.unicorn
            .reg_read(RegisterARM64::X0)
            .map_err(|error| format!("read X0 failed: {error}"))
    }

    fn write_heap_cstring(&mut self, value: &str) -> Result<u64, String> {
        let mut state = self.state.borrow_mut();
        let address = state.heap_top;
        let bytes = value.as_bytes();
        state.heap_top = align_up(state.heap_top + bytes.len() as u64 + 1, 0x10);
        self.unicorn
            .mem_write(address, bytes)
            .map_err(|error| format!("write string failed: {error}"))?;
        self.unicorn
            .mem_write(address + bytes.len() as u64, &[0])
            .map_err(|error| format!("write NUL failed: {error}"))?;
        Ok(address)
    }

    fn read_cstring(&self, address: u64) -> Result<String, String> {
        read_cstring(&self.unicorn, address)
    }
}

fn map_image(unicorn: &mut Unicorn<'_, ()>, image: &ElfImage, base: u64) -> Result<(), String> {
    let first = image
        .segments
        .iter()
        .map(|segment| base + segment.virtual_address)
        .min()
        .ok_or_else(|| "ELF has no loadable segments".to_string())?;
    let last = image
        .segments
        .iter()
        .map(|segment| base + segment.virtual_address + segment.memory_size)
        .max()
        .ok_or_else(|| "ELF has no loadable segments".to_string())?;
    let map_start = align_down(first, 0x1000);
    let map_end = align_up(last.max(map_start + 1), 0x1000);
    unicorn
        .mem_map(map_start, map_end - map_start, Prot::ALL)
        .map_err(|error| format!("map image 0x{map_start:x} failed: {error}"))?;

    for segment in &image.segments {
        let start = base + segment.virtual_address;
        if segment.file_size > 0 {
            let begin = segment.file_offset as usize;
            let end = begin + segment.file_size as usize;
            if end > image.bytes.len() {
                return Err("ELF segment exceeds file size".to_string());
            }
            unicorn
                .mem_write(start, &image.bytes[begin..end])
                .map_err(|error| format!("write 0x{start:x} failed: {error}"))?;
        }
    }
    Ok(())
}

fn apply_relocations(
    unicorn: &mut Unicorn<'_, ()>,
    image: &ElfImage,
    base: u64,
    state: &Rc<RefCell<EmulatorState>>,
    prefer_main: bool,
) -> Result<(), String> {
    for relocation in &image.relocations {
        let target = base + relocation.offset;
        if image.is_relative_relocation(relocation) {
            let value = base.wrapping_add(relocation.addend as u64);
            write_u64(unicorn, target, value)?;
            continue;
        }
        if image.is_symbol_relocation(relocation) {
            let name = relocation.symbol.clone().unwrap_or_default();
            let value = {
                let mut state = state.borrow_mut();
                let address = if prefer_main {
                    state
                        .main_symbols
                        .get(&name)
                        .or_else(|| state.libcxx_symbols.get(&name))
                        .copied()
                } else {
                    state
                        .libcxx_symbols
                        .get(&name)
                        .or_else(|| state.main_symbols.get(&name))
                        .copied()
                };
                address.unwrap_or_else(|| state.stubs.alloc(StubKind::Import(name)))
            };
            write_u64(unicorn, target, value)?;
        }
    }
    Ok(())
}

fn setup_jni_tables(
    unicorn: &mut Unicorn<'_, ()>,
    state: &Rc<RefCell<EmulatorState>>,
) -> Result<(), String> {
    let mut state = state.borrow_mut();
    let table = JNIENV_BASE + 0x1000;
    let env = state.jni_env;
    write_u64(unicorn, env, table)?;
    for index in 0..=260u32 {
        let stub = state.stubs.alloc(StubKind::Jni(index));
        write_u64(unicorn, table + index as u64 * 8, stub)?;
    }

    let vm_table = JNIENV_BASE + 0x3000;
    let vm = state.java_vm;
    write_u64(unicorn, vm, vm_table)?;
    for index in 0..=10u32 {
        let stub = state.stubs.alloc(StubKind::JavaVm(index));
        write_u64(unicorn, vm_table + index as u64 * 8, stub)?;
    }
    Ok(())
}

fn handle_stub(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState, kind: StubKind) {
    let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(HALT_BASE);
    match kind {
        StubKind::Jni(index) => handle_jni(uc, state, index),
        StubKind::JavaVm(index) => handle_java_vm(uc, state, index),
        StubKind::Import(name) => handle_import(uc, state, &name),
    }
    let _ = uc.reg_write(RegisterARM64::PC, state.jump_pc.take().unwrap_or(lr));
}

fn handle_jni(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState, index: u32) {
    let x0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
    let x3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
    let x4 = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
    state
        .recent_jni
        .push(format!("{index}({x0:x},{x1:x},{x2:x},{x3:x},{x4:x})"));
    if state.recent_jni.len() > 48 {
        state.recent_jni.remove(0);
    }
    match index {
        JNI_FIND_CLASS => {
            let name = read_cstring(uc, x1).unwrap_or_default();
            let handle = state.jni.alloc_class(name);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_GET_SUPERCLASS => {
            let name = match state.jni.get(x1) {
                Some(JniObject::Class(name)) => name.clone(),
                _ => String::new(),
            };
            if name.is_empty() || name == "java/lang/Object" {
                let _ = uc.reg_write(RegisterARM64::X0, 0);
            } else {
                let handle = state.jni.alloc_class("java/lang/Object");
                let _ = uc.reg_write(RegisterARM64::X0, handle);
            }
        }
        JNI_IS_ASSIGNABLE_FROM => {
            let _ = uc.reg_write(RegisterARM64::X0, 1);
        }
        JNI_NEW_GLOBAL_REF => {
            let value = state
                .jni
                .get(x1)
                .cloned()
                .unwrap_or(JniObject::Null);
            let handle = state.jni.alloc(value);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_DELETE_GLOBAL_REF | JNI_DELETE_LOCAL_REF => {
            state.jni.objects.remove(&x1);
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        JNI_GET_OBJECT_REF_TYPE => {
            let _ = uc.reg_write(RegisterARM64::X0, 1);
        }
        JNI_GET_OBJECT_CLASS => {
            let class_name = match state.jni.get(x1) {
                Some(JniObject::String(_)) => "java/lang/String",
                Some(JniObject::ByteArray(_)) => "[B",
                Some(JniObject::Integer(_)) => "java/lang/Integer",
                Some(JniObject::Long(_)) => "java/lang/Long",
                Some(JniObject::Boolean(_)) => "java/lang/Boolean",
                Some(JniObject::Class(_)) => "java/lang/Class",
                Some(JniObject::Method { .. }) => "java/lang/reflect/Method",
                _ => "java/lang/Object",
            };
            let handle = state.jni.alloc_class(class_name);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_GET_METHOD_ID | JNI_GET_STATIC_METHOD_ID => {
            let class = match state.jni.get(x1) {
                Some(JniObject::Class(name)) => name.clone(),
                _ => String::new(),
            };
            let name = read_cstring(uc, x2).unwrap_or_default();
            let sig = read_cstring(uc, x3).unwrap_or_default();
            let handle = state.jni.alloc_method(class, name, sig);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_CALL_STATIC_OBJECT_METHOD_V => {
            let (class, name) = match state.jni.get(x2) {
                Some(JniObject::Method { class, name, .. }) => (class.clone(), name.clone()),
                _ => (String::new(), String::new()),
            };
            let value = if name == "b" && class.contains("mobsec") {
                let op = read_va_list_i32(uc, x3).unwrap_or(0);
                state.ms_ops.push(op);
                state.recent_jni.push(format!("MS.b-op={op}"));
                let value = ms_b(op, state.cert.as_deref(), now_ms());
                jni_value(value)
            } else if name == "currentThread" {
                JniObject::String("java/lang/Thread".to_string())
            } else {
                JniObject::Null
            };
            let handle = state.jni.alloc(value);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_CALL_OBJECT_METHOD_V => {
            let (name, sig) = match state.jni.get(x2) {
                Some(JniObject::Method { name, sig, .. }) => (name.clone(), sig.clone()),
                _ => (String::new(), String::new()),
            };
            let value = if name.contains("getBytes") || sig.contains("getBytes") {
                let text = match state.jni.get(x1) {
                    Some(JniObject::String(value)) => value.clone(),
                    _ => String::new(),
                };
                state
                    .recent_jni
                    .push(format!("getBytes-obj={} len={}", jni_type_name(state.jni.get(x1)), text.len()));
                JniObject::ByteArray(text.into_bytes())
            } else if name.contains("currentThread") || sig.contains("currentThread") {
                JniObject::String("java/lang/Thread".to_string())
            } else if name.contains("getStackTrace") || sig.contains("getStackTrace") {
                JniObject::Null
            } else {
                JniObject::Null
            };
            let handle = state.jni.alloc(value);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_CALL_BOOLEAN_METHOD_V | JNI_CALL_INT_METHOD_V | JNI_CALL_LONG_METHOD_V => {
            let method = match state.jni.get(x2) {
                Some(JniObject::Method { sig, name, .. }) => format!("{name}:{sig}"),
                _ => String::new(),
            };
            let value = if method.contains("booleanValue")
                || method.contains("intValue")
                || method.contains("longValue")
            {
                jni_numeric_value(state.jni.get(x1)).unwrap_or(0)
            } else {
                0
            };
            let _ = uc.reg_write(RegisterARM64::X0, value);
        }
        JNI_CALL_VOID_METHOD_V => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        JNI_GET_STATIC_INT_FIELD => {
            let _ = uc.reg_write(RegisterARM64::X0, 64);
        }
        JNI_CALL_STATIC_INT_METHOD_V => {
            let _ = uc.reg_write(RegisterARM64::X0, 64);
        }
        JNI_NEW_STRING_UTF => {
            let value = read_cstring(uc, x1).unwrap_or_default();
            let handle = state.jni.alloc_string(value);
            let _ = uc.reg_write(RegisterARM64::X0, handle);
        }
        JNI_GET_STRING_UTF_CHARS => {
            let text = match state.jni.get(x1) {
                Some(JniObject::String(value)) => value.clone(),
                _ => String::new(),
            };
            let address = alloc_bytes(uc, state, text.as_bytes());
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        JNI_RELEASE_STRING_UTF_CHARS | JNI_RELEASE_BYTE_ARRAY_ELEMENTS => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        JNI_GET_BYTE_ARRAY_REGION => {
            let bytes = match state.jni.get(x1) {
                Some(JniObject::ByteArray(value)) => value.clone(),
                _ => Vec::new(),
            };
            let start = x2 as usize;
            let len = x3 as usize;
            state.recent_jni.push(format!(
                "region-type={} start={start} len={len} dst=0x{x4:x} avail={}",
                jni_type_name(state.jni.get(x1)),
                bytes.len()
            ));
            if x4 != 0 && start <= bytes.len() && len <= bytes.len().saturating_sub(start) {
                let _ = uc.mem_write(x4, &bytes[start..start + len]);
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        JNI_GET_PRIMITIVE_ARRAY_CRITICAL => {
            let value = match state.jni.get(x1) {
                Some(JniObject::ByteArray(value)) => value.clone(),
                _ => Vec::new(),
            };
            let address = alloc_bytes(uc, state, &value);
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        JNI_RELEASE_PRIMITIVE_ARRAY_CRITICAL => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        JNI_GET_ARRAY_LENGTH => {
            let length = match state.jni.get(x1) {
                Some(JniObject::ByteArray(value)) => value.len() as u64,
                _ => 0,
            };
            let _ = uc.reg_write(RegisterARM64::X0, length);
        }
        JNI_GET_BYTE_ARRAY_ELEMENTS => {
            let value = match state.jni.get(x1) {
                Some(JniObject::ByteArray(value)) => value.clone(),
                _ => Vec::new(),
            };
            let address = alloc_bytes(uc, state, &value);
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        _ => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
    }
}

fn handle_java_vm(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState, index: u32) {
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    match index {
        JVM_GET_ENV => {
            if x1 != 0 {
                let _ = write_u64(uc, x1, state.jni_env);
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        _ => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
    }
}

fn handle_import(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState, name: &str) {
    let x0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
    let x3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
    state.recent_imports.push(format!("{name}({x0:x},{x1:x},{x2:x},{x3:x})"));
    if state.recent_imports.len() > 24 {
        state.recent_imports.remove(0);
    }
    match name {
        "malloc" | "memalign" => {
            let size = if name == "memalign" { x1 } else { x0 };
            let address = alloc_heap(state, size.max(16));
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        "calloc" => {
            let size = x0.saturating_mul(x1).max(16);
            let address = alloc_heap(state, size);
            let _ = uc.mem_write(address, &vec![0u8; size as usize]);
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        "realloc" => {
            let new_size = x1.max(16);
            let address = alloc_heap(state, new_size);
            if x0 != 0 {
                let old_size = state.allocations.get(&x0).copied().unwrap_or(0);
                let copy_size = old_size.min(new_size as usize);
                if copy_size > 0 {
                    let data = uc.mem_read_as_vec(x0, copy_size).unwrap_or_default();
                    let _ = uc.mem_write(address, &data);
                }
                state.allocations.remove(&x0);
            }
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        "posix_memalign" => {
            let address = alloc_heap(state, x2.max(16));
            if x0 != 0 {
                let _ = write_u64(uc, x0, address);
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "free" => {
            state.allocations.remove(&x0);
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "memcpy" | "memmove" | "__memcpy_chk" | "__memmove_chk" => {
            let size = if name.contains("chk") { x3 } else { x2 };
            let data = uc.mem_read_as_vec(x1, size as usize).unwrap_or_default();
            let _ = uc.mem_write(x0, &data);
            let _ = uc.reg_write(RegisterARM64::X0, x0);
        }
        "memset" | "__memset_chk" => {
            let size = if name.contains("chk") { x3 } else { x2 };
            let _ = uc.mem_write(x0, &vec![x1 as u8; size as usize]);
            let _ = uc.reg_write(RegisterARM64::X0, x0);
        }
        "strlen" => {
            let value = read_cstring(uc, x0).unwrap_or_default();
            let _ = uc.reg_write(RegisterARM64::X0, value.len() as u64);
        }
        "strcmp" | "strcasecmp" => {
            let a = read_cstring(uc, x0).unwrap_or_default();
            let b = read_cstring(uc, x1).unwrap_or_default();
            let _ = uc.reg_write(RegisterARM64::X0, if a == b { 0 } else { 1 });
        }
        "strncmp" => {
            let a = read_cstring(uc, x0).unwrap_or_default();
            let b = read_cstring(uc, x1).unwrap_or_default();
            let n = x2 as usize;
            let _ = uc.reg_write(RegisterARM64::X0, if a.as_bytes()[..a.len().min(n)] == b.as_bytes()[..b.len().min(n)] { 0 } else { 1 });
        }
        "strchr" => {
            let text = read_cstring(uc, x0).unwrap_or_default();
            let needle = x1 as u8 as char;
            let _ = uc.reg_write(RegisterARM64::X0, if text.contains(needle) { x0 } else { 0 });
        }
        "strtol" | "strtoll" | "strtol_l" | "strtoll_l" => {
            let text = read_cstring(uc, x0).unwrap_or_default();
            let (value, consumed) = parse_integer_prefix(&text, x2 as u32, true);
            if x1 != 0 {
                let _ = write_u64(uc, x1, x0 + consumed as u64);
            }
            let _ = uc.reg_write(RegisterARM64::X0, value as u64);
        }
        "strtoul" | "strtoull" | "strtoull_l" => {
            let text = read_cstring(uc, x0).unwrap_or_default();
            let (value, consumed) = parse_integer_prefix(&text, x2 as u32, false);
            if x1 != 0 {
                let _ = write_u64(uc, x1, x0 + consumed as u64);
            }
            let _ = uc.reg_write(RegisterARM64::X0, value);
        }
        "atoi" | "atol" | "atoll" => {
            let text = read_cstring(uc, x0).unwrap_or_default();
            let (value, _) = parse_integer_prefix(&text, 10, true);
            let _ = uc.reg_write(RegisterARM64::X0, value as u64);
        }
        "strcpy" | "strncpy" => {
            let text = read_cstring(uc, x1).unwrap_or_default();
            let _ = uc.mem_write(x0, text.as_bytes());
            let _ = uc.mem_write(x0 + text.len() as u64, &[0]);
            let _ = uc.reg_write(RegisterARM64::X0, x0);
        }
        "strdup" => {
            let text = read_cstring(uc, x0).unwrap_or_default();
            let address = alloc_bytes(uc, state, text.as_bytes());
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        "gettimeofday" => {
            if x0 != 0 {
                let _ = write_u64(uc, x0, now_sec());
                let _ = write_u64(uc, x0 + 8, 0);
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "clock_gettime" => {
            if x1 != 0 {
                let _ = write_u64(uc, x1, now_sec());
                let _ = write_u64(uc, x1 + 8, 0);
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "time" => {
            if x0 != 0 {
                let _ = write_u64(uc, x0, now_sec());
            }
            let _ = uc.reg_write(RegisterARM64::X0, now_sec());
        }
        "pthread_key_create" => {
            let key = state.next_pthread_key;
            state.next_pthread_key += 1;
            if x0 != 0 {
                let _ = uc.mem_write(x0, &key.to_le_bytes());
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "pthread_setspecific" => {
            state.pthread_keys.insert(x0, x1);
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "pthread_getspecific" => {
            let value = state.pthread_keys.get(&x0).copied().unwrap_or(0);
            let _ = uc.reg_write(RegisterARM64::X0, value);
        }
        "pthread_key_delete" => {
            state.pthread_keys.remove(&x0);
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "pthread_once" => {
            if !state.pthread_once_done.contains_key(&x0) {
                state.pthread_once_done.insert(x0, true);
                if x1 != 0 {
                    state.jump_pc = Some(x1);
                }
            }
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "pthread_mutex_init" | "pthread_mutex_lock" | "pthread_mutex_unlock"
        | "pthread_mutex_destroy" | "pthread_cond_init" | "pthread_cond_wait"
        | "pthread_cond_signal" | "pthread_cond_broadcast" | "pthread_cond_destroy"
        | "pthread_create" | "pthread_detach" => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "getpid" => {
            let _ = uc.reg_write(RegisterARM64::X0, 1000);
        }
        "gettid" => {
            let _ = uc.reg_write(RegisterARM64::X0, 1001);
        }
        "rand" => {
            let _ = uc.reg_write(RegisterARM64::X0, 0x1234_5678);
        }
        "srand" => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "mmap" => {
            let address = alloc_heap(state, 0x1000);
            let _ = uc.reg_write(RegisterARM64::X0, address);
        }
        "syscall" => {
            let result = match x0 {
                nr::GETPID => 1000,
                nr::GETTID => 1001,
                nr::CLOCK_GETTIME => {
                    if x2 != 0 {
                        let _ = write_u64(uc, x2, now_sec());
                        let _ = write_u64(uc, x2 + 8, 0);
                    }
                    0
                }
                _ => 0,
            };
            let _ = uc.reg_write(RegisterARM64::X0, result);
        }
        "munmap" | "mprotect" => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "dlopen" | "dlsym" => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
        "abort" | "exit" | "__stack_chk_fail" => {
            let _ = uc.emu_stop();
        }
        _ => {
            let _ = uc.reg_write(RegisterARM64::X0, 0);
        }
    }
}

fn handle_syscall(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState) {
    let number = uc.reg_read(RegisterARM64::X8).unwrap_or(u64::MAX);
    let x0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
    let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(HALT_BASE);
    state.trace.note(number);
    let result = match number {
        nr::MMAP => alloc_heap(state, x1.max(0x1000)),
        nr::MUNMAP | nr::MPROTECT => 0,
        nr::GETPID => 1000,
        nr::GETTID => 1001,
        nr::FUTEX => 0,
        nr::CLOCK_GETTIME | nr::GETTIMEOFDAY => {
            if x1 != 0 {
                let _ = write_u64(uc, x1, now_sec());
                let _ = write_u64(uc, x1 + 8, 0);
            }
            0
        }
        nr::PRCTL => 0,
        nr::CLONE => 1002,
        nr::BRK => {
            if x0 > state.heap_top {
                state.heap_top = x0;
            }
            state.heap_top
        }
        nr::OPENAT => {
            let path = read_cstring(uc, x1).unwrap_or_default();
            let fd = state.next_fd;
            state.next_fd += 1;
            state.files.insert(fd, path.into_bytes());
            fd as u64
        }
        nr::CLOSE => {
            state.files.remove(&(x0 as i32));
            0
        }
        nr::READ => 0,
        nr::FSTAT => {
            if x1 != 0 {
                let _ = uc.mem_write(x1, &[0u8; 128]);
            }
            0
        }
        nr::FACCESSAT => 0,
        _ => 0,
    };
    let _ = uc.reg_write(RegisterARM64::X0, result);
    let _ = uc.reg_write(RegisterARM64::PC, lr);
}

fn read_va_list_i32(uc: &Unicorn<'_, ()>, va_list: u64) -> Option<i32> {
    let base_p = read_u64(uc, va_list).ok()?;
    let base_integer = read_u64(uc, va_list + 8).ok()?;
    let mask_integer = read_i32(uc, va_list + 24).ok()?;
    let mut mask = mask_integer;
    if mask & i32::MIN != 0 && mask + 8 <= 0 {
        let pointer = base_integer.wrapping_add(mask as i64 as u64);
        read_i32(uc, pointer).ok()
    } else {
        read_i32(uc, base_p).ok()
    }
}

fn jni_value(value: MsValue) -> JniObject {
    match value {
        MsValue::Null => JniObject::Null,
        MsValue::Bool(value) => JniObject::Boolean(value),
        MsValue::Int(value) => JniObject::Integer(value),
        MsValue::Long(value) => JniObject::Long(value),
        MsValue::Str(value) => JniObject::String(value),
        MsValue::Bytes(value) => JniObject::ByteArray(value),
    }
}

fn jni_numeric_value(object: Option<&JniObject>) -> Option<u64> {
    match object {
        Some(JniObject::Boolean(value)) => Some(u64::from(*value)),
        Some(JniObject::Integer(value)) => Some(*value as u64),
        Some(JniObject::Long(value)) => Some(*value),
        _ => None,
    }
}

fn jni_type_name(object: Option<&JniObject>) -> &'static str {
    match object {
        Some(JniObject::Class(_)) => "class",
        Some(JniObject::Method { .. }) => "method",
        Some(JniObject::String(_)) => "string",
        Some(JniObject::ByteArray(_)) => "byte-array",
        Some(JniObject::Integer(_)) => "integer",
        Some(JniObject::Long(_)) => "long",
        Some(JniObject::Boolean(_)) => "boolean",
        Some(JniObject::Null) | None => "null",
    }
}

fn alloc_heap(state: &mut EmulatorState, size: u64) -> u64 {
    let address = state.heap_top;
    let size = size.max(16);
    state.heap_top = align_up(state.heap_top + size, 0x10);
    state.allocations.insert(address, size as usize);
    address
}

fn alloc_bytes(uc: &mut Unicorn<'_, ()>, state: &mut EmulatorState, bytes: &[u8]) -> u64 {
    let address = alloc_heap(state, bytes.len() as u64 + 1);
    let _ = uc.mem_write(address, bytes);
    let _ = uc.mem_write(address + bytes.len() as u64, &[0]);
    address
}

fn read_cstring(uc: &Unicorn<'_, ()>, address: u64) -> Result<String, String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    for offset in 0..4096u64 {
        let byte = uc
            .mem_read_as_vec(address + offset, 1)
            .map_err(|error| format!("read string failed: {error}"))?;
        if byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn read_u64(uc: &Unicorn<'_, ()>, address: u64) -> Result<u64, String> {
    let bytes = uc
        .mem_read_as_vec(address, 8)
        .map_err(|error| format!("read u64 failed: {error}"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])))
}

fn write_u64(uc: &mut Unicorn<'_, ()>, address: u64, value: u64) -> Result<(), String> {
    uc.mem_write(address, &value.to_le_bytes())
        .map_err(|error| format!("write u64 failed: {error}"))
}

fn read_i32(uc: &Unicorn<'_, ()>, address: u64) -> Result<i32, String> {
    let bytes = uc
        .mem_read_as_vec(address, 4)
        .map_err(|error| format!("read i32 failed: {error}"))?;
    Ok(i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
}

fn parse_integer_prefix(text: &str, requested_base: u32, signed: bool) -> (u64, usize) {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }

    let negative = if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        let negative = bytes[index] == b'-';
        index += 1;
        negative
    } else {
        false
    };

    let mut base = requested_base;
    if base == 0 {
        base = if index + 1 < bytes.len() && bytes[index] == b'0' {
            match bytes[index + 1] {
                b'x' | b'X' => {
                    index += 2;
                    16
                }
                b'o' | b'O' => {
                    index += 2;
                    8
                }
                b'b' | b'B' => {
                    index += 2;
                    2
                }
                _ => 10,
            }
        } else {
            10
        };
    } else if base == 16
        && index + 1 < bytes.len()
        && bytes[index] == b'0'
        && matches!(bytes[index + 1], b'x' | b'X')
    {
        index += 2;
    }

    let digits_start = index;
    let mut value = 0u64;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => (bytes[index] - b'0') as u32,
            b'a'..=b'z' => (bytes[index] - b'a' + 10) as u32,
            b'A'..=b'Z' => (bytes[index] - b'A' + 10) as u32,
            _ => break,
        };
        if digit >= base || base < 2 || base > 36 {
            break;
        }
        value = value.wrapping_mul(base as u64).wrapping_add(digit as u64);
        index += 1;
    }

    if index == digits_start {
        return (0, 0);
    }
    if signed && negative {
        value = 0u64.wrapping_sub(value);
    }
    (value, index)
}

fn parse_signature_text(text: &str) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index + 1 < lines.len() {
        let key = lines[index].trim();
        if key.starts_with("X-") {
            headers.insert(key.to_string(), lines[index + 1].trim().to_string());
        }
        index += 2;
    }
    headers
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    now_sec() * 1000
}
