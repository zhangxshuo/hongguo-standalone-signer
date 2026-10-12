use crate::jni::MsValue;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum StubKind {
    Import(String),
    Jni(u32),
    JavaVm(u32),
}

#[derive(Debug)]
pub struct StubTable {
    pub base: u64,
    pub size: u64,
    pub next: u64,
    pub kinds: HashMap<u64, StubKind>,
}

impl StubTable {
    pub fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            next: 0,
            kinds: HashMap::new(),
        }
    }

    pub fn alloc(&mut self, kind: StubKind) -> u64 {
        let address = self.base + self.next;
        self.next += 0x10;
        self.kinds.insert(address, kind);
        address
    }

    pub fn get(&self, address: u64) -> Option<&StubKind> {
        self.kinds.get(&address)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.base + self.size
    }
}

pub const JNI_FIND_CLASS: u32 = 6;
pub const JNI_GET_SUPERCLASS: u32 = 10;
pub const JNI_IS_ASSIGNABLE_FROM: u32 = 11;
pub const JNI_NEW_GLOBAL_REF: u32 = 21;
pub const JNI_DELETE_GLOBAL_REF: u32 = 22;
pub const JNI_DELETE_LOCAL_REF: u32 = 23;
pub const JNI_GET_OBJECT_CLASS: u32 = 31;
pub const JNI_GET_METHOD_ID: u32 = 33;
pub const JNI_CALL_BOOLEAN_METHOD_V: u32 = 38;
pub const JNI_CALL_OBJECT_METHOD_V: u32 = 35;
pub const JNI_CALL_INT_METHOD_V: u32 = 50;
pub const JNI_CALL_LONG_METHOD_V: u32 = 53;
pub const JNI_CALL_VOID_METHOD_V: u32 = 62;
pub const JNI_GET_STATIC_METHOD_ID: u32 = 113;
pub const JNI_CALL_STATIC_OBJECT_METHOD_V: u32 = 115;
pub const JNI_CALL_STATIC_INT_METHOD_V: u32 = 130;
pub const JNI_NEW_STRING_UTF: u32 = 167;
pub const JNI_GET_STRING_UTF_CHARS: u32 = 169;
pub const JNI_RELEASE_STRING_UTF_CHARS: u32 = 170;
pub const JNI_GET_ARRAY_LENGTH: u32 = 171;
pub const JNI_GET_BYTE_ARRAY_ELEMENTS: u32 = 184;
pub const JNI_RELEASE_BYTE_ARRAY_ELEMENTS: u32 = 192;
pub const JNI_GET_BYTE_ARRAY_REGION: u32 = 200;
pub const JNI_GET_PRIMITIVE_ARRAY_CRITICAL: u32 = 222;
pub const JNI_RELEASE_PRIMITIVE_ARRAY_CRITICAL: u32 = 223;
pub const JNI_GET_STATIC_INT_FIELD: u32 = 150;
pub const JNI_GET_OBJECT_REF_TYPE: u32 = 232;

pub const JVM_GET_ENV: u32 = 6;

#[derive(Debug, Clone)]
pub enum JniObject {
    Class(String),
    Method {
        class: String,
        name: String,
        sig: String,
    },
    String(String),
    ByteArray(Vec<u8>),
    Integer(i32),
    Long(u64),
    Boolean(bool),
    Null,
}

impl JniObject {
    pub fn as_ms_value(&self) -> MsValue {
        match self {
            JniObject::Integer(value) => MsValue::Int(*value),
            JniObject::Long(value) => MsValue::Long(*value),
            JniObject::Boolean(value) => MsValue::Bool(*value),
            JniObject::String(value) => MsValue::Str(value.clone()),
            JniObject::ByteArray(value) => MsValue::Bytes(value.clone()),
            _ => MsValue::Null,
        }
    }
}

#[derive(Debug, Default)]
pub struct JniState {
    next_handle: u64,
    pub objects: HashMap<u64, JniObject>,
}

impl JniState {
    pub fn new() -> Self {
        Self {
            next_handle: 0x2000_0000,
            objects: HashMap::new(),
        }
    }

    pub fn alloc(&mut self, object: JniObject) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 0x10;
        self.objects.insert(handle, object);
        handle
    }

    pub fn get(&self, handle: u64) -> Option<&JniObject> {
        self.objects.get(&handle)
    }

    pub fn get_mut(&mut self, handle: u64) -> Option<&mut JniObject> {
        self.objects.get_mut(&handle)
    }

    pub fn alloc_string(&mut self, value: impl Into<String>) -> u64 {
        self.alloc(JniObject::String(value.into()))
    }

    pub fn alloc_byte_array(&mut self, value: Vec<u8>) -> u64 {
        self.alloc(JniObject::ByteArray(value))
    }

    pub fn alloc_class(&mut self, name: impl Into<String>) -> u64 {
        self.alloc(JniObject::Class(name.into()))
    }

    pub fn alloc_method(
        &mut self,
        class: impl Into<String>,
        name: impl Into<String>,
        sig: impl Into<String>,
    ) -> u64 {
        self.alloc(JniObject::Method {
            class: class.into(),
            name: name.into(),
            sig: sig.into(),
        })
    }
}
