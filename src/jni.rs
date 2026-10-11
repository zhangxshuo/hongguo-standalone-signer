#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsValue {
    Null,
    Bool(bool),
    Int(i32),
    Long(u64),
    Str(String),
    Bytes(Vec<u8>),
}

/// JNI callbacks used by the `com.bytedance.mobsec.metasec.ml.MS.b` path.
///
/// This mirrors the working Java FqTrace implementation:
/// - 65539        -> /data/user/0/<pkg>/files/.msdata
/// - 16777218     -> certificate bytes
/// - 16777232     -> 68132
/// - 16777233     -> 6.8.1.32
/// - 33554433/34  -> true
/// - 268435470    -> current time in milliseconds
pub fn ms_b(op: i32, cert: Option<&[u8]>, now_ms: u64) -> MsValue {
    match op {
        65539 => MsValue::Str(
            "/data/user/0/com.dragon.read.oversea.gp/files/.msdata".to_string(),
        ),
        16777218 => cert
            .map(|bytes| MsValue::Bytes(bytes.to_vec()))
            .unwrap_or(MsValue::Null),
        16777232 => MsValue::Int(68132),
        16777233 => MsValue::Str("6.8.1.32".to_string()),
        33554433 | 33554434 => MsValue::Bool(true),
        268435470 => MsValue::Long(now_ms),
        _ => MsValue::Null,
    }
}
