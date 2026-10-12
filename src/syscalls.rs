use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct SyscallTrace {
    pub counts: BTreeMap<u64, u64>,
}

impl SyscallTrace {
    pub fn note(&mut self, number: u64) {
        *self.counts.entry(number).or_insert(0) += 1;
    }

    pub fn summary(&self) -> String {
        self.counts
            .iter()
            .map(|(number, count)| format!("{number}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Linux AArch64 syscall numbers relevant to the metasec signer path.
pub mod nr {
    pub const GETCWD: u64 = 17;
    pub const DUP: u64 = 23;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const MKDIRAT: u64 = 34;
    pub const UNLINKAT: u64 = 35;
    pub const FACCESSAT: u64 = 48;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const PREAD64: u64 = 67;
    pub const FSTAT: u64 = 80;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const FUTEX: u64 = 98;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const PRCTL: u64 = 167;
    pub const GETTIMEOFDAY: u64 = 169;
    pub const GETPID: u64 = 172;
    pub const GETTID: u64 = 178;
    pub const BRK: u64 = 214;
    pub const MMAP: u64 = 222;
    pub const MUNMAP: u64 = 215;
    pub const CLONE: u64 = 220;
    pub const MPROTECT: u64 = 226;
}
