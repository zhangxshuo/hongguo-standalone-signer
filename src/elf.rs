use goblin::elf::header::EM_AARCH64;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;

#[derive(Debug, Clone)]
pub struct LoadSegment {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct ElfImage {
    pub bytes: Vec<u8>,
    pub entry: u64,
    pub image_base: u64,
    pub segments: Vec<LoadSegment>,
}

impl ElfImage {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        let elf = Elf::parse(&bytes).map_err(|error| format!("ELF parse failed: {error}"))?;
        if elf.header.e_machine != EM_AARCH64 {
            return Err(format!(
                "unsupported ELF machine: expected AArch64, got {}",
                elf.header.e_machine
            ));
        }

        let mut segments = Vec::new();
        let mut image_base = u64::MAX;
        for header in &elf.program_headers {
            if header.p_type != PT_LOAD {
                continue;
            }
            image_base = image_base.min(header.p_vaddr);
            segments.push(LoadSegment {
                virtual_address: header.p_vaddr,
                memory_size: header.p_memsz,
                file_size: header.p_filesz,
                file_offset: header.p_offset,
                flags: header.p_flags,
            });
        }
        if segments.is_empty() {
            return Err("ELF has no PT_LOAD segments".to_string());
        }

        Ok(Self {
            bytes,
            entry: elf.entry,
            image_base: if image_base == u64::MAX { 0 } else { image_base },
            segments,
        })
    }

    pub fn rebase(&self, requested_base: u64) -> u64 {
        if self.image_base == 0 {
            requested_base
        } else {
            requested_base.saturating_sub(self.image_base)
        }
    }
}
