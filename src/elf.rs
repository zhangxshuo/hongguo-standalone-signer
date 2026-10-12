use goblin::elf::header::EM_AARCH64;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::reloc::{
    R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE,
};
use goblin::elf::Elf;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct LoadSegment {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub offset: u64,
    pub r_type: u32,
    pub symbol: Option<String>,
    pub addend: i64,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub is_import: bool,
}

#[derive(Debug, Clone)]
pub struct ElfImage {
    pub bytes: Vec<u8>,
    pub entry: u64,
    pub image_base: u64,
    pub segments: Vec<LoadSegment>,
    pub symbols: HashMap<String, Symbol>,
    pub relocations: Vec<Relocation>,
    pub needed: Vec<String>,
    pub init_array: Option<(u64, u64)>,
}

impl ElfImage {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        let (entry, image_base, segments, symbols, relocations, needed, init_array) = {
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

            let mut symbols = HashMap::new();
            for symbol in elf.dynsyms.iter() {
                let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                symbols.insert(
                    name.to_string(),
                    Symbol {
                        name: name.to_string(),
                        value: symbol.st_value,
                        size: symbol.st_size,
                        is_import: symbol.st_shndx == 0,
                    },
                );
            }

            let mut relocations = Vec::new();
            for reloc in elf
                .dynrelas
                .iter()
                .chain(elf.dynrels.iter())
                .chain(elf.pltrelocs.iter())
            {
                let symbol = if reloc.r_sym == 0 {
                    None
                } else {
                    elf.dynsyms
                        .get(reloc.r_sym)
                        .and_then(|symbol| elf.dynstrtab.get_at(symbol.st_name))
                        .map(|name| name.to_string())
                };
                relocations.push(Relocation {
                    offset: reloc.r_offset,
                    r_type: reloc.r_type,
                    symbol,
                    addend: reloc.r_addend.unwrap_or(0),
                });
            }

            let mut init_array = None;
            for section in &elf.section_headers {
                let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
                    continue;
                };
                if name == ".init_array" && section.sh_size >= 8 {
                    init_array = Some((section.sh_addr, section.sh_size));
                    break;
                }
            }

            (
                elf.entry,
                if image_base == u64::MAX { 0 } else { image_base },
                segments,
                symbols,
                relocations,
                elf.libraries.iter().map(|name| name.to_string()).collect(),
                init_array,
            )
        };

        Ok(Self {
            bytes,
            entry,
            image_base,
            segments,
            symbols,
            relocations,
            needed,
            init_array,
        })
    }

    pub fn is_relative_relocation(&self, relocation: &Relocation) -> bool {
        relocation.r_type == R_AARCH64_RELATIVE
    }

    pub fn is_symbol_relocation(&self, relocation: &Relocation) -> bool {
        relocation.r_type == R_AARCH64_GLOB_DAT
            || relocation.r_type == R_AARCH64_JUMP_SLOT
            || relocation.r_type == R_AARCH64_ABS64
    }
}
