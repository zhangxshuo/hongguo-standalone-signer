use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use base64::Engine;
use ctr::Ctr128BE;
use std::fs;

type Aes128Ctr = Ctr128BE<Aes128>;

pub fn unwrap_spade(spade_a_b64: &str, flag: i32) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(spade_a_b64)
        .ok()?;
    unwrap_v1(&raw, flag)
}

pub fn unwrap_v1(spade: &[u8], flag: i32) -> Option<String> {
    if spade.len() < 3 {
        return None;
    }
    let b_var5 = spade[0] ^ spade[1] ^ spade[2];
    let type_len = b_var5 as i32 - 0x30;
    if type_len < 1 {
        return None;
    }
    let work_len = (spade.len() as i32 - b_var5 as i32 + 0x2f) as usize;
    if work_len < 1 || 1 + work_len > spade.len() {
        return None;
    }
    let mut dest = spade[1..1 + work_len].to_vec();

    let type_len = type_len as usize;
    let type_tail = spade.len() - type_len;
    if type_tail < 2 {
        return None;
    }
    let b16 = spade[type_tail - 2];
    let b14 = spade[type_tail - 1];
    let mut kind = vec![0u8; type_len];
    for index in 0..type_len {
        kind[index] = b14 ^ b16 ^ spade[type_tail + index];
    }
    if zero_padded_match(&kind, b"app_v2", type_len) || zero_padded_match(&kind, b"web_v2", type_len)
    {
        return None;
    }

    let mut b14 = 0x55u8;
    let mut b16 = 0xfau8;
    for index in 0..work_len {
        let b6 = dest[index];
        let popcount = (index as u32).count_ones() as i32;
        let (b3, b7, xor_value) = if index & 1 != 0 {
            (b16, b6, b14)
        } else {
            (b6, b14, b16)
        };
        let c_var4 = if flag != 0 {
            popcount + 0x15
        } else {
            signed_byte(-0x15 - popcount)
        };
        dest[index] = ((c_var4 + (xor_value ^ b6) as i32) & 0xff) as u8;
        b14 = b7;
        b16 = b3;
    }

    let first = dest[0];
    let key_len = if (0x30..=0x39).contains(&first) {
        (first - 0x30) as usize
    } else if (0x61..=0x7a).contains(&first) {
        (first - 0x57) as usize
    } else {
        return None;
    };
    let end = work_len.checked_sub(key_len & 0xff)?;
    if end < 2 || end > dest.len() {
        return None;
    }
    let key = String::from_utf8_lossy(&dest[1..end]).to_string();
    if key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(key.to_ascii_lowercase())
    } else {
        None
    }
}

pub fn decrypt_file(
    spade_a_b64: &str,
    input_path: &str,
    output_path: &str,
    flag: i32,
) -> Result<(), String> {
    let key_text = unwrap_spade(spade_a_b64, flag)
        .or_else(|| unwrap_spade(spade_a_b64, 1 - flag))
        .ok_or_else(|| "spade key unwrap failed".to_string())?;
    let key = decode_hex_16(&key_text)?;
    let data = fs::read(input_path).map_err(|error| format!("read encrypted mp4 failed: {error}"))?;
    let decrypted = decrypt_mp4(&data, &key)?;
    fs::write(output_path, decrypted).map_err(|error| format!("write decrypted mp4 failed: {error}"))
}

pub fn decrypt_mp4(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    let moov = find_box(data, &[b"moov"], 0, data.len())
        .ok_or_else(|| "moov box not found".to_string())?;
    let mut output = data.to_vec();
    let mut decrypted_tracks = 0usize;

    let mut cursor = moov.0;
    while cursor + 8 <= moov.1 {
        let Some((box_type, box_start, box_size, header_size)) = box_header(data, cursor) else {
            break;
        };
        if box_type == *b"trak" {
            let track_start = box_start + header_size;
            let track_end = box_start + box_size;
            let handler = find_box(data, &[b"mdia", b"hdlr"], track_start, track_end)
                .and_then(|(payload, end)| {
                    if payload + 12 <= end {
                        Some(data[payload + 8..payload + 12].to_vec())
                    } else {
                        None
                    }
                });
            if let Some(handler) = handler {
                if handler == b"vide" || handler == b"soun" {
                    if let Some(iv8) = find_senc_iv(data, track_start, track_end) {
                        let (sizes, offsets) = parse_track_samples(data, &handler, track_start, track_end)?;
                        if !sizes.is_empty() {
                            decrypt_track(&mut output, key, iv8, &sizes, &offsets)?;
                            decrypted_tracks += 1;
                        }
                    }
                }
            }
        }
        if box_size == 0 {
            break;
        }
        cursor = box_start + box_size;
    }

    if decrypted_tracks == 0 {
        return Err("no encrypted track found".to_string());
    }
    strip_cenc_signaling(&mut output);
    Ok(output)
}

fn decrypt_track(
    data: &mut [u8],
    key: &[u8; 16],
    base_iv: u64,
    sizes: &[u32],
    offsets: &[u64],
) -> Result<(), String> {
    for (index, (size, offset)) in sizes.iter().zip(offsets.iter()).enumerate() {
        let start = *offset as usize;
        let end = start
            .checked_add(*size as usize)
            .ok_or_else(|| "sample offset overflow".to_string())?;
        if end > data.len() {
            return Err("sample range exceeds mp4 file".to_string());
        }
        let counter = ((base_iv.wrapping_add(index as u64)) as u128) << 64;
        let iv = counter.to_be_bytes();
        let mut cipher = Aes128Ctr::new_from_slices(key.as_slice(), iv.as_slice())
            .map_err(|_| "initialize AES-CTR failed".to_string())?;
        cipher.apply_keystream(&mut data[start..end]);
    }
    Ok(())
}

fn strip_cenc_signaling(data: &mut [u8]) {
    for (from, to) in [
        (b"encv".as_slice(), b"hvc1".as_slice()),
        (b"enca".as_slice(), b"mp4a".as_slice()),
        (b"sinf".as_slice(), b"free".as_slice()),
        (b"senc".as_slice(), b"free".as_slice()),
        (b"saiz".as_slice(), b"free".as_slice()),
        (b"saio".as_slice(), b"free".as_slice()),
        (b"pssh".as_slice(), b"free".as_slice()),
    ] {
        let mut offset = 0usize;
        while let Some(position) = find_bytes(&data[offset..], from) {
            let position = offset + position;
            data[position..position + 4].copy_from_slice(to);
            offset = position + 4;
        }
    }
}

fn parse_track_samples(
    data: &[u8],
    handler: &[u8],
    track_start: usize,
    track_end: usize,
) -> Result<(Vec<u32>, Vec<u64>), String> {
    let Some((stbl_start, stbl_end)) =
        find_box(data, &[b"mdia", b"minf", b"stbl"], track_start, track_end)
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let known_handler = find_box(data, &[b"mdia", b"hdlr"], track_start, track_end)
        .and_then(|(payload, end)| {
            if payload + 12 <= end {
                Some(data[payload + 8..payload + 12].to_vec())
            } else {
                None
            }
        });
    if known_handler.as_deref() != Some(handler) {
        return Ok((Vec::new(), Vec::new()));
    }

    let Some((stsz, stsz_end)) = find_box(data, &[b"stsz"], stbl_start, stbl_end) else {
        return Ok((Vec::new(), Vec::new()));
    };
    if stsz + 12 > stsz_end {
        return Err("invalid stsz".to_string());
    }
    let sample_size = read_u32(data, stsz + 4)?;
    let sample_count = read_u32(data, stsz + 8)? as usize;
    let mut sizes = Vec::with_capacity(sample_count);
    if sample_size != 0 {
        sizes.resize(sample_count, sample_size);
    } else {
        let mut offset = stsz + 12;
        for _ in 0..sample_count {
            sizes.push(read_u32(data, offset)?);
            offset += 4;
        }
    }

    let mut chunk_offsets = Vec::new();
    if let Some((stco, _)) = find_box(data, &[b"stco"], stbl_start, stbl_end) {
        let count = read_u32(data, stco + 4)? as usize;
        let mut offset = stco + 8;
        for _ in 0..count {
            chunk_offsets.push(read_u32(data, offset)? as u64);
            offset += 4;
        }
    } else if let Some((co64, _)) = find_box(data, &[b"co64"], stbl_start, stbl_end) {
        let count = read_u32(data, co64 + 4)? as usize;
        let mut offset = co64 + 8;
        for _ in 0..count {
            chunk_offsets.push(read_u64(data, offset)?);
            offset += 8;
        }
    }
    if chunk_offsets.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let Some((stsc, stsc_end)) = find_box(data, &[b"stsc"], stbl_start, stbl_end) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let entries = read_u32(data, stsc + 4)? as usize;
    let mut runs = Vec::with_capacity(entries);
    let mut offset = stsc + 8;
    for _ in 0..entries {
        if offset + 12 > stsc_end {
            break;
        }
        runs.push((
            read_u32(data, offset)?,
            read_u32(data, offset + 4)?,
            read_u32(data, offset + 8)?,
        ));
        offset += 12;
    }

    let mut samples_per_chunk = vec![0u32; chunk_offsets.len()];
    for (index, (first_chunk, samples, _)) in runs.iter().enumerate() {
        let last_chunk = if index + 1 < runs.len() {
            runs[index + 1].0.saturating_sub(1)
        } else {
            chunk_offsets.len() as u32
        };
        for chunk in *first_chunk..=last_chunk {
            if chunk >= 1 && (chunk as usize) <= samples_per_chunk.len() {
                samples_per_chunk[chunk as usize - 1] = *samples;
            }
        }
    }

    let mut offsets = Vec::with_capacity(sample_count);
    let mut sample_index = 0usize;
    for (chunk_index, chunk_offset) in chunk_offsets.iter().enumerate() {
        let mut offset = *chunk_offset;
        for _ in 0..samples_per_chunk[chunk_index] {
            if sample_index >= sample_count {
                break;
            }
            offsets.push(offset);
            offset += sizes[sample_index] as u64;
            sample_index += 1;
        }
    }
    sizes.truncate(offsets.len());
    Ok((sizes, offsets))
}

fn find_senc_iv(data: &[u8], start: usize, end: usize) -> Option<u64> {
    let limit = end.min(data.len());
    let mut cursor = start;
    while cursor + 4 <= limit {
        if &data[cursor..cursor + 4] == b"senc" && cursor + 20 <= limit {
            return Some(read_u64(data, cursor + 12).ok()?);
        }
        cursor += 1;
    }
    None
}

fn find_box(data: &[u8], path: &[&[u8]], start: usize, end: usize) -> Option<(usize, usize)> {
    if path.is_empty() {
        return None;
    }
    let mut cursor = start;
    while cursor + 8 <= end {
        let (box_type, box_start, box_size, header_size) = box_header(data, cursor)?;
        if box_size == 0 {
            return None;
        }
        let payload_start = box_start + header_size;
        let payload_end = box_start.checked_add(box_size)?;
        if payload_end > end {
            return None;
        }
        if box_type == path[0] {
            if path.len() == 1 {
                return Some((payload_start, payload_end));
            }
            return find_box(data, &path[1..], payload_start, payload_end);
        }
        cursor = payload_end;
    }
    None
}

fn box_header(data: &[u8], offset: usize) -> Option<([u8; 4], usize, usize, usize)> {
    if offset + 8 > data.len() {
        return None;
    }
    let size32 = read_u32(data, offset).ok()? as usize;
    let box_type = [data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]];
    let (size, header_size) = if size32 == 1 {
        if offset + 16 > data.len() {
            return None;
        }
        (read_u64(data, offset + 8).ok()? as usize, 16)
    } else if size32 == 0 {
        (data.len() - offset, 8)
    } else {
        (size32, 8)
    };
    if size < header_size || offset.checked_add(size)? > data.len() {
        return None;
    }
    Some((box_type, offset, size, header_size))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err("u32 read exceeds file".to_string());
    }
    Ok(u32::from_be_bytes(
        data[offset..offset + 4].try_into().unwrap_or([0; 4]),
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err("u64 read exceeds file".to_string());
    }
    Ok(u64::from_be_bytes(
        data[offset..offset + 8].try_into().unwrap_or([0; 8]),
    ))
}

fn decode_hex_16(text: &str) -> Result<[u8; 16], String> {
    if text.len() != 32 {
        return Err("content key must be 32 hex chars".to_string());
    }
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid content key".to_string())?;
    }
    Ok(output)
}

fn signed_byte(value: i32) -> i32 {
    let byte = value & 0xff;
    if byte >= 128 {
        byte - 256
    } else {
        byte
    }
}

fn zero_padded_match(value: &[u8], expected: &[u8], count: usize) -> bool {
    for index in 0..count {
        let actual = value.get(index).copied().unwrap_or(0);
        let wanted = expected.get(index).copied().unwrap_or(0);
        if actual != wanted {
            return false;
        }
        if actual == 0 {
            return true;
        }
    }
    true
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}
