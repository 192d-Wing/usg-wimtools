//! WIM's 32 KiB LZX chunk variant. No unsafe code or native dependencies.
use std::io::{self, ErrorKind};
fn bad(s: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, s)
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    word: u16,
    left: u8,
}
impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            word: 0,
            left: 0,
        }
    }
    fn read(&mut self, n: u8) -> io::Result<u32> {
        let mut value = 0;
        for _ in 0..n {
            if self.left == 0 {
                let pair = self
                    .data
                    .get(self.pos..self.pos + 2)
                    .ok_or_else(|| bad("truncated LZX bitstream"))?;
                self.word = u16::from_le_bytes([pair[0], pair[1]]);
                self.pos += 2;
                self.left = 16;
            }
            value = (value << 1) | u32::from((self.word >> (self.left - 1)) & 1);
            self.left -= 1;
        }
        Ok(value)
    }
    fn align_raw(&mut self) -> io::Result<()> {
        if self.left == 0 {
            self.read(16)?;
        } else {
            self.left = 0;
        }
        Ok(())
    }
    fn raw(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| bad("LZX size overflow"))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| bad("truncated LZX raw block"))?;
        self.pos = end;
        Ok(s)
    }
}

struct Huffman {
    first: [u32; 17],
    count: [u32; 17],
    start: [usize; 17],
    symbols: Vec<usize>,
}
impl Huffman {
    fn new(lengths: &[u8]) -> io::Result<Self> {
        let mut count = [0u32; 17];
        for &n in lengths {
            if n > 16 {
                return Err(bad("invalid Huffman length"));
            }
            if n != 0 {
                count[n as usize] += 1;
            }
        }
        let mut first = [0u32; 17];
        let mut start = [0usize; 17];
        let mut code = 0u32;
        let mut total = 0usize;
        for n in 1..=16 {
            code = (code + count[n - 1]) << 1;
            if code + count[n] > 1u32 << n {
                return Err(bad("oversubscribed Huffman tree"));
            }
            first[n] = code;
            start[n] = total;
            total += count[n] as usize;
        }
        let mut symbols = Vec::with_capacity(total);
        for n in 1..=16 {
            for (sym, &len) in lengths.iter().enumerate() {
                if len == n as u8 {
                    symbols.push(sym);
                }
            }
        }
        Ok(Self {
            first,
            count,
            start,
            symbols,
        })
    }
    fn symbol(&self, bits: &mut Bits<'_>) -> io::Result<usize> {
        let mut code = 0;
        for n in 1..=16 {
            code = (code << 1) | bits.read(1)?;
            if code >= self.first[n] && code - self.first[n] < self.count[n] {
                return Ok(self.symbols[self.start[n] + (code - self.first[n]) as usize]);
            }
        }
        Err(bad("invalid Huffman code"))
    }
}
fn lengths(bits: &mut Bits<'_>, lens: &mut [u8]) -> io::Result<()> {
    let mut pre = [0u8; 20];
    for n in &mut pre {
        *n = bits.read(4)? as u8;
    }
    let tree = Huffman::new(&pre)?;
    let mut i = 0;
    while i < lens.len() {
        let sym = tree.symbol(bits)?;
        match sym {
            0..=16 => {
                lens[i] = (u32::from(lens[i]) + 17 - sym as u32) as u8 % 17;
                i += 1;
            }
            17 | 18 => {
                let count = if sym == 17 {
                    4 + bits.read(4)?
                } else {
                    20 + bits.read(5)?
                } as usize;
                if count > lens.len() - i {
                    return Err(bad("LZX zero run exceeds tree"));
                }
                lens[i..i + count].fill(0);
                i += count;
            }
            19 => {
                let count = 4 + bits.read(1)? as usize;
                let code = tree.symbol(bits)?;
                if code > 16 || count > lens.len() - i {
                    return Err(bad("invalid LZX tree run"));
                }
                let value = (usize::from(lens[i]) + 17 - code) % 17;
                lens[i..i + count].fill(value as u8);
                i += count;
            }
            _ => return Err(bad("invalid LZX pretree symbol")),
        }
    }
    Ok(())
}

/// Decode one self-contained WIM chunk, applying the WIM E8 transform.
pub fn decompress(input: &[u8], output_len: usize) -> io::Result<Vec<u8>> {
    if output_len == 0 || output_len > 32768 {
        return Err(bad("invalid LZX chunk output size"));
    }
    let mut bits = Bits::new(input);
    let mut out = Vec::with_capacity(output_len);
    let mut main_lengths = [0u8; 496];
    let mut len_lengths = [0u8; 249];
    let mut recent = [1usize; 3];
    while out.len() < output_len {
        let kind = bits.read(3)?;
        let block_len = if bits.read(1)? == 1 {
            32768
        } else {
            bits.read(16)? as usize
        };
        if block_len == 0 || block_len > output_len - out.len() {
            return Err(bad("LZX block exceeds chunk"));
        }
        let end = out.len() + block_len;
        if kind == 3 {
            bits.align_raw()?;
            for r in &mut recent {
                let b = bits.raw(4)?;
                *r = u32::from_le_bytes(b.try_into().unwrap()) as usize;
            }
            out.extend_from_slice(bits.raw(block_len)?);
            if block_len % 2 != 0 && out.len() < output_len {
                bits.raw(1)?;
            }
            continue;
        }
        if kind != 1 && kind != 2 {
            return Err(bad("unsupported LZX block type"));
        }
        let mut aligned_lens = [0u8; 8];
        if kind == 2 {
            for n in &mut aligned_lens {
                *n = bits.read(3)? as u8;
            }
        }
        let aligned = Huffman::new(&aligned_lens)?;
        lengths(&mut bits, &mut main_lengths[..256])?;
        lengths(&mut bits, &mut main_lengths[256..])?;
        lengths(&mut bits, &mut len_lengths)?;
        let main = Huffman::new(&main_lengths)?;
        let lentree = Huffman::new(&len_lengths)?;
        while out.len() < end {
            let symbol = main.symbol(&mut bits)?;
            if symbol < 256 {
                out.push(symbol as u8);
                continue;
            }
            let match_code = symbol - 256;
            let slot = match_code >> 3;
            let mut len = match_code & 7;
            if len == 7 {
                len += lentree.symbol(&mut bits)?;
            }
            len += 2;
            let distance = if slot < 3 {
                let d = recent[slot];
                if slot != 0 {
                    recent[slot] = recent[0];
                    recent[0] = d;
                }
                d
            } else {
                let extra = if slot < 4 { 0 } else { (slot / 2) - 1 };
                let mut base = 0usize;
                for i in 0..slot {
                    base += 1usize << if i < 4 { 0 } else { (i / 2) - 1 };
                }
                let suffix = if kind == 2 && extra >= 3 {
                    ((bits.read((extra - 3) as u8)? as usize) << 3) | aligned.symbol(&mut bits)?
                } else {
                    bits.read(extra as u8)? as usize
                };
                let d = base + suffix - 2;
                recent = [d, recent[0], recent[1]];
                d
            };
            if distance == 0 || distance > out.len() || len > end - out.len() {
                return Err(bad("invalid LZX match"));
            }
            for _ in 0..len {
                let value = out[out.len() - distance];
                out.push(value);
            }
        }
    }
    // WIM applies the E8 inverse independently to each chunk.
    if out.len() > 10 {
        let mut i = 0;
        while i < out.len() - 10 {
            if out[i] == 0xe8 {
                let value = i32::from_le_bytes(out[i + 1..i + 5].try_into().unwrap());
                let pos = i as i32;
                if value >= -pos && value < 12_000_000 {
                    let decoded = if value >= 0 {
                        value - pos
                    } else {
                        value + 12_000_000
                    };
                    out[i + 1..i + 5].copy_from_slice(&decoded.to_le_bytes());
                }
                i += 5;
            } else {
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncompressed_wim_block_and_truncation() {
        // 3-bit type 3, size flag 0, 16-bit length 3, then word padding.
        let mut data = vec![0x00, 0x60, 0x00, 0x30];
        for _ in 0..3 {
            data.extend_from_slice(&1u32.to_le_bytes());
        }
        data.extend_from_slice(b"abc");
        assert_eq!(decompress(&data, 3).unwrap(), b"abc");
        for n in 0..data.len() {
            assert!(decompress(&data[..n], 3).is_err());
        }
        assert!(decompress(&data, 4).is_err());
    }
    #[test]
    fn canonical_huffman_and_invalid_tree() {
        let tree = Huffman::new(&[1, 2, 2]).unwrap();
        let mut bits = Bits::new(&[0, 0b0101_1000]);
        assert_eq!(tree.symbol(&mut bits).unwrap(), 0);
        assert_eq!(tree.symbol(&mut bits).unwrap(), 1);
        assert_eq!(tree.symbol(&mut bits).unwrap(), 2);
        assert!(Huffman::new(&[1, 1, 1]).is_err());
    }
}
