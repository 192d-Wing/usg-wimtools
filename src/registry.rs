//! Read-only REGF hive inspection. No transaction-log replay or registry writes.
use crate::{invalid, u16_at, u32_at, unsupported};
use std::{
    collections::{HashMap, HashSet},
    io,
};
const BASE: usize = 4096;
const MAX_HIVE: usize = 128 * 1024 * 1024;
const MAX_VALUE: usize = 16344;
#[derive(Debug)]
pub struct Hive {
    bytes: Vec<u8>,
    cells: HashMap<u32, (usize, usize)>,
    pub root_offset: u32,
    pub major: u32,
    pub minor: u32,
}
#[derive(Debug)]
pub struct Value {
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
}
#[derive(Debug)]
pub struct Key {
    pub name: String,
    pub subkeys: Vec<String>,
    pub values: Vec<Value>,
}
fn name(bytes: &[u8], compressed: bool) -> io::Result<String> {
    if compressed {
        return Ok(bytes.iter().map(|&b| char::from(b)).collect());
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid("odd registry name length"));
    }
    let s: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    String::from_utf16(&s)
        .map_err(|_| unsupported("registry names with unpaired surrogates are unsupported"))
}
impl Hive {
    pub fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() < BASE || &bytes[..4] != b"regf" {
            return Err(invalid("not a registry hive"));
        }
        if bytes.len() > MAX_HIVE {
            return Err(unsupported("registry hive exceeds 128 MiB"));
        }
        if u32_at(&bytes, 4) != u32_at(&bytes, 8) {
            return Err(unsupported("dirty hive requires transaction-log replay"));
        }
        let major = u32_at(&bytes, 20);
        let minor = u32_at(&bytes, 24);
        if major != 1
            || !(2..=6).contains(&minor)
            || u32_at(&bytes, 28) != 0
            || u32_at(&bytes, 32) != 1
        {
            return Err(unsupported("unsupported registry hive version or type"));
        }
        let mut sum = 0u32;
        for chunk in bytes[..508].as_chunks::<4>().0 {
            sum ^= u32::from_le_bytes(*chunk);
        }
        if sum == 0 {
            sum = 1;
        } else if sum == u32::MAX {
            sum = u32::MAX - 1;
        }
        if sum != u32_at(&bytes, 508) {
            return Err(invalid("registry header checksum mismatch"));
        }
        let root_offset = u32_at(&bytes, 36);
        let bins = u32_at(&bytes, 40) as usize;
        let end = BASE
            .checked_add(bins)
            .filter(|&n| n <= bytes.len())
            .ok_or_else(|| invalid("registry bins outside file"))?;
        if bins == 0 || !bins.is_multiple_of(4096) {
            return Err(invalid("invalid registry bins size"));
        }
        let mut cells = HashMap::new();
        let mut bin = BASE;
        while bin < end {
            if bin + 32 > end
                || &bytes[bin..bin + 4] != b"hbin"
                || u32_at(&bytes, bin + 4) as usize != bin - BASE
            {
                return Err(invalid("invalid registry bin header"));
            }
            let size = u32_at(&bytes, bin + 8) as usize;
            let bin_end = bin
                .checked_add(size)
                .filter(|&n| n <= end)
                .ok_or_else(|| invalid("registry bin exceeds hive"))?;
            if size < 4096 || !size.is_multiple_of(4096) {
                return Err(invalid("invalid registry bin size"));
            }
            let mut p = bin + 32;
            while p < bin_end {
                if p + 4 > bin_end {
                    return Err(invalid("truncated cell length"));
                }
                let raw = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                let size =
                    raw.checked_abs()
                        .ok_or_else(|| invalid("invalid cell size"))? as usize;
                if size < 8
                    || !size.is_multiple_of(8)
                    || p.checked_add(size).is_none_or(|e| e > bin_end)
                {
                    return Err(invalid("invalid registry cell bounds"));
                }
                if raw < 0 {
                    cells.insert((p - BASE) as u32, (p + 4, p + size));
                }
                p += size;
            }
            bin = bin_end;
        }
        let hive = Self {
            bytes,
            cells,
            root_offset,
            major,
            minor,
        };
        hive.key_node(root_offset)?;
        Ok(hive)
    }
    fn cell(&self, off: u32) -> io::Result<&[u8]> {
        let (a, b) = self
            .cells
            .get(&off)
            .ok_or_else(|| invalid(format!("invalid or unallocated hive cell 0x{off:x}")))?;
        Ok(&self.bytes[*a..*b])
    }
    fn key_node(&self, off: u32) -> io::Result<&[u8]> {
        let cell = self.cell(off)?;
        if cell.len() < 76 || &cell[..2] != b"nk" {
            return Err(invalid("invalid registry key node"));
        }
        Ok(cell)
    }
    fn key_name(&self, off: u32) -> io::Result<String> {
        let k = self.key_node(off)?;
        let len = usize::from(u16_at(k, 72));
        let b = k
            .get(76..76 + len)
            .ok_or_else(|| invalid("truncated registry key name"))?;
        name(b, u16_at(k, 2) & 0x20 != 0)
    }
    fn collect_list(
        &self,
        off: u32,
        out: &mut Vec<u32>,
        visited: &mut HashSet<u32>,
        depth: usize,
    ) -> io::Result<()> {
        if depth > 32 || !visited.insert(off) {
            return Err(invalid("cyclic or deep subkey list"));
        }
        let b = self.cell(off)?;
        if b.len() < 4 {
            return Err(invalid("short subkey list"));
        }
        let count = usize::from(u16_at(b, 2));
        let sig = &b[..2];
        let width = match sig {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return Err(unsupported("unsupported subkey list")),
        };
        if 4 + count * width > b.len() {
            return Err(invalid("truncated subkey list"));
        }
        for i in 0..count {
            let child = u32_at(b, 4 + i * width);
            if sig == b"ri" {
                self.collect_list(child, out, visited, depth + 1)?;
            } else {
                out.push(child);
            }
        }
        Ok(())
    }
    fn subkeys(&self, off: u32) -> io::Result<Vec<u32>> {
        let node = self.key_node(off)?;
        let count = u32_at(node, 20) as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > 1_000_000 {
            return Err(unsupported("too many subkeys"));
        }
        let mut entries = Vec::new();
        self.collect_list(u32_at(node, 28), &mut entries, &mut HashSet::new(), 0)?;
        if entries.len() != count {
            return Err(invalid("subkey count mismatch"));
        }
        Ok(entries)
    }
    fn value(&self, off: u32) -> io::Result<Value> {
        let v = self.cell(off)?;
        if v.len() < 20 || &v[..2] != b"vk" {
            return Err(invalid("invalid value cell"));
        }
        let n = usize::from(u16_at(v, 2));
        let raw = v
            .get(20..20 + n)
            .ok_or_else(|| invalid("truncated value name"))?;
        let name = name(raw, u16_at(v, 16) & 1 != 0)?;
        let size = u32_at(v, 4);
        let len = (size & 0x7fff_ffff) as usize;
        if len > MAX_VALUE {
            return Err(unsupported("segmented or large registry value"));
        }
        let data = if size & 0x8000_0000 != 0 {
            if len > 4 {
                return Err(invalid("inline value too large"));
            }
            v[8..8 + len].to_vec()
        } else if len == 0 {
            Vec::new()
        } else {
            let c = self.cell(u32_at(v, 8))?;
            c.get(..len)
                .ok_or_else(|| invalid("truncated value data"))?
                .to_vec()
        };
        Ok(Value {
            name,
            kind: u32_at(v, 12),
            data,
        })
    }
    fn values(&self, off: u32) -> io::Result<Vec<Value>> {
        let node = self.key_node(off)?;
        let count = u32_at(node, 36) as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let list = self.cell(u32_at(node, 40))?;
        let size = count
            .checked_mul(4)
            .ok_or_else(|| invalid("values overflow"))?;
        if size > list.len() {
            return Err(invalid("truncated value list"));
        }
        (0..count)
            .map(|i| self.value(u32_at(list, i * 4)))
            .collect()
    }
    /// Path is relative to the hive root, separated by slash or backslash.
    pub fn key(&self, path: &str) -> io::Result<Key> {
        let mut current = self.root_offset;
        for part in path.split(['\\', '/']).filter(|x| !x.is_empty()) {
            if part == "." || part == ".." {
                return Err(invalid("invalid registry path"));
            }
            if u16_at(self.key_node(current)?, 2) & 0x10 != 0 {
                return Err(unsupported("registry links are not followed"));
            }
            let mut found = None;
            for off in self.subkeys(current)? {
                if self.key_name(off)?.eq_ignore_ascii_case(part) && found.replace(off).is_some() {
                    return Err(invalid("ambiguous registry key"));
                }
            }
            current = found.ok_or_else(|| invalid(format!("registry key not found: {part}")))?;
        }
        let node = self.key_node(current)?;
        if u16_at(node, 2) & 0x10 != 0 {
            return Err(unsupported("registry links are not followed"));
        }
        let names = self
            .subkeys(current)?
            .iter()
            .map(|&p| self.key_name(p))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Key {
            name: self.key_name(current)?,
            subkeys: names,
            values: self.values(current)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put16(b: &mut [u8], p: usize, v: u16) {
        b[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], p: usize, v: u32) {
        b[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 8192];
        b[..4].copy_from_slice(b"regf");
        put32(&mut b, 4, 1);
        put32(&mut b, 8, 1);
        put32(&mut b, 20, 1);
        put32(&mut b, 24, 5);
        put32(&mut b, 32, 1);
        put32(&mut b, 36, 32);
        put32(&mut b, 40, 4096);
        b[4096..4100].copy_from_slice(b"hbin");
        put32(&mut b, 4104, 4096);
        let mut p = 4128;
        fn cell(b: &mut [u8], p: &mut usize, payload: &[u8]) -> u32 {
            let size = (payload.len() + 4 + 7) & !7;
            let offset = (*p - 4096) as u32;
            b[*p..*p + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
            b[*p + 4..*p + 4 + payload.len()].copy_from_slice(payload);
            *p += size;
            offset
        }
        let mut root = vec![0u8; 80];
        root[..2].copy_from_slice(b"nk");
        put16(&mut root, 2, 0x20);
        put32(&mut root, 20, 1);
        put16(&mut root, 72, 4);
        root[76..80].copy_from_slice(b"ROOT");
        let root_offset = cell(&mut b, &mut p, &root);
        let mut child = vec![0u8; 82];
        child[..2].copy_from_slice(b"nk");
        put16(&mut child, 2, 0x20);
        put32(&mut child, 36, 1);
        put16(&mut child, 72, 6);
        child[76..82].copy_from_slice(b"Select");
        let child_offset = cell(&mut b, &mut p, &child);
        let mut v = vec![0u8; 27];
        v[..2].copy_from_slice(b"vk");
        put16(&mut v, 2, 7);
        put32(&mut v, 4, 0x80000004);
        put32(&mut v, 8, 1);
        put32(&mut v, 12, 4);
        put16(&mut v, 16, 1);
        v[20..27].copy_from_slice(b"Current");
        let value_offset = cell(&mut b, &mut p, &v);
        let values = cell(&mut b, &mut p, &value_offset.to_le_bytes());
        let mut list = vec![0u8; 12];
        list[..2].copy_from_slice(b"lh");
        put16(&mut list, 2, 1);
        put32(&mut list, 4, child_offset);
        let list_offset = cell(&mut b, &mut p, &list);
        put32(&mut b, 4096 + root_offset as usize + 4 + 28, list_offset);
        put32(&mut b, 4096 + child_offset as usize + 4 + 40, values);
        let free = 8192 - p;
        put32(&mut b, p, free as u32);
        let mut checksum = 0;
        for chunk in b[..508].as_chunks::<4>().0 {
            checksum ^= u32::from_le_bytes(*chunk);
        }
        put32(&mut b, 508, checksum);
        b
    }
    #[test]
    fn traverse_and_read_inline_dword() {
        let h = Hive::parse(fixture()).unwrap();
        let key = h.key("select").unwrap();
        assert_eq!(key.name, "Select");
        assert_eq!(key.values.len(), 1);
        assert_eq!(key.values[0].name, "Current");
        assert_eq!(key.values[0].data, [1, 0, 0, 0]);
        assert!(h.key("missing").is_err());
        assert!(h.key("../Select").is_err());
    }
    #[test]
    fn rejects_dirty_corrupt_and_truncated_hives() {
        let original = fixture();
        for end in [0, 32, 4095, 4096, 8191] {
            assert!(Hive::parse(original[..end].to_vec()).is_err());
        }
        let mut dirty = original.clone();
        put32(&mut dirty, 8, 2);
        assert!(Hive::parse(dirty).is_err());
        let mut checksum = original.clone();
        checksum[508] ^= 1;
        assert!(Hive::parse(checksum).is_err());
        let mut bad = original.clone();
        put32(&mut bad, 4128, 0);
        assert!(Hive::parse(bad).is_err());
        let mut free = original;
        put32(&mut free, 4128, 88);
        assert!(Hive::parse(free).is_err());
    }
}
