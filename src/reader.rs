//! Little-endian byte reader for the SELinux kernel binary policy format.
//!
//! The kernel policydb is a flat, little-endian binary blob with no internal
//! offsets — every structure must be read sequentially. This reader provides
//! bounds-checked primitive reads plus the handful of compound readers
//! (length-prefixed strings, ebitmaps, MLS levels/ranges, contexts) that the
//! format builds everything else out of.

/// Sequential, bounds-checked cursor over a policy blob.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn ensure(&self, n: usize) -> Result<(), String> {
        if self.pos.saturating_add(n) > self.data.len() {
            Err(format!(
                "unexpected EOF at offset {:#x}: need {} more byte(s), have {}",
                self.pos,
                n,
                self.remaining()
            ))
        } else {
            Ok(())
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, String> {
        self.ensure(1)?;
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        self.ensure(2)?;
        let bytes: [u8; 2] = self.data[self.pos..self.pos + 2].try_into().unwrap();
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        self.ensure(4)?;
        let bytes: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().unwrap();
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64, String> {
        self.ensure(8)?;
        let bytes: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().unwrap();
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        self.ensure(n)?;
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), String> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    /// A key of already-known length: `len` raw bytes, interpreted as a
    /// (possibly NUL-padded) string. Used for symbol-table datum names, where
    /// the length is read as a separate field ahead of the fixed-size fields.
    pub fn read_key(&mut self, len: usize) -> Result<String, String> {
        if len == 0 {
            return Ok(String::new());
        }
        let start = self.pos();
        let bytes = self.read_bytes(len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|e| format!("invalid UTF-8 key at {:#x}: {}", start, e))
    }

    /// A length-prefixed string: `u32` byte length followed by the raw bytes.
    /// The kernel does not null-terminate these, but some producers do, so a
    /// trailing NUL is tolerated and stripped.
    pub fn read_string(&mut self) -> Result<String, String> {
        let len = self.read_u32()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let start = self.pos;
        let bytes = self.read_bytes(len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|e| format!("invalid UTF-8 string at {:#x}: {}", start, e))
    }

    /// Read an ebitmap and return the indices of every set bit.
    ///
    /// Layout: `mapsize(u32)`, `highbit(u32)`, `count(u32)`, then `count`
    /// nodes of `startbit(u32)` + `map(u64)`.
    pub fn read_ebitmap(&mut self) -> Result<Vec<u32>, String> {
        let _mapsize = self.read_u32()?;
        let highbit = self.read_u32()?;
        let count = self.read_u32()?;

        let mut bits = Vec::new();
        if highbit == 0 {
            return Ok(bits);
        }
        for _ in 0..count {
            let startbit = self.read_u32()?;
            let map = self.read_u64()?;
            for bit in 0..64u32 {
                if map & (1u64 << bit) != 0 {
                    bits.push(startbit + bit);
                }
            }
        }
        Ok(bits)
    }

    /// Skip an ebitmap without materialising its bits.
    pub fn skip_ebitmap(&mut self) -> Result<(), String> {
        let _mapsize = self.read_u32()?;
        let _highbit = self.read_u32()?;
        let count = self.read_u32()?;
        self.skip(count as usize * 12) // startbit(u32) + map(u64)
    }

    /// MLS level: `sensitivity(u32)` + category ebitmap.
    pub fn skip_mls_level(&mut self) -> Result<(), String> {
        let _sens = self.read_u32()?;
        self.skip_ebitmap()
    }

    /// MLS range (`mls_read_range_helper`): an `items` count, then 1 or 2
    /// sensitivities, then 1 or 2 category ebitmaps. When `items == 1` the
    /// high level mirrors the low level and only one of each is stored.
    pub fn skip_mls_range(&mut self) -> Result<(), String> {
        let items = self.read_u32()?;
        let _sens_low = self.read_u32()?;
        if items > 1 {
            let _sens_high = self.read_u32()?;
        }
        self.skip_ebitmap()?; // low categories
        if items > 1 {
            self.skip_ebitmap()?; // high categories
        }
        Ok(())
    }

    /// A context struct: `user(u32)`, `role(u32)`, `type(u32)`, and — when the
    /// policy is MLS — an MLS range. Returns the type value, the only field we
    /// surface.
    pub fn read_context_type(&mut self, mls: bool) -> Result<u32, String> {
        let _user = self.read_u32()?;
        let _role = self.read_u32()?;
        let typ = self.read_u32()?;
        if mls {
            self.skip_mls_range()?;
        }
        Ok(typ)
    }

    pub fn skip_context(&mut self, mls: bool) -> Result<(), String> {
        self.read_context_type(mls)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives() {
        let data = [0x8C, 0xFF, 0x7C, 0xF9, 0x05, 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 0xF97C_FF8C);
        assert_eq!(r.read_u16().unwrap(), 5);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn string_with_nul() {
        let data = [0x06, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_string().unwrap(), "hello");
    }

    #[test]
    fn ebitmap_bits() {
        // mapsize=64, highbit=64, count=1, startbit=0, map=0x05 -> bits 0 and 2
        let data = [
            0x40, 0, 0, 0, 0x40, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_ebitmap().unwrap(), vec![0, 2]);
    }

    #[test]
    fn ebitmap_empty() {
        let data = [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut r = Reader::new(&data);
        assert!(r.read_ebitmap().unwrap().is_empty());
    }
}
