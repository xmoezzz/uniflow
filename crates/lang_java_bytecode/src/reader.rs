//! A minimal big-endian byte cursor shared by classfile, constant-pool and
//! bytecode decoding. The JVM classfile format is entirely big-endian.

use anyhow::{bail, Result};

pub struct Reader<'a> {
    bytes: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub fn u8(&mut self) -> Result<u8> {
        if self.pos >= self.bytes.len() {
            bail!("unexpected end of class file at offset {}", self.pos);
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    pub fn u16(&mut self) -> Result<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    pub fn i16(&mut self) -> Result<i16> {
        Ok(self.u16()? as i16)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let hi = self.u16()? as u32;
        let lo = self.u16()? as u32;
        Ok((hi << 16) | lo)
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let hi = self.u32()? as u64;
        let lo = self.u32()? as u64;
        Ok((hi << 32) | lo)
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }

    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }

    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.bytes.len() {
            bail!(
                "unexpected end of class file: wanted {len} bytes at offset {}",
                self.pos
            );
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.bytes(len)?;
        Ok(())
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}
