use crate::{Deserialize, Result, Serialize};

use std::io::{Read, Write};

use bitfield::bitfield;

bitfield! {
    /// Version and type of a PPPoE header combined in a single octet.
    #[derive(Clone, Eq, PartialEq)]
    pub struct VerType(u8);
    impl Debug;

    u8;

    pub ver, set_ver: 7, 4;
    pub ty, set_ty: 3, 0;
}

impl Default for VerType {
    fn default() -> Self {
        Self(0x11)
    }
}

impl Serialize for VerType {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        self.0.serialize(w)
    }
}

impl Deserialize for VerType {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        self.0.deserialize(r)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Addr(pub std::net::Ipv4Addr);

impl Default for Ipv4Addr {
    fn default() -> Self {
        Self(std::net::Ipv4Addr::UNSPECIFIED)
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self(addr)
    }
}

impl Serialize for Ipv4Addr {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        u32::from(self.0).serialize(w)
    }
}

impl Deserialize for Ipv4Addr {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut tmp = u32::default();
        tmp.deserialize(r)?;

        self.0 = tmp.into();
        Ok(())
    }
}
