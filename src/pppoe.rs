use crate::{Deserialize, Error, Result, Serialize, VerType};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const PASP: u8 = 0x00; // PPPoE Active Session PPP Packet
const PADI: u8 = 0x09;
const PADO: u8 = 0x07;
const PADR: u8 = 0x19;
const PADS: u8 = 0x65;
const PADT: u8 = 0xa7;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PPPoECode {
    PPP = PASP,
    Padi = PADI,
    Pado = PADO,
    Padr = PADR,
    Pads = PADS,
    Padt = PADT,
}

impl Default for PPPoECode {
    fn default() -> Self {
        Self::PPP
    }
}

impl TryFrom<u8> for PPPoECode {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self> {
        match code {
            PADI => Ok(Self::Padi),
            PADO => Ok(Self::Pado),
            PADR => Ok(Self::Padr),
            PADS => Ok(Self::Pads),
            PADT => Ok(Self::Padt),
            _ => Err(Error::InvalidPPPoECode(code)),
        }
    }
}

impl Serialize for PPPoECode {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        (*self as u8).serialize(w)
    }
}

impl Deserialize for PPPoECode {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut code = 0u8;
        code.deserialize(r)?;

        *self = Self::try_from(code)?;
        Ok(())
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEHeader {
    pub ver_type: VerType,
    pub code: PPPoECode,
    pub session_id: u16,
    pub len: u16,
}
