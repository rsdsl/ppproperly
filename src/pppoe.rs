use crate::{Deserialize, Error, Result, Serialize, VerType};

use std::io::{self, Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const PASP: u8 = 0x00; // PPPoE Active Session PPP Packet
const PADI: u8 = 0x09;
const PADO: u8 = 0x07;
const PADR: u8 = 0x19;
const PADS: u8 = 0x65;
const PADT: u8 = 0xa7;

const TAG_AC_COOKIE: u16 = 0x0104;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
const TAG_CREDITS: u16 = 0x0106;
const TAG_CREDIT_SCALE_FACTOR: u16 = 0x0109;
const TAG_END_OF_LIST: u16 = 0x0000;
const TAG_GENERIC_ERROR: u16 = 0x0203;
const TAG_HOST_UNIQ: u16 = 0x0103;
const TAG_METRICS: u16 = 0x0107;
const TAG_PPP_MAX_PAYLOAD: u16 = 0x0120;
const TAG_RELAY_SESSION_ID: u16 = 0x0110;
const TAG_SEQUENCE_NUMBER: u16 = 0x0108;
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
const TAG_VENDOR_SPECIFIC: u16 = 0x0105;

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

#[repr(u16)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PPPoETag {
    None = 0xffff, // Dummy variant for deserialization initialization.
    ACCookie(Vec<u8>) = TAG_AC_COOKIE,
    ACName(String) = TAG_AC_NAME,
    ACSystemError(String) = TAG_AC_SYSTEM_ERROR,
    Credits = TAG_CREDITS,
    CreditScaleFactor = TAG_CREDIT_SCALE_FACTOR,
    EndOfList = TAG_END_OF_LIST,
    GenericError(String) = TAG_GENERIC_ERROR,
    HostUniq(Vec<u8>) = TAG_HOST_UNIQ,
    Metrics = TAG_METRICS,
    PPPMaxPayload = TAG_PPP_MAX_PAYLOAD,
    RelaySessionID(Vec<u8>) = TAG_RELAY_SESSION_ID,
    SequenceNumber = TAG_SEQUENCE_NUMBER,
    ServiceName(String) = TAG_SERVICE_NAME,
    ServiceNameError(String) = TAG_SERVICE_NAME_ERROR,
    VendorSpecific(Vec<u8>) = TAG_VENDOR_SPECIFIC,
}

impl PPPoETag {
    fn discriminant(&self) -> u16 {
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    fn len(&self) -> usize {
        match *self {
            PPPoETag::ACCookie(ref val) => val.len(),
            PPPoETag::ACName(ref val) => val.len(),
            PPPoETag::ACSystemError(ref val) => val.len(),
            PPPoETag::GenericError(ref val) => val.len(),
            PPPoETag::HostUniq(ref val) => val.len(),
            PPPoETag::RelaySessionID(ref val) => val.len(),
            PPPoETag::ServiceName(ref val) => val.len(),
            PPPoETag::ServiceNameError(ref val) => val.len(),
            PPPoETag::VendorSpecific(ref val) => val.len(),
            _ => 0,
        }
    }
}

impl Serialize for PPPoETag {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        self.discriminant().serialize(w)?;

        match *self {
            Self::ACCookie(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                val.serialize(w)?;
            }
            Self::ACName(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                // Call `as_bytes` to avoid writing another u8 length field.
                val.as_bytes().serialize(w)?;
            }
            Self::ACSystemError(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                // Call `as_bytes` to avoid writing another u8 length field.
                val.as_bytes().serialize(w)?;
            }
            Self::GenericError(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                // Call `as_bytes` to avoid writing another u8 length field.
                val.as_bytes().serialize(w)?;
            }
            Self::HostUniq(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                val.serialize(w)?;
            }
            Self::RelaySessionID(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                val.serialize(w)?;
            }
            Self::ServiceName(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                // Call `as_bytes` to avoid writing another u8 length field.
                val.as_bytes().serialize(w)?;
            }
            Self::ServiceNameError(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                // Call `as_bytes` to avoid writing another u8 length field.
                val.as_bytes().serialize(w)?;
            }
            Self::VendorSpecific(ref val) => {
                let n: u16 = val.len().try_into()?;
                n.serialize(w)?;

                val.serialize(w)?;
            }
            _ => {}
        }

        Ok(())
    }
}

impl Deserialize for PPPoETag {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut tag_type = 0xffff_u16;
        tag_type.deserialize(r)?;

        match tag_type {
            TAG_AC_COOKIE => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::ACCookie(val);
            }
            TAG_AC_NAME => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::ACName(String::from_utf8(val)?);
            }
            TAG_AC_SYSTEM_ERROR => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::ACSystemError(String::from_utf8(val)?);
            }
            TAG_CREDITS => *self = Self::Credits,
            TAG_CREDIT_SCALE_FACTOR => *self = Self::CreditScaleFactor,
            TAG_END_OF_LIST => *self = Self::EndOfList,
            TAG_GENERIC_ERROR => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::GenericError(String::from_utf8(val)?);
            }
            TAG_HOST_UNIQ => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::HostUniq(val);
            }
            TAG_METRICS => *self = Self::Metrics,
            TAG_PPP_MAX_PAYLOAD => *self = Self::PPPMaxPayload,
            TAG_RELAY_SESSION_ID => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::RelaySessionID(val);
            }
            TAG_SEQUENCE_NUMBER => *self = Self::SequenceNumber,
            TAG_SERVICE_NAME => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::ServiceName(String::from_utf8(val)?);
            }
            TAG_SERVICE_NAME_ERROR => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::ServiceNameError(String::from_utf8(val)?);
            }
            TAG_VENDOR_SPECIFIC => {
                let mut n = 0u16;
                n.deserialize(r)?;

                let mut val = Vec::new();
                val.deserialize(&mut r.take(n.into()))?;

                *self = Self::VendorSpecific(val);
            }
            _ => return Err(Error::InvalidPPPoETag(tag_type)),
        }

        Ok(())
    }
}

impl Serialize for Vec<PPPoETag> {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for tag in self {
            tag.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<PPPoETag> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        loop {
            let mut tag = PPPoETag::None;
            let result = tag.deserialize(r);

            match result {
                Ok(_) => {
                    if let PPPoETag::EndOfList = tag {
                        break;
                    }

                    self.push(tag);
                }
                Err(e) => {
                    if let Error::Io(ref ioe) = e {
                        if ioe.kind() == io::ErrorKind::UnexpectedEof {
                            break;
                        } else {
                            return Err(e);
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADI {
    pub header: PPPoEHeader,
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADI {
    pub fn new(tags: Vec<PPPoETag>) -> Result<Self> {
        Ok(Self {
            header: PPPoEHeader {
                ver_type: VerType::default(),
                code: PPPoECode::Padi,
                session_id: 0,
                len: tags
                    .iter()
                    .map(|tag| 4 + tag.len())
                    .reduce(|acc, n| acc + n)
                    .unwrap_or(0)
                    .try_into()?,
            },
            tags,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.header.session_id != 0 {
            return Err(Error::NonZeroSessionID(self.header.session_id));
        }

        if self.header.code != PPPoECode::Padi {
            return Err(Error::InvalidPPPoECode(self.header.code as u8));
        }

        if !self
            .tags
            .iter()
            .any(|tag| matches!(tag, PPPoETag::ServiceName(_)))
        {
            return Err(Error::MissingServiceName);
        }

        if 4 + self.header.len > 1484 {
            return Err(Error::PADITooBig(4 + self.header.len));
        }

        Ok(())
    }
}
