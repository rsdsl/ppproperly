use crate::{Deserialize, Error, Result, Serialize, VerType};

use std::io::{Read, Write};

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
pub enum PPPoETagType {
    ACCookie = TAG_AC_COOKIE,
    ACName = TAG_AC_NAME,
    ACSystemError = TAG_AC_SYSTEM_ERROR,
    Credits = TAG_CREDITS,
    CreditScaleFactor = TAG_CREDIT_SCALE_FACTOR,
    EndOfList = TAG_END_OF_LIST,
    GenericError = TAG_GENERIC_ERROR,
    HostUniq = TAG_HOST_UNIQ,
    Metrics = TAG_METRICS,
    PPPMaxPayload = TAG_PPP_MAX_PAYLOAD,
    RelaySessionID = TAG_RELAY_SESSION_ID,
    SequenceNumber = TAG_SEQUENCE_NUMBER,
    ServiceName = TAG_SERVICE_NAME,
    ServiceNameError = TAG_SERVICE_NAME_ERROR,
    VendorSpecific = TAG_VENDOR_SPECIFIC,
}

impl TryFrom<u16> for PPPoETagType {
    type Error = Error;

    fn try_from(tag_type: u16) -> Result<Self> {
        match tag_type {
            TAG_AC_COOKIE => Ok(Self::ACCookie),
            TAG_AC_NAME => Ok(Self::ACName),
            TAG_AC_SYSTEM_ERROR => Ok(Self::ACSystemError),
            TAG_CREDITS => Ok(Self::Credits),
            TAG_CREDIT_SCALE_FACTOR => Ok(Self::CreditScaleFactor),
            TAG_END_OF_LIST => Ok(Self::EndOfList),
            TAG_GENERIC_ERROR => Ok(Self::GenericError),
            TAG_HOST_UNIQ => Ok(Self::HostUniq),
            TAG_METRICS => Ok(Self::Metrics),
            TAG_PPP_MAX_PAYLOAD => Ok(Self::PPPMaxPayload),
            TAG_RELAY_SESSION_ID => Ok(Self::RelaySessionID),
            TAG_SEQUENCE_NUMBER => Ok(Self::SequenceNumber),
            TAG_SERVICE_NAME => Ok(Self::ServiceName),
            TAG_SERVICE_NAME_ERROR => Ok(Self::ServiceNameError),
            TAG_VENDOR_SPECIFIC => Ok(Self::VendorSpecific),
            _ => Err(Error::InvalidPPPoETag(tag_type)),
        }
    }
}

impl Serialize for PPPoETagType {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        (self.clone() as u16).serialize(w)
    }
}

impl Deserialize for PPPoETagType {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut tag_type = 0xffff_u16;
        tag_type.deserialize(r)?;

        *self = Self::try_from(tag_type)?;
        Ok(())
    }
}

/*#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADI {
    pub header: PPPoEHeader,
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADI {
    pub fn new(tags: Vec<PPPoETag>) -> Self {
        Self {
            header: PPPoEHeader {
                ver_type: VerType::default(),
                code: PPPoECode::Padi,
                session_id: 0,
            },
            tags,
        }
    }
}*/
