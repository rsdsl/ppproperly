use crate::{Deserialize, Error, Result, Serialize, VerType};

use std::io::{Read, Take, Write};

use ppproperly_macros::{Deserialize, Serialize};

const ETHER_TYPE_PPPOED: u16 = 0x8863;
const ETHER_TYPE_PPPOES: u16 = 0x8864;

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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MACAddr(pub [u8; 6]);

impl MACAddr {
    pub const UNSPECIFIED: MACAddr = MACAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    pub const BROADCAST: MACAddr = MACAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

impl From<[u8; 6]> for MACAddr {
    fn from(mac: [u8; 6]) -> Self {
        Self(mac)
    }
}

impl Serialize for MACAddr {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        self.0.serialize(w)?;
        Ok(())
    }
}

impl Deserialize for MACAddr {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut buf = Vec::new();
        buf.deserialize(&mut r.take(6))?;

        self.0.copy_from_slice(&buf);
        Ok(())
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtherType {
    PPPoED = ETHER_TYPE_PPPOED,
    PPPoES = ETHER_TYPE_PPPOES,
}

impl Default for EtherType {
    fn default() -> Self {
        Self::PPPoED
    }
}

impl TryFrom<u16> for EtherType {
    type Error = Error;

    fn try_from(ether_type: u16) -> Result<Self> {
        match ether_type {
            ETHER_TYPE_PPPOED => Ok(Self::PPPoED),
            ETHER_TYPE_PPPOES => Ok(Self::PPPoES),
            _ => Err(Error::InvalidEtherType(ether_type)),
        }
    }
}

impl Serialize for EtherType {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        (*self as u16).serialize(w)
    }
}

impl Deserialize for EtherType {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut ether_type = 0u16;
        ether_type.deserialize(r)?;

        *self = Self::try_from(ether_type)?;
        Ok(())
    }
}

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
    pub dst_mac: MACAddr,
    pub src_mac: MACAddr,
    pub ether_type: EtherType,
    pub ver_type: VerType,
    pub code: PPPoECode,
    pub session_id: u16,
    pub len: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PPPoETagPayload {
    ACCookie(Vec<u8>),
    ACName(String),
    ACSystemError(String),
    Credits,
    CreditScaleFactor,
    EndOfList,
    GenericError(String),
    HostUniq(Vec<u8>),
    Metrics,
    PPPMaxPayload,
    RelaySessionID(Vec<u8>),
    SequenceNumber,
    ServiceName(String),
    ServiceNameError(String),
    VendorSpecific(Vec<u8>),
}

impl Serialize for PPPoETagPayload {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::ACCookie(payload) => payload.serialize(w),
            Self::ACName(payload) => payload.as_bytes().serialize(w),
            Self::ACSystemError(payload) => payload.as_bytes().serialize(w),
            Self::Credits => Ok(()),
            Self::CreditScaleFactor => Ok(()),
            Self::EndOfList => Ok(()),
            Self::GenericError(payload) => payload.as_bytes().serialize(w),
            Self::HostUniq(payload) => payload.serialize(w),
            Self::Metrics => Ok(()),
            Self::PPPMaxPayload => Ok(()),
            Self::RelaySessionID(payload) => payload.serialize(w),
            Self::SequenceNumber => Ok(()),
            Self::ServiceName(payload) => payload.as_bytes().serialize(w),
            Self::ServiceNameError(payload) => payload.as_bytes().serialize(w),
            Self::VendorSpecific(payload) => payload.serialize(w),
        }
    }
}

impl PPPoETagPayload {
    fn discriminant(&self) -> u16 {
        match *self {
            Self::ACCookie(_) => TAG_AC_COOKIE,
            Self::ACName(_) => TAG_AC_NAME,
            Self::ACSystemError(_) => TAG_AC_SYSTEM_ERROR,
            Self::Credits => TAG_CREDITS,
            Self::CreditScaleFactor => TAG_CREDIT_SCALE_FACTOR,
            Self::EndOfList => TAG_END_OF_LIST,
            Self::GenericError(_) => TAG_GENERIC_ERROR,
            Self::HostUniq(_) => TAG_HOST_UNIQ,
            Self::Metrics => TAG_METRICS,
            Self::PPPMaxPayload => TAG_PPP_MAX_PAYLOAD,
            Self::RelaySessionID(_) => TAG_RELAY_SESSION_ID,
            Self::SequenceNumber => TAG_SEQUENCE_NUMBER,
            Self::ServiceName(_) => TAG_SERVICE_NAME,
            Self::ServiceNameError(_) => TAG_SERVICE_NAME_ERROR,
            Self::VendorSpecific(_) => TAG_VENDOR_SPECIFIC,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::ACCookie(payload) => payload.len().try_into().unwrap(),
            Self::ACName(payload) => payload.len().try_into().unwrap(),
            Self::ACSystemError(payload) => payload.len().try_into().unwrap(),
            Self::Credits => 0,
            Self::CreditScaleFactor => 0,
            Self::EndOfList => 0,
            Self::GenericError(payload) => payload.len().try_into().unwrap(),
            Self::HostUniq(payload) => payload.len().try_into().unwrap(),
            Self::Metrics => 0,
            Self::PPPMaxPayload => 0,
            Self::RelaySessionID(payload) => payload.len().try_into().unwrap(),
            Self::SequenceNumber => 0,
            Self::ServiceName(payload) => payload.len().try_into().unwrap(),
            Self::ServiceNameError(payload) => payload.len().try_into().unwrap(),
            Self::VendorSpecific(payload) => payload.len().try_into().unwrap(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        mut r: Take<&mut R>,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            TAG_AC_COOKIE => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ACCookie(tmp);
            }
            TAG_AC_NAME => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ACName(String::from_utf8(tmp)?);
            }
            TAG_AC_SYSTEM_ERROR => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ACSystemError(String::from_utf8(tmp)?);
            }
            TAG_CREDITS => {
                *self = Self::Credits;
            }
            TAG_CREDIT_SCALE_FACTOR => {
                *self = Self::CreditScaleFactor;
            }
            TAG_END_OF_LIST => {
                *self = Self::EndOfList;
            }
            TAG_GENERIC_ERROR => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::GenericError(String::from_utf8(tmp)?);
            }
            TAG_HOST_UNIQ => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::HostUniq(tmp);
            }
            TAG_METRICS => {
                *self = Self::Metrics;
            }
            TAG_PPP_MAX_PAYLOAD => {
                *self = Self::PPPMaxPayload;
            }
            TAG_RELAY_SESSION_ID => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::RelaySessionID(tmp);
            }
            TAG_SEQUENCE_NUMBER => {
                *self = Self::SequenceNumber;
            }
            TAG_SERVICE_NAME => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ServiceName(String::from_utf8(tmp)?);
            }
            TAG_SERVICE_NAME_ERROR => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ServiceNameError(String::from_utf8(tmp)?);
            }
            TAG_VENDOR_SPECIFIC => {
                let mut tmp = Vec::default();
                tmp.deserialize(&mut r)?;

                *self = Self::VendorSpecific(tmp);
            }
            _ => return Err(Error::InvalidPPPoETag(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoETag {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u16"))]
    #[ppproperly(len_for = "payload")]
    payload: PPPoETagPayload,
}

impl PPPoETag {
    pub fn len(&self) -> u16 {
        4 + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

impl From<PPPoETagPayload> for PPPoETag {
    fn from(payload: PPPoETagPayload) -> Self {
        Self { payload }
    }
}

impl Serialize for [PPPoETag] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for tag in self {
            tag.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<PPPoETag> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = PPPoETag::from(PPPoETagPayload::EndOfList);

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PPPoEPkt {
    Padi(PPPoEPADI),
    Pado(PPPoEPADO),
    Padr(PPPoEPADR),
    Pads(PPPoEPADS),
    Padt(PPPoEPADT),
}

impl Default for PPPoEPkt {
    fn default() -> Self {
        Self::Padi(PPPoEPADI::default())
    }
}

impl Serialize for PPPoEPkt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Padi(payload) => payload.serialize(w),
            Self::Pado(payload) => payload.serialize(w),
            Self::Padr(payload) => payload.serialize(w),
            Self::Pads(payload) => payload.serialize(w),
            Self::Padt(payload) => payload.serialize(w),
        }
    }
}

impl PPPoEPkt {
    fn discriminant(&self) -> u8 {
        match *self {
            Self::Padi(_) => PADI,
            Self::Pado(_) => PADO,
            Self::Padr(_) => PADR,
            Self::Pads(_) => PADS,
            Self::Padt(_) => PADT,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Padi(payload) => payload.len(),
            Self::Pado(payload) => payload.len(),
            Self::Padr(payload) => payload.len(),
            Self::Pads(payload) => payload.len(),
            Self::Padt(payload) => payload.len(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        mut r: Take<&mut R>,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            PADI => {
                let mut tmp = PPPoEPADI::default();
                tmp.deserialize(&mut r)?;

                *self = Self::Padi(tmp);
            }
            PADO => {
                let mut tmp = PPPoEPADO::default();
                tmp.deserialize(&mut r)?;

                *self = Self::Pado(tmp);
            }
            PADR => {
                let mut tmp = PPPoEPADR::default();
                tmp.deserialize(&mut r)?;

                *self = Self::Padr(tmp);
            }
            PADS => {
                let mut tmp = PPPoEPADS::default();
                tmp.deserialize(&mut r)?;

                *self = Self::Pads(tmp);
            }
            PADT => {
                let mut tmp = PPPoEPADT::default();
                tmp.deserialize(&mut r)?;

                *self = Self::Padt(tmp);
            }
            _ => return Err(Error::InvalidPPPoECode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEFullPkt {
    dst_mac: MACAddr,
    src_mac: MACAddr,
    ether_type: EtherType,
    ver_type: VerType,
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    session_id: u16,
    #[ppproperly(len_for = "payload")]
    payload: PPPoEPkt,
}

impl PPPoEFullPkt {
    pub fn new_padi(src_mac: MACAddr, tags: Vec<PPPoETag>) -> Self {
        Self {
            dst_mac: MACAddr::BROADCAST,
            src_mac,
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            session_id: 0,
            payload: PPPoEPkt::Padi(PPPoEPADI { tags }),
        }
    }

    pub fn new_pado(dst_mac: MACAddr, src_mac: MACAddr, tags: Vec<PPPoETag>) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            session_id: 0,
            payload: PPPoEPkt::Pado(PPPoEPADO { tags }),
        }
    }

    pub fn new_padr(dst_mac: MACAddr, src_mac: MACAddr, tags: Vec<PPPoETag>) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            session_id: 0,
            payload: PPPoEPkt::Padr(PPPoEPADR { tags }),
        }
    }

    pub fn new_pads(
        dst_mac: MACAddr,
        src_mac: MACAddr,
        session_id: u16,
        tags: Vec<PPPoETag>,
    ) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            session_id,
            payload: PPPoEPkt::Pads(PPPoEPADS { tags }),
        }
    }

    pub fn new_padt(
        dst_mac: MACAddr,
        src_mac: MACAddr,
        session_id: u16,
        tags: Vec<PPPoETag>,
    ) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            session_id,
            payload: PPPoEPkt::Padt(PPPoEPADT { tags }),
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADI {
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADI {
    pub fn len(&self) -> u16 {
        self.tags
            .iter()
            .map(|tag| tag.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADO {
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADO {
    pub fn len(&self) -> u16 {
        self.tags
            .iter()
            .map(|tag| tag.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADR {
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADR {
    pub fn len(&self) -> u16 {
        self.tags
            .iter()
            .map(|tag| tag.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADS {
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADS {
    pub fn len(&self) -> u16 {
        self.tags
            .iter()
            .map(|tag| tag.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PPPoEPADT {
    pub tags: Vec<PPPoETag>,
}

impl PPPoEPADT {
    pub fn len(&self) -> u16 {
        self.tags
            .iter()
            .map(|tag| tag.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}
