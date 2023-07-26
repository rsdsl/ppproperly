use crate::{Deserialize, Error, PppPkt, Result, Serialize, VerType};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const ETHER_TYPE_PPPOED: u16 = 0x8863;
const ETHER_TYPE_PPPOES: u16 = 0x8864;

const PPP: u8 = 0x00; // Pppoe Active Session PPP Packet
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
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const UNSPECIFIED: MacAddr = MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    pub const BROADCAST: MacAddr = MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

impl From<[u8; 6]> for MacAddr {
    fn from(mac_addr: [u8; 6]) -> Self {
        Self(mac_addr)
    }
}

impl Serialize for MacAddr {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        self.0.serialize(w)?;
        Ok(())
    }
}

impl Deserialize for MacAddr {
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
    PppoeDiscovery = ETHER_TYPE_PPPOED,
    PppoeSession = ETHER_TYPE_PPPOES,
}

impl Default for EtherType {
    fn default() -> Self {
        Self::PppoeDiscovery
    }
}

impl TryFrom<u16> for EtherType {
    type Error = Error;

    fn try_from(ether_type: u16) -> Result<Self> {
        match ether_type {
            ETHER_TYPE_PPPOED => Ok(Self::PppoeDiscovery),
            ETHER_TYPE_PPPOES => Ok(Self::PppoeSession),
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
pub enum PppoeCode {
    Ppp = PPP,
    Padi = PADI,
    Pado = PADO,
    Padr = PADR,
    Pads = PADS,
    Padt = PADT,
}

impl Default for PppoeCode {
    fn default() -> Self {
        Self::Ppp
    }
}

impl TryFrom<u8> for PppoeCode {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self> {
        match code {
            PPP => Ok(Self::Ppp),
            PADI => Ok(Self::Padi),
            PADO => Ok(Self::Pado),
            PADR => Ok(Self::Padr),
            PADS => Ok(Self::Pads),
            PADT => Ok(Self::Padt),
            _ => Err(Error::InvalidPppoeCode(code)),
        }
    }
}

impl Serialize for PppoeCode {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        (*self as u8).serialize(w)
    }
}

impl Deserialize for PppoeCode {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut code = 0u8;
        code.deserialize(r)?;

        *self = Self::try_from(code)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PppoeVal {
    AcCookie(Vec<u8>),
    AcName(String),
    AcSystemError(String),
    Credits,
    CreditScaleFactor,
    EndOfList,
    GenericError(String),
    HostUniq(Vec<u8>),
    Metrics,
    PppMaxPayload,
    RelaySessionId(Vec<u8>),
    SequenceNumber,
    ServiceName(String),
    ServiceNameError(String),
    VendorSpecific(Vec<u8>),
}

impl Serialize for PppoeVal {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::AcCookie(payload) => payload.serialize(w),
            Self::AcName(payload) => payload.as_bytes().serialize(w),
            Self::AcSystemError(payload) => payload.as_bytes().serialize(w),
            Self::Credits => Ok(()),
            Self::CreditScaleFactor => Ok(()),
            Self::EndOfList => Ok(()),
            Self::GenericError(payload) => payload.as_bytes().serialize(w),
            Self::HostUniq(payload) => payload.serialize(w),
            Self::Metrics => Ok(()),
            Self::PppMaxPayload => Ok(()),
            Self::RelaySessionId(payload) => payload.serialize(w),
            Self::SequenceNumber => Ok(()),
            Self::ServiceName(payload) => payload.as_bytes().serialize(w),
            Self::ServiceNameError(payload) => payload.as_bytes().serialize(w),
            Self::VendorSpecific(payload) => payload.serialize(w),
        }
    }
}

impl PppoeVal {
    fn discriminant(&self) -> u16 {
        match self {
            Self::AcCookie(_) => TAG_AC_COOKIE,
            Self::AcName(_) => TAG_AC_NAME,
            Self::AcSystemError(_) => TAG_AC_SYSTEM_ERROR,
            Self::Credits => TAG_CREDITS,
            Self::CreditScaleFactor => TAG_CREDIT_SCALE_FACTOR,
            Self::EndOfList => TAG_END_OF_LIST,
            Self::GenericError(_) => TAG_GENERIC_ERROR,
            Self::HostUniq(_) => TAG_HOST_UNIQ,
            Self::Metrics => TAG_METRICS,
            Self::PppMaxPayload => TAG_PPP_MAX_PAYLOAD,
            Self::RelaySessionId(_) => TAG_RELAY_SESSION_ID,
            Self::SequenceNumber => TAG_SEQUENCE_NUMBER,
            Self::ServiceName(_) => TAG_SERVICE_NAME,
            Self::ServiceNameError(_) => TAG_SERVICE_NAME_ERROR,
            Self::VendorSpecific(_) => TAG_VENDOR_SPECIFIC,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::AcCookie(payload) => payload.len().try_into().unwrap(),
            Self::AcName(payload) => payload.len().try_into().unwrap(),
            Self::AcSystemError(payload) => payload.len().try_into().unwrap(),
            Self::Credits => 0,
            Self::CreditScaleFactor => 0,
            Self::EndOfList => 0,
            Self::GenericError(payload) => payload.len().try_into().unwrap(),
            Self::HostUniq(payload) => payload.len().try_into().unwrap(),
            Self::Metrics => 0,
            Self::PppMaxPayload => 0,
            Self::RelaySessionId(payload) => payload.len().try_into().unwrap(),
            Self::SequenceNumber => 0,
            Self::ServiceName(payload) => payload.len().try_into().unwrap(),
            Self::ServiceNameError(payload) => payload.len().try_into().unwrap(),
            Self::VendorSpecific(data) => data.len().try_into().unwrap(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            TAG_AC_COOKIE => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::AcCookie(tmp);
            }
            TAG_AC_NAME => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::AcName(String::from_utf8(tmp)?);
            }
            TAG_AC_SYSTEM_ERROR => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::AcSystemError(String::from_utf8(tmp)?);
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

                tmp.deserialize(r)?;
                *self = Self::GenericError(String::from_utf8(tmp)?);
            }
            TAG_HOST_UNIQ => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::HostUniq(tmp);
            }
            TAG_METRICS => {
                *self = Self::Metrics;
            }
            TAG_PPP_MAX_PAYLOAD => {
                *self = Self::PppMaxPayload;
            }
            TAG_RELAY_SESSION_ID => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::RelaySessionId(tmp);
            }
            TAG_SEQUENCE_NUMBER => {
                *self = Self::SequenceNumber;
            }
            TAG_SERVICE_NAME => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::ServiceName(String::from_utf8(tmp)?);
            }
            TAG_SERVICE_NAME_ERROR => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::ServiceNameError(String::from_utf8(tmp)?);
            }
            TAG_VENDOR_SPECIFIC => {
                let mut tmp = Vec::default();

                tmp.deserialize(r)?;
                *self = Self::VendorSpecific(tmp);
            }
            _ => return Err(Error::InvalidPppoeTag(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoeTag {
    #[ppproperly(discriminant_for(field = "data", data_type = "u16"))]
    #[ppproperly(len_for(field = "data", offset = 0, data_type = "u16"))]
    data: PppoeVal,
}

impl PppoeTag {
    pub fn len(&self) -> u16 {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

impl From<PppoeVal> for PppoeTag {
    fn from(data: PppoeVal) -> Self {
        Self { data }
    }
}

impl Serialize for [PppoeTag] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for tag in self {
            tag.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<PppoeTag> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = PppoeTag::from(PppoeVal::EndOfList);

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PppoeData {
    Ppp(PppPkt),
    Padi(PppoePadi),
    Pado(PppoePado),
    Padr(PppoePadr),
    Pads(PppoePads),
    Padt(PppoePadt),
}

impl Default for PppoeData {
    fn default() -> Self {
        Self::Padi(PppoePadi::default())
    }
}

impl Serialize for PppoeData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Ppp(payload) => payload.serialize(w),
            Self::Padi(payload) => payload.serialize(w),
            Self::Pado(payload) => payload.serialize(w),
            Self::Padr(payload) => payload.serialize(w),
            Self::Pads(payload) => payload.serialize(w),
            Self::Padt(payload) => payload.serialize(w),
        }
    }
}

impl PppoeData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Ppp(_) => PPP,
            Self::Padi(_) => PADI,
            Self::Pado(_) => PADO,
            Self::Padr(_) => PADR,
            Self::Pads(_) => PADS,
            Self::Padt(_) => PADT,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Ppp(payload) => payload.len(),
            Self::Padi(payload) => payload.len(),
            Self::Pado(payload) => payload.len(),
            Self::Padr(payload) => payload.len(),
            Self::Pads(payload) => payload.len(),
            Self::Padt(payload) => payload.len(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            PPP => {
                let mut tmp = PppPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Ppp(tmp);
            }
            PADI => {
                let mut tmp = PppoePadi::default();

                tmp.deserialize(r)?;
                *self = Self::Padi(tmp);
            }
            PADO => {
                let mut tmp = PppoePado::default();

                tmp.deserialize(r)?;
                *self = Self::Pado(tmp);
            }
            PADR => {
                let mut tmp = PppoePadr::default();

                tmp.deserialize(r)?;
                *self = Self::Padr(tmp);
            }
            PADS => {
                let mut tmp = PppoePads::default();

                tmp.deserialize(r)?;
                *self = Self::Pads(tmp);
            }
            PADT => {
                let mut tmp = PppoePadt::default();

                tmp.deserialize(r)?;
                *self = Self::Padt(tmp);
            }
            _ => return Err(Error::InvalidPppoeCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePkt {
    dst_mac: MacAddr,
    src_mac: MacAddr,
    ether_type: EtherType,
    ver_type: VerType,
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    session_id: u16,
    #[ppproperly(len_for(field = "data", offset = 0, data_type = "u16"))]
    data: PppoeData,
}

impl PppoePkt {
    pub fn new_padi(src_mac: MacAddr, tags: Vec<PppoeTag>) -> Self {
        Self {
            dst_mac: MacAddr::BROADCAST,
            src_mac,
            ether_type: EtherType::PppoeDiscovery,
            ver_type: VerType::default(),
            session_id: 0,
            data: PppoeData::Padi(PppoePadi { tags }),
        }
    }

    pub fn new_pado(dst_mac: MacAddr, src_mac: MacAddr, tags: Vec<PppoeTag>) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PppoeDiscovery,
            ver_type: VerType::default(),
            session_id: 0,
            data: PppoeData::Pado(PppoePado { tags }),
        }
    }

    pub fn new_padr(dst_mac: MacAddr, src_mac: MacAddr, tags: Vec<PppoeTag>) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PppoeDiscovery,
            ver_type: VerType::default(),
            session_id: 0,
            data: PppoeData::Padr(PppoePadr { tags }),
        }
    }

    pub fn new_pads(
        dst_mac: MacAddr,
        src_mac: MacAddr,
        session_id: u16,
        tags: Vec<PppoeTag>,
    ) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PppoeDiscovery,
            ver_type: VerType::default(),
            session_id,
            data: PppoeData::Pads(PppoePads { tags }),
        }
    }

    pub fn new_padt(
        dst_mac: MacAddr,
        src_mac: MacAddr,
        session_id: u16,
        tags: Vec<PppoeTag>,
    ) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PppoeDiscovery,
            ver_type: VerType::default(),
            session_id,
            data: PppoeData::Padt(PppoePadt { tags }),
        }
    }

    pub fn new_ppp(dst_mac: MacAddr, src_mac: MacAddr, session_id: u16, pkt: PppPkt) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: EtherType::PppoeSession,
            ver_type: VerType::default(),
            session_id,
            data: PppoeData::Ppp(pkt),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePadi {
    pub tags: Vec<PppoeTag>,
}

impl PppoePadi {
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePado {
    pub tags: Vec<PppoeTag>,
}

impl PppoePado {
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePadr {
    pub tags: Vec<PppoeTag>,
}

impl PppoePadr {
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePads {
    pub tags: Vec<PppoeTag>,
}

impl PppoePads {
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppoePadt {
    pub tags: Vec<PppoeTag>,
}

impl PppoePadt {
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
