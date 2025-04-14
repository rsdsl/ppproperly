use crate::{ChapPkt, Deserialize, Error, IpcpPkt, Ipv6cpPkt, LcpPkt, PapPkt, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const LCP: u16 = 0xc021;
pub const PAP: u16 = 0xc023;
pub const CHAP: u16 = 0xc223;
pub const IPCP: u16 = 0x8021;
pub const IPV6CP: u16 = 0x8057;

pub const LQR: u16 = 0xc025;
pub const VAN_JACOBSON: u16 = 0x002d;

pub const CHAP_MD5: u8 = 5;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChapAlgorithm {
    Md5 = CHAP_MD5,
}

impl Default for ChapAlgorithm {
    fn default() -> Self {
        Self::Md5
    }
}

impl TryFrom<u8> for ChapAlgorithm {
    type Error = Error;

    fn try_from(chap_algorithm: u8) -> Result<Self> {
        match chap_algorithm {
            CHAP_MD5 => Ok(Self::Md5),
            _ => Err(Error::InvalidChapAlgorithm(chap_algorithm)),
        }
    }
}

impl Serialize for ChapAlgorithm {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        (*self as u8).serialize(w)
    }
}

impl Deserialize for ChapAlgorithm {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut chap_algorithm = u8::default();
        chap_algorithm.deserialize(r)?;

        *self = Self::try_from(chap_algorithm)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthProto {
    Pap,
    Chap(ChapAlgorithm),
    Unhandled(u16, Vec<u8>),
}

impl Default for AuthProto {
    fn default() -> Self {
        Self::Pap
    }
}

impl Serialize for AuthProto {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Pap => Ok(()),
            Self::Chap(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl AuthProto {
    fn discriminant(&self) -> u16 {
        match self {
            Self::Pap => PAP,
            Self::Chap(_) => CHAP,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::Pap => 0,
            Self::Chap(_) => 1,
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled auth protocol {} length {} exceeds 255",
                    *ty,
                    payload.len()
                )
            }),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            PAP => {
                *self = Self::Pap;
            }
            CHAP => {
                let mut tmp = ChapAlgorithm::default();

                tmp.deserialize(r)?;
                *self = Self::Chap(tmp);
            }
            _ => {
                let mut tmp = Vec::new();

                r.read_to_end(&mut tmp)?;
                *self = Self::Unhandled(*discriminant, tmp);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthProtocol {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    pub protocol: AuthProto,
}

impl AuthProtocol {
    pub fn len(&self) -> u8 {
        2 + self.protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<AuthProto> for AuthProtocol {
    fn from(protocol: AuthProto) -> Self {
        Self { protocol }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualityProto {
    LinkQualityReport(u32),
}

impl Default for QualityProto {
    fn default() -> Self {
        Self::LinkQualityReport(0)
    }
}

impl Serialize for QualityProto {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::LinkQualityReport(payload) => payload.serialize(w),
        }
    }
}

impl QualityProto {
    fn discriminant(&self) -> u16 {
        match self {
            Self::LinkQualityReport(_) => LQR,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::LinkQualityReport(_) => 4,
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            LQR => {
                let mut tmp = u32::default();

                tmp.deserialize(r)?;
                *self = Self::LinkQualityReport(tmp);
            }
            _ => return Err(Error::InvalidQualityProtocol(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualityProtocol {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    pub protocol: QualityProto,
}

impl QualityProtocol {
    pub fn len(&self) -> u8 {
        2 + self.protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<QualityProto> for QualityProtocol {
    fn from(protocol: QualityProto) -> Self {
        Self { protocol }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpCompressionProto {
    VanJacobsonTcpIp(VanJacobsonConfig),
    Unhandled(u16, Vec<u8>),
}

impl Default for IpCompressionProto {
    fn default() -> Self {
        Self::VanJacobsonTcpIp(VanJacobsonConfig::default())
    }
}

impl Serialize for IpCompressionProto {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::VanJacobsonTcpIp(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl IpCompressionProto {
    fn discriminant(&self) -> u16 {
        match self {
            Self::VanJacobsonTcpIp(_) => VAN_JACOBSON,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::VanJacobsonTcpIp(payload) => payload.len(),
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled ip compression protocol {} length {} exceeds 255",
                    *ty,
                    payload.len()
                )
            }),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            VAN_JACOBSON => {
                let mut tmp = VanJacobsonConfig::default();

                tmp.deserialize(r)?;
                *self = Self::VanJacobsonTcpIp(tmp);
            }
            _ => {
                let mut tmp = Vec::new();

                r.read_to_end(&mut tmp)?;
                *self = Self::Unhandled(*discriminant, tmp);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpCompressionProtocol {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    pub protocol: IpCompressionProto,
}

impl IpCompressionProtocol {
    pub fn len(&self) -> u8 {
        2 + self.protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<IpCompressionProto> for IpCompressionProtocol {
    fn from(protocol: IpCompressionProto) -> Self {
        Self { protocol }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct VanJacobsonConfig {
    max_slot_id: u8,
    comp_slot_id: u8,
}

impl VanJacobsonConfig {
    pub fn len(&self) -> u8 {
        2
    }

    pub fn is_empty(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PppData {
    Lcp(LcpPkt),
    Pap(PapPkt),
    Chap(ChapPkt),
    Ipcp(IpcpPkt),
    Ipv6cp(Ipv6cpPkt),
    Unhandled(u16, Vec<u8>),
}

impl Default for PppData {
    fn default() -> Self {
        Self::Lcp(LcpPkt::default())
    }
}

impl Serialize for PppData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Lcp(payload) => payload.serialize(w),
            Self::Pap(payload) => payload.serialize(w),
            Self::Chap(payload) => payload.serialize(w),
            Self::Ipcp(payload) => payload.serialize(w),
            Self::Ipv6cp(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl PppData {
    fn discriminant(&self) -> u16 {
        match self {
            Self::Lcp(_) => LCP,
            Self::Pap(_) => PAP,
            Self::Chap(_) => CHAP,
            Self::Ipcp(_) => IPCP,
            Self::Ipv6cp(_) => IPV6CP,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Lcp(payload) => payload.len(),
            Self::Pap(payload) => payload.len(),
            Self::Chap(payload) => payload.len(),
            Self::Ipcp(payload) => payload.len(),
            Self::Ipv6cp(payload) => payload.len(),
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled ppp protocol {} packet length {} exceeds 65535",
                    *ty,
                    payload.len()
                )
            }),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u16,
    ) -> Result<()> {
        match *discriminant {
            LCP => {
                let mut tmp = LcpPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Lcp(tmp);
            }
            PAP => {
                let mut tmp = PapPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Pap(tmp);
            }
            CHAP => {
                let mut tmp = ChapPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Chap(tmp);
            }
            IPCP => {
                let mut tmp = IpcpPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Ipcp(tmp);
            }
            IPV6CP => {
                let mut tmp = Ipv6cpPkt::default();

                tmp.deserialize(r)?;
                *self = Self::Ipv6cp(tmp);
            }
            _ => {
                let mut tmp = Vec::new();

                r.read_to_end(&mut tmp)?;
                *self = Self::Unhandled(*discriminant, tmp);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u16"))]
    pub data: PppData,
}

impl PppPkt {
    pub fn new_lcp(lcp: LcpPkt) -> Self {
        Self {
            data: PppData::Lcp(lcp),
        }
    }

    pub fn new_pap(pap: PapPkt) -> Self {
        Self {
            data: PppData::Pap(pap),
        }
    }

    pub fn new_chap(chap: ChapPkt) -> Self {
        Self {
            data: PppData::Chap(chap),
        }
    }

    pub fn new_ipcp(ipcp: IpcpPkt) -> Self {
        Self {
            data: PppData::Ipcp(ipcp),
        }
    }

    pub fn new_ipv6cp(ipv6cp: Ipv6cpPkt) -> Self {
        Self {
            data: PppData::Ipv6cp(ipv6cp),
        }
    }

    pub fn len(&self) -> u16 {
        2 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}
