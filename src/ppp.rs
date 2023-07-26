use crate::{Deserialize, Error, LcpPkt, PapPkt, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const LCP: u16 = 0xc021;
const PAP: u16 = 0xc023;
const CHAP: u16 = 0xc223;
const LQR: u16 = 0xc025;

const CHAP_MD5: u8 = 5;

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
        }
    }
}

impl AuthProto {
    fn discriminant(&self) -> u16 {
        match self {
            Self::Pap => PAP,
            Self::Chap(_) => CHAP,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::Pap => 0,
            Self::Chap(_) => 1,
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
            _ => return Err(Error::InvalidAuthProtocol(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthProtocol {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    protocol: AuthProto,
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
    protocol: QualityProto,
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
pub enum PppData {
    Lcp(LcpPkt),
    Pap(PapPkt),
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
        }
    }
}

impl PppData {
    fn discriminant(&self) -> u16 {
        match self {
            Self::Lcp(_) => LCP,
            Self::Pap(_) => PAP,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Lcp(payload) => payload.len(),
            Self::Pap(payload) => payload.len(),
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
            _ => return Err(Error::InvalidPppProtocol(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PppPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u16"))]
    data: PppData,
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

    pub fn len(&self) -> u16 {
        2 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}
