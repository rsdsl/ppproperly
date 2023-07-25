use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

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
pub enum AuthProtocol {
    Pap,
    Chap(ChapAlgorithm),
}

impl Default for AuthProtocol {
    fn default() -> Self {
        Self::Pap
    }
}

impl Serialize for AuthProtocol {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Pap => Ok(()),
            Self::Chap(payload) => payload.serialize(w),
        }
    }
}

impl AuthProtocol {
    fn discriminant(&self) -> u16 {
        match *self {
            Self::Pap => PAP,
            Self::Chap(_) => CHAP,
        }
    }

    fn len(&self) -> u8 {
        match *self {
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
pub struct AuthProtocolInfo {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    protocol: AuthProtocol,
}

impl AuthProtocolInfo {
    pub fn len(&self) -> u8 {
        2 + self.protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<AuthProtocol> for AuthProtocolInfo {
    fn from(protocol: AuthProtocol) -> Self {
        Self { protocol }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualityProtocol {
    LinkQualityReport(u32),
}

impl Default for QualityProtocol {
    fn default() -> Self {
        Self::LinkQualityReport(0)
    }
}

impl Serialize for QualityProtocol {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::LinkQualityReport(payload) => payload.serialize(w),
        }
    }
}

impl QualityProtocol {
    fn discriminant(&self) -> u16 {
        match *self {
            Self::LinkQualityReport(_) => LQR,
        }
    }

    fn len(&self) -> u8 {
        match *self {
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
pub struct QualityProtocolInfo {
    #[ppproperly(discriminant_for(field = "protocol", data_type = "u16"))]
    protocol: QualityProtocol,
}

impl QualityProtocolInfo {
    pub fn len(&self) -> u8 {
        2 + self.protocol.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<QualityProtocol> for QualityProtocolInfo {
    fn from(protocol: QualityProtocol) -> Self {
        Self { protocol }
    }
}
