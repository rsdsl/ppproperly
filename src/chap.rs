use crate::{Deserialize, Error, Result, Serialize};

use std::fmt;
use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const CHAP_CHALLENGE: u8 = 1;
pub const CHAP_RESPONSE: u8 = 2;
pub const CHAP_SUCCESS: u8 = 3;
pub const CHAP_FAILURE: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChapData {
    Challenge(ChapChallenge),
    Response(ChapResponse),
    Success(ChapSuccess),
    Failure(ChapFailure),
    Unhandled(u8, Vec<u8>),
}

impl Default for ChapData {
    fn default() -> Self {
        Self::Challenge(ChapChallenge::default())
    }
}

impl Serialize for ChapData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Challenge(payload) => payload.serialize(w),
            Self::Response(payload) => payload.serialize(w),
            Self::Success(payload) => payload.serialize(w),
            Self::Failure(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl ChapData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Challenge(_) => CHAP_CHALLENGE,
            Self::Response(_) => CHAP_RESPONSE,
            Self::Success(_) => CHAP_SUCCESS,
            Self::Failure(_) => CHAP_FAILURE,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Challenge(payload) => payload.len(),
            Self::Response(payload) => payload.len(),
            Self::Success(payload) => payload.len(),
            Self::Failure(payload) => payload.len(),
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled chap code {} length {} exceeds 65535",
                    *ty,
                    payload.len()
                )
            }),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            CHAP_CHALLENGE => {
                let mut tmp = ChapChallenge::default();

                tmp.deserialize(r)?;
                *self = Self::Challenge(tmp);
            }
            CHAP_RESPONSE => {
                let mut tmp = ChapResponse::default();

                tmp.deserialize(r)?;
                *self = Self::Response(tmp);
            }
            CHAP_SUCCESS => {
                let mut tmp = ChapSuccess::default();

                tmp.deserialize(r)?;
                *self = Self::Success(tmp);
            }
            CHAP_FAILURE => {
                let mut tmp = ChapFailure::default();

                tmp.deserialize(r)?;
                *self = Self::Failure(tmp);
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
pub struct ChapPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    pub identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    pub data: ChapData,
}

impl ChapPkt {
    pub fn new_challenge(identifier: u8, value: Vec<u8>, name: String) -> Self {
        Self {
            identifier,
            data: ChapData::Challenge(ChapChallenge { value, name }),
        }
    }

    pub fn new_response(identifier: u8, value: Vec<u8>, name: String) -> Self {
        Self {
            identifier,
            data: ChapData::Response(ChapResponse { value, name }),
        }
    }

    pub fn new_success(identifier: u8, message: String) -> Self {
        Self {
            identifier,
            data: ChapData::Success(ChapSuccess { message }),
        }
    }

    pub fn new_failure(identifier: u8, message: String) -> Self {
        Self {
            identifier,
            data: ChapData::Failure(ChapFailure { message }),
        }
    }

    pub fn len(&self) -> u16 {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

impl fmt::Display for ChapPkt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CHAP id={}: ", self.identifier)?;
        match &self.data {
            ChapData::Challenge(challenge) => challenge.fmt(f),
            ChapData::Response(resp) => resp.fmt(f),
            ChapData::Success(success) => success.fmt(f),
            ChapData::Failure(fail) => fail.fmt(f),
            ChapData::Unhandled(ty, payload) => write!(f, "uc={} {:?}", ty, payload),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapChallenge {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    pub value: Vec<u8>,
    pub name: String,
}

impl ChapChallenge {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

impl fmt::Display for ChapChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Challenge {:?} {}", self.value, self.name)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapResponse {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    pub value: Vec<u8>,
    pub name: String,
}

impl ChapResponse {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

impl fmt::Display for ChapResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Response {:?} {}", self.value, self.name)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapSuccess {
    pub message: String,
}

impl ChapSuccess {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}

impl fmt::Display for ChapSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Success: {}", self.message)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapFailure {
    pub message: String,
}

impl ChapFailure {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}

impl fmt::Display for ChapFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failure: {}", self.message)
    }
}
