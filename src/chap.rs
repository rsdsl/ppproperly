use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChapData {
    Challenge(ChapChallenge),
    Response(ChapResponse),
    Success(ChapSuccess),
    Failure(ChapFailure),
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
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::Challenge(payload) => payload.len(),
            Self::Response(payload) => payload.len(),
            Self::Success(payload) => payload.len(),
            Self::Failure(payload) => payload.len(),
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
            _ => return Err(Error::InvalidChapCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    data: ChapData,
}

impl ChapPkt {
    pub fn len(&self) -> u16 {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapChallenge {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    value: Vec<u8>,
    name: String,
}

impl ChapChallenge {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapResponse {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    value: Vec<u8>,
    name: String,
}

impl ChapResponse {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapSuccess {
    message: String,
}

impl ChapSuccess {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapFailure {
    message: String,
}

impl ChapFailure {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}
