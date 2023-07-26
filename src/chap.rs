use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const CHAP_CHALLENGE: u8 = 1;
const CHAP_RESPONSE: u8 = 2;
const CHAP_SUCCESS: u8 = 3;
const CHAP_FAILURE: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CHAPPkt {
    Challenge(CHAPChallenge),
    Response(CHAPResponse),
    Success(CHAPSuccess),
    Failure(CHAPFailure),
}

impl Default for CHAPPkt {
    fn default() -> Self {
        Self::Challenge(CHAPChallenge::default())
    }
}

impl Serialize for CHAPPkt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Challenge(payload) => payload.serialize(w),
            Self::Response(payload) => payload.serialize(w),
            Self::Success(payload) => payload.serialize(w),
            Self::Failure(payload) => payload.serialize(w),
        }
    }
}

impl CHAPPkt {
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
                let mut tmp = CHAPChallenge::default();

                tmp.deserialize(r)?;
                *self = Self::Challenge(tmp);
            }
            CHAP_RESPONSE => {
                let mut tmp = CHAPResponse::default();

                tmp.deserialize(r)?;
                *self = Self::Response(tmp);
            }
            CHAP_SUCCESS => {
                let mut tmp = CHAPSuccess::default();

                tmp.deserialize(r)?;
                *self = Self::Success(tmp);
            }
            CHAP_FAILURE => {
                let mut tmp = CHAPFailure::default();

                tmp.deserialize(r)?;
                *self = Self::Failure(tmp);
            }
            _ => return Err(Error::InvalidCHAPCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CHAPFullPkt {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "payload", offset = 4, data_type = "u16"))]
    payload: CHAPPkt,
}

impl CHAPFullPkt {
    pub fn len(&self) -> u16 {
        4 + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CHAPChallenge {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    value: Vec<u8>,
    name: String,
}

impl CHAPChallenge {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CHAPResponse {
    #[ppproperly(len_for(field = "value", offset = 0, data_type = "u8"))]
    value: Vec<u8>,
    name: String,
}

impl CHAPResponse {
    pub fn len(&self) -> u16 {
        (1 + self.value.len() + self.name.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CHAPSuccess {
    message: String,
}

impl CHAPSuccess {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CHAPFailure {
    message: String,
}

impl CHAPFailure {
    pub fn len(&self) -> u16 {
        self.message.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
    }
}
