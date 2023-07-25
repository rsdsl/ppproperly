use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const PAP_AUTH_REQUEST: u8 = 1;
const PAP_AUTH_ACK: u8 = 2;
const PAP_AUTH_NAK: u8 = 3;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PAPString(pub String);

impl Serialize for PAPString {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        self.0.as_str().serialize(w)
    }
}

impl Deserialize for PAPString {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        self.0.deserialize(r)
    }
}

impl PAPString {
    pub fn len(&self) -> u8 {
        self.0.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PAPPkt {
    AuthenticateRequest(PAPAuthenticateRequest),
    AuthenticateAck(PAPAuthenticateAck),
    AuthenticateNak(PAPAuthenticateNak),
}

impl Default for PAPPkt {
    fn default() -> Self {
        Self::AuthenticateRequest(PAPAuthenticateRequest::default())
    }
}

impl Serialize for PAPPkt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::AuthenticateRequest(payload) => payload.serialize(w),
            Self::AuthenticateAck(payload) => payload.serialize(w),
            Self::AuthenticateNak(payload) => payload.serialize(w),
        }
    }
}

impl PAPPkt {
    fn discriminant(&self) -> u8 {
        match self {
            Self::AuthenticateRequest(_) => PAP_AUTH_REQUEST,
            Self::AuthenticateAck(_) => PAP_AUTH_ACK,
            Self::AuthenticateNak(_) => PAP_AUTH_NAK,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::AuthenticateRequest(payload) => payload.len(),
            Self::AuthenticateAck(payload) => payload.len(),
            Self::AuthenticateNak(payload) => payload.len(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            PAP_AUTH_REQUEST => {
                let mut tmp = PAPAuthenticateRequest::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateRequest(tmp);
            }
            PAP_AUTH_ACK => {
                let mut tmp = PAPAuthenticateAck::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateAck(tmp);
            }
            PAP_AUTH_NAK => {
                let mut tmp = PAPAuthenticateNak::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateNak(tmp);
            }
            _ => return Err(Error::InvalidPAPCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PAPFullPkt {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "payload", offset = 4, data_type = "u16"))]
    payload: PAPPkt,
}

impl PAPFullPkt {
    pub fn len(&self) -> u16 {
        4 + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PAPAuthenticateRequest {
    #[ppproperly(len_for(field = "peer_id", offset = 0, data_type = "u8"))]
    peer_id: PAPString,
    #[ppproperly(len_for(field = "passwd", offset = 0, data_type = "u8"))]
    passwd: PAPString,
}

impl PAPAuthenticateRequest {
    pub fn len(&self) -> u16 {
        (2 + self.peer_id.len() + self.passwd.len()).into()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PAPAuthenticateAck {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    msg: PAPString,
}

impl PAPAuthenticateAck {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).into()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PAPAuthenticateNak {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    msg: PAPString,
}

impl PAPAuthenticateNak {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).into()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}
