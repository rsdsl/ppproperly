use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

const PAP_AUTH_REQUEST: u8 = 1;
const PAP_AUTH_ACK: u8 = 2;
const PAP_AUTH_NAK: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PapData {
    AuthenticateRequest(PapAuthenticateRequest),
    AuthenticateAck(PapAuthenticateAck),
    AuthenticateNak(PapAuthenticateNak),
}

impl Default for PapData {
    fn default() -> Self {
        Self::AuthenticateRequest(PapAuthenticateRequest::default())
    }
}

impl Serialize for PapData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::AuthenticateRequest(payload) => payload.serialize(w),
            Self::AuthenticateAck(payload) => payload.serialize(w),
            Self::AuthenticateNak(payload) => payload.serialize(w),
        }
    }
}

impl PapData {
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
                let mut tmp = PapAuthenticateRequest::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateRequest(tmp);
            }
            PAP_AUTH_ACK => {
                let mut tmp = PapAuthenticateAck::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateAck(tmp);
            }
            PAP_AUTH_NAK => {
                let mut tmp = PapAuthenticateNak::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticateNak(tmp);
            }
            _ => return Err(Error::InvalidPapCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    data: PapData,
}

impl PapPkt {
    pub fn new_authenticate_request(identifier: u8, peer_id: String, passwd: String) -> Self {
        Self {
            identifier,
            data: PapData::AuthenticateRequest(PapAuthenticateRequest { peer_id, passwd }),
        }
    }

    pub fn new_authenticate_ack(identifier: u8, msg: String) -> Self {
        Self {
            identifier,
            data: PapData::AuthenticateAck(PapAuthenticateAck { msg }),
        }
    }

    pub fn new_authenticate_nak(identifier: u8, msg: String) -> Self {
        Self {
            identifier,
            data: PapData::AuthenticateNak(PapAuthenticateNak { msg }),
        }
    }

    pub fn len(&self) -> u16 {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateRequest {
    #[ppproperly(len_for(field = "peer_id", offset = 0, data_type = "u8"))]
    peer_id: String,
    #[ppproperly(len_for(field = "passwd", offset = 0, data_type = "u8"))]
    passwd: String,
}

impl PapAuthenticateRequest {
    pub fn len(&self) -> u16 {
        (2 + self.peer_id.len() + self.passwd.len())
            .try_into()
            .unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateAck {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    msg: String,
}

impl PapAuthenticateAck {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateNak {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    msg: String,
}

impl PapAuthenticateNak {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}
