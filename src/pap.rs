use crate::{Deserialize, Error, Result, Serialize};

use std::fmt;
use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const PAP_AUTH_REQUEST: u8 = 1;
pub const PAP_AUTH_ACK: u8 = 2;
pub const PAP_AUTH_NAK: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PapData {
    AuthenticateRequest(PapAuthenticateRequest),
    AuthenticateAck(PapAuthenticateAck),
    AuthenticateNak(PapAuthenticateNak),
    Unhandled(u8, Vec<u8>),
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
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl PapData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::AuthenticateRequest(_) => PAP_AUTH_REQUEST,
            Self::AuthenticateAck(_) => PAP_AUTH_ACK,
            Self::AuthenticateNak(_) => PAP_AUTH_NAK,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::AuthenticateRequest(payload) => payload.len(),
            Self::AuthenticateAck(payload) => payload.len(),
            Self::AuthenticateNak(payload) => payload.len(),
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled pap code {} length {} exceeds 65535",
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
pub struct PapPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    pub identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    pub data: PapData,
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

impl fmt::Display for PapPkt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PAP id={}: ", self.identifier)?;
        match &self.data {
            PapData::AuthenticateRequest(auth_req) => auth_req.fmt(f),
            PapData::AuthenticateAck(auth_ack) => auth_ack.fmt(f),
            PapData::AuthenticateNak(auth_nak) => auth_nak.fmt(f),
            PapData::Unhandled(ty, payload) => write!(f, "uc={} {:?}", ty, payload),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateRequest {
    #[ppproperly(len_for(field = "peer_id", offset = 0, data_type = "u8"))]
    pub peer_id: String,
    #[ppproperly(len_for(field = "passwd", offset = 0, data_type = "u8"))]
    pub passwd: String,
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

impl fmt::Display for PapAuthenticateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let passwd_censored = "*".repeat(self.passwd.len());
        write!(
            f,
            "Auth-Req peerid={} passwd={}",
            self.peer_id, passwd_censored
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateAck {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    pub msg: String,
}

impl PapAuthenticateAck {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

impl fmt::Display for PapAuthenticateAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Auth-Ack: {}", self.msg)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PapAuthenticateNak {
    #[ppproperly(len_for(field = "msg", offset = 0, data_type = "u8"))]
    pub msg: String,
}

impl PapAuthenticateNak {
    pub fn len(&self) -> u16 {
        (1 + self.msg.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }
}

impl fmt::Display for PapAuthenticateNak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Auth-Nak: {}", self.msg)
    }
}
