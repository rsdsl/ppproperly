use crate::{Deserialize, Error, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const IPV6CP_CONFIGURE_REQUEST: u8 = 1;
pub const IPV6CP_CONFIGURE_ACK: u8 = 2;
pub const IPV6CP_CONFIGURE_NAK: u8 = 3;
pub const IPV6CP_CONFIGURE_REJECT: u8 = 4;
pub const IPV6CP_TERMINATE_REQUEST: u8 = 5;
pub const IPV6CP_TERMINATE_ACK: u8 = 6;
pub const IPV6CP_CODE_REJECT: u8 = 7;

pub const OPT_INTERFACE_IDENTIFIER: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv6cpOpt {
    InterfaceId(u64),
    Unhandled(u8, Vec<u8>),
}

impl Serialize for Ipv6cpOpt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::InterfaceId(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl Ipv6cpOpt {
    fn discriminant(&self) -> u8 {
        match self {
            Self::InterfaceId(_) => OPT_INTERFACE_IDENTIFIER,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::InterfaceId(_) => 8,
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled ipv6cp option {} length {} exceeds 255",
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
            OPT_INTERFACE_IDENTIFIER => {
                let mut tmp = u64::default();

                tmp.deserialize(r)?;
                *self = Self::InterfaceId(tmp);
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpOption {
    #[ppproperly(discriminant_for(field = "value", data_type = "u8"))]
    #[ppproperly(len_for(field = "value", offset = 2, data_type = "u8"))]
    pub value: Ipv6cpOpt,
}

impl Ipv6cpOption {
    pub fn len(&self) -> u8 {
        2 + self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<Ipv6cpOpt> for Ipv6cpOption {
    fn from(value: Ipv6cpOpt) -> Self {
        Self { value }
    }
}

impl Serialize for [Ipv6cpOption] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for option in self {
            option.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<Ipv6cpOption> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = Ipv6cpOption::from(Ipv6cpOpt::InterfaceId(u64::default()));

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv6cpData {
    ConfigureRequest(Ipv6cpConfigureRequest),
    ConfigureAck(Ipv6cpConfigureAck),
    ConfigureNak(Ipv6cpConfigureNak),
    ConfigureReject(Ipv6cpConfigureReject),
    TerminateRequest(Ipv6cpTerminateRequest),
    TerminateAck(Ipv6cpTerminateAck),
    CodeReject(Ipv6cpCodeReject),
}

impl Default for Ipv6cpData {
    fn default() -> Self {
        Self::ConfigureRequest(Ipv6cpConfigureRequest::default())
    }
}

impl Serialize for Ipv6cpData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::ConfigureRequest(payload) => payload.serialize(w),
            Self::ConfigureAck(payload) => payload.serialize(w),
            Self::ConfigureNak(payload) => payload.serialize(w),
            Self::ConfigureReject(payload) => payload.serialize(w),
            Self::TerminateRequest(payload) => payload.serialize(w),
            Self::TerminateAck(payload) => payload.serialize(w),
            Self::CodeReject(payload) => payload.serialize(w),
        }
    }
}

impl Ipv6cpData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::ConfigureRequest(_) => IPV6CP_CONFIGURE_REQUEST,
            Self::ConfigureAck(_) => IPV6CP_CONFIGURE_ACK,
            Self::ConfigureNak(_) => IPV6CP_CONFIGURE_NAK,
            Self::ConfigureReject(_) => IPV6CP_CONFIGURE_REJECT,
            Self::TerminateRequest(_) => IPV6CP_TERMINATE_REQUEST,
            Self::TerminateAck(_) => IPV6CP_TERMINATE_ACK,
            Self::CodeReject(_) => IPV6CP_CODE_REJECT,
        }
    }

    fn len(&self) -> u16 {
        match self {
            Self::ConfigureRequest(payload) => payload.len(),
            Self::ConfigureAck(payload) => payload.len(),
            Self::ConfigureNak(payload) => payload.len(),
            Self::ConfigureReject(payload) => payload.len(),
            Self::TerminateRequest(payload) => payload.len(),
            Self::TerminateAck(payload) => payload.len(),
            Self::CodeReject(payload) => payload.len(),
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        r: &mut R,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            IPV6CP_CONFIGURE_REQUEST => {
                let mut tmp = Ipv6cpConfigureRequest::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureRequest(tmp);
            }
            IPV6CP_CONFIGURE_ACK => {
                let mut tmp = Ipv6cpConfigureAck::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureAck(tmp);
            }
            IPV6CP_CONFIGURE_NAK => {
                let mut tmp = Ipv6cpConfigureNak::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureNak(tmp);
            }
            IPV6CP_CONFIGURE_REJECT => {
                let mut tmp = Ipv6cpConfigureReject::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureReject(tmp);
            }
            IPV6CP_TERMINATE_REQUEST => {
                let mut tmp = Ipv6cpTerminateRequest::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateRequest(tmp);
            }
            IPV6CP_TERMINATE_ACK => {
                let mut tmp = Ipv6cpTerminateAck::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateAck(tmp);
            }
            IPV6CP_CODE_REJECT => {
                let mut tmp = Ipv6cpCodeReject::default();

                tmp.deserialize(r)?;
                *self = Self::CodeReject(tmp);
            }
            _ => return Err(Error::InvalidIpv6cpCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    pub identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    pub data: Ipv6cpData,
}

impl Ipv6cpPkt {
    pub fn new_configure_request(identifier: u8, options: Vec<Ipv6cpOption>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::ConfigureRequest(Ipv6cpConfigureRequest { options }),
        }
    }

    pub fn new_configure_ack(identifier: u8, options: Vec<Ipv6cpOption>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::ConfigureAck(Ipv6cpConfigureAck { options }),
        }
    }

    pub fn new_configure_nak(identifier: u8, options: Vec<Ipv6cpOption>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::ConfigureNak(Ipv6cpConfigureNak { options }),
        }
    }

    pub fn new_configure_reject(identifier: u8, options: Vec<Ipv6cpOption>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::ConfigureReject(Ipv6cpConfigureReject { options }),
        }
    }

    pub fn new_terminate_request(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::TerminateRequest(Ipv6cpTerminateRequest { data }),
        }
    }

    pub fn new_terminate_ack(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::TerminateAck(Ipv6cpTerminateAck { data }),
        }
    }

    pub fn new_code_reject(identifier: u8, pkt: Vec<u8>) -> Self {
        Self {
            identifier,
            data: Ipv6cpData::CodeReject(Ipv6cpCodeReject { pkt }),
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
pub struct Ipv6cpConfigureRequest {
    pub options: Vec<Ipv6cpOption>,
}

impl Ipv6cpConfigureRequest {
    pub fn len(&self) -> u16 {
        self.options
            .iter()
            .map(|option| option.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
            .into()
    }

    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpConfigureAck {
    pub options: Vec<Ipv6cpOption>,
}

impl Ipv6cpConfigureAck {
    pub fn len(&self) -> u16 {
        self.options
            .iter()
            .map(|option| option.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
            .into()
    }

    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpConfigureNak {
    pub options: Vec<Ipv6cpOption>,
}

impl Ipv6cpConfigureNak {
    pub fn len(&self) -> u16 {
        self.options
            .iter()
            .map(|option| option.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
            .into()
    }

    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpConfigureReject {
    pub options: Vec<Ipv6cpOption>,
}

impl Ipv6cpConfigureReject {
    pub fn len(&self) -> u16 {
        self.options
            .iter()
            .map(|option| option.len())
            .reduce(|acc, n| acc + n)
            .unwrap_or(0)
            .into()
    }

    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpTerminateRequest {
    pub data: Vec<u8>,
}

impl Ipv6cpTerminateRequest {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpTerminateAck {
    pub data: Vec<u8>,
}

impl Ipv6cpTerminateAck {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6cpCodeReject {
    pub pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl Ipv6cpCodeReject {
    pub fn len(&self) -> u16 {
        self.pkt.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.pkt.is_empty()
    }
}
