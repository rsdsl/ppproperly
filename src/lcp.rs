use crate::{AuthProtocol, Deserialize, Error, QualityProtocol, Result, Serialize};

use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const LCP_CONFIGURE_REQUEST: u8 = 1;
pub const LCP_CONFIGURE_ACK: u8 = 2;
pub const LCP_CONFIGURE_NAK: u8 = 3;
pub const LCP_CONFIGURE_REJECT: u8 = 4;
pub const LCP_TERMINATE_REQUEST: u8 = 5;
pub const LCP_TERMINATE_ACK: u8 = 6;
pub const LCP_CODE_REJECT: u8 = 7;
pub const LCP_PROTOCOL_REJECT: u8 = 8;
pub const LCP_ECHO_REQUEST: u8 = 9;
pub const LCP_ECHO_REPLY: u8 = 10;
pub const LCP_DISCARD_REQUEST: u8 = 11;

pub const OPT_MRU: u8 = 1;
pub const OPT_AUTHENTICATION_PROTOCOL: u8 = 3;
pub const OPT_QUALITY_PROTOCOL: u8 = 4;
pub const OPT_MAGIC_NUMBER: u8 = 5;
pub const OPT_PROTOCOL_FIELD_COMPRESSION: u8 = 7;
pub const OPT_ADDR_CTL_FIELD_COMPRESSION: u8 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LcpOpt {
    Mru(u16),
    AuthenticationProtocol(AuthProtocol),
    QualityProtocol(QualityProtocol),
    MagicNumber(u32),
    ProtocolFieldCompression,
    AddrCtlFieldCompression,
    Unhandled(u8, Vec<u8>),
}

impl Serialize for LcpOpt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::Mru(payload) => payload.serialize(w),
            Self::AuthenticationProtocol(payload) => payload.serialize(w),
            Self::QualityProtocol(payload) => payload.serialize(w),
            Self::MagicNumber(payload) => payload.serialize(w),
            Self::ProtocolFieldCompression => Ok(()),
            Self::AddrCtlFieldCompression => Ok(()),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl LcpOpt {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Mru(_) => OPT_MRU,
            Self::AuthenticationProtocol(_) => OPT_AUTHENTICATION_PROTOCOL,
            Self::QualityProtocol(_) => OPT_QUALITY_PROTOCOL,
            Self::MagicNumber(_) => OPT_MAGIC_NUMBER,
            Self::ProtocolFieldCompression => OPT_PROTOCOL_FIELD_COMPRESSION,
            Self::AddrCtlFieldCompression => OPT_ADDR_CTL_FIELD_COMPRESSION,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::Mru(_) => 2,
            Self::AuthenticationProtocol(payload) => payload.len(),
            Self::QualityProtocol(payload) => payload.len(),
            Self::MagicNumber(_) => 4,
            Self::ProtocolFieldCompression => 0,
            Self::AddrCtlFieldCompression => 0,
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled lcp option {} length {} exceeds 255",
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
            OPT_MRU => {
                let mut tmp = u16::default();

                tmp.deserialize(r)?;
                *self = Self::Mru(tmp);
            }
            OPT_AUTHENTICATION_PROTOCOL => {
                let mut tmp = AuthProtocol::default();

                tmp.deserialize(r)?;
                *self = Self::AuthenticationProtocol(tmp);
            }
            OPT_QUALITY_PROTOCOL => {
                let mut tmp = QualityProtocol::default();

                tmp.deserialize(r)?;
                *self = Self::QualityProtocol(tmp);
            }
            OPT_MAGIC_NUMBER => {
                let mut tmp = u32::default();

                tmp.deserialize(r)?;
                *self = Self::MagicNumber(tmp);
            }
            OPT_PROTOCOL_FIELD_COMPRESSION => {
                *self = Self::ProtocolFieldCompression;
            }
            OPT_ADDR_CTL_FIELD_COMPRESSION => {
                *self = Self::AddrCtlFieldCompression;
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
pub struct LcpOption {
    #[ppproperly(discriminant_for(field = "value", data_type = "u8"))]
    #[ppproperly(len_for(field = "value", offset = 2, data_type = "u8"))]
    pub value: LcpOpt,
}

impl LcpOption {
    pub fn len(&self) -> u8 {
        2 + self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<LcpOpt> for LcpOption {
    fn from(value: LcpOpt) -> Self {
        Self { value }
    }
}

impl Serialize for [LcpOption] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for option in self {
            option.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<LcpOption> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = LcpOption::from(LcpOpt::MagicNumber(0));

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LcpData {
    ConfigureRequest(LcpConfigureRequest),
    ConfigureAck(LcpConfigureAck),
    ConfigureNak(LcpConfigureNak),
    ConfigureReject(LcpConfigureReject),
    TerminateRequest(LcpTerminateRequest),
    TerminateAck(LcpTerminateAck),
    CodeReject(LcpCodeReject),
    ProtocolReject(LcpProtocolReject),
    EchoRequest(LcpEchoRequest),
    EchoReply(LcpEchoReply),
    DiscardRequest(LcpDiscardRequest),
    Unhandled(u8, Vec<u8>),
}

impl Default for LcpData {
    fn default() -> Self {
        Self::ConfigureRequest(LcpConfigureRequest::default())
    }
}

impl Serialize for LcpData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::ConfigureRequest(payload) => payload.serialize(w),
            Self::ConfigureAck(payload) => payload.serialize(w),
            Self::ConfigureNak(payload) => payload.serialize(w),
            Self::ConfigureReject(payload) => payload.serialize(w),
            Self::TerminateRequest(payload) => payload.serialize(w),
            Self::TerminateAck(payload) => payload.serialize(w),
            Self::CodeReject(payload) => payload.serialize(w),
            Self::ProtocolReject(payload) => payload.serialize(w),
            Self::EchoRequest(payload) => payload.serialize(w),
            Self::EchoReply(payload) => payload.serialize(w),
            Self::DiscardRequest(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl LcpData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::ConfigureRequest(_) => LCP_CONFIGURE_REQUEST,
            Self::ConfigureAck(_) => LCP_CONFIGURE_ACK,
            Self::ConfigureNak(_) => LCP_CONFIGURE_NAK,
            Self::ConfigureReject(_) => LCP_CONFIGURE_REJECT,
            Self::TerminateRequest(_) => LCP_TERMINATE_REQUEST,
            Self::TerminateAck(_) => LCP_TERMINATE_ACK,
            Self::CodeReject(_) => LCP_CODE_REJECT,
            Self::ProtocolReject(_) => LCP_PROTOCOL_REJECT,
            Self::EchoRequest(_) => LCP_ECHO_REQUEST,
            Self::EchoReply(_) => LCP_ECHO_REPLY,
            Self::DiscardRequest(_) => LCP_DISCARD_REQUEST,
            Self::Unhandled(ty, _) => *ty,
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
            Self::ProtocolReject(payload) => payload.len(),
            Self::EchoRequest(payload) => payload.len(),
            Self::EchoReply(payload) => payload.len(),
            Self::DiscardRequest(payload) => payload.len(),
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled lcp code {} length {} exceeds 65535",
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
            LCP_CONFIGURE_REQUEST => {
                let mut tmp = LcpConfigureRequest::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureRequest(tmp);
            }
            LCP_CONFIGURE_ACK => {
                let mut tmp = LcpConfigureAck::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureAck(tmp);
            }
            LCP_CONFIGURE_NAK => {
                let mut tmp = LcpConfigureNak::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureNak(tmp);
            }
            LCP_CONFIGURE_REJECT => {
                let mut tmp = LcpConfigureReject::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureReject(tmp);
            }
            LCP_TERMINATE_REQUEST => {
                let mut tmp = LcpTerminateRequest::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateRequest(tmp);
            }
            LCP_TERMINATE_ACK => {
                let mut tmp = LcpTerminateAck::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateAck(tmp);
            }
            LCP_CODE_REJECT => {
                let mut tmp = LcpCodeReject::default();

                tmp.deserialize(r)?;
                *self = Self::CodeReject(tmp);
            }
            LCP_PROTOCOL_REJECT => {
                let mut tmp = LcpProtocolReject::default();

                tmp.deserialize(r)?;
                *self = Self::ProtocolReject(tmp);
            }
            LCP_ECHO_REQUEST => {
                let mut tmp = LcpEchoRequest::default();

                tmp.deserialize(r)?;
                *self = Self::EchoRequest(tmp);
            }
            LCP_ECHO_REPLY => {
                let mut tmp = LcpEchoReply::default();

                tmp.deserialize(r)?;
                *self = Self::EchoReply(tmp);
            }
            LCP_DISCARD_REQUEST => {
                let mut tmp = LcpDiscardRequest::default();

                tmp.deserialize(r)?;
                *self = Self::DiscardRequest(tmp);
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
pub struct LcpPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    pub identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    pub data: LcpData,
}

impl LcpPkt {
    pub fn new_configure_request(identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            identifier,
            data: LcpData::ConfigureRequest(LcpConfigureRequest { options }),
        }
    }

    pub fn new_configure_ack(identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            identifier,
            data: LcpData::ConfigureAck(LcpConfigureAck { options }),
        }
    }

    pub fn new_configure_nak(identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            identifier,
            data: LcpData::ConfigureNak(LcpConfigureNak { options }),
        }
    }

    pub fn new_configure_reject(identifier: u8, options: Vec<LcpOption>) -> Self {
        Self {
            identifier,
            data: LcpData::ConfigureReject(LcpConfigureReject { options }),
        }
    }

    pub fn new_terminate_request(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::TerminateRequest(LcpTerminateRequest { data }),
        }
    }

    pub fn new_terminate_ack(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::TerminateAck(LcpTerminateAck { data }),
        }
    }

    pub fn new_code_reject(identifier: u8, pkt: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::CodeReject(LcpCodeReject { pkt }),
        }
    }

    pub fn new_protocol_reject(identifier: u8, protocol: u16, pkt: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::ProtocolReject(LcpProtocolReject { protocol, pkt }),
        }
    }

    pub fn new_echo_request(identifier: u8, magic: u32, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::EchoRequest(LcpEchoRequest { magic, data }),
        }
    }

    pub fn new_echo_reply(identifier: u8, magic: u32, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::EchoReply(LcpEchoReply { magic, data }),
        }
    }

    pub fn new_discard_request(identifier: u8, magic: u32, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: LcpData::DiscardRequest(LcpDiscardRequest { magic, data }),
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
pub struct LcpConfigureRequest {
    pub options: Vec<LcpOption>,
}

impl LcpConfigureRequest {
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
pub struct LcpConfigureAck {
    pub options: Vec<LcpOption>,
}

impl LcpConfigureAck {
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
pub struct LcpConfigureNak {
    pub options: Vec<LcpOption>,
}

impl LcpConfigureNak {
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
pub struct LcpConfigureReject {
    pub options: Vec<LcpOption>,
}

impl LcpConfigureReject {
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
pub struct LcpTerminateRequest {
    pub data: Vec<u8>,
}

impl LcpTerminateRequest {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpTerminateAck {
    pub data: Vec<u8>,
}

impl LcpTerminateAck {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpCodeReject {
    pub pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl LcpCodeReject {
    pub fn len(&self) -> u16 {
        self.pkt.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.pkt.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpProtocolReject {
    pub protocol: u16,
    pub pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl LcpProtocolReject {
    pub fn len(&self) -> u16 {
        (2 + self.pkt.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpEchoRequest {
    pub magic: u32,
    pub data: Vec<u8>,
}

impl LcpEchoRequest {
    pub fn len(&self) -> u16 {
        (4 + self.data.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpEchoReply {
    pub magic: u32,
    pub data: Vec<u8>,
}

impl LcpEchoReply {
    pub fn len(&self) -> u16 {
        (4 + self.data.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LcpDiscardRequest {
    pub magic: u32,
    pub data: Vec<u8>,
}

impl LcpDiscardRequest {
    pub fn len(&self) -> u16 {
        (4 + self.data.len()).try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}
