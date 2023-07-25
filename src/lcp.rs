use crate::{AuthProtocolInfo, Deserialize, Error, QualityProtocolInfo, Result, Serialize};

use std::io::{Read, Take, Write};

use ppproperly_macros::{Deserialize, Serialize};

const LCP_CONFIGURE_REQUEST: u8 = 1;
const LCP_CONFIGURE_ACK: u8 = 2;
const LCP_CONFIGURE_NAK: u8 = 3;
const LCP_CONFIGURE_REJECT: u8 = 4;
const LCP_TERMINATE_REQUEST: u8 = 5;
const LCP_TERMINATE_ACK: u8 = 6;
const LCP_CODE_REJECT: u8 = 7;
const LCP_PROTOCOL_REJECT: u8 = 8;
const LCP_ECHO_REQUEST: u8 = 9;
const LCP_ECHO_REPLY: u8 = 10;
const LCP_DISCARD_REQUEST: u8 = 11;

const OPT_MRU: u8 = 1;
const OPT_AUTHENTICATION_PROTOCOL: u8 = 3;
const OPT_QUALITY_PROTOCOL: u8 = 4;
const OPT_MAGIC_NUMBER: u8 = 5;
const OPT_PROTOCOL_FIELD_COMPRESSION: u8 = 7;
const OPT_ADDR_CTL_FIELD_COMPRESSION: u8 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LCPOptionPayload {
    MRU(u16),
    AuthenticationProtocol(AuthProtocolInfo),
    QualityProtocol(QualityProtocolInfo),
    MagicNumber(u32),
    ProtocolFieldCompression,
    AddrCtlFieldCompression,
}

impl Serialize for LCPOptionPayload {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::MRU(payload) => payload.serialize(w),
            Self::AuthenticationProtocol(payload) => payload.serialize(w),
            Self::QualityProtocol(payload) => payload.serialize(w),
            Self::MagicNumber(payload) => payload.serialize(w),
            Self::ProtocolFieldCompression => Ok(()),
            Self::AddrCtlFieldCompression => Ok(()),
        }
    }
}

impl LCPOptionPayload {
    fn discriminant(&self) -> u8 {
        match *self {
            Self::MRU(_) => OPT_MRU,
            Self::AuthenticationProtocol(_) => OPT_AUTHENTICATION_PROTOCOL,
            Self::QualityProtocol(_) => OPT_QUALITY_PROTOCOL,
            Self::MagicNumber(_) => OPT_MAGIC_NUMBER,
            Self::ProtocolFieldCompression => OPT_PROTOCOL_FIELD_COMPRESSION,
            Self::AddrCtlFieldCompression => OPT_ADDR_CTL_FIELD_COMPRESSION,
        }
    }

    fn len(&self) -> u8 {
        match *self {
            Self::MRU(_) => 2,
            Self::AuthenticationProtocol(ref payload) => payload.len(),
            Self::QualityProtocol(ref payload) => payload.len(),
            Self::MagicNumber(_) => 4,
            Self::ProtocolFieldCompression => 0,
            Self::AddrCtlFieldCompression => 0,
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        mut r: Take<&mut R>,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            OPT_MRU => {
                let mut tmp = u16::default();
                tmp.deserialize(&mut r)?;

                *self = Self::MRU(tmp);
            }
            OPT_AUTHENTICATION_PROTOCOL => {
                let mut tmp = AuthProtocolInfo::default();
                tmp.deserialize(&mut r)?;

                *self = Self::AuthenticationProtocol(tmp);
            }
            OPT_QUALITY_PROTOCOL => {
                let mut tmp = QualityProtocolInfo::default();
                tmp.deserialize(&mut r)?;

                *self = Self::QualityProtocol(tmp);
            }
            OPT_MAGIC_NUMBER => {
                let mut tmp = u32::default();
                tmp.deserialize(&mut r)?;

                *self = Self::MagicNumber(tmp);
            }
            OPT_PROTOCOL_FIELD_COMPRESSION => {
                *self = Self::ProtocolFieldCompression;
            }
            OPT_ADDR_CTL_FIELD_COMPRESSION => {
                *self = Self::AddrCtlFieldCompression;
            }
            _ => return Err(Error::InvalidLCPOptionType(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPOption {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    #[ppproperly(len_for(field = "payload", offset = 2, data_type = "u8"))]
    payload: LCPOptionPayload,
}

impl LCPOption {
    pub fn len(&self) -> u8 {
        4 + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

impl From<LCPOptionPayload> for LCPOption {
    fn from(payload: LCPOptionPayload) -> Self {
        Self { payload }
    }
}

impl Serialize for [LCPOption] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for option in self {
            option.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<LCPOption> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = LCPOption::from(LCPOptionPayload::MagicNumber(0));

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LCPPkt {
    ConfigureRequest(LCPConfigureRequest),
    ConfigureAck(LCPConfigureAck),
    ConfigureNak(LCPConfigureNak),
    ConfigureReject(LCPConfigureReject),
    TerminateRequest(LCPTerminateRequest),
    TerminateAck(LCPTerminateAck),
    CodeReject(LCPCodeReject),
    ProtocolReject(LCPProtocolReject),
    EchoRequest(LCPEchoRequest),
    EchoReply(LCPEchoReply),
    DiscardRequest(LCPDiscardRequest),
}

impl Default for LCPPkt {
    fn default() -> Self {
        Self::ConfigureRequest(LCPConfigureRequest::default())
    }
}

impl Serialize for LCPPkt {
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
        }
    }
}

impl LCPPkt {
    fn discriminant(&self) -> u8 {
        match *self {
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
        }
    }

    fn deserialize_with_discriminant<R: Read>(
        &mut self,
        mut r: Take<&mut R>,
        discriminant: &u8,
    ) -> Result<()> {
        match *discriminant {
            LCP_CONFIGURE_REQUEST => {
                let mut tmp = LCPConfigureRequest::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ConfigureRequest(tmp);
            }
            LCP_CONFIGURE_ACK => {
                let mut tmp = LCPConfigureAck::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ConfigureAck(tmp);
            }
            LCP_CONFIGURE_NAK => {
                let mut tmp = LCPConfigureNak::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ConfigureNak(tmp);
            }
            LCP_CONFIGURE_REJECT => {
                let mut tmp = LCPConfigureReject::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ConfigureReject(tmp);
            }
            LCP_TERMINATE_REQUEST => {
                let mut tmp = LCPTerminateRequest::default();
                tmp.deserialize(&mut r)?;

                *self = Self::TerminateRequest(tmp);
            }
            LCP_TERMINATE_ACK => {
                let mut tmp = LCPTerminateAck::default();
                tmp.deserialize(&mut r)?;

                *self = Self::TerminateAck(tmp);
            }
            LCP_CODE_REJECT => {
                let mut tmp = LCPCodeReject::default();
                tmp.deserialize(&mut r)?;

                *self = Self::CodeReject(tmp);
            }
            LCP_PROTOCOL_REJECT => {
                let mut tmp = LCPProtocolReject::default();
                tmp.deserialize(&mut r)?;

                *self = Self::ProtocolReject(tmp);
            }
            LCP_ECHO_REQUEST => {
                let mut tmp = LCPEchoRequest::default();
                tmp.deserialize(&mut r)?;

                *self = Self::EchoRequest(tmp);
            }
            LCP_ECHO_REPLY => {
                let mut tmp = LCPEchoReply::default();
                tmp.deserialize(&mut r)?;

                *self = Self::EchoReply(tmp);
            }
            LCP_DISCARD_REQUEST => {
                let mut tmp = LCPDiscardRequest::default();
                tmp.deserialize(&mut r)?;

                *self = Self::DiscardRequest(tmp);
            }
            _ => return Err(Error::InvalidLCPCode(*discriminant)),
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPFullPkt {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "payload", offset = 4, data_type = "u16"))]
    payload: LCPPkt,
}

impl LCPFullPkt {
    pub fn len(&self) -> u16 {
        4 + self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPConfigureRequest {
    options: Vec<LCPOption>,
}

impl LCPConfigureRequest {
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
pub struct LCPConfigureAck {
    options: Vec<LCPOption>,
}

impl LCPConfigureAck {
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
pub struct LCPConfigureNak {
    options: Vec<LCPOption>,
}

impl LCPConfigureNak {
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
pub struct LCPConfigureReject {
    options: Vec<LCPOption>,
}

impl LCPConfigureReject {
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
pub struct LCPTerminateRequest {
    data: Vec<u8>,
}

impl LCPTerminateRequest {
    pub fn len(&self) -> u16 {
        u16::try_from(self.data.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPTerminateAck {
    data: Vec<u8>,
}

impl LCPTerminateAck {
    pub fn len(&self) -> u16 {
        u16::try_from(self.data.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPCodeReject {
    pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl LCPCodeReject {
    pub fn len(&self) -> u16 {
        u16::try_from(self.pkt.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.pkt.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPProtocolReject {
    protocol: u16,
    pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl LCPProtocolReject {
    pub fn len(&self) -> u16 {
        2 + u16::try_from(self.pkt.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPEchoRequest {
    magic: u32,
    data: Vec<u8>,
}

impl LCPEchoRequest {
    pub fn len(&self) -> u16 {
        4 + u16::try_from(self.data.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPEchoReply {
    magic: u32,
    data: Vec<u8>,
}

impl LCPEchoReply {
    pub fn len(&self) -> u16 {
        4 + u16::try_from(self.data.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPDiscardRequest {
    magic: u32,
    data: Vec<u8>,
}

impl LCPDiscardRequest {
    pub fn len(&self) -> u16 {
        4 + u16::try_from(self.data.len()).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}
