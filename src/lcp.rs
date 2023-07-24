use crate::{Deserialize, Error, Result, Serialize};

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

#[derive(Debug, Eq, PartialEq)]
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

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LCPFullPkt {
    #[ppproperly(discriminant_for(field = "payload", data_type = "u8"))]
    identifier: u8,
    #[ppproperly(len_for(field = "payload", offset = 4))]
    payload: LCPPkt,
}
