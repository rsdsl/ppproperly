use crate::{Deserialize, Error, IpCompressionProtocol, Ipv4Addr, Result, Serialize};

use std::fmt;
use std::io::{Read, Write};

use ppproperly_macros::{Deserialize, Serialize};

pub const IPCP_CONFIGURE_REQUEST: u8 = 1;
pub const IPCP_CONFIGURE_ACK: u8 = 2;
pub const IPCP_CONFIGURE_NAK: u8 = 3;
pub const IPCP_CONFIGURE_REJECT: u8 = 4;
pub const IPCP_TERMINATE_REQUEST: u8 = 5;
pub const IPCP_TERMINATE_ACK: u8 = 6;
pub const IPCP_CODE_REJECT: u8 = 7;

// The IP-Addresses option is deprecated and won't be implemented by me.
// Contributions are welcome.
pub const OPT_IP_COMPRESSION_PROTOCOL: u8 = 2;
pub const OPT_IP_ADDRESS: u8 = 3;
pub const OPT_PRIMARY_DNS: u8 = 129;
pub const OPT_SECONDARY_DNS: u8 = 131;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcpOpt {
    IpCompressionProtocol(IpCompressionProtocol),
    IpAddr(Ipv4Addr),
    PrimaryDns(Ipv4Addr),
    SecondaryDns(Ipv4Addr),
    Unhandled(u8, Vec<u8>),
}

impl Serialize for IpcpOpt {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::IpCompressionProtocol(payload) => payload.serialize(w),
            Self::IpAddr(payload) => payload.serialize(w),
            Self::PrimaryDns(payload) => payload.serialize(w),
            Self::SecondaryDns(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl IpcpOpt {
    fn discriminant(&self) -> u8 {
        match self {
            Self::IpCompressionProtocol(_) => OPT_IP_COMPRESSION_PROTOCOL,
            Self::IpAddr(_) => OPT_IP_ADDRESS,
            Self::PrimaryDns(_) => OPT_PRIMARY_DNS,
            Self::SecondaryDns(_) => OPT_SECONDARY_DNS,
            Self::Unhandled(ty, _) => *ty,
        }
    }

    fn len(&self) -> u8 {
        match self {
            Self::IpCompressionProtocol(payload) => payload.len(),
            Self::IpAddr(_) => 4,
            Self::PrimaryDns(_) => 4,
            Self::SecondaryDns(_) => 4,
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled ipcp option {} length {} exceeds 255",
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
            OPT_IP_COMPRESSION_PROTOCOL => {
                let mut tmp = IpCompressionProtocol::default();

                tmp.deserialize(r)?;
                *self = Self::IpCompressionProtocol(tmp);
            }
            OPT_IP_ADDRESS => {
                let mut tmp = Ipv4Addr::default();

                tmp.deserialize(r)?;
                *self = Self::IpAddr(tmp);
            }
            OPT_PRIMARY_DNS => {
                let mut tmp = Ipv4Addr::default();

                tmp.deserialize(r)?;
                *self = Self::PrimaryDns(tmp);
            }
            OPT_SECONDARY_DNS => {
                let mut tmp = Ipv4Addr::default();

                tmp.deserialize(r)?;
                *self = Self::SecondaryDns(tmp);
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
pub struct IpcpOption {
    #[ppproperly(discriminant_for(field = "value", data_type = "u8"))]
    #[ppproperly(len_for(field = "value", offset = 2, data_type = "u8"))]
    pub value: IpcpOpt,
}

impl IpcpOption {
    pub fn len(&self) -> u8 {
        2 + self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 2
    }
}

impl From<IpcpOpt> for IpcpOption {
    fn from(value: IpcpOpt) -> Self {
        Self { value }
    }
}

impl Serialize for [IpcpOption] {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        for option in self {
            option.serialize(w)?;
        }

        Ok(())
    }
}

impl Deserialize for Vec<IpcpOption> {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        while r.bytes().size_hint().0 > 0 {
            let mut tmp = IpcpOption::from(IpcpOpt::IpAddr(Ipv4Addr::default()));

            tmp.deserialize(r)?;
            self.push(tmp);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcpData {
    ConfigureRequest(IpcpConfigureRequest),
    ConfigureAck(IpcpConfigureAck),
    ConfigureNak(IpcpConfigureNak),
    ConfigureReject(IpcpConfigureReject),
    TerminateRequest(IpcpTerminateRequest),
    TerminateAck(IpcpTerminateAck),
    CodeReject(IpcpCodeReject),
    Unhandled(u8, Vec<u8>),
}

impl Default for IpcpData {
    fn default() -> Self {
        Self::ConfigureRequest(IpcpConfigureRequest::default())
    }
}

impl Serialize for IpcpData {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Self::ConfigureRequest(payload) => payload.serialize(w),
            Self::ConfigureAck(payload) => payload.serialize(w),
            Self::ConfigureNak(payload) => payload.serialize(w),
            Self::ConfigureReject(payload) => payload.serialize(w),
            Self::TerminateRequest(payload) => payload.serialize(w),
            Self::TerminateAck(payload) => payload.serialize(w),
            Self::CodeReject(payload) => payload.serialize(w),
            Self::Unhandled(_, payload) => w.write_all(payload).map_err(Error::from),
        }
    }
}

impl IpcpData {
    fn discriminant(&self) -> u8 {
        match self {
            Self::ConfigureRequest(_) => IPCP_CONFIGURE_REQUEST,
            Self::ConfigureAck(_) => IPCP_CONFIGURE_ACK,
            Self::ConfigureNak(_) => IPCP_CONFIGURE_NAK,
            Self::ConfigureReject(_) => IPCP_CONFIGURE_REJECT,
            Self::TerminateRequest(_) => IPCP_TERMINATE_REQUEST,
            Self::TerminateAck(_) => IPCP_TERMINATE_ACK,
            Self::CodeReject(_) => IPCP_CODE_REJECT,
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
            Self::Unhandled(ty, payload) => payload.len().try_into().unwrap_or_else(|_| {
                panic!(
                    "unhandled ipcp code {} length {} exceeds 65535",
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
            IPCP_CONFIGURE_REQUEST => {
                let mut tmp = IpcpConfigureRequest::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureRequest(tmp);
            }
            IPCP_CONFIGURE_ACK => {
                let mut tmp = IpcpConfigureAck::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureAck(tmp);
            }
            IPCP_CONFIGURE_NAK => {
                let mut tmp = IpcpConfigureNak::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureNak(tmp);
            }
            IPCP_CONFIGURE_REJECT => {
                let mut tmp = IpcpConfigureReject::default();

                tmp.deserialize(r)?;
                *self = Self::ConfigureReject(tmp);
            }
            IPCP_TERMINATE_REQUEST => {
                let mut tmp = IpcpTerminateRequest::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateRequest(tmp);
            }
            IPCP_TERMINATE_ACK => {
                let mut tmp = IpcpTerminateAck::default();

                tmp.deserialize(r)?;
                *self = Self::TerminateAck(tmp);
            }
            IPCP_CODE_REJECT => {
                let mut tmp = IpcpCodeReject::default();

                tmp.deserialize(r)?;
                *self = Self::CodeReject(tmp);
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
pub struct IpcpPkt {
    #[ppproperly(discriminant_for(field = "data", data_type = "u8"))]
    pub identifier: u8,
    #[ppproperly(len_for(field = "data", offset = 4, data_type = "u16"))]
    pub data: IpcpData,
}

impl IpcpPkt {
    pub fn new_configure_request(identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self {
            identifier,
            data: IpcpData::ConfigureRequest(IpcpConfigureRequest { options }),
        }
    }

    pub fn new_configure_ack(identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self {
            identifier,
            data: IpcpData::ConfigureAck(IpcpConfigureAck { options }),
        }
    }

    pub fn new_configure_nak(identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self {
            identifier,
            data: IpcpData::ConfigureNak(IpcpConfigureNak { options }),
        }
    }

    pub fn new_configure_reject(identifier: u8, options: Vec<IpcpOption>) -> Self {
        Self {
            identifier,
            data: IpcpData::ConfigureReject(IpcpConfigureReject { options }),
        }
    }

    pub fn new_terminate_request(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: IpcpData::TerminateRequest(IpcpTerminateRequest { data }),
        }
    }

    pub fn new_terminate_ack(identifier: u8, data: Vec<u8>) -> Self {
        Self {
            identifier,
            data: IpcpData::TerminateAck(IpcpTerminateAck { data }),
        }
    }

    pub fn new_code_reject(identifier: u8, pkt: Vec<u8>) -> Self {
        Self {
            identifier,
            data: IpcpData::CodeReject(IpcpCodeReject { pkt }),
        }
    }

    pub fn len(&self) -> u16 {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 4
    }
}

impl fmt::Display for IpcpPkt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPCP id={}: ", self.identifier)?;
        match &self.data {
            IpcpData::ConfigureRequest(cfg_req) => cfg_req.fmt(f),
            IpcpData::ConfigureAck(cfg_ack) => cfg_ack.fmt(f),
            IpcpData::ConfigureNak(cfg_nak) => cfg_nak.fmt(f),
            IpcpData::ConfigureReject(cfg_rej) => cfg_rej.fmt(f),
            IpcpData::TerminateRequest(term_req) => term_req.fmt(f),
            IpcpData::TerminateAck(term_ack) => term_ack.fmt(f),
            IpcpData::CodeReject(code_rej) => code_rej.fmt(f),
            IpcpData::Unhandled(ty, payload) => write!(f, "uc={} {:?}", ty, payload),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpConfigureRequest {
    pub options: Vec<IpcpOption>,
}

impl IpcpConfigureRequest {
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

impl fmt::Display for IpcpConfigureRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cfg-Req {:?}", self.options)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpConfigureAck {
    pub options: Vec<IpcpOption>,
}

impl IpcpConfigureAck {
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

impl fmt::Display for IpcpConfigureAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cfg-Ack {:?}", self.options)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpConfigureNak {
    pub options: Vec<IpcpOption>,
}

impl IpcpConfigureNak {
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

impl fmt::Display for IpcpConfigureNak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cfg-Nak {:?}", self.options)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpConfigureReject {
    pub options: Vec<IpcpOption>,
}

impl IpcpConfigureReject {
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

impl fmt::Display for IpcpConfigureReject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cfg-Rej {:?}", self.options)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpTerminateRequest {
    pub data: Vec<u8>,
}

impl IpcpTerminateRequest {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Display for IpcpTerminateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Term-Req {}",
            std::str::from_utf8(&self.data).unwrap_or(&format!("{:?}", self.data))
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpTerminateAck {
    pub data: Vec<u8>,
}

impl IpcpTerminateAck {
    pub fn len(&self) -> u16 {
        self.data.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Display for IpcpTerminateAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Term-Ack {}",
            std::str::from_utf8(&self.data).unwrap_or(&format!("{:?}", self.data))
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcpCodeReject {
    pub pkt: Vec<u8>, // Vec makes MRU truncating easier without overwriting (de)ser impls.
}

impl IpcpCodeReject {
    pub fn len(&self) -> u16 {
        self.pkt.len().try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.pkt.is_empty()
    }
}

impl fmt::Display for IpcpCodeReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code-Rej {:?}", self.pkt)
    }
}
