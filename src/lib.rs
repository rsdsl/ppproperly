pub mod de;
pub use de::*;

pub mod error;
pub use error::*;

pub mod lcp;
pub use lcp::*;

pub mod ppp;
pub use ppp::*;

pub mod pppoe;
pub use pppoe::*;

pub mod ser;
pub use ser::*;

pub mod types;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::{de::Deserialize, ser::Serialize, *};

    use ppproperly_macros::{Deserialize, Serialize};

    #[test]
    fn test_derive_serialize() -> Result<()> {
        #[derive(Serialize)]
        struct Foo {
            bar: i32,
        }

        let foo = Foo { bar: 1337 };

        let mut buf = Vec::new();
        foo.serialize(&mut buf)?;

        assert_eq!(&buf, &1337_i32.to_be_bytes());
        Ok(())
    }

    #[test]
    fn test_derive_deserialize() -> Result<()> {
        #[derive(Deserialize)]
        struct Foo {
            bar: i32,
        }

        let mut foo = Foo { bar: 0 };

        let buf = 1337_i32.to_be_bytes();
        foo.deserialize(&mut buf.as_ref())?;

        assert_eq!(foo.bar, 1337);
        Ok(())
    }

    #[test]
    fn test_serialize_vertype() -> Result<()> {
        let ver_type = VerType::default();

        let mut buf = Vec::new();
        ver_type.serialize(&mut buf)?;

        assert_eq!(&buf, &0x11_u8.to_be_bytes());
        Ok(())
    }

    #[test]
    fn test_deserialize_vertype() -> Result<()> {
        let mut ver_type = VerType(0);

        let buf = 0x11_u8.to_be_bytes();
        ver_type.deserialize(&mut buf.as_ref())?;

        assert_eq!(ver_type, VerType::default());
        Ok(())
    }

    #[test]
    fn test_serialize_bytes() -> Result<()> {
        let bytes = [0, 1, 2, 3];

        let mut buf = Vec::new();
        bytes.serialize(&mut buf)?;

        assert_eq!(&buf, &[0, 1, 2, 3]);
        Ok(())
    }

    #[test]
    fn test_deserialize_bytes() -> Result<()> {
        let mut bytes: Vec<u8> = Vec::new();

        let buf = [0, 1, 2, 3];
        bytes.deserialize(&mut buf.as_ref())?;

        assert_eq!(&bytes, &[0, 1, 2, 3]);
        Ok(())
    }

    #[test]
    fn test_serialize_str() -> Result<()> {
        let s = "Hello, World!";

        let mut buf = Vec::new();
        s.serialize(&mut buf)?;

        assert_eq!(&buf, "\x0dHello, World!".as_bytes());
        Ok(())
    }

    #[test]
    fn test_deserialize_string() -> Result<()> {
        let mut s = String::new();

        let mut buf = "\x0dHello, World!?".as_bytes();
        s.deserialize(&mut buf)?;

        assert_eq!(s, String::from("Hello, World!"));
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_header() -> Result<()> {
        let header = PPPoEHeader {
            dst_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            src_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            ether_type: EtherType::PPPoED,
            ver_type: VerType::default(),
            code: PPPoECode::Padt,
            session_id: 1337,
            len: 0,
        };

        let mut buf = Vec::new();
        header.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
                0x11, 0xa7, 0x05, 0x39, 0x00, 0x00
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_header() -> Result<()> {
        let mut header = PPPoEHeader::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0xa7, 0x05, 0x39, 0x00, 0x00,
        ];
        header.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            header,
            PPPoEHeader {
                dst_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                src_mac: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                ether_type: EtherType::PPPoED,
                ver_type: VerType::default(),
                code: PPPoECode::Padt,
                session_id: 1337,
                len: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_tags() -> Result<()> {
        let tags: Vec<PPPoETag> = vec![
            PPPoETagPayload::HostUniq(vec![13, 37]).into(),
            PPPoETagPayload::GenericError(String::from("err")).into(),
            PPPoETagPayload::Metrics.into(),
        ];

        let mut buf = Vec::new();
        tags.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x01, 0x03, 0x00, 0x02, 0x0d, 0x25, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72, 0x01,
                0x07, 0x00, 0x00,
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_tags() -> Result<()> {
        let mut tags: Vec<PPPoETag> = Vec::new();

        let buf = [
            0x01, 0x03, 0x00, 0x02, 0x0d, 0x25, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72, 0x01,
            0x07, 0x00, 0x00,
        ];
        tags.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            tags,
            vec![
                PPPoETagPayload::HostUniq(vec![13, 37]).into(),
                PPPoETagPayload::GenericError(String::from("err")).into(),
                PPPoETagPayload::Metrics.into(),
            ]
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padi() -> Result<()> {
        let padi = PPPoEFullPkt::new_padi(
            MACAddr::UNSPECIFIED,
            vec![PPPoETagPayload::HostUniq(vec![13, 37]).into()],
        );

        let mut buf = Vec::new();
        padi.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x63,
                0x11, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x02, 0x0d, 0x25
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_padi() -> Result<()> {
        let mut padi = PPPoEFullPkt::default();

        let buf = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x63,
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x02, 0x0d, 0x25,
        ];
        padi.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padi,
            PPPoEFullPkt::new_padi(
                MACAddr::UNSPECIFIED,
                vec![PPPoETagPayload::HostUniq(vec![13, 37]).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_pado() -> Result<()> {
        let pado = PPPoEFullPkt::new_pado(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            vec![
                PPPoETagPayload::ACName("isp_ac".into()).into(),
                PPPoETagPayload::ServiceName("isp_svc".into()).into(),
            ],
        );

        let mut buf = Vec::new();
        pado.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
                0x11, 0x07, 0x00, 0x00, 0x00, 0x15, 0x01, 0x02, 0x00, 0x06, 0x69, 0x73, 0x70, 0x5f,
                0x61, 0x63, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f, 0x73, 0x76, 0x63
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_pado() -> Result<()> {
        let mut pado = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0x07, 0x00, 0x00, 0x00, 0x15, 0x01, 0x02, 0x00, 0x06, 0x69, 0x73, 0x70, 0x5f,
            0x61, 0x63, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f, 0x73, 0x76, 0x63,
        ];
        pado.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            pado,
            PPPoEFullPkt::new_pado(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                vec![
                    PPPoETagPayload::ACName("isp_ac".into()).into(),
                    PPPoETagPayload::ServiceName("isp_svc".into()).into()
                ]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padr() -> Result<()> {
        let padr = PPPoEFullPkt::new_padr(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            vec![PPPoETagPayload::ServiceName("isp_svc".into()).into()],
        );

        let mut buf = Vec::new();
        padr.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x63,
                0x11, 0x19, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
                0x73, 0x76, 0x63
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_padr() -> Result<()> {
        let mut padr = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x63,
            0x11, 0x19, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
            0x73, 0x76, 0x63,
        ];
        padr.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padr,
            PPPoEFullPkt::new_padr(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                vec![PPPoETagPayload::ServiceName("isp_svc".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_pads() -> Result<()> {
        let pads = PPPoEFullPkt::new_pads(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            vec![PPPoETagPayload::ServiceName("isp_svc".into()).into()],
        );

        let mut buf = Vec::new();
        pads.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
                0x11, 0x65, 0x00, 0x01, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
                0x73, 0x76, 0x63
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_pads() -> Result<()> {
        let mut pads = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0x65, 0x00, 0x01, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
            0x73, 0x76, 0x63,
        ];
        pads.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            pads,
            PPPoEFullPkt::new_pads(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                vec![PPPoETagPayload::ServiceName("isp_svc".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padt() -> Result<()> {
        let padt = PPPoEFullPkt::new_padt(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            vec![PPPoETagPayload::GenericError("err".into()).into()],
        );

        let mut buf = Vec::new();
        padt.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
                0x11, 0xa7, 0x00, 0x01, 0x00, 0x07, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_padt() -> Result<()> {
        let mut padt = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0xa7, 0x00, 0x01, 0x00, 0x07, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72,
        ];
        padt.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padt,
            PPPoEFullPkt::new_padt(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                vec![PPPoETagPayload::GenericError("err".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_request() -> Result<()> {
        let configure_request = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_configure_request(
                0x41,
                vec![
                    LCPOptionPayload::MRU(1492).into(),
                    LCPOptionPayload::AuthenticationProtocol(
                        AuthProtocol::Chap(ChapAlgorithm::Md5).into(),
                    )
                    .into(),
                    LCPOptionPayload::MagicNumber(1337).into(),
                ],
            )),
        );

        let mut buf = Vec::new();
        configure_request.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x01, 0x41, 0x00, 0x13, 0x01, 0x04,
                0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_configure_request() -> Result<()> {
        let mut configure_request = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x01, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_request,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_configure_request(
                    0x41,
                    vec![
                        LCPOptionPayload::MRU(1492).into(),
                        LCPOptionPayload::AuthenticationProtocol(
                            AuthProtocol::Chap(ChapAlgorithm::Md5).into()
                        )
                        .into(),
                        LCPOptionPayload::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_ack() -> Result<()> {
        let configure_ack = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_configure_ack(
                0x41,
                vec![
                    LCPOptionPayload::MRU(1492).into(),
                    LCPOptionPayload::AuthenticationProtocol(
                        AuthProtocol::Chap(ChapAlgorithm::Md5).into(),
                    )
                    .into(),
                    LCPOptionPayload::MagicNumber(1337).into(),
                ],
            )),
        );

        let mut buf = Vec::new();
        configure_ack.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x02, 0x41, 0x00, 0x13, 0x01, 0x04,
                0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_configure_ack() -> Result<()> {
        let mut configure_ack = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x02, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_ack.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_ack,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_configure_ack(
                    0x41,
                    vec![
                        LCPOptionPayload::MRU(1492).into(),
                        LCPOptionPayload::AuthenticationProtocol(
                            AuthProtocol::Chap(ChapAlgorithm::Md5).into()
                        )
                        .into(),
                        LCPOptionPayload::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_nak() -> Result<()> {
        let configure_nak = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_configure_nak(
                0x41,
                vec![
                    LCPOptionPayload::MRU(1492).into(),
                    LCPOptionPayload::AuthenticationProtocol(
                        AuthProtocol::Chap(ChapAlgorithm::Md5).into(),
                    )
                    .into(),
                    LCPOptionPayload::MagicNumber(1337).into(),
                ],
            )),
        );

        let mut buf = Vec::new();
        configure_nak.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x03, 0x41, 0x00, 0x13, 0x01, 0x04,
                0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_configure_nak() -> Result<()> {
        let mut configure_nak = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x03, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_nak.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_nak,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_configure_nak(
                    0x41,
                    vec![
                        LCPOptionPayload::MRU(1492).into(),
                        LCPOptionPayload::AuthenticationProtocol(AuthProtocol::Chap(
                            ChapAlgorithm::Md5
                        ))
                        .into(),
                        LCPOptionPayload::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_reject() -> Result<()> {
        let configure_reject = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_configure_reject(
                0x41,
                vec![
                    LCPOptionPayload::MRU(1492).into(),
                    LCPOptionPayload::AuthenticationProtocol(
                        AuthProtocol::Chap(ChapAlgorithm::Md5).into(),
                    )
                    .into(),
                    LCPOptionPayload::MagicNumber(1337).into(),
                ],
            )),
        );

        let mut buf = Vec::new();
        configure_reject.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x04, 0x41, 0x00, 0x13, 0x01, 0x04,
                0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_configure_reject() -> Result<()> {
        let mut configure_reject = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x04, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_reject.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_reject,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_configure_reject(
                    0x41,
                    vec![
                        LCPOptionPayload::MRU(1492).into(),
                        LCPOptionPayload::AuthenticationProtocol(AuthProtocol::Chap(
                            ChapAlgorithm::Md5
                        ))
                        .into(),
                        LCPOptionPayload::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_terminate_request() -> Result<()> {
        let terminate_request = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_terminate_request(0x41, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        terminate_request.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x05, 0x41, 0x00, 0x06, 0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_terminate_request() -> Result<()> {
        let mut terminate_request = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x05, 0x41, 0x00, 0x06, 0x41, 0x41,
        ];
        terminate_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            terminate_request,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_terminate_request(0x41, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_terminate_ack() -> Result<()> {
        let terminate_ack = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_terminate_ack(0x41, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        terminate_ack.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x06, 0x41, 0x00, 0x06, 0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_terminate_ack() -> Result<()> {
        let mut terminate_ack = PPPoEFullPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x06, 0x41, 0x00, 0x06, 0x41, 0x41,
        ];
        terminate_ack.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            terminate_ack,
            PPPoEFullPkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PPPFullPkt::new_lcp(LCPFullPkt::new_terminate_ack(0x41, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_code_reject() -> Result<()> {
        let code_reject = PPPoEFullPkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PPPFullPkt::new_lcp(LCPFullPkt::new_code_reject(0x41, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        code_reject.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x07, 0x41, 0x00, 0x06, 0x41, 0x41
            ]
        );
        Ok(())
    }
}
