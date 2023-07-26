pub mod chap;
pub use chap::*;

pub mod de;
pub use de::*;

pub mod error;
pub use error::*;

pub mod lcp;
pub use lcp::*;

pub mod pap;
pub use pap::*;

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
    fn test_serialize_pppoe_tags() -> Result<()> {
        let tags: Vec<PppoeTag> = vec![
            PppoeVal::HostUniq(vec![13, 37]).into(),
            PppoeVal::GenericError(String::from("err")).into(),
            PppoeVal::Metrics.into(),
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
        let mut tags: Vec<PppoeTag> = Vec::new();

        let buf = [
            0x01, 0x03, 0x00, 0x02, 0x0d, 0x25, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72, 0x01,
            0x07, 0x00, 0x00,
        ];
        tags.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            tags,
            vec![
                PppoeVal::HostUniq(vec![13, 37]).into(),
                PppoeVal::GenericError(String::from("err")).into(),
                PppoeVal::Metrics.into(),
            ]
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padi() -> Result<()> {
        let padi = PppoePkt::new_padi(
            MacAddr::UNSPECIFIED,
            vec![PppoeVal::HostUniq(vec![13, 37]).into()],
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
        let mut padi = PppoePkt::default();

        let buf = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x63,
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x02, 0x0d, 0x25,
        ];
        padi.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padi,
            PppoePkt::new_padi(
                MacAddr::UNSPECIFIED,
                vec![PppoeVal::HostUniq(vec![13, 37]).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_pado() -> Result<()> {
        let pado = PppoePkt::new_pado(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            vec![
                PppoeVal::AcName("isp_ac".into()).into(),
                PppoeVal::ServiceName("isp_svc".into()).into(),
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
        let mut pado = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0x07, 0x00, 0x00, 0x00, 0x15, 0x01, 0x02, 0x00, 0x06, 0x69, 0x73, 0x70, 0x5f,
            0x61, 0x63, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f, 0x73, 0x76, 0x63,
        ];
        pado.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            pado,
            PppoePkt::new_pado(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                vec![
                    PppoeVal::AcName("isp_ac".into()).into(),
                    PppoeVal::ServiceName("isp_svc".into()).into()
                ]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padr() -> Result<()> {
        let padr = PppoePkt::new_padr(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            vec![PppoeVal::ServiceName("isp_svc".into()).into()],
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
        let mut padr = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x63,
            0x11, 0x19, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
            0x73, 0x76, 0x63,
        ];
        padr.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padr,
            PppoePkt::new_padr(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                vec![PppoeVal::ServiceName("isp_svc".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_pads() -> Result<()> {
        let pads = PppoePkt::new_pads(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            vec![PppoeVal::ServiceName("isp_svc".into()).into()],
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
        let mut pads = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0x65, 0x00, 0x01, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f,
            0x73, 0x76, 0x63,
        ];
        pads.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            pads,
            PppoePkt::new_pads(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                vec![PppoeVal::ServiceName("isp_svc".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padt() -> Result<()> {
        let padt = PppoePkt::new_padt(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            vec![PppoeVal::GenericError("err".into()).into()],
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
        let mut padt = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0xa7, 0x00, 0x01, 0x00, 0x07, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72,
        ];
        padt.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padt,
            PppoePkt::new_padt(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                vec![PppoeVal::GenericError("err".into()).into()]
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_request() -> Result<()> {
        let configure_request = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_configure_request(
                0x41,
                vec![
                    LcpOpt::Mru(1492).into(),
                    LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                        .into(),
                    LcpOpt::MagicNumber(1337).into(),
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
        let mut configure_request = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x01, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_request,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_configure_request(
                    0x41,
                    vec![
                        LcpOpt::Mru(1492).into(),
                        LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                            .into(),
                        LcpOpt::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_ack() -> Result<()> {
        let configure_ack = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_configure_ack(
                0x41,
                vec![
                    LcpOpt::Mru(1492).into(),
                    LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                        .into(),
                    LcpOpt::MagicNumber(1337).into(),
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
        let mut configure_ack = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x02, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_ack.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_ack,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_configure_ack(
                    0x41,
                    vec![
                        LcpOpt::Mru(1492).into(),
                        LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                            .into(),
                        LcpOpt::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_nak() -> Result<()> {
        let configure_nak = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_configure_nak(
                0x41,
                vec![
                    LcpOpt::Mru(1492).into(),
                    LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                        .into(),
                    LcpOpt::MagicNumber(1337).into(),
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
        let mut configure_nak = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x03, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_nak.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_nak,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_configure_nak(
                    0x41,
                    vec![
                        LcpOpt::Mru(1492).into(),
                        LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                            .into(),
                        LcpOpt::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_configure_reject() -> Result<()> {
        let configure_reject = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_configure_reject(
                0x41,
                vec![
                    LcpOpt::Mru(1492).into(),
                    LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                        .into(),
                    LcpOpt::MagicNumber(1337).into(),
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
        let mut configure_reject = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x15, 0xc0, 0x21, 0x04, 0x41, 0x00, 0x13, 0x01, 0x04,
            0x05, 0xd4, 0x03, 0x05, 0xc2, 0x23, 0x05, 0x05, 0x06, 0x00, 0x00, 0x05, 0x39,
        ];
        configure_reject.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            configure_reject,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_configure_reject(
                    0x41,
                    vec![
                        LcpOpt::Mru(1492).into(),
                        LcpOpt::AuthenticationProtocol(AuthProto::Chap(ChapAlgorithm::Md5).into())
                            .into(),
                        LcpOpt::MagicNumber(1337).into()
                    ]
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_terminate_request() -> Result<()> {
        let terminate_request = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_terminate_request(0x41, vec![0x41, 0x41])),
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
        let mut terminate_request = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x05, 0x41, 0x00, 0x06, 0x41, 0x41,
        ];
        terminate_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            terminate_request,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_terminate_request(0x41, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_terminate_ack() -> Result<()> {
        let terminate_ack = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_terminate_ack(0x41, vec![0x41, 0x41])),
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
        let mut terminate_ack = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x06, 0x41, 0x00, 0x06, 0x41, 0x41,
        ];
        terminate_ack.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            terminate_ack,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_terminate_ack(0x41, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_code_reject() -> Result<()> {
        let code_reject = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_code_reject(0x41, vec![0x41, 0x41])),
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

    #[test]
    fn test_deserialize_lcp_code_reject() -> Result<()> {
        let mut code_reject = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x08, 0xc0, 0x21, 0x07, 0x41, 0x00, 0x06, 0x41, 0x41,
        ];
        code_reject.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            code_reject,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_code_reject(0x41, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_protocol_reject() -> Result<()> {
        let protocol_reject = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_protocol_reject(0x41, 0x1337, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        protocol_reject.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0a, 0xc0, 0x21, 0x08, 0x41, 0x00, 0x08, 0x13, 0x37,
                0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_protocol_reject() -> Result<()> {
        let mut protocol_reject = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0a, 0xc0, 0x21, 0x08, 0x41, 0x00, 0x08, 0x13, 0x37,
            0x41, 0x41,
        ];
        protocol_reject.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            protocol_reject,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_protocol_reject(0x41, 0x1337, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_echo_request() -> Result<()> {
        let echo_request = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_echo_request(0x41, 0x1337, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        echo_request.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x09, 0x41, 0x00, 0x0a, 0x00, 0x00,
                0x13, 0x37, 0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_echo_request() -> Result<()> {
        let mut echo_request = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x09, 0x41, 0x00, 0x0a, 0x00, 0x00,
            0x13, 0x37, 0x41, 0x41,
        ];
        echo_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            echo_request,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_echo_request(0x41, 0x1337, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_echo_reply() -> Result<()> {
        let echo_reply = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_echo_reply(0x41, 0x1337, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        echo_reply.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x0a, 0x41, 0x00, 0x0a, 0x00, 0x00,
                0x13, 0x37, 0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_echo_reply() -> Result<()> {
        let mut echo_reply = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x0a, 0x41, 0x00, 0x0a, 0x00, 0x00,
            0x13, 0x37, 0x41, 0x41,
        ];
        echo_reply.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            echo_reply,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_echo_reply(0x41, 0x1337, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_lcp_discard_request() -> Result<()> {
        let discard_request = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_lcp(LcpPkt::new_discard_request(0x41, 0x1337, vec![0x41, 0x41])),
        );

        let mut buf = Vec::new();
        discard_request.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x0b, 0x41, 0x00, 0x0a, 0x00, 0x00,
                0x13, 0x37, 0x41, 0x41
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_lcp_discard_request() -> Result<()> {
        let mut discard_request = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc0, 0x21, 0x0b, 0x41, 0x00, 0x0a, 0x00, 0x00,
            0x13, 0x37, 0x41, 0x41,
        ];
        discard_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            discard_request,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_lcp(LcpPkt::new_discard_request(0x41, 0x1337, vec![0x41, 0x41]))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pap_authenticate_request() -> Result<()> {
        let authenticate_request = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_pap(PapPkt::new_authenticate_request(
                0x41,
                "foo".into(),
                "bar".into(),
            )),
        );

        let mut buf = Vec::new();
        authenticate_request.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0e, 0xc0, 0x23, 0x01, 0x41, 0x00, 0x0c, 0x03, 0x66,
                0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pap_authenticate_request() -> Result<()> {
        let mut authenticate_request = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0e, 0xc0, 0x23, 0x01, 0x41, 0x00, 0x0c, 0x03, 0x66,
            0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72,
        ];
        authenticate_request.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            authenticate_request,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_pap(PapPkt::new_authenticate_request(
                    0x41,
                    "foo".into(),
                    "bar".into()
                ))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pap_authenticate_ack() -> Result<()> {
        let authenticate_ack = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_pap(PapPkt::new_authenticate_ack(0x41, "ok".into())),
        );

        let mut buf = Vec::new();
        authenticate_ack.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x09, 0xc0, 0x23, 0x02, 0x41, 0x00, 0x07, 0x02, 0x6f,
                0x6b
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pap_authenticate_ack() -> Result<()> {
        let mut authenticate_ack = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x09, 0xc0, 0x23, 0x02, 0x41, 0x00, 0x07, 0x02, 0x6f,
            0x6b,
        ];
        authenticate_ack.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            authenticate_ack,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_pap(PapPkt::new_authenticate_ack(0x41, "ok".into()))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pap_authenticate_nak() -> Result<()> {
        let authenticate_nak = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_pap(PapPkt::new_authenticate_nak(0x41, "no".into())),
        );

        let mut buf = Vec::new();
        authenticate_nak.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x09, 0xc0, 0x23, 0x03, 0x41, 0x00, 0x07, 0x02, 0x6e,
                0x6f
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pap_authenticate_nak() -> Result<()> {
        let mut authenticate_nak = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x09, 0xc0, 0x23, 0x03, 0x41, 0x00, 0x07, 0x02, 0x6e,
            0x6f,
        ];
        authenticate_nak.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            authenticate_nak,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_pap(PapPkt::new_authenticate_nak(0x41, "no".into()))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_chap_challenge() -> Result<()> {
        let challenge = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            1,
            PppPkt::new_chap(ChapPkt::new_challenge(0x41, vec![0x13, 0x37], "foo".into())),
        );

        let mut buf = Vec::new();
        challenge.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc2, 0x23, 0x01, 0x41, 0x00, 0x0a, 0x02, 0x13,
                0x37, 0x66, 0x6f, 0x6f
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_chap_challenge() -> Result<()> {
        let mut challenge = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc2, 0x23, 0x01, 0x41, 0x00, 0x0a, 0x02, 0x13,
            0x37, 0x66, 0x6f, 0x6f,
        ];
        challenge.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            challenge,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                1,
                PppPkt::new_chap(ChapPkt::new_challenge(0x41, vec![0x13, 0x37], "foo".into()))
            )
        );
        Ok(())
    }

    #[test]
    fn test_serialize_chap_response() -> Result<()> {
        let response = PppoePkt::new_ppp(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            1,
            PppPkt::new_chap(ChapPkt::new_response(0x41, vec![0x13, 0x37], "foo".into())),
        );

        let mut buf = Vec::new();
        response.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
                0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc2, 0x23, 0x02, 0x41, 0x00, 0x0a, 0x02, 0x13,
                0x37, 0x66, 0x6f, 0x6f
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_chap_response() -> Result<()> {
        let mut response = PppoePkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x88, 0x64,
            0x11, 0x00, 0x00, 0x01, 0x00, 0x0c, 0xc2, 0x23, 0x01, 0x41, 0x00, 0x0a, 0x02, 0x13,
            0x37, 0x66, 0x6f, 0x6f,
        ];
        response.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            response,
            PppoePkt::new_ppp(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                1,
                PppPkt::new_chap(ChapPkt::new_response(0x41, vec![0x13, 0x37], "foo".into()))
            )
        );
        Ok(())
    }
}
