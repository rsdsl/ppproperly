pub mod de;
pub use de::*;

pub mod error;
pub use error::*;

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
        let tags = vec![
            PPPoETag::HostUniq(vec![13, 37]),
            PPPoETag::GenericError(String::from("err")),
            PPPoETag::Metrics,
        ];

        let mut buf = Vec::new();
        tags.serialize(&mut buf)?;

        assert_eq!(
            &buf,
            &[
                0x01, 0x03, 0x00, 0x02, 0x0d, 0x25, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72, 0x01,
                0x07
            ]
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_pppoe_tags() -> Result<()> {
        let mut tags: Vec<PPPoETag> = Vec::new();

        let buf = [
            0x01, 0x03, 0x00, 0x02, 0x0d, 0x25, 0x02, 0x03, 0x00, 0x03, 0x65, 0x72, 0x72, 0x01,
            0x07,
        ];
        tags.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            tags,
            vec![
                PPPoETag::HostUniq(vec![13, 37]),
                PPPoETag::GenericError(String::from("err")),
                PPPoETag::Metrics
            ]
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padi() -> Result<()> {
        let padi = PPPoEPADIPkt::new(MACAddr::UNSPECIFIED, vec![PPPoETag::HostUniq(vec![13, 37])])?;

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
        let mut padi = PPPoEPADIPkt::default();

        let buf = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x63,
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x02, 0x0d, 0x25,
        ];
        padi.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            padi,
            PPPoEPADIPkt::new(MACAddr::UNSPECIFIED, vec![PPPoETag::HostUniq(vec![13, 37])])?
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_pado() -> Result<()> {
        let pado = PPPoEPADOPkt::new(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            vec![
                PPPoETag::ACName("isp_ac".into()),
                PPPoETag::ServiceName("isp_svc".into()),
            ],
        )?;

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
        let mut pado = PPPoEPADOPkt::default();

        let buf = [
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x88, 0x63,
            0x11, 0x07, 0x00, 0x00, 0x00, 0x15, 0x01, 0x02, 0x00, 0x06, 0x69, 0x73, 0x70, 0x5f,
            0x61, 0x63, 0x01, 0x01, 0x00, 0x07, 0x69, 0x73, 0x70, 0x5f, 0x73, 0x76, 0x63,
        ];
        pado.deserialize(&mut buf.as_ref())?;

        assert_eq!(
            pado,
            PPPoEPADOPkt::new(
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
                [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
                vec![
                    PPPoETag::ACName("isp_ac".into()),
                    PPPoETag::ServiceName("isp_svc".into())
                ]
            )?
        );
        Ok(())
    }

    #[test]
    fn test_serialize_pppoe_padr() -> Result<()> {
        let padr = PPPoEPADRPkt::new(
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01].into(),
            [0x00, 0x00, 0x5e, 0x00, 0x53, 0x02].into(),
            vec![PPPoETag::ServiceName("isp_svc".into())],
        )?;

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
}
