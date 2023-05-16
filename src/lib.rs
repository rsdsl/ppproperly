pub mod de;
pub use de::*;

pub mod error;
pub use error::*;

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
}
