mod de;
mod ser;

pub mod error;
pub use error::*;

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
}
