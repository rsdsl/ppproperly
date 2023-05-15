pub mod error;
pub use error::*;

mod de;
mod ser;

#[cfg(test)]
mod tests {
    use super::{ser::Serialize, *};

    use ppproperly_macros::Serialize;

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
}
