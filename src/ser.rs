use crate::Result;

use std::io::Write;

pub trait Serialize {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()>;
}

macro_rules! impl_serialize {
    ($($t:ty) *) => {
        $(
            impl Serialize for $t {
                fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
                    w.write_all(&self.to_be_bytes())?;
                    Ok(())
                }
            }
        )*
    };
}

impl_serialize!(i8 i16 i32 i64 i128 u8 u16 u32 u64 u128);
