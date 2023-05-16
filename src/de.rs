use crate::Result;

use std::io::Read;
use std::mem;

pub trait Deserialize {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()>;
}

macro_rules! impl_deserialize {
    ($($t:ty) *) => {
        $(
            impl Deserialize for $t {
                fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
                    let mut buf = [0; mem::size_of::<$t>()];
                    r.read_exact(&mut buf)?;

                    *self = <$t>::from_be_bytes(buf);
                    Ok(())
                }
            }
        )*
    };
}

impl_deserialize!(i8 i16 i32 i64 i128 u8 u16 u32 u64 u128);

impl Deserialize for String {
    fn deserialize<R: Read>(&mut self, r: &mut R) -> Result<()> {
        let mut n = 0u8;
        n.deserialize(r)?;

        r.take(n.into()).read_to_string(self)?;
        Ok(())
    }
}
