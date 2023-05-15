use crate::Result;

use std::io::Write;

pub trait Serialize {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()>;
}

impl Serialize for i32 {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}
